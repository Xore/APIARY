"""
Isolation Forest + HBOS model for point anomaly detection.

Feature engineering is designed for events from:
  - Cowrie (SSH/Telnet honeypot)
  - Dionaea (multi-protocol)
  - Zeek conn/dns/http logs
  - Conpot (ICS)
  - HTTP honeypot

See docs/ml-worker-plan.md §4 and §5 for full feature list.
"""
import os
import math
import time
import joblib
import numpy as np
from datetime import datetime, timezone
from typing import Optional

from sklearn.ensemble import IsolationForest
from pyod.models.hbos import HBOS

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
N_FEATURES    = 15
CONTAMINATION = 0.01   # assume ~1% of events are anomalous
N_ESTIMATORS  = 200

# Known scanner ASNs / Tor exit prefix heuristic (extend as needed)
KNOWN_SCANNER_PREFIXES = {
    "45.33",   # Linode/Akamai scan ranges
    "198.20",  # Shodan
    "66.240",  # Shodan
    "71.6",    # Shodan
    "80.82",   # Shodan
    "89.248",  # Shodan
    "93.120",  # Censys
    "162.142", # Censys
    "167.94",  # Censys
}


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    probs = [v / len(data) for v in freq.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def _str_entropy(s: str) -> float:
    return _shannon_entropy(s.encode("utf-8", errors="replace"))


def _ts_to_hour(ts_str: Optional[str]) -> int:
    if not ts_str:
        return 0
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.hour
    except Exception:
        return 0


def _ts_to_dow(ts_str: Optional[str]) -> int:
    if not ts_str:
        return 0
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.weekday()
    except Exception:
        return 0


def _proto_enc(proto: Optional[str]) -> int:
    return {"tcp": 0, "udp": 1, "icmp": 2}.get((proto or "").lower(), 3)


def _is_known_scanner(ip: Optional[str]) -> int:
    if not ip:
        return 0
    prefix = ".".join(ip.split(".")[:2])
    return 1 if prefix in KNOWN_SCANNER_PREFIXES else 0


class IsoForestModel:
    """
    Wraps IsolationForest + HBOS.
    Both are fitted on the first retrain() call.
    Before first training, scores default to 0.5 (neutral).
    """

    def __init__(self, model_dir: str = "/models") -> None:
        self.model_dir  = model_dir
        self.iso: Optional[IsolationForest] = None
        self.hbos: Optional[HBOS] = None
        self._load_latest()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def extract_features(self, src: dict) -> np.ndarray:
        """Convert a raw ES source dict to a feature vector."""
        ts  = src.get("@timestamp") or src.get("timestamp")
        ip  = src.get("src_ip") or src.get("id.orig_h") or ""
        port = int(src.get("dst_port") or src.get("id.resp_p") or 0)

        payload_hex = src.get("payload_hex", "")
        payload_bytes = bytes.fromhex(payload_hex) if payload_hex else b""

        username  = src.get("username",  "")
        password  = src.get("password",  "")
        cmd_count = int(src.get("cmd_count") or 0)
        duration  = float(src.get("duration") or 0.0)
        failed    = int(src.get("failed_logins_1h") or 0)
        uniq_ports= int(src.get("unique_ports_1h") or 1)

        features = np.array([
            _ts_to_hour(ts),                       # 0
            _ts_to_dow(ts),                        # 1
            min(port, 65535) / 65535.0,            # 2  normalised port
            _proto_enc(src.get("proto")),           # 3
            min(duration, 3600) / 3600.0,          # 4  session duration
            min(cmd_count, 200) / 200.0,           # 5
            _shannon_entropy(payload_bytes) / 8.0, # 6  payload entropy
            min(len(payload_bytes), 65535) / 65535.0, # 7 payload len
            min(len(username), 128) / 128.0,       # 8
            _str_entropy(password) / 8.0,          # 9
            min(failed, 500) / 500.0,              # 10 failed logins rolling
            min(uniq_ports, 65535) / 65535.0,      # 11 port scan width
            _is_known_scanner(ip),                 # 12 bool
            0.0,                                   # 13 reserved: is_tor_exit
            0.0,                                   # 14 reserved: is_vpn
        ], dtype=np.float32)

        return features.reshape(1, -1)

    def score(self, features: np.ndarray) -> float:
        """Return anomaly score in [0, 1] (1 = most anomalous)."""
        if self.iso is None:
            return 0.5
        # sklearn IsoForest: score_samples returns negative scores;
        # more negative = more anomalous. Map to [0, 1].
        raw = self.iso.score_samples(features)[0]
        # Typical range: [-0.5, 0.5] → normalise
        return float(np.clip((-raw) * 2, 0.0, 1.0))

    def hbos_score(self, features: np.ndarray) -> float:
        """Return HBOS outlier score normalised to [0, 1]."""
        if self.hbos is None:
            return 0.5
        raw = self.hbos.decision_function(features)[0]
        # pyod returns unnormalised scores; clip to reasonable range
        return float(np.clip(raw / 10.0, 0.0, 1.0))

    def explain(self, features: np.ndarray, scores: dict) -> str:
        """Generate a human-readable explanation of the anomaly."""
        f = features.flatten()
        parts = []

        if f[11] > 0.01:
            n_ports = int(f[11] * 65535)
            parts.append(f"Port scan: {n_ports} unique ports in last hour")
        if f[6] > 0.6:
            parts.append(f"High payload entropy ({f[6]*8:.1f} bits — possible encryption/packing)")
        if f[10] > 0.1:
            n_fail = int(f[10] * 500)
            parts.append(f"Brute-force: {n_fail} failed logins in last hour")
        if f[12] == 1.0:
            parts.append("Source matches known scanner ASN (Shodan/Censys)")
        if f[4] < 0.005 and f[5] > 0.01:
            parts.append("Very short session with commands (automated exploit attempt)")
        if scores.get("lstm_ae", 0) > 0.85:
            parts.append("Unusual temporal sequence vs. learned baseline (LSTM-AE)")

        if not parts:
            parts.append(f"Statistical outlier (composite score {scores.get('isolation_forest', 0):.2f})")

        return ". ".join(parts) + "."

    def retrain(self, sources: list) -> None:
        """Retrain IsoForest and HBOS on a list of raw ES source dicts."""
        X = np.vstack([self.extract_features(s) for s in sources])
        X = X.reshape(len(sources), N_FEATURES)

        self.iso = IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )
        self.iso.fit(X)

        self.hbos = HBOS(contamination=CONTAMINATION)
        self.hbos.fit(X)

        self._save()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self) -> None:
        ts = int(time.time())
        iso_path  = os.path.join(self.model_dir, f"isoforest_{ts}.joblib")
        hbos_path = os.path.join(self.model_dir, f"hbos_{ts}.joblib")
        os.makedirs(self.model_dir, exist_ok=True)
        joblib.dump(self.iso,  iso_path)
        joblib.dump(self.hbos, hbos_path)
        # Update symlinks
        _symlink(iso_path,  os.path.join(self.model_dir, "current_isoforest.joblib"))
        _symlink(hbos_path, os.path.join(self.model_dir, "current_hbos.joblib"))

    def _load_latest(self) -> None:
        iso_link  = os.path.join(self.model_dir, "current_isoforest.joblib")
        hbos_link = os.path.join(self.model_dir, "current_hbos.joblib")
        if os.path.exists(iso_link):
            self.iso  = joblib.load(iso_link)
        if os.path.exists(hbos_link):
            self.hbos = joblib.load(hbos_link)


def _symlink(target: str, link: str) -> None:
    if os.path.lexists(link):
        os.remove(link)
    os.symlink(target, link)
