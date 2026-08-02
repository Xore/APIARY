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
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Optional

from sklearn.ensemble import IsolationForest
from pyod.models.hbos import HBOS

from models.lifecycle import prune_old_versions, write_version_metadata

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------
N_FEATURES    = 15
CONTAMINATION = 0.01   # assume ~1% of events are anomalous
N_ESTIMATORS  = 200

# Normalisation ceiling for cmd_count / cmd_count_norm (#277), shared with
# models/lstm_autoencoder.py's featurise_temporal() so both models agree on
# what "a lot of commands in one session" means.
MAX_CMD_COUNT = 200

# Acceptance gate (#65, docs/ml-worker-plan.md §11.1) -- unsupervised
# retraining has no labels to score precision/recall against, so the bar is
# label-free: does the candidate score without error, and does its anomaly
# rate on a holdout slice stay within tolerance of the model it would
# replace, measured on the SAME slice so the comparison isn't confounded by
# traffic changing between two different measurements in time.
HOLDOUT_FRACTION = 0.1   # newest slice of each retrain batch, never trained on
HOLDOUT_MIN       = 50   # floor regardless of fraction, so small batches still get a real check
ACCEPT_TOLERANCE  = 3.0  # candidate's holdout anomaly rate may be at most this many times the reference rate

# Worst-case retrain() cost bound (#62 task 33 -- "bounded HBOS", not just
# "usually fast"). IsolationForest.fit() is O(n_samples * N_ESTIMATORS *
# log(n_samples) * N_FEATURES); HBOS.fit() builds per-feature histograms in
# O(n_samples * N_FEATURES). Both scale linearly in n_samples with no other
# cap upstream -- worker.py's retrain trigger fetches everything matching a
# 24h window across 2 index patterns, which is unbounded on a busy honeypot.
# Capping the actual fit() input here makes the bound a property of the
# model, not something every caller has to remember to enforce.
MAX_TRAIN_SAMPLES = 20_000

# #190: n_jobs=-1 requests one worker per HOST-visible core (this codebase's
# reference deployment has 16), not per the container's actual `cpus: "2.0"`
# cgroup quota -- the same category of mismatch that caused LSTM-AE's real
# thread-pool livelock (models/lstm_autoencoder.py, discovered the same
# session this was audited). IsolationForest.predict()/score_samples() use
# this setting too, not just fit() -- so an oversubscribed pool here sits on
# the hot per-event scoring path, not just the occasional retrain. Bounded to
# match the compose file's cpu limit instead of auto-detecting a core count
# the scheduler will never actually grant this container.
N_JOBS = int(os.getenv("ML_N_JOBS", "2"))

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


# ------------------------------------------------------------------
# Real-document field extraction (#62 task 32/33).
#
# A real honeypot-v2-*/suricata-v2-* document nests everything under
# honeypot.*/source.*/destination.*/network.*/user.*/suricata.eve.* --
# see docs/ml-worker-plan.md §5.3 and ml-worker/tests/fixtures.py for the
# ground-truth shape each helper below reads, cited to the actual sensor
# logging source (not assumed). ECS-promoted fields are read first where
# they exist (the one place field names are consistent across sensors);
# per-sensor honeypot.* fields fill in what the geoip-honeypot ingest
# pipeline doesn't promote (see issue #132 for why some of that is a
# pipeline gap rather than something readable from here at all).
# ------------------------------------------------------------------

def _get_ip(src: dict) -> str:
    ip = (src.get("source") or {}).get("ip")
    if ip:
        return ip
    hp = src.get("honeypot") or {}
    if hp.get("src_ip"):
        return hp["src_ip"]
    eve = ((src.get("suricata") or {}).get("eve")) or {}
    return eve.get("src_ip") or ""


def _get_port(src: dict) -> int:
    dest = src.get("destination") or {}
    if dest.get("port") is not None:
        return int(dest["port"])
    hp = src.get("honeypot") or {}
    if hp.get("dst_port") is not None:
        return int(hp["dst_port"])
    if hp.get("port") is not None:
        return int(hp["port"])
    eve = ((src.get("suricata") or {}).get("eve")) or {}
    if eve.get("dest_port") is not None:
        return int(eve["dest_port"])
    return 0


def _get_transport_proto(src: dict) -> Optional[str]:
    """Transport-layer protocol (tcp/udp/icmp) for _proto_enc -- distinct
    from application-layer identifiers like Cowrie's "ssh", multipot's
    "vnc"/"redis"/"mysql"/etc (its own `proto` field is the *application*
    protocol -- confirmed by reading multipot/protocols.go's actual
    log.emit() call sites, not assumed), or Conpot's "modbus" data_type --
    none of which _proto_enc was ever meant to encode."""
    net = src.get("network") or {}
    if net.get("transport"):
        return net["transport"]
    hp = src.get("honeypot") or {}
    conn = hp.get("connection")
    if isinstance(conn, dict) and conn.get("transport"):
        return conn["transport"]  # Dionaea: connection.protocol is app-layer (e.g. "smbd"); .transport is tcp/udp
    if hp.get("eventid", "").startswith("cowrie."):
        return "tcp"  # SSH/Telnet are structurally TCP-only; Cowrie's own log never states it
    if hp.get("sensor") == "http-honeypot":
        return "tcp"  # HTTP(S) is structurally TCP-only
    if "event" in hp and "eventid" not in hp:
        return "tcp"  # multipot's own event shape; every one of its listeners is TCP (main.go has no UDP path)
    # Conpot exposes neither a transport field nor a fixed single transport
    # across its personas (SNMP is UDP, everything else here is TCP) -- no
    # honest inference available, left unset.
    return net.get("protocol") or hp.get("protocol")


def _get_username(src: dict) -> str:
    user = (src.get("user") or {}).get("name")
    if user:
        return user
    return (src.get("honeypot") or {}).get("username") or ""


def _get_password(src: dict) -> str:
    return (src.get("honeypot") or {}).get("password") or ""


def _get_duration(src: dict) -> float:
    # Only Cowrie's cowrie.session.closed event carries this; every other
    # source has no session-duration concept in its own log format.
    return float((src.get("honeypot") or {}).get("duration") or 0.0)


@dataclass
class RetrainResult:
    """Evidence for one retrain() call -- accepted or not, and why. Returned
    to the caller (worker.py) so it can be written to ml-worker-metrics
    (#65, docs/ml-worker-plan.md §11.4); also embedded verbatim in the
    accepted version's metadata sidecar (lifecycle.write_version_metadata)."""
    accepted: bool
    reason: str
    train_samples: int
    holdout_samples: int
    anomaly_rate_new: float
    anomaly_rate_previous: Optional[float]


def _accept_decision(candidate_rate: float, previous_rate: Optional[float]) -> tuple:
    """The acceptance policy itself (#65, docs/ml-worker-plan.md §11.1),
    isolated from fitting/scoring so it's testable with plain floats rather
    than needing a real stochastic model fit to land on a particular
    outcome. Returns (accepted, reason)."""
    reference_rate = previous_rate if previous_rate is not None else CONTAMINATION
    ceiling = max(reference_rate, CONTAMINATION) * ACCEPT_TOLERANCE
    if candidate_rate <= ceiling:
        return True, "accepted"
    return False, (
        f"holdout anomaly rate {candidate_rate:.3f} exceeds {ceiling:.3f} "
        f"(reference {reference_rate:.3f} x tolerance {ACCEPT_TOLERANCE})"
    )


def _percentile_normalize(raw: float, p50: float, p99: float, lower_is_more_anomalous: bool) -> float:
    """Map a raw model score to [0, 1] using THIS model's own observed p50
    (typical/unremarkable) and p99 (near the top of what its own fit
    actually produced) as anchors, instead of a fixed linear formula that
    assumes a hand-picked "typical range" (#174).

    Found live: IsolationForest.score_samples() commonly ran ~-0.48 for
    real production traffic, nowhere near the old formula's assumed
    center of 0 -- and HBOS.decision_function() commonly ran 26-32, while
    the old formula divided by 10 and clipped, so every real score
    saturated at the ceiling (100% of a 4000-event live sample). Anchoring
    to p50/p99 computed fresh from each retrain's own holdout data means
    this can't go stale the way a hand-picked constant did: it recalibrates
    every retrain to whatever that fit actually produced.

    p50 maps to 0.2 (typical, unremarkable -- half of everything is
    literally this ordinary), p99 maps to 0.95 (only the top 1% of this
    model's OWN fit gets this high, consistent with CONTAMINATION=0.01).
    Extrapolates and clips beyond either anchor.
    """
    if p99 == p50:
        return 0.5
    frac = (p50 - raw) / (p50 - p99) if lower_is_more_anomalous else (raw - p50) / (p99 - p50)
    return float(np.clip(0.2 + frac * 0.75, 0.0, 1.0))


def _anomaly_rate(iso: IsolationForest, hbos: HBOS, X: np.ndarray) -> float:
    """Fraction of X either model's OWN contamination-driven decision
    boundary calls anomalous -- IsolationForest.predict()==-1,
    HBOS.predict()==1 -- not an externally chosen score cutoff, so this rate
    reflects what each model actually learned rather than an arbitrary
    threshold picked to make the comparison come out a certain way."""
    if len(X) == 0:
        return 0.0
    iso_flag = iso.predict(X) == -1
    hbos_flag = hbos.predict(X) == 1
    return float(np.logical_or(iso_flag, hbos_flag).mean())


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

    def extract_features(self, src: dict, cmd_count: int = 0,
                          failed_logins_1h: int = 0, unique_ports_1h: int = 1,
                          payload_bytes: bytes = b"") -> np.ndarray:
        """Convert a real honeypot-v2-*/suricata-v2-* ES _source dict to a
        feature vector. See the module-level _get_* helpers and
        docs/ml-worker-plan.md §5.3 for exactly where each value is read
        from per sensor.

        cmd_count/failed_logins_1h/unique_ports_1h are now real (#277) --
        the caller supplies them, computed once per batch by
        models.session_features.SessionFeatureTracker (the live/online
        path, worker.py's score_and_write_events()) or
        compute_batch_session_features() (retrain()'s historical batches).
        This mirrors featurise_temporal()'s inter_arrival_s contract in
        models/lstm_autoencoder.py: the stateful bookkeeping (per-session
        counters, rolling 1h windows) lives with the caller, not inside this
        otherwise-pure function. Defaults (0/0/1) are the pre-#277 neutral
        values, kept only so a caller that genuinely has no session/window
        context (most direct unit tests) doesn't have to fabricate one.

        payload_hex remains unwired -- no sensor in this stack's real
        ingest pipeline emits a consistent raw-payload byte field (#277
        remaining scope; see docs/ml-worker-plan.md §5.3).
        """
        ts   = src.get("@timestamp") or src.get("timestamp")
        ip   = _get_ip(src)
        port = _get_port(src)

        username  = _get_username(src)
        password  = _get_password(src)
        duration  = _get_duration(src)

        features = np.array([
            _ts_to_hour(ts),                       # 0
            _ts_to_dow(ts),                        # 1
            min(port, 65535) / 65535.0,            # 2  normalised port
            _proto_enc(_get_transport_proto(src)), # 3
            min(duration, 3600) / 3600.0,          # 4  session duration
            min(cmd_count, MAX_CMD_COUNT) / MAX_CMD_COUNT, # 5
            _shannon_entropy(payload_bytes) / 8.0, # 6  payload entropy
            min(len(payload_bytes), 65535) / 65535.0, # 7 payload len
            min(len(username), 128) / 128.0,       # 8
            _str_entropy(password) / 8.0,          # 9
            min(failed_logins_1h, 500) / 500.0,    # 10 failed logins rolling
            min(unique_ports_1h, 65535) / 65535.0, # 11 port scan width
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
        # more negative = more anomalous.
        raw = self.iso.score_samples(features)[0]
        calib = getattr(self.iso, "hp_calib", None)
        if calib is not None:
            return _percentile_normalize(raw, calib["p50"], calib["p99"], lower_is_more_anomalous=True)
        # Fallback for a model saved before #174 (no calibration attached
        # yet) -- the original fixed-range formula, kept only so an
        # in-flight model isn't left with no score() at all until its next
        # retrain recalibrates it.
        return float(np.clip((-raw) * 2, 0.0, 1.0))

    def hbos_score(self, features: np.ndarray) -> float:
        """Return HBOS outlier score normalised to [0, 1]."""
        if self.hbos is None:
            return 0.5
        raw = self.hbos.decision_function(features)[0]
        calib = getattr(self.hbos, "hp_calib", None)
        if calib is not None:
            # pyod convention: higher decision_function = more anomalous
            # (opposite of sklearn's IsolationForest).
            return _percentile_normalize(raw, calib["p50"], calib["p99"], lower_is_more_anomalous=False)
        # Fallback for a model saved before #174 -- see score()'s comment.
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

    def retrain(self, sources: list) -> RetrainResult:
        """Retrain candidate IsoForest/HBOS models and gate promotion on the
        acceptance bar (#65, docs/ml-worker-plan.md §11.1) -- fit on a train
        split, evaluate label-free on a holdout split never trained on, and
        only replace the currently active model if the candidate's holdout
        anomaly rate stays within ACCEPT_TOLERANCE of the outgoing model's
        (or CONTAMINATION, if this is the first-ever retrain). A rejected
        candidate is discarded; the active model keeps serving.

        Capped at MAX_TRAIN_SAMPLES regardless of how many sources the
        caller collected -- see the constant's comment for the cost
        rationale. Keeps the most recent slice on the (reasonable, not
        guaranteed) assumption that callers append in roughly chronological
        order; a cap that's approximately-recent is still a real bound and
        is far better than an unbounded one.

        cmd_count/failed_logins_1h/unique_ports_1h (#277) are computed once
        here via compute_batch_session_features() -- a pure, batch-local
        pass over exactly this capped set of sources, deliberately not
        shared with the live SessionFeatureTracker (see that module's own
        docstring for why a historical retrain batch and "live so far"
        state answer different questions).
        """
        if len(sources) > MAX_TRAIN_SAMPLES:
            sources = sources[-MAX_TRAIN_SAMPLES:]

        n = len(sources)
        if n < 2:
            return RetrainResult(
                accepted=False, reason="not enough data to retrain",
                train_samples=n, holdout_samples=0,
                anomaly_rate_new=0.0, anomaly_rate_previous=None,
            )

        # Local import: models.session_features imports _get_ip/_get_port
        # from this module, so importing it at module scope here would be
        # circular.
        from models.session_features import compute_batch_session_features
        batch_features = compute_batch_session_features(sources)

        # Holdout is the newest slice -- never trained on, evaluated after
        # fitting. sources are the caller's fetch order (worker.py sorts
        # ascending by @timestamp), so this is the most-recent-events split,
        # not a random one.
        holdout_n = min(max(HOLDOUT_MIN, int(n * HOLDOUT_FRACTION)), n - 1)
        train_sources, train_features = sources[:n - holdout_n], batch_features[:n - holdout_n]
        holdout_sources, holdout_features = sources[n - holdout_n:], batch_features[n - holdout_n:]

        X_train = np.vstack([
            self.extract_features(s, **f) for s, f in zip(train_sources, train_features)
        ]).reshape(len(train_sources), N_FEATURES)
        X_holdout = np.vstack([
            self.extract_features(s, **f) for s, f in zip(holdout_sources, holdout_features)
        ]).reshape(len(holdout_sources), N_FEATURES)

        candidate_iso = IsolationForest(
            n_estimators=N_ESTIMATORS,
            contamination=CONTAMINATION,
            random_state=42,
            n_jobs=N_JOBS,
        )
        candidate_hbos = HBOS(contamination=CONTAMINATION)
        try:
            candidate_iso.fit(X_train)
            candidate_hbos.fit(X_train)
            candidate_rate = _anomaly_rate(candidate_iso, candidate_hbos, X_holdout)
            if not np.isfinite(candidate_rate):
                raise ValueError(f"non-finite anomaly rate: {candidate_rate}")
            # #174: calibration anchors travel with the fitted model object
            # itself (joblib.dump/load preserve arbitrary extra attributes,
            # not just sklearn/pyod's own) -- computed from THIS retrain's
            # own holdout, so score()/hbos_score() recalibrate every retrain
            # instead of trusting a constant that can go stale.
            if len(X_holdout) > 0:
                iso_raw_holdout = candidate_iso.score_samples(X_holdout)
                hbos_raw_holdout = candidate_hbos.decision_function(X_holdout)
                candidate_iso.hp_calib = {
                    "p50": float(np.percentile(iso_raw_holdout, 50)),
                    "p99": float(np.percentile(iso_raw_holdout, 99)),
                }
                candidate_hbos.hp_calib = {
                    "p50": float(np.percentile(hbos_raw_holdout, 50)),
                    "p99": float(np.percentile(hbos_raw_holdout, 99)),
                }
        except Exception as exc:
            return RetrainResult(
                accepted=False, reason=f"candidate failed to fit or score holdout: {exc}",
                train_samples=len(train_sources), holdout_samples=len(holdout_sources),
                anomaly_rate_new=0.0, anomaly_rate_previous=None,
            )

        previous_rate = None
        if self.iso is not None and self.hbos is not None:
            previous_rate = _anomaly_rate(self.iso, self.hbos, X_holdout)

        accept, reason = _accept_decision(candidate_rate, previous_rate)
        result = RetrainResult(
            accepted=accept, reason=reason,
            train_samples=len(train_sources), holdout_samples=len(holdout_sources),
            anomaly_rate_new=candidate_rate, anomaly_rate_previous=previous_rate,
        )

        if accept:
            self.iso = candidate_iso
            self.hbos = candidate_hbos
            self._save(result)

        return result

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self, result: RetrainResult) -> None:
        ts = int(time.time())
        iso_path  = os.path.join(self.model_dir, f"isoforest_{ts}.joblib")
        hbos_path = os.path.join(self.model_dir, f"hbos_{ts}.joblib")
        os.makedirs(self.model_dir, exist_ok=True)
        joblib.dump(self.iso,  iso_path)
        joblib.dump(self.hbos, hbos_path)
        # Update symlinks
        _symlink(iso_path,  os.path.join(self.model_dir, "current_isoforest.joblib"))
        _symlink(hbos_path, os.path.join(self.model_dir, "current_hbos.joblib"))
        # Version metadata + retention (#65, docs/ml-worker-plan.md §11.3):
        # the evidence for why this version was promoted, kept next to the
        # model file itself so it survives independent of Elasticsearch
        # retention, and pruning back to MAX_RETAINED_VERSIONS so /models/
        # doesn't grow two files per model every RETRAIN_INTERVAL forever.
        meta = {"timestamp": ts, **asdict(result)}
        write_version_metadata(self.model_dir, "isoforest", ts, meta)
        write_version_metadata(self.model_dir, "hbos", ts, meta)
        prune_old_versions(self.model_dir, "isoforest")
        prune_old_versions(self.model_dir, "hbos")

    def _load_latest(self) -> None:
        iso_link  = os.path.join(self.model_dir, "current_isoforest.joblib")
        hbos_link = os.path.join(self.model_dir, "current_hbos.joblib")
        if os.path.exists(iso_link):
            self.iso  = joblib.load(iso_link)
        if os.path.exists(hbos_link):
            self.hbos = joblib.load(hbos_link)


def _symlink(target: str, link: str) -> None:
    """Atomically point `link` at `target` (#169). Writes a temporary
    symlink in the same directory, then os.replace()s it onto `link` --
    os.replace is an atomic rename on POSIX when source and destination
    share a filesystem (true here: both live directly under model_dir), so
    a process killed between these two calls can never observe `link`
    missing. It's either the previous target or the new one, never absent
    -- unlike the previous remove-then-symlink sequence, which had a window
    where `link` didn't exist at all."""
    directory = os.path.dirname(link) or "."
    temp_link = os.path.join(directory, f".{os.path.basename(link)}.tmp-{os.getpid()}-{time.time_ns()}")
    os.symlink(target, temp_link)
    os.replace(temp_link, link)
