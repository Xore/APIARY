"""
LSTM Autoencoder for temporal sequence anomaly detection.

Groups events by src_ip into sliding windows of length SEQ_LEN.
Anomaly = reconstruction loss above threshold.

Based on: CNN-BiLSTM-AE architecture (Park et al., MDPI 2025)
See docs/ml-worker-plan.md §4.2 and §5.2.
"""
import os
import time
import collections
from datetime import datetime
from typing import Optional

import numpy as np
import torch
import torch.nn as nn
from loguru import logger

from models.isolation_forest import (
    _get_ip, _get_port, _get_transport_proto, _proto_enc, _ts_to_hour,
)

SEQ_LEN   = 15    # sliding window length (events per sequence)
INPUT_DIM = 6     # features per timestep (see §5.2 in plan)
HIDDEN_DIM = 64
LATENT_DIM = 16
N_LAYERS   = 2
LR_FINETUNE = 1e-5
FINETUNE_EPOCHS = 5
BATCH_SIZE  = 32

# Bounded CPU fallback (#63) -- mirrors MAX_TRAIN_SAMPLES's rationale in
# models/isolation_forest.py (#62): retrain() builds every overlapping
# length-SEQ_LEN window per src_ip with no other cap upstream. One IP
# dominating worker.py's MAX_TRAIN_SAMPLES-capped fetch could otherwise still
# produce up to ~MAX_TRAIN_SAMPLES overlapping windows in a single CPU
# fine-tune cycle -- stated worst case, not whatever the busiest attacker
# happened to send that day.
MAX_TRAIN_WINDOWS = 4_000


def _ts_to_epoch(ts_str: Optional[str]) -> Optional[float]:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def featurise_temporal(src: dict, inter_arrival_s: float) -> np.ndarray:
    """Build the 6-dim per-timestep vector docs/ml-worker-plan.md §5.2
    documents: [hour_of_day, dst_port_norm, proto_enc, payload_entropy,
    inter_arrival_log, cmd_count_norm].

    Reads the real honeypot-v2-*/suricata-v2-* schema via
    models.isolation_forest's field readers (#62 task 32/33) rather than the
    flat schema no real document has. payload_entropy and cmd_count_norm
    stay at documented neutral defaults for the same reason
    extract_features() leaves them unwired: no sensor emits a consistent
    raw-payload field, and no per-session command counter was ever wired to
    a real stateful aggregator. inter_arrival_s is the caller's
    responsibility (LSTMAEModel tracks last-seen-per-IP state) so this stays
    a pure, independently testable function.
    """
    ts = src.get("@timestamp") or src.get("timestamp")
    hour_norm  = _ts_to_hour(ts) / 23.0
    port_norm  = min(_get_port(src), 65535) / 65535.0
    proto_norm = _proto_enc(_get_transport_proto(src)) / 3.0
    entropy_norm = 0.0  # not wired -- see docstring
    inter_log  = min(float(np.log1p(max(inter_arrival_s, 0.0))) / 10.0, 1.0)
    cmd_count_norm = 0.0  # not wired -- see docstring
    return np.array(
        [hour_norm, port_norm, proto_norm, entropy_norm, inter_log, cmd_count_norm],
        dtype=np.float32,
    )


class BiLSTMAE(nn.Module):
    """
    Bidirectional LSTM Autoencoder.
    Encoder: BiLSTM → latent vector
    Decoder: LSTM → reconstructed sequence
    Anomaly detected via MSE reconstruction loss.
    """

    def __init__(self) -> None:
        super().__init__()
        self.encoder = nn.LSTM(
            input_size=INPUT_DIM,
            hidden_size=HIDDEN_DIM,
            num_layers=N_LAYERS,
            batch_first=True,
            bidirectional=True,
            dropout=0.1,
        )
        # Bottleneck
        self.enc_fc = nn.Linear(HIDDEN_DIM * 2, LATENT_DIM)
        self.dec_fc = nn.Linear(LATENT_DIM, HIDDEN_DIM)

        self.decoder = nn.LSTM(
            input_size=HIDDEN_DIM,
            hidden_size=INPUT_DIM,
            num_layers=1,
            batch_first=True,
        )

    def forward(self, x: torch.Tensor):
        # x: (batch, seq_len, input_dim)
        enc_out, _ = self.encoder(x)     # (batch, seq_len, hidden*2)
        # Take last timestep of forward direction
        latent = self.enc_fc(enc_out[:, -1, :])   # (batch, latent)
        dec_in = self.dec_fc(latent)              # (batch, hidden)
        dec_in = dec_in.unsqueeze(1).repeat(1, SEQ_LEN, 1)  # (batch, seq, hidden)
        recon, _ = self.decoder(dec_in)           # (batch, seq, input_dim)
        return recon


class LSTMAEModel:
    """
    Manages the BiLSTMAE model: online scoring, fine-tuning, persistence.
    Maintains per-IP sliding windows in memory.
    """

    def __init__(self, model_dir: str = "/models") -> None:
        self.model_dir = model_dir
        self.device    = torch.device("cpu")
        self.net       = BiLSTMAE().to(self.device)
        self.threshold = 0.05  # initial reconstruction loss threshold
        # Per-IP sliding window buffers: ip → deque of feature vectors
        self._buffers: dict = collections.defaultdict(
            lambda: collections.deque(maxlen=SEQ_LEN)
        )
        # Per-IP last-seen event epoch, for real inter-arrival computation.
        self._last_seen: dict = {}
        self._load_latest()

    def score(self, src: dict) -> float:
        """
        Append this event to its src_ip's sliding window and return a
        reconstruction-loss-based anomaly score in [0, 1].

        Takes the raw ES _source dict directly (like
        IsoForestModel.extract_features()) rather than a slice of an
        unrelated model's feature vector -- see the commit that fixed this
        (#63) for why that was broken.

        Returns 0.0 before SEQ_LEN events have accumulated for this IP (real
        "no signal yet", same as before). That is distinct from the bounded
        CPU-fallback path below, which returns 0.5 -- this codebase's
        established neutral-default convention (IsoForestModel/HBOS return
        0.5 before their first retrain too) -- if inference itself fails, so
        a scoring error can never silently read as "confirmed normal".
        """
        ip = _get_ip(src) or "unknown"
        now = _ts_to_epoch(src.get("@timestamp") or src.get("timestamp"))
        last = self._last_seen.get(ip)
        inter_arrival = (now - last) if (now is not None and last is not None and now >= last) else 60.0
        if now is not None:
            self._last_seen[ip] = now

        vec = featurise_temporal(src, inter_arrival)
        self._buffers[ip].append(vec)
        if len(self._buffers[ip]) < SEQ_LEN:
            return 0.0  # not enough history yet

        seq = np.array(list(self._buffers[ip]), dtype=np.float32)  # (SEQ_LEN, 6)
        x   = torch.tensor(seq).unsqueeze(0).to(self.device)       # (1, SEQ_LEN, 6)

        try:
            self.net.eval()
            with torch.no_grad():
                recon = self.net(x)                             # (1, SEQ_LEN, 6)
                loss  = nn.functional.mse_loss(recon, x).item()
        except Exception as exc:
            logger.warning(f"LSTM-AE inference failed for {ip}, falling back to neutral score: {exc}")
            return 0.5

        # Normalise: above threshold → score > 0.5
        return float(min(loss / (self.threshold * 4), 1.0))

    def retrain(self, sources: list) -> None:
        """
        Fine-tune the model on recent events, grouped and time-ordered by
        src_ip so inter-arrival is computed the same way score() computes it
        online.

        Bounded per MAX_TRAIN_WINDOWS -- see the constant's comment for the
        cost rationale; caps the actual fit() input the same way
        IsoForestModel.retrain()'s MAX_TRAIN_SAMPLES does (#62), keeping the
        most recent windows.
        """
        by_ip: dict = collections.defaultdict(list)
        for src in sources:
            ip = _get_ip(src) or "unknown"
            ts = _ts_to_epoch(src.get("@timestamp") or src.get("timestamp"))
            by_ip[ip].append((ts if ts is not None else 0.0, src))

        sequences = []
        for ip, events in by_ip.items():
            events.sort(key=lambda pair: pair[0])
            vecs = []
            last_ts = None
            for ts, src in events:
                inter = (ts - last_ts) if (last_ts is not None and ts >= last_ts) else 60.0
                vecs.append(featurise_temporal(src, inter))
                last_ts = ts
            for i in range(0, len(vecs) - SEQ_LEN + 1):
                sequences.append(np.array(vecs[i:i + SEQ_LEN], dtype=np.float32))

        if len(sequences) > MAX_TRAIN_WINDOWS:
            sequences = sequences[-MAX_TRAIN_WINDOWS:]

        if len(sequences) < BATCH_SIZE:
            return  # not enough data

        dataset = torch.tensor(np.array(sequences), dtype=torch.float32)
        loader  = torch.utils.data.DataLoader(
            dataset, batch_size=BATCH_SIZE, shuffle=True
        )

        optimiser = torch.optim.Adam(self.net.parameters(), lr=LR_FINETUNE)
        self.net.train()
        for epoch in range(FINETUNE_EPOCHS):
            total_loss = 0.0
            for batch in loader:
                batch = batch.to(self.device)
                optimiser.zero_grad()
                recon = self.net(batch)
                loss  = nn.functional.mse_loss(recon, batch)
                loss.backward()
                optimiser.step()
                total_loss += loss.item()

        # Update threshold to 2× mean reconstruction loss
        self.net.eval()
        losses = []
        with torch.no_grad():
            for batch in loader:
                batch = batch.to(self.device)
                recon = self.net(batch)
                losses.append(nn.functional.mse_loss(recon, batch).item())
        self.threshold = float(np.mean(losses)) * 2.0
        self._save()

    def _save(self) -> None:
        ts   = int(time.time())
        path = os.path.join(self.model_dir, f"lstm_ae_{ts}.pt")
        os.makedirs(self.model_dir, exist_ok=True)
        torch.save({"model": self.net.state_dict(), "threshold": self.threshold}, path)
        link = os.path.join(self.model_dir, "current_lstm_ae.pt")
        if os.path.lexists(link):
            os.remove(link)
        os.symlink(path, link)

    def _load_latest(self) -> None:
        link = os.path.join(self.model_dir, "current_lstm_ae.pt")
        if os.path.exists(link):
            ckpt = torch.load(link, map_location=self.device)
            self.net.load_state_dict(ckpt["model"])
            self.threshold = ckpt.get("threshold", 0.05)
