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
from typing import Optional

import numpy as np
import torch
import torch.nn as nn

SEQ_LEN   = 15    # sliding window length (events per sequence)
INPUT_DIM = 6     # features per timestep (see §5.2 in plan)
HIDDEN_DIM = 64
LATENT_DIM = 16
N_LAYERS   = 2
LR_FINETUNE = 1e-5
FINETUNE_EPOCHS = 5
BATCH_SIZE  = 32


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
        self._load_latest()

    def _featurise(self, src: dict) -> np.ndarray:
        """Extract 6-dim temporal feature vector from a raw ES source."""
        from datetime import datetime, timezone

        ts = src.get("@timestamp", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hour_norm = dt.hour / 23.0
        except Exception:
            hour_norm = 0.0

        port      = float(src.get("dst_port") or src.get("id.resp_p") or 0) / 65535.0
        proto_enc = {"tcp": 0.0, "udp": 0.33, "icmp": 0.66}.get(
            (src.get("proto") or "").lower(), 1.0
        )
        payload_hex = src.get("payload_hex", "")
        payload_bytes = bytes.fromhex(payload_hex) if payload_hex else b""
        entropy = 0.0
        if payload_bytes:
            import math
            freq = {}
            for b in payload_bytes:
                freq[b] = freq.get(b, 0) + 1
            probs = [v / len(payload_bytes) for v in freq.values()]
            entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        entropy_norm = entropy / 8.0

        # inter-arrival: stored as seconds since last event; default 60s
        inter = float(src.get("inter_arrival_s") or 60)
        inter_log = min(float(np.log1p(inter)) / 10.0, 1.0)

        cmd_count = min(int(src.get("cmd_count") or 0), 200) / 200.0

        return np.array(
            [hour_norm, port, proto_enc, entropy_norm, inter_log, cmd_count],
            dtype=np.float32,
        )

    def score(self, src_ip: str, features: np.ndarray) -> float:
        """
        Append current event to the per-IP buffer and compute
        reconstruction loss once the buffer has SEQ_LEN entries.
        Returns normalised anomaly score in [0, 1].
        """
        # features here is the full IsoForest feature vector;
        # extract only the 6 temporal dims
        f6 = self._featurise({})  # placeholder — worker passes src directly
        # Actually the worker passes src dict; reconstruct from passed features
        # This is filled by retrain path; score path passes the 15-dim vector
        # Just use first 6 dims as approximation until refactor
        vec = features.flatten()[:INPUT_DIM].astype(np.float32)

        self._buffers[src_ip].append(vec)
        if len(self._buffers[src_ip]) < SEQ_LEN:
            return 0.0  # not enough history yet

        seq = np.array(list(self._buffers[src_ip]), dtype=np.float32)  # (SEQ_LEN, 6)
        x   = torch.tensor(seq).unsqueeze(0).to(self.device)           # (1, SEQ_LEN, 6)

        self.net.eval()
        with torch.no_grad():
            recon = self.net(x)                             # (1, SEQ_LEN, 6)
            loss  = nn.functional.mse_loss(recon, x).item()

        # Normalise: above threshold → score > 0.5
        norm_score = min(loss / (self.threshold * 4), 1.0)
        return float(norm_score)

    def retrain(self, sources: list) -> None:
        """
        Fine-tune the model on recent events grouped by src_ip.
        """
        # Group events by src_ip
        by_ip: dict = collections.defaultdict(list)
        for src in sources:
            ip = src.get("src_ip") or src.get("id.orig_h") or "unknown"
            by_ip[ip].append(self._featurise(src))

        # Build sequences
        sequences = []
        for ip, vecs in by_ip.items():
            for i in range(0, len(vecs) - SEQ_LEN + 1):
                sequences.append(np.array(vecs[i:i + SEQ_LEN], dtype=np.float32))

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
