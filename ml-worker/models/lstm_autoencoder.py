"""
LSTM Autoencoder for temporal sequence anomaly detection.

Groups events by src_ip into sliding windows of length SEQ_LEN.
Anomaly = reconstruction loss above threshold.

Based on: CNN-BiLSTM-AE architecture (Park et al., MDPI 2025)
See docs/ml-worker-plan.md §4.2 and §5.2.
"""
import copy
import json
import os
import time
import collections
from dataclasses import asdict
from datetime import datetime
from typing import Optional

import numpy as np
import torch
import torch.nn as nn
from loguru import logger

# PyTorch sizes its intra-op thread pool to the HOST's visible CPU count by
# default, not the container's cgroup CPU quota (docker-compose.yml caps
# this service at 2.0 CPUs; the homeserver has 16). Under that mismatch,
# every nn.LSTM forward pass spawns far more threads than the quota can
# actually run concurrently, and they contend for CPU time rather than
# making progress -- observed live as a hard stall (200%+ CPU, zero
# throughput, checkpoints frozen) the first time LSTMAEModel.score() ever
# ran under real load. It never ran before that: hbos_score is exactly 0.5
# (never > 0.5) until the first retrain accepts a real model, so this
# codepath was untested against the container's actual CPU limit until
# then. The model here is tiny (SEQ_LEN=15, HIDDEN_DIM=64) -- there is
# nothing to gain from multi-threading a single sequence through it, so
# pin this process to one thread rather than tune it to match "2.0".
torch.set_num_threads(1)

from models.isolation_forest import (
    _get_ip, _get_port, _get_transport_proto, _proto_enc, _ts_to_hour,
    _accept_decision, _percentile_normalize, HOLDOUT_FRACTION, HOLDOUT_MIN, MAX_CMD_COUNT,
    RetrainResult,
)
from models.session_features import compute_batch_session_features
# _symlink comes from lifecycle directly since #2230 (it moved there so
# rollback.py can share it); previously re-imported via isolation_forest.
from models.lifecycle import prune_old_versions, staged_rollback_version, write_version_metadata, _symlink

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

# #170: each IP's own window is already bounded (deque(maxlen=SEQ_LEN)), but
# the NUMBER of distinct IPs tracked across a long-running worker is not --
# unbounded IP cardinality is a real memory/disk question in its own right,
# not something to persist without a cap just because the per-IP windows
# already are. Persisting only the most-recently-active IPs means a source
# that's gone quiet stops taking up sidecar space, which is also the set
# most likely to still matter across a short restart.
MAX_PERSISTED_IPS = 2_000


def _ts_to_epoch(ts_str: Optional[str]) -> Optional[float]:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def featurise_temporal(src: dict, inter_arrival_s: float, cmd_count: int = 0) -> np.ndarray:
    """Build the 6-dim per-timestep vector docs/ml-worker-plan.md §5.2
    documents: [hour_of_day, dst_port_norm, proto_enc, payload_entropy,
    inter_arrival_log, cmd_count_norm].

    Reads the real honeypot-v2-*/suricata-v2-* schema via
    models.isolation_forest's field readers (#62 task 32/33) rather than the
    flat schema no real document has. payload_entropy stays at its
    documented neutral default -- no sensor emits a consistent raw-payload
    field (#277 remaining scope). cmd_count is now real (#277): the caller
    supplies it (models.session_features.SessionFeatureTracker for the
    online path, compute_batch_session_features() for retrain()), the same
    contract inter_arrival_s already used -- LSTMAEModel tracks the
    per-session/per-IP state, this stays a pure, independently testable
    function of (event, context).
    """
    ts = src.get("@timestamp") or src.get("timestamp")
    hour_norm  = _ts_to_hour(ts) / 23.0
    port_norm  = min(_get_port(src), 65535) / 65535.0
    proto_norm = _proto_enc(_get_transport_proto(src)) / 3.0
    entropy_norm = 0.0  # not wired -- see docstring
    inter_log  = min(float(np.log1p(max(inter_arrival_s, 0.0))) / 10.0, 1.0)
    cmd_count_norm = min(cmd_count, MAX_CMD_COUNT) / MAX_CMD_COUNT
    return np.array(
        [hour_norm, port_norm, proto_norm, entropy_norm, inter_log, cmd_count_norm],
        dtype=np.float32,
    )


def _anomaly_rate(net: "BiLSTMAE", threshold: float, X: torch.Tensor) -> float:
    """Fraction of X (a batch of SEQ_LEN windows) this net/threshold pair
    would call anomalous -- score() >= 0.5, i.e. reconstruction loss over
    2x this model's own calibrated baseline. Mirrors IsoForestModel's
    _anomaly_rate in spirit (#65, docs/ml-worker-plan.md §11.1): each
    model's own declared boundary, not an externally chosen cutoff."""
    if len(X) == 0:
        return 0.0
    net.eval()
    with torch.no_grad():
        recon = net(X)
        per_sequence_loss = nn.functional.mse_loss(recon, X, reduction="none").mean(dim=(1, 2))
    return float((per_sequence_loss > threshold * 2).float().mean().item())


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
        # #2894: p50/p99 of THIS model's own holdout reconstruction loss,
        # recomputed every accepted retrain -- see score()'s own comment
        # for why the fixed-divisor formula this replaces saturated.
        # None until the first accepted retrain (or a model saved before
        # this existed is loaded); score() falls back to the old formula
        # in that case, same posture isolation_forest.py's hp_calib takes.
        self.calib: "dict | None" = None
        # Per-IP sliding window buffers: ip → deque of feature vectors
        self._buffers: dict = collections.defaultdict(
            lambda: collections.deque(maxlen=SEQ_LEN)
        )
        # Per-IP last-seen event epoch, for real inter-arrival computation.
        # OrderedDict, not dict: score() relinks a touched IP to the end on
        # every visit, so iteration order is always least- to
        # most-recently-active -- what _evict_oldest_ip needs to find and
        # remove the right entry in O(1). #884: each IP's own window was
        # already bounded (deque(maxlen=SEQ_LEN)), but the NUMBER of
        # distinct IPs in _buffers/_last_seen was not -- both grew for
        # every distinct src_ip ever observed, unbounded, for the whole
        # process lifetime (MAX_PERSISTED_IPS bounded save_buffers()'s
        # persisted snapshot only, never this live state).
        self._last_seen: collections.OrderedDict = collections.OrderedDict()
        # True once a real fit (loaded from disk or accepted by retrain())
        # exists -- distinct from "self.net exists", since BiLSTMAE() is
        # always constructed with random weights at __init__. Without this,
        # the very first retrain would compare its candidate against an
        # untrained random net's reconstruction loss, which isn't a
        # meaningful "previous model" to hold anything to (#65).
        self._trained = False
        self._load_latest()
        self._load_buffers()

    def score(self, src: dict, cmd_count: int = 0) -> "float | None":
        """
        Append this event to its src_ip's sliding window and, when this
        model actually has an opinion, return a reconstruction-loss-based
        anomaly score in [0, 1].

        Takes the raw ES _source dict directly (like
        IsoForestModel.extract_features()) rather than a slice of an
        unrelated model's feature vector -- see the commit that fixed this
        (#63) for why that was broken. cmd_count (#277) is the caller's
        responsibility, same as inter_arrival_s -- worker.py's
        score_and_write_events() supplies it from the SAME
        SessionFeatureTracker.observe() call already made for
        IsoForestModel.extract_features(), so one event is only ever
        observed once.

        Returns None whenever this detector has NO usable opinion
        (#1969): before the first accepted fit loaded or trained any
        weights (BiLSTMAE() always constructs with random weights, so the
        old behaviour of scoring through them let random-weight noise
        masquerade as a middling vote); before SEQ_LEN events have
        accumulated for this IP (the old exact-0.0 "no signal yet"
        sentinel); or if inference itself fails (the old neutral-0.5
        fallback -- an error reading as a confident midpoint vote is its
        own flavour of wrong, and compute_composite()'s
        availability-renormalisation makes exclusion strictly more honest
        than either sentinel). The per-IP bookkeeping above runs on every
        call regardless, so windows accumulate during abstention and the
        detector starts producing opinions the moment it is trained and
        primed, never losing history to the abstaining period.
        """
        ip = _get_ip(src) or "unknown"
        now = _ts_to_epoch(src.get("@timestamp") or src.get("timestamp"))
        last = self._last_seen.get(ip)
        inter_arrival = (now - last) if (now is not None and last is not None and now >= last) else 60.0
        if now is not None:
            self._last_seen.pop(ip, None)  # re-insert at the end: marks it most-recently-active
            self._last_seen[ip] = now
            if len(self._last_seen) > MAX_PERSISTED_IPS:
                oldest, _ = self._last_seen.popitem(last=False)
                self._buffers.pop(oldest, None)

        vec = featurise_temporal(src, inter_arrival, cmd_count=cmd_count)
        self._buffers[ip].append(vec)

        if not self._trained:
            return None  # random-weight net: noise, not an opinion (#1969)
        if len(self._buffers[ip]) < SEQ_LEN:
            return None  # not enough history yet

        seq = np.array(list(self._buffers[ip]), dtype=np.float32)  # (SEQ_LEN, 6)
        x   = torch.tensor(seq).unsqueeze(0).to(self.device)       # (1, SEQ_LEN, 6)

        try:
            self.net.eval()
            with torch.no_grad():
                recon = self.net(x)                             # (1, SEQ_LEN, 6)
                loss  = nn.functional.mse_loss(recon, x).item()
        except Exception as exc:
            logger.warning(f"LSTM-AE inference failed for {ip}, abstaining (no opinion, excluded from the composite): {exc}")
            return None

        # #2894: percentile-anchored normalisation, mirroring
        # isolation_forest.py's #174 fix for the identical failure mode.
        # The fixed-divisor formula this replaces (`min(loss / (threshold
        # * 4), 1.0)`) saturated at the 1.0 ceiling for real production
        # traffic -- measured live against 7 days / 1.2M real alerts
        # (2026-09-03): mean lstm_ae score 0.9966, 92.9% of alerts sitting
        # at exactly 1.0. #174's own finding for IsoForest/HBOS before its
        # fix was the same shape (100% saturated in a 4000-event sample) --
        # a fixed constant assuming a hand-picked "typical loss range" goes
        # stale the moment real reconstruction losses run higher than that
        # guess, same as HBOS's old /10 divisor did.
        if self.calib is not None:
            return _percentile_normalize(loss, self.calib["p50"], self.calib["p99"], lower_is_more_anomalous=False)
        # Fallback for a model saved before this existed (no calib
        # attached yet) -- the original fixed-range formula, kept only so
        # an in-flight model isn't left with no score() until its next
        # accepted retrain computes real anchors.
        return float(min(loss / (self.threshold * 4), 1.0))

    def retrain(self, sources: list) -> RetrainResult:
        """
        Fine-tune a candidate on recent events, grouped and time-ordered by
        src_ip so inter-arrival is computed the same way score() computes it
        online, then gate promotion on the acceptance bar (#65,
        docs/ml-worker-plan.md §11.1) -- shared with IsoForestModel via
        _accept_decision(), evaluated on a holdout slice of windows never
        trained on. A rejected fine-tune is rolled back (the in-place
        gradient steps are undone by restoring the pre-retrain weights), so
        the active model is unaffected either way.

        Bounded per MAX_TRAIN_WINDOWS -- see the constant's comment for the
        cost rationale; caps the actual fit() input the same way
        IsoForestModel.retrain()'s MAX_TRAIN_SAMPLES does (#62), keeping the
        most recent windows.

        cmd_count (#277) is computed once for the whole batch via
        compute_batch_session_features() -- same one-pass-per-retrain
        contract as IsoForestModel.retrain(), not per-IP, since cmd_count is
        keyed by Cowrie session, not by src_ip.
        """
        batch_features = compute_batch_session_features(sources)

        by_ip: dict = collections.defaultdict(list)
        for src, feats in zip(sources, batch_features):
            ip = _get_ip(src) or "unknown"
            ts = _ts_to_epoch(src.get("@timestamp") or src.get("timestamp"))
            by_ip[ip].append((ts if ts is not None else 0.0, src, feats["cmd_count"]))

        sequences = []
        for ip, events in by_ip.items():
            events.sort(key=lambda triple: triple[0])
            vecs = []
            last_ts = None
            for ts, src, cmd_count in events:
                inter = (ts - last_ts) if (last_ts is not None and ts >= last_ts) else 60.0
                vecs.append(featurise_temporal(src, inter, cmd_count=cmd_count))
                last_ts = ts
            for i in range(0, len(vecs) - SEQ_LEN + 1):
                sequences.append(np.array(vecs[i:i + SEQ_LEN], dtype=np.float32))

        if len(sequences) > MAX_TRAIN_WINDOWS:
            sequences = sequences[-MAX_TRAIN_WINDOWS:]

        n = len(sequences)
        if n < BATCH_SIZE + HOLDOUT_MIN:
            return RetrainResult(
                accepted=False, reason="not enough windows to retrain",
                train_samples=n, holdout_samples=0,
                anomaly_rate_new=0.0, anomaly_rate_previous=None,
            )

        # Holdout is the newest windows, never trained on -- same rationale
        # as IsoForestModel.retrain(): the most-recent-events split, not a
        # random one, since sequences are already time-ordered per IP.
        holdout_n = min(max(HOLDOUT_MIN, int(n * HOLDOUT_FRACTION)), n - BATCH_SIZE)
        train_sequences = sequences[:n - holdout_n]
        holdout_sequences = sequences[n - holdout_n:]
        X_holdout = torch.tensor(np.array(holdout_sequences), dtype=torch.float32).to(self.device)

        # Score the OUTGOING model on the holdout before any weights change.
        previous_rate = _anomaly_rate(self.net, self.threshold, X_holdout) if self._trained else None

        # Fine-tuning is in-place (optimiser.step() mutates self.net's
        # weights directly) -- snapshot first so a rejected candidate can be
        # reverted rather than left half-applied.
        original_state = copy.deepcopy(self.net.state_dict())
        original_threshold = self.threshold

        dataset = torch.tensor(np.array(train_sequences), dtype=torch.float32)
        loader  = torch.utils.data.DataLoader(
            dataset, batch_size=BATCH_SIZE, shuffle=True
        )

        optimiser = torch.optim.Adam(self.net.parameters(), lr=LR_FINETUNE)
        self.net.train()
        for epoch in range(FINETUNE_EPOCHS):
            for batch in loader:
                batch = batch.to(self.device)
                optimiser.zero_grad()
                recon = self.net(batch)
                loss  = nn.functional.mse_loss(recon, batch)
                loss.backward()
                optimiser.step()

        # Candidate threshold: 2x mean reconstruction loss over the train
        # split (unchanged formula from the original draft).
        self.net.eval()
        train_losses = []
        with torch.no_grad():
            for batch in loader:
                batch = batch.to(self.device)
                recon = self.net(batch)
                train_losses.append(nn.functional.mse_loss(recon, batch).item())
        candidate_threshold = float(np.mean(train_losses)) * 2.0 if train_losses else original_threshold

        # #174: evaluate the candidate against original_threshold (the
        # OUTGOING model's own fixed bar) whenever a real one exists, not
        # candidate_threshold. Scoring against candidate_threshold was
        # self-referential -- that value is 2x THIS SAME cycle's own mean
        # training loss, so _anomaly_rate's internal *2 compounded it to 4x
        # mean, a bar candidate_threshold's own fine-tune had (by
        # construction) just been optimized to sit comfortably under.
        # Confirmed live against 24h of real production traffic:
        # anomaly_rate_new read exactly 0.0 on every retrain cycle observed,
        # both before and after #815, because not even the single most
        # extreme sequence in a 26k-sequence batch reached 4x that batch's
        # own mean loss. previous_rate never had this problem --
        # self.threshold there is a bar fixed BEFORE this cycle's fine-tune,
        # so it isn't self-referential -- which is exactly why the fix here
        # is to hold the candidate to that identical fixed bar too: "does
        # the new model's holdout reconstruction cross the SAME line the
        # outgoing model is being judged against" is what the acceptance
        # gate's own intent (RetrainResult docstring, docs/ml-worker-plan.md
        # §11.1: reject a candidate that regresses vs. the outgoing model)
        # actually calls for.
        #
        # Bootstrap exception: on the very first-ever retrain (self._trained
        # was False before this call), original_threshold is just __init__'s
        # arbitrary uncalibrated 0.05 default, not a real previously-fit
        # baseline -- confirmed live, holding a genuine fine-tuned candidate
        # to that arbitrary constant rejected literally every holdout
        # sequence (anomaly_rate_new pinned at 1.0, not a real
        # discriminating signal either, just a different broken constant).
        # There is no real prior baseline to compare against yet in this
        # one case, so this falls back to the original self-referential
        # formula deliberately -- the same posture _accept_decision already
        # takes for its own reference_rate when previous_rate is None.
        #
        # candidate_threshold itself is untouched either way -- it's still
        # exactly what gets promoted to self.threshold (and therefore what
        # score()'s own online boundary uses) if accepted; only the
        # ACCEPTANCE DECISION's own reference bar changes here.
        acceptance_reference = original_threshold if self._trained else candidate_threshold
        candidate_rate = _anomaly_rate(self.net, acceptance_reference, X_holdout)
        accept, reason = _accept_decision(candidate_rate, previous_rate)
        result = RetrainResult(
            accepted=accept, reason=reason,
            train_samples=len(train_sequences), holdout_samples=len(holdout_sequences),
            anomaly_rate_new=candidate_rate, anomaly_rate_previous=previous_rate,
        )

        if accept:
            self.threshold = candidate_threshold
            self._trained = True
            # #2894: recalibrate score()'s normalisation anchors from this
            # accepted candidate's own holdout reconstruction loss, same
            # holdout split _anomaly_rate just scored above -- p50/p99 of
            # the SAME distribution the acceptance decision itself used,
            # not a fresh measurement of anything.
            if len(X_holdout) > 0:
                self.net.eval()
                with torch.no_grad():
                    recon = self.net(X_holdout)
                    holdout_losses = nn.functional.mse_loss(recon, X_holdout, reduction="none").mean(dim=(1, 2))
                holdout_losses = holdout_losses.cpu().numpy()
                self.calib = {
                    "p50": float(np.percentile(holdout_losses, 50)),
                    "p99": float(np.percentile(holdout_losses, 99)),
                }
            self._save(result)
        else:
            self.net.load_state_dict(original_state)  # undo the in-place fine-tune
            self.threshold = original_threshold

        return result

    def _save(self, result: RetrainResult) -> None:
        # #2230: same staged-rollback surface as IsoForestModel._save() --
        # detect BEFORE the new version file exists (see that comment).
        staged = staged_rollback_version(self.model_dir, "lstm_ae")
        if staged is not None:
            logger.warning(
                f"lstm_ae: accepted retrain overrides a manually staged rollback "
                f"(live pointer was v{staged}); restart will load this NEW model -- "
                f"re-run rollback.py lstm_ae {staged} if the rollback was intended")

        ts   = int(time.time())
        path = os.path.join(self.model_dir, f"lstm_ae_{ts}.pt")
        os.makedirs(self.model_dir, exist_ok=True)
        torch.save({"model": self.net.state_dict(), "threshold": self.threshold, "calib": self.calib}, path)
        link = os.path.join(self.model_dir, "current_lstm_ae.pt")
        _symlink(path, link)  # atomic promotion (#169) -- shared with IsoForestModel
        # Version metadata + retention (#65, docs/ml-worker-plan.md §11.3) --
        # same contract as IsoForestModel._save().
        write_version_metadata(self.model_dir, "lstm_ae", ts, {"timestamp": ts, **asdict(result)})
        prune_old_versions(self.model_dir, "lstm_ae")

    def _load_latest(self) -> None:
        link = os.path.join(self.model_dir, "current_lstm_ae.pt")
        if os.path.exists(link):
            ckpt = torch.load(link, map_location=self.device)
            self.net.load_state_dict(ckpt["model"])
            self.threshold = ckpt.get("threshold", 0.05)
            self.calib = ckpt.get("calib")  # #2894: absent on a pre-#2894 checkpoint
            self._trained = True

    def _buffers_path(self) -> str:
        return os.path.join(self.model_dir, "current_lstm_ae_buffers.json")

    def save_buffers(self) -> None:
        """Persist per-IP sliding windows so a restart doesn't reopen a real
        temporal-detection coverage gap for sessions in progress (#170) --
        _load_latest() only ever restored the network weights and
        threshold, never this. Bounded to the MAX_PERSISTED_IPS
        most-recently-active IPs (by _last_seen); written atomically
        (temp file + os.replace) so a crash mid-write can't corrupt the
        sidecar or leave it half-written.
        """
        items = sorted(self._last_seen.items(), key=lambda kv: kv[1], reverse=True)[:MAX_PERSISTED_IPS]
        kept_ips = {ip for ip, _ in items}
        payload = {
            "buffers": {
                ip: [vec.tolist() for vec in self._buffers[ip]]
                for ip in kept_ips if ip in self._buffers
            },
            "last_seen": dict(items),
        }
        path = self._buffers_path()
        os.makedirs(self.model_dir, exist_ok=True)
        temp_path = f"{path}.tmp-{os.getpid()}-{time.time_ns()}"
        with open(temp_path, "w") as handle:
            json.dump(payload, handle)
        os.replace(temp_path, path)

    def _load_buffers(self) -> None:
        path = self._buffers_path()
        if not os.path.exists(path):
            return
        try:
            with open(path) as handle:
                payload = json.load(handle)
        except (OSError, ValueError) as exc:
            logger.warning(f"Failed to load persisted LSTM-AE buffers (non-fatal, starting cold): {exc}")
            return
        for ip, vectors in payload.get("buffers", {}).items():
            self._buffers[ip] = collections.deque(
                (np.array(vec, dtype=np.float32) for vec in vectors), maxlen=SEQ_LEN
            )
        # #2229: save_buffers() writes `last_seen` sorted by timestamp
        # descending (newest first, so the [:MAX_PERSISTED_IPS] slice keeps
        # the most-recently-active entries); a plain .update() would hand
        # that document order straight to this OrderedDict, inverting the
        # least->most-recent invariant __init__ documents and score()'s
        # popitem(last=False) eviction depends on. Re-sort ascending here so
        # the restored order matches what a live-built _last_seen would be.
        for ip, ts in sorted(payload.get("last_seen", {}).items(), key=lambda kv: kv[1]):
            self._last_seen[ip] = ts
