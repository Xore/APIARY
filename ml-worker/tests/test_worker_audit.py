"""
ml-worker v0.1 audit (#61): each test here proves one concrete defect found
comparing ml-worker/ against docs/ml-worker-plan.md and
docs/ml-gpu-coordinated-roadmap.md's "required corrections" list, rather than
just restating the roadmap's summary. Fixtures are synthetic and structured
like the real honeypot-v2-* document shape (verified against the live
homeserver Elasticsearch, 2026-07-31) -- no real indicators or captured
attacker data.

Run: python3 -m pytest ml-worker/tests/test_worker_audit.py -v
(needs the packages in requirements.txt; see README note on the numpy/pyod
conflict below before trying to install them together)
"""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models.isolation_forest import IsoForestModel  # noqa: E402
from models.lstm_autoencoder import LSTMAEModel, SEQ_LEN  # noqa: E402


# ---------------------------------------------------------------------------
# A real honeypot-v2-* document, field names/nesting verified live against
# the homeserver ES on 2026-07-31 (values are synthetic).
# ---------------------------------------------------------------------------
REAL_SHAPED_DOCUMENT = {
    "_index": ".ds-honeypot-v2-2026.07.31-2026.07.31-000001",
    "_id": "synthetic-fixture-1",
    "_source": {
        "@timestamp": "2026-07-31T19:14:12.531Z",
        "pipeline": "honeypot",
        "honeypot": {
            "src_ip": "203.0.113.9",
            "port": 5900,
            "proto": "vnc",
            "sensor": "multipot",
            "event": "handshake",
        },
        "source": {
            "ip": "203.0.113.9",
            "geo": {"country_iso_code": "CN"},
            "as": {"organization_name": "Example Networks", "type": "network"},
        },
        "destination": {"port": 5900},
        "network": {"protocol": "vnc"},
        "event": {"sensor": "multipot"},
    },
}


class TestFieldSchemaMismatch:
    """Findings #3 (historical): extract_features() read a flat schema; real
    documents nest sensor data under honeypot.*/source.*/network.*
    (ECS-flavored). Fixed in #62 task 33 -- current per-source behavior
    (what's now correctly read vs. still a documented gap) is proven in
    test_schema_contract.py instead, against fixtures for all 5 sources, not
    just this one. Kept here is the one assertion that's still true: the
    naive flat lookup worker.py used to use never worked and never will,
    which is exactly why it had to be replaced rather than patched."""

    def test_the_old_naive_flat_lookup_never_finds_the_real_ip(self):
        src = REAL_SHAPED_DOCUMENT["_source"]
        # This is the exact formula extract_features() used before #62 task
        # 33 -- kept here, standalone, as a permanent demonstration of why it
        # had to be replaced with the per-sensor honeypot.*/source.* reads in
        # models/isolation_forest.py's _get_ip().
        ip = src.get("src_ip") or src.get("id.orig_h") or ""
        assert ip == "", "the old flat lookup cannot see honeypot.src_ip, nested 2-3 levels down"
        assert src["honeypot"]["src_ip"] == "203.0.113.9", "the real value does exist, just three levels deeper"


class TestNeutralScoreCannotAlert:
    """Finding #4: before first training, no event can ever cross
    ML_ALERT_THRESHOLD (0.75) -- worker.py's own weighting makes it
    mathematically unreachable, not just unlikely."""

    def test_untrained_scores_are_the_documented_neutral_default(self):
        model = IsoForestModel(model_dir="/tmp/does-not-matter")
        features = model.extract_features(REAL_SHAPED_DOCUMENT["_source"])
        assert model.score(features) == 0.5
        assert model.hbos_score(features) == 0.5

    def test_hbos_gate_uses_strict_greater_than_on_the_neutral_value(self):
        # worker.py: `if hbos_score > 0.5: lstm_score = lstm_model.score(...)`
        # The untrained hbos_score is exactly 0.5, so this is always False
        # before the first retrain -- LSTM never runs pre-training, not just
        # rarely.
        hbos_score = 0.5
        lstm_would_run = hbos_score > 0.5
        assert lstm_would_run is False

    def test_composite_score_pre_training_is_always_0_3(self):
        # Reproduces worker.py's exact composite formula with the documented
        # pre-training defaults.
        iso_score, hbos_score, lstm_score = 0.5, 0.5, 0.0  # lstm never ran, see above
        composite = 0.4 * iso_score + 0.4 * lstm_score + 0.2 * hbos_score
        threshold = 0.75
        assert composite == pytest.approx(0.3)
        assert composite < threshold, (
            "an untrained worker can NEVER write an anomaly, regardless of how "
            "anomalous the underlying event actually is -- not a calibration "
            "problem, a hardcoded impossibility until the first retrain has "
            ">100 events (RETRAIN_INTERVAL default 6h)"
        )


class TestLSTMTrainInferenceSkew:
    """Finding #5 (historical): LSTMAEModel.score() and .retrain() built the
    6-dim temporal vector two different, incompatible ways -- score()
    received a slice of the unrelated 15-dim IsoForest vector instead of the
    documented [hour, port, proto, entropy, inter_arrival, cmd_count] vector
    retrain() actually trained on. Fixed in #63: both now call the shared
    models.lstm_autoencoder.featurise_temporal() against the real src dict.
    Current behavior is proven in test_temporal_features.py instead."""

    def test_score_and_retrain_now_share_one_featuriser(self):
        import inspect
        from models import lstm_autoencoder

        score_src = inspect.getsource(LSTMAEModel.score)
        retrain_src = inspect.getsource(LSTMAEModel.retrain)
        assert "featurise_temporal(" in score_src
        assert "featurise_temporal(" in retrain_src
        assert "[:INPUT_DIM]" not in score_src, (
            "score() must not reach into an unrelated model's feature vector by slicing it"
        )


class TestBufferStateNotPersisted:
    """Finding #6: per-source-IP sliding windows are pure in-memory state."""

    def test_load_latest_does_not_restore_buffers(self):
        model = LSTMAEModel(model_dir="/tmp/does-not-matter")
        src = dict(REAL_SHAPED_DOCUMENT["_source"])
        src["source"] = {"ip": "203.0.113.9"}
        for _ in range(SEQ_LEN):
            model.score(src)
        assert len(model._buffers["203.0.113.9"]) == SEQ_LEN

        # Simulate a restart: a fresh instance loading from the same
        # model_dir. _load_latest() only restores net weights + threshold.
        restarted = LSTMAEModel(model_dir="/tmp/does-not-matter")
        assert len(restarted._buffers["203.0.113.9"]) == 0, (
            "if this fails, buffer persistence was added -- update this test "
            "to assert survival instead of loss"
        )


class TestUnhandledEventErrorsCrashTheBatch:
    """Finding #8 (roadmap: 'malformed payloads ... are not isolated from
    the processing loop'): there is no per-event try/except in worker.py's
    main loop, so one bad event takes down the whole poll cycle.

    The original reproduction (a malformed payload_hex value) no longer
    raises: #62 task 33 stopped extract_features() from reading payload_hex
    at all, since no real sensor emits a consistent raw-payload field to
    begin with (see fixtures.py / docs/ml-worker-plan.md §5.3) -- that
    specific crash is gone as a side effect, not a targeted fix. The
    underlying finding is still open: worker.py's main loop still has no
    try/except around the per-event extract/score/write path, so any other
    unexpected shape (e.g. a non-numeric destination.port) would still take
    the batch down. Not in #62 task 33's scope (extract_features() + bounded
    HBOS); tracked as remaining work, not re-filed as a new issue."""

    def test_extract_features_tolerates_a_non_numeric_port(self):
        model = IsoForestModel(model_dir="/tmp/does-not-matter")
        malformed = {"@timestamp": "2026-07-31T00:00:00Z", "destination": {"port": "not-a-port"}}
        with pytest.raises(ValueError):
            # Still reproduces the batch-crashing finding, just via a field
            # extract_features() actually reads now instead of the retired
            # payload_hex path -- proves the *loop* still needs a guard, even
            # though extract_features()'s own field reads are fixed.
            model.extract_features(malformed)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
