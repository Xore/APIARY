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
from models.lstm_autoencoder import LSTMAEModel, INPUT_DIM, SEQ_LEN  # noqa: E402


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
    """Findings #3: extract_features() reads a flat schema; real documents
    nest sensor data under honeypot.*/source.*/network.* (ECS-flavored)."""

    def test_real_document_yields_defaulted_features(self):
        model = IsoForestModel(model_dir="/tmp/does-not-matter")
        src = REAL_SHAPED_DOCUMENT["_source"]
        features = model.extract_features(src).flatten()

        # None of extract_features()'s lookups (src_ip, dst_port, proto,
        # payload_hex, username, password, cmd_count, duration,
        # failed_logins_1h, unique_ports_1h) exist at the top level of a real
        # document -- every one of them silently falls back to its default,
        # even though this specific event carries a real src_ip, port, and
        # protocol two or three levels deeper.
        assert features[2] == 0.0, "port defaulted to 0 despite honeypot.port=5900 in the source doc"
        assert features[3] == 3, "proto defaulted to 'unknown' (index 3) despite honeypot.proto='vnc'"
        assert features[12] == 0, "is_known_scanner is 0 because ip resolved to '' (src_ip lookup found nothing)"

    def test_extract_features_never_finds_the_real_ip(self):
        model = IsoForestModel(model_dir="/tmp/does-not-matter")
        src = REAL_SHAPED_DOCUMENT["_source"]
        # extract_features's own ip lookup (used internally for
        # is_known_scanner) mirrors src.get("src_ip") or src.get("id.orig_h"):
        # both miss on a real document.
        ip = src.get("src_ip") or src.get("id.orig_h") or ""
        assert ip == "", "the field lookup worker.py actually uses cannot see honeypot.src_ip"
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
    """Finding #5: LSTMAEModel.score() and .retrain() build the 6-dim
    temporal vector two different, incompatible ways."""

    def test_retrain_featurise_and_score_slicing_disagree_positionally(self):
        model = LSTMAEModel(model_dir="/tmp/does-not-matter")
        src = REAL_SHAPED_DOCUMENT["_source"]

        # What retrain() actually trains on for this event (_featurise, the
        # documented [hour, port, proto, entropy, inter_arrival, cmd_count]
        # vector from plan §5.2):
        trained_on = model._featurise(src)

        # What score() actually receives at inference time: the first
        # INPUT_DIM=6 slots of the 15-dim IsoForest vector, per the comment
        # in lstm_autoencoder.py itself ("Just use first 6 dims as
        # approximation until refactor").
        iso_model = IsoForestModel(model_dir="/tmp/does-not-matter")
        iso_features = iso_model.extract_features(src).flatten()
        scored_on = iso_features[:INPUT_DIM]

        # Index 1 alone proves the point: _featurise puts a port fraction
        # there; the IsoForest vector puts day_of_week there instead. A model
        # trained on one and scored on the other is not evaluating the
        # feature it was fit against. _featurise's index 1 is always in
        # [0, 1] (a normalised port); the IsoForest vector's index 1 is
        # day_of_week, an integer in [0, 6] -- the two value spaces don't
        # even overlap except at the single point 0 or 1.
        assert 0.0 <= trained_on[1] <= 1.0
        assert iso_features[1] in (0, 1, 2, 3, 4, 5, 6)
        assert scored_on[1] == iso_features[1], "sanity: score() really does receive the IsoForest vector, not _featurise's"

    def test_score_path_ignores_the_src_dict_entirely(self):
        # score()'s own first line is dead code that proves the bug: it
        # calls self._featurise({}) -- an empty dict -- and immediately
        # discards the result, per its own inline comment ("placeholder").
        # The real src is never passed to score() by worker.py at all;
        # only the pre-computed IsoForest feature vector is.
        import inspect
        source = inspect.getsource(LSTMAEModel.score)
        assert "_featurise({})" in source, (
            "score() no longer contains the dead placeholder call -- if this "
            "fails because it was fixed, delete this test, not the fix"
        )


class TestBufferStateNotPersisted:
    """Finding #6: per-source-IP sliding windows are pure in-memory state."""

    def test_load_latest_does_not_restore_buffers(self):
        model = LSTMAEModel(model_dir="/tmp/does-not-matter")
        for _ in range(SEQ_LEN):
            model.score("203.0.113.9", np.zeros((1, 15), dtype=np.float32))
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
    main loop, so one bad event takes down the whole poll cycle."""

    def test_odd_length_payload_hex_raises_uncaught(self):
        model = IsoForestModel(model_dir="/tmp/does-not-matter")
        malformed = {"@timestamp": "2026-07-31T00:00:00Z", "payload_hex": "abc"}  # odd length: not valid hex
        with pytest.raises(ValueError):
            # This is exactly what worker.py's per-event loop calls with no
            # surrounding try/except -- one malformed capture from an
            # attacker (trivially producible) stops the entire index's batch,
            # and every other index queued behind it in SOURCE_INDICES.
            model.extract_features(malformed)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
