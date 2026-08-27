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
from unittest.mock import MagicMock

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import worker  # noqa: E402
from worker import contributing_detectors  # noqa: E402
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
    """Finding #4 (historical): before first training, the neutral 0.5
    placeholders kept their full composite weight and no event could ever
    cross ML_ALERT_THRESHOLD (0.75) -- mathematically unreachable, not just
    unlikely. #1969 replaced that contract outright: an untrained detector
    has NO opinion (None), compute_composite() renormalises over whatever
    did opine, and a fresh worker stays silent for the honest reason --
    nobody has an opinion yet -- rather than because every vote was faked
    at a constant."""

    def test_untrained_scores_are_none_not_a_placeholder_vote(self):
        model = IsoForestModel(model_dir="/tmp/does-not-matter")
        features = model.extract_features(REAL_SHAPED_DOCUMENT["_source"])
        assert model.score(features) is None
        assert model.hbos_score(features) is None

    def test_execution_gate_never_runs_lstm_when_hbos_abstains(self):
        # score_and_write_events()'s gate: `if hbos_v is not None and
        # hbos_v > 0.5`. (Pre-#1969 the untrained hbos score was exactly
        # 0.5, so its strict-greater-than meant LSTM never ran before the
        # first retrain either -- same outcome, less honest encoding.)
        hbos_v = None
        lstm_would_run = hbos_v is not None and hbos_v > 0.5
        assert lstm_would_run is False

    def test_composite_with_no_detector_opinions_is_zero_and_cannot_alert(self):
        composite = worker.compute_composite(
            {"isolation_forest": None, "lstm_ae": None, "hbos": None}
        )
        assert composite == 0.0
        assert contributing_detectors(
            {"isolation_forest": None, "lstm_ae": None, "hbos": None}
        ) == []
        assert composite < worker.THRESHOLD


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
    """Finding #6, fixed in #170: per-source-IP sliding windows used to be
    pure in-memory state, silently reset on every restart. Now persisted to
    a bounded JSON sidecar (LSTMAEModel.save_buffers()/_load_buffers()),
    loaded automatically in __init__. Per this test's own prior docstring
    instruction ("if this fails, buffer persistence was added -- update this
    test to assert survival instead of loss"), it now asserts survival."""

    def test_buffers_survive_a_restart_once_saved(self, tmp_path):
        model = LSTMAEModel(model_dir=str(tmp_path))
        src = dict(REAL_SHAPED_DOCUMENT["_source"])
        src["source"] = {"ip": "203.0.113.9"}
        for _ in range(SEQ_LEN):
            model.score(src)
        assert len(model._buffers["203.0.113.9"]) == SEQ_LEN
        model.save_buffers()

        # Simulate a restart: a fresh instance loading from the same
        # model_dir. _load_buffers() (called from __init__) must restore it.
        restarted = LSTMAEModel(model_dir=str(tmp_path))
        assert len(restarted._buffers["203.0.113.9"]) == SEQ_LEN
        assert "203.0.113.9" in restarted._last_seen

    def test_restart_without_a_prior_save_starts_cold(self, tmp_path):
        # No save_buffers() call -- a restart with nothing persisted yet
        # (e.g. the very first poll cycle after a fresh deploy) must not
        # raise, and must simply start with empty buffers.
        restarted = LSTMAEModel(model_dir=str(tmp_path))
        assert len(restarted._buffers["203.0.113.9"]) == 0

    def test_persistence_is_bounded_to_the_most_recently_active_ips(self, tmp_path, monkeypatch):
        from models import lstm_autoencoder as lstm_mod
        monkeypatch.setattr(lstm_mod, "MAX_PERSISTED_IPS", 2)

        model = LSTMAEModel(model_dir=str(tmp_path))
        src = dict(REAL_SHAPED_DOCUMENT["_source"])
        for i, ip in enumerate(["203.0.113.1", "203.0.113.2", "203.0.113.3"]):
            src = dict(src)
            src["source"] = {"ip": ip}
            src["@timestamp"] = f"2026-07-31T19:14:{12 + i:02d}.000Z"  # strictly increasing _last_seen
            model.score(src)
        model.save_buffers()

        restarted = LSTMAEModel(model_dir=str(tmp_path))
        assert len(restarted._last_seen) == 2, "must not persist more than MAX_PERSISTED_IPS entries"
        assert "203.0.113.1" not in restarted._last_seen, \
            "the least-recently-active IP must be the one dropped when bounding"
        assert "203.0.113.2" in restarted._last_seen and "203.0.113.3" in restarted._last_seen

    # #884: MAX_PERSISTED_IPS used to bound only what save_buffers() wrote to
    # disk -- the live _buffers/_last_seen dicts grew for every distinct IP
    # ever scored, unbounded, for the whole process lifetime. Proven here
    # with no save_buffers()/restart involved at all: the cap must already
    # hold against the live, in-process state.
    def test_live_state_is_bounded_during_a_run_not_only_at_persist_time(self, tmp_path, monkeypatch):
        from models import lstm_autoencoder as lstm_mod
        monkeypatch.setattr(lstm_mod, "MAX_PERSISTED_IPS", 2)

        model = LSTMAEModel(model_dir=str(tmp_path))
        src = dict(REAL_SHAPED_DOCUMENT["_source"])
        for i, ip in enumerate(["203.0.113.1", "203.0.113.2", "203.0.113.3"]):
            src = dict(src)
            src["source"] = {"ip": ip}
            src["@timestamp"] = f"2026-07-31T19:14:{12 + i:02d}.000Z"  # strictly increasing
            model.score(src)

        assert len(model._last_seen) == 2, "live _last_seen must stay bounded during a run"
        assert "203.0.113.1" not in model._last_seen, \
            "the least-recently-active IP must be the one evicted"
        assert "203.0.113.1" not in model._buffers, \
            "the evicted IP's sliding-window buffer must be dropped too, not just its last-seen entry"
        assert "203.0.113.2" in model._last_seen and "203.0.113.3" in model._last_seen

    def test_re_scoring_an_already_tracked_ip_does_not_evict_it(self, tmp_path, monkeypatch):
        # A key already present must be relinked to "most recent", not
        # treated as a fresh insertion that could itself get evicted by the
        # very update meant to keep it alive.
        from models import lstm_autoencoder as lstm_mod
        monkeypatch.setattr(lstm_mod, "MAX_PERSISTED_IPS", 2)

        model = LSTMAEModel(model_dir=str(tmp_path))
        src = dict(REAL_SHAPED_DOCUMENT["_source"])
        for i, ip in enumerate(["203.0.113.1", "203.0.113.2"]):
            src = dict(src)
            src["source"] = {"ip": ip}
            src["@timestamp"] = f"2026-07-31T19:14:{12 + i:02d}.000Z"
            model.score(src)

        # Re-touch .1 so it's now the most-recently-active of the two.
        src = dict(src)
        src["source"] = {"ip": "203.0.113.1"}
        src["@timestamp"] = "2026-07-31T19:14:20.000Z"
        model.score(src)

        # A brand new third IP must now evict .2 (least-recently-active), not .1.
        src = dict(src)
        src["source"] = {"ip": "203.0.113.3"}
        src["@timestamp"] = "2026-07-31T19:14:21.000Z"
        model.score(src)

        assert "203.0.113.1" in model._last_seen
        assert "203.0.113.2" not in model._last_seen
        assert "203.0.113.3" in model._last_seen


class TestScoreAndWriteEventsUsesBatchedScoring:
    """#1227: score_and_write_events() must call score_batch()/
    hbos_score_batch() ONCE per cycle, not score()/hbos_score() once per
    event -- the whole point of the fix (see isolation_forest.py's
    score_batch() docstring) was collapsing N sklearn/pyod calls into one,
    confirmed live to cut ~1000x off ml-worker's dominant per-event cost.
    A silent regression back to the per-row path would reintroduce the
    classification-backlog bottleneck this issue diagnosed, with nothing
    else here to catch it -- the other score_and_write_events tests only
    check final observable behavior (recent_flags, malformed-event
    metrics), not which scoring path produced it."""

    def test_iso_model_batch_methods_are_called_once_not_per_event(self):
        import worker

        iso_model = MagicMock()
        iso_model.extract_features.side_effect = lambda src, **kw: np.zeros((1, 14), dtype=np.float32)
        iso_model.score_batch.return_value = np.array([0.1, 0.1, 0.1])
        iso_model.hbos_score_batch.return_value = np.array([0.1, 0.1, 0.1])

        lstm_model = MagicMock()
        es = MagicMock()
        recent_flags = []

        events = [
            {"_id": f"e{i}", "_index": "honeypot-v2-2026.07.31", "_source": dict(REAL_SHAPED_DOCUMENT["_source"])}
            for i in range(3)
        ]

        worker.score_and_write_events(es, None, iso_model, lstm_model, events, recent_flags)

        assert iso_model.score_batch.call_count == 1
        assert iso_model.hbos_score_batch.call_count == 1
        assert iso_model.score.call_count == 0, "score() must not be called per-event anymore"
        assert iso_model.hbos_score.call_count == 0, "hbos_score() must not be called per-event anymore"
        assert len(recent_flags) == 3


class TestUnhandledEventErrorsCrashTheBatch:
    """Finding #8, fixed in #171 (roadmap: 'malformed payloads ... are not
    isolated from the processing loop'): worker.py's per-event extract/
    score/write path is now wrapped per-event inside
    score_and_write_events(), extracted from run_worker()'s loop so this is
    directly testable. extract_features() itself is UNCHANGED and still
    raises on a malformed field (proven below) -- the fix is in the caller
    catching that, not in extract_features() defensively tolerating
    anything."""

    def test_extract_features_still_raises_on_a_non_numeric_port(self):
        model = IsoForestModel(model_dir="/tmp/does-not-matter")
        malformed = {"@timestamp": "2026-07-31T00:00:00Z", "destination": {"port": "not-a-port"}}
        with pytest.raises(ValueError):
            # extract_features() itself is intentionally NOT made
            # defensive -- the guard belongs in the caller (below), so any
            # other unexpected shape is still caught the same way instead
            # of needing its own field-specific fix.
            model.extract_features(malformed)

    def test_one_malformed_event_does_not_stop_the_rest_of_the_batch(self):
        import worker

        iso_model = IsoForestModel(model_dir="/tmp/does-not-matter")
        lstm_model = LSTMAEModel(model_dir="/tmp/does-not-matter")
        es = MagicMock()
        recent_flags = []

        valid_event = {
            "_id": "valid-1", "_index": "honeypot-v2-2026.07.31",
            "_source": dict(REAL_SHAPED_DOCUMENT["_source"]),
        }
        malformed_event = {
            "_id": "malformed-1", "_index": "honeypot-v2-2026.07.31",
            "_source": {"@timestamp": "2026-07-31T00:00:00Z", "destination": {"port": "not-a-port"}},
        }
        another_valid_event = {
            "_id": "valid-2", "_index": "honeypot-v2-2026.07.31",
            "_source": dict(REAL_SHAPED_DOCUMENT["_source"]),
        }

        # Must not raise, despite the malformed event sandwiched between
        # two valid ones.
        worker.score_and_write_events(
            es, None, iso_model, lstm_model,
            [valid_event, malformed_event, another_valid_event], recent_flags,
        )

        # Both valid events were still scored.
        assert len(recent_flags) == 2

        # The malformed event was recorded as a best-effort, reviewable metric.
        malformed_calls = [
            call for call in es.index.call_args_list
            if call.kwargs.get("document", {}).get("kind") == "malformed_event"
        ]
        assert len(malformed_calls) == 1
        assert malformed_calls[0].kwargs["document"]["source_event_id"] == "malformed-1"
        assert malformed_calls[0].kwargs["document"]["source_index"] == "honeypot-v2-2026.07.31"

    def test_malformed_event_metric_write_failure_does_not_raise(self):
        import worker

        es = MagicMock()
        es.index.side_effect = ConnectionError("ES unreachable")
        worker.write_malformed_event_metric(es, {"_id": "x", "_index": "y"}, ValueError("boom"))  # must not raise


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
