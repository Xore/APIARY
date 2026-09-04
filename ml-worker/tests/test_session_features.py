"""
#277: cmd_count, failed_logins_1h, and unique_ports_1h were hardcoded at
neutral defaults (0/0/1), which meant a real intrusion -- login, then dozens
of destructive commands -- scored identically to a session that did
nothing. These tests prove the real wiring: models.session_features'
per-batch and per-process aggregators, and that IsoForestModel/LSTMAEModel
now receive real values instead of the old constants.

payload_hex is NOT covered here -- still unwired, see #277's remaining scope
and models/session_features.py's module docstring for why.

Run: python3 -m pytest ml-worker/tests/test_session_features.py -v
"""
import tempfile
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fixtures  # noqa: E402
import worker  # noqa: E402
from models.isolation_forest import IsoForestModel, MAX_CMD_COUNT  # noqa: E402
from models.lstm_autoencoder import LSTMAEModel  # noqa: E402
from models.session_features import (  # noqa: E402
    SessionFeatureTracker, compute_batch_session_features,
)


# #1609: these model_dir values are placeholders -- most tests using them never
# write. But `/tmp/does-not-matter*` is a SHARED path, and CI now runs seven
# self-hosted runner instances each under its OWN system user on one host with
# PrivateTmp=no. The first user to run a test that DOES write creates the
# directory 0755 as itself, and every other runner user then fails inside it:
#
#   RuntimeError: [enforce fail at inline_container.cc:747] . open file failed
#
# from torch's PyTorchFileWriter, in the bounded-CPU retrain test below.
# Harmless with one runner; a cross-user collision with several. A per-process
# mkdtemp is unique, 0700, and owned by whoever is running.
_PLACEHOLDER_MODEL_ROOT = tempfile.mkdtemp(prefix="ml-worker-tests-")


def _placeholder_model_dir(name: str) -> str:
    """Writable per-process stand-in for a model_dir the test does not care about."""
    return os.path.join(_PLACEHOLDER_MODEL_ROOT, name)



def _cowrie_login_failed_at(offset_s, src_ip="203.0.113.9"):
    src = dict(fixtures.COWRIE_LOGIN_FAILED["_source"])
    src["honeypot"] = dict(src["honeypot"])
    src["honeypot"]["src_ip"] = src_ip
    src["source"] = {"ip": src_ip}
    from datetime import datetime, timedelta, timezone
    base = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
    ts = (base + timedelta(seconds=offset_s)).isoformat().replace("+00:00", "Z")
    src["@timestamp"] = ts
    return src


class TestComputeBatchSessionFeaturesCmdCount:
    """cmd_count (#277): a per-session running counter, incremented only on
    cowrie.command.input events -- the real intrusion #277 describes
    (login, then a stream of destructive commands) is exactly what this
    must now surface."""

    def test_commands_in_the_same_session_increment(self):
        docs = [d["_source"] for d in fixtures.COWRIE_SAME_IP_SEQUENCE]  # 16 same-session commands
        feats = compute_batch_session_features(docs)
        counts = [f["cmd_count"] for f in feats]
        assert counts == list(range(1, 17)), "cmd_count must increase by exactly 1 per command, in time order"

    def test_non_command_events_do_not_increment_and_carry_the_running_count(self):
        commands = [d["_source"] for d in fixtures.COWRIE_SAME_IP_SEQUENCE[:3]]
        login = _cowrie_login_failed_at(-10)  # before the sequence starts, same session? different session actually
        # A login-failed event has its own session id (fixture default),
        # distinct from COWRIE_SAME_IP_SEQUENCE's "seq-session-1" -- proves
        # cmd_count is scoped per-session, not per-IP.
        feats = compute_batch_session_features([login] + commands)
        assert feats[0]["cmd_count"] == 0, "a failed-login event in an unrelated session must not carry a command count"
        assert [f["cmd_count"] for f in feats[1:]] == [1, 2, 3]

    def test_different_sessions_count_independently(self):
        session_a = [d["_source"] for d in fixtures.COWRIE_SAME_IP_SEQUENCE[:5]]
        session_b = []
        for i in range(3):
            src = dict(fixtures._cowrie_command_at(100 + i * 2.0, f"other-{i}")["_source"])
            src["honeypot"] = dict(src["honeypot"])
            src["honeypot"]["session"] = "other-session"
            session_b.append(src)

        feats = compute_batch_session_features(session_a + session_b)
        assert [f["cmd_count"] for f in feats[:5]] == [1, 2, 3, 4, 5]
        assert [f["cmd_count"] for f in feats[5:]] == [1, 2, 3], \
            "a different session must start its own count from zero, not continue session_a's"

    def test_result_order_matches_input_order_even_when_events_are_out_of_order(self):
        docs = [d["_source"] for d in fixtures.COWRIE_SAME_IP_SEQUENCE[:4]]
        shuffled = [docs[2], docs[0], docs[3], docs[1]]  # deliberately not time-ordered
        feats = compute_batch_session_features(shuffled)
        # docs[2] is the 3rd command chronologically -> cmd_count 3, etc.
        assert feats[0]["cmd_count"] == 3  # docs[2]
        assert feats[1]["cmd_count"] == 1  # docs[0]
        assert feats[2]["cmd_count"] == 4  # docs[3]
        assert feats[3]["cmd_count"] == 2  # docs[1]


class TestComputeBatchSessionFeaturesRollingWindows:
    """failed_logins_1h / unique_ports_1h (#277): rolling count/distinct
    ports per src_ip over the preceding hour (docs/ml-worker-plan.md §5.1),
    not the old hardcoded 0/1."""

    def test_failed_logins_accumulate_within_the_window(self):
        events = [_cowrie_login_failed_at(i * 60) for i in range(5)]  # 5 failed logins, 1 min apart
        feats = compute_batch_session_features(events)
        assert [f["failed_logins_1h"] for f in feats] == [1, 2, 3, 4, 5]

    def test_failed_logins_outside_the_window_are_pruned(self):
        far_past = _cowrie_login_failed_at(0)
        within_window = _cowrie_login_failed_at(1800)     # 30 min later
        outside_window = _cowrie_login_failed_at(4000)    # ~66 min later -- past the 1h window from t=0
        feats = compute_batch_session_features([far_past, within_window, outside_window])
        assert feats[2]["failed_logins_1h"] == 2, \
            "the event at t=0 is more than 1h before t=4000 and must have aged out"

    def test_different_src_ips_have_independent_windows(self):
        a1 = _cowrie_login_failed_at(0, src_ip="203.0.113.1")
        b1 = _cowrie_login_failed_at(10, src_ip="203.0.113.2")
        a2 = _cowrie_login_failed_at(20, src_ip="203.0.113.1")
        feats = compute_batch_session_features([a1, b1, a2])
        assert feats[0]["failed_logins_1h"] == 1
        assert feats[1]["failed_logins_1h"] == 1, "a different src_ip must not see the first IP's failed logins"
        assert feats[2]["failed_logins_1h"] == 2

    def test_unique_ports_counts_distinct_ports_touched_by_one_ip(self):
        events = []
        for i, port in enumerate([22, 80, 22, 443, 80]):
            src = _cowrie_login_failed_at(i * 60)
            src["destination"] = {"port": port}
            events.append(src)
        feats = compute_batch_session_features(events)
        # Running distinct-port counts as each new port is touched:
        # 22 -> {22}=1, 80 -> {22,80}=2, 22 -> still 2, 443 -> 3, 80 -> still 3
        assert [f["unique_ports_1h"] for f in feats] == [1, 2, 2, 3, 3]


class TestSessionFeatureTrackerLivePath:
    """The stateful, long-lived tracker worker.py's score_and_write_events()
    uses -- same rolling-window contract as compute_batch_session_features,
    but called incrementally, once per real event, and persisted across
    restarts (#170's precedent for LSTM buffers)."""

    def test_observe_increments_cmd_count_across_calls(self, tmp_path):
        tracker = SessionFeatureTracker(model_dir=str(tmp_path))
        docs = [d["_source"] for d in fixtures.COWRIE_SAME_IP_SEQUENCE[:3]]
        results = [tracker.observe(d) for d in docs]
        assert [r["cmd_count"] for r in results] == [1, 2, 3]

    def test_state_survives_a_restart_once_saved(self, tmp_path):
        tracker = SessionFeatureTracker(model_dir=str(tmp_path))
        for d in fixtures.COWRIE_SAME_IP_SEQUENCE[:3]:
            tracker.observe(d["_source"])
        tracker.save()

        restarted = SessionFeatureTracker(model_dir=str(tmp_path))
        next_result = restarted.observe(fixtures.COWRIE_SAME_IP_SEQUENCE[3]["_source"])
        assert next_result["cmd_count"] == 4, "the running count must continue from the persisted state, not reset to 1"

    def test_restart_without_a_prior_save_starts_cold(self, tmp_path):
        restarted = SessionFeatureTracker(model_dir=str(tmp_path))
        result = restarted.observe(fixtures.COWRIE_SAME_IP_SEQUENCE[0]["_source"])
        assert result["cmd_count"] == 1

    # #884: MAX_PERSISTED_IPS/MAX_PERSISTED_SESSIONS used to bound only what
    # save() wrote to disk -- the live _ip_last_seen/_session_last_seen (and
    # the _WindowState dicts they key) grew for every distinct src_ip/session
    # ever observed, unbounded, for the whole process lifetime. Proven here
    # with no save()/restart involved at all.
    def test_live_state_is_bounded_during_a_run_not_only_at_persist_time(self, tmp_path, monkeypatch):
        import models.session_features as sf_mod
        monkeypatch.setattr(sf_mod, "MAX_PERSISTED_IPS", 2)
        monkeypatch.setattr(sf_mod, "MAX_PERSISTED_SESSIONS", 2)

        tracker = SessionFeatureTracker(model_dir=str(tmp_path))
        for i in range(3):
            doc = dict(fixtures.COWRIE_SAME_IP_SEQUENCE[0]["_source"])
            doc["honeypot"] = dict(doc["honeypot"])
            doc["honeypot"]["src_ip"] = f"203.0.113.{i + 1}"
            doc["honeypot"]["session"] = f"session-{i + 1}"
            # _get_ip (models.isolation_forest) prefers the ECS-promoted
            # source.ip over honeypot.src_ip -- both must move together.
            doc["source"] = {"ip": f"203.0.113.{i + 1}"}
            doc["@timestamp"] = f"2026-07-31T19:14:{12 + i:02d}.000Z"
            tracker.observe(doc)

        assert len(tracker._ip_last_seen) == 2, "live _ip_last_seen must stay bounded during a run"
        assert len(tracker._session_last_seen) == 2, "live _session_last_seen must stay bounded during a run"
        assert "203.0.113.1" not in tracker._ip_last_seen, \
            "the least-recently-active IP must be the one evicted"
        assert "session-1" not in tracker._session_last_seen, \
            "the least-recently-active session must be the one evicted"
        assert "203.0.113.1" not in tracker._state.ip_ports
        assert "203.0.113.1" not in tracker._state.ip_failed_logins
        assert "session-1" not in tracker._state.session_counts


class TestExtractFeaturesUsesRealValues:
    """IsoForestModel.extract_features() (#277): cmd_count/failed_logins_1h/
    unique_ports_1h are now real parameters, not hardcoded constants --
    proven by observing the actual feature-vector positions change."""

    def test_cmd_count_changes_feature_index_5(self):
        model = IsoForestModel(model_dir=_placeholder_model_dir("does-not-matter"))
        src = fixtures.COWRIE_COMMAND_INPUT["_source"]
        no_commands = model.extract_features(src)
        many_commands = model.extract_features(src, cmd_count=150)
        assert no_commands[0][5] == 0.0
        assert many_commands[0][5] == pytest.approx(150 / MAX_CMD_COUNT)

    def test_failed_logins_and_unique_ports_change_indices_10_and_11(self):
        model = IsoForestModel(model_dir=_placeholder_model_dir("does-not-matter"))
        src = fixtures.COWRIE_LOGIN_FAILED["_source"]
        neutral = model.extract_features(src)
        real = model.extract_features(src, failed_logins_1h=50, unique_ports_1h=12)
        assert neutral[0][10] == 0.0 and neutral[0][11] == pytest.approx(1 / 65535.0)
        assert real[0][10] == pytest.approx(50 / 500.0)
        assert real[0][11] == pytest.approx(12 / 65535.0)

    def test_default_call_without_context_keeps_the_pre_277_neutral_shape(self):
        # Direct callers with no session/window context (most unit tests)
        # must still get a valid, neutral feature vector -- not an error.
        model = IsoForestModel(model_dir=_placeholder_model_dir("does-not-matter"))
        features = model.extract_features(fixtures.COWRIE_LOGIN_FAILED["_source"])
        assert features.shape == (1, 15)


class TestExplainSurfacesRealPortScanSignal:
    """explain()'s "Port scan: N unique ports" narrative (models/
    isolation_forest.py) reads feature index 11 -- before #277 this could
    never fire for real since unique_ports_1h was hardcoded to the
    normalised-equivalent of 1. Proves it now fires for a real value."""

    def test_port_scan_explanation_fires_with_a_real_unique_ports_value(self):
        model = IsoForestModel(model_dir=_placeholder_model_dir("does-not-matter"))
        src = fixtures.COWRIE_LOGIN_FAILED["_source"]
        features = model.extract_features(src, unique_ports_1h=1000)
        explanation = model.explain(features, {"isolation_forest": 0.5})
        assert "Port scan" in explanation


class TestScoreAndWriteEventsWiresSessionTracker:
    """worker.score_and_write_events() (#277): with a session_tracker
    supplied, every event is observe()'d exactly once and the result feeds
    both models -- the actual end-to-end wiring the rest of this file tests
    in isolation."""

    def test_observe_is_called_once_per_event_and_feeds_extract_features(self):
        iso_model = IsoForestModel(model_dir=_placeholder_model_dir("does-not-matter"))
        lstm_model = LSTMAEModel(model_dir=_placeholder_model_dir("does-not-matter"))
        es = MagicMock()
        recent_flags = []

        tracker = MagicMock()
        tracker.observe.return_value = {"cmd_count": 7, "failed_logins_1h": 3, "unique_ports_1h": 9}

        real_extract = iso_model.extract_features
        captured = []

        def spy_extract(src, **kwargs):
            captured.append(kwargs)
            return real_extract(src, **kwargs)

        iso_model.extract_features = spy_extract

        event = {
            "_id": "1", "_index": "honeypot-v2-2026.08.01",
            "_source": dict(fixtures.COWRIE_LOGIN_FAILED["_source"]),
        }
        worker.score_and_write_events(es, None, iso_model, lstm_model, [event], recent_flags, tracker)

        assert tracker.observe.call_count == 1
        assert captured == [{"cmd_count": 7, "failed_logins_1h": 3, "unique_ports_1h": 9}]

    def test_no_tracker_falls_back_to_neutral_defaults(self):
        # Backward compatibility: existing callers (and tests) that don't
        # pass a session_tracker must keep working exactly as before #277.
        iso_model = IsoForestModel(model_dir=_placeholder_model_dir("does-not-matter"))
        lstm_model = LSTMAEModel(model_dir=_placeholder_model_dir("does-not-matter"))
        es = MagicMock()
        recent_flags = []
        event = {
            "_id": "1", "_index": "honeypot-v2-2026.08.01",
            "_source": dict(fixtures.COWRIE_LOGIN_FAILED["_source"]),
        }
        worker.score_and_write_events(es, None, iso_model, lstm_model, [event], recent_flags)
        assert len(recent_flags) == 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
