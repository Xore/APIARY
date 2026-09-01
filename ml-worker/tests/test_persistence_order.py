"""
#2229: LSTMAEModel.save_buffers()/_load_buffers() and
SessionFeatureTracker.save()/_load() both persist `last_seen` in a way
that, before this fix, restored into their OrderedDicts in something other
than the documented least->most-recently-active order -- inverted for the
LSTM-AE (save() sorts descending, load() applied that order as-is) and
arbitrary for SessionFeatureTracker (save() iterates Python sets). Either
way, popitem(last=False) eviction after a restart picked the wrong
(hottest, not coldest) entry to drop under cardinality pressure.

These tests exercise a real save -> fresh instance -> load round-trip
(not a mocked one) and assert the restored iteration order is
monotonically non-decreasing in last_seen value, then that an eviction
under cardinality pressure after restart drops the minimum, not the
maximum.

Run: python3 -m pytest ml-worker/tests/test_persistence_order.py -v
"""
import sys
import tempfile
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models.lstm_autoencoder import LSTMAEModel, MAX_PERSISTED_IPS, SEQ_LEN  # noqa: E402
from models.session_features import (  # noqa: E402
    SessionFeatureTracker, MAX_PERSISTED_IPS as SF_MAX_IPS, MAX_PERSISTED_SESSIONS,
)


def _assert_monotonically_non_decreasing(ordered_items):
    values = [v for _, v in ordered_items]
    assert values == sorted(values), "iteration order must be least- to most-recently-active"


class TestLSTMAERestoreOrder:
    def test_round_trip_restores_ascending_order(self):
        with tempfile.TemporaryDirectory() as model_dir:
            source = LSTMAEModel(model_dir=model_dir)
            # Distinct, increasing timestamps so ordering is unambiguous.
            for i, ip in enumerate(["cold-ip-1", "cold-ip-2", "warm-ip-3", "warm-ip-4", "hot-ip-5"]):
                source._last_seen[ip] = float(1000 + i)
                source._buffers[ip]  # touch to create the deque entry too
            source.save_buffers()

            restored = LSTMAEModel(model_dir=model_dir)
            _assert_monotonically_non_decreasing(restored._last_seen.items())
            assert next(iter(restored._last_seen)) == "cold-ip-1"
            assert next(reversed(restored._last_seen)) == "hot-ip-5"

    def test_eviction_after_restart_drops_the_coldest_not_the_hottest(self):
        with tempfile.TemporaryDirectory() as model_dir:
            source = LSTMAEModel(model_dir=model_dir)
            for i in range(MAX_PERSISTED_IPS):
                ip = f"ip-{i}"
                source._last_seen[ip] = float(i)
                source._buffers[ip].append(np.zeros(6, dtype=np.float32))
            source.save_buffers()

            restored = LSTMAEModel(model_dir=model_dir)
            assert len(restored._last_seen) == MAX_PERSISTED_IPS
            # One more arrival crosses the cap -- score()'s own eviction path.
            restored._last_seen.pop("new-arrival", None)
            restored._last_seen["new-arrival"] = float(MAX_PERSISTED_IPS)
            assert len(restored._last_seen) > MAX_PERSISTED_IPS
            evicted, _ = restored._last_seen.popitem(last=False)
            assert evicted == "ip-0", "eviction must drop the minimum-last_seen entry, not the maximum"
            assert "new-arrival" in restored._last_seen, "the just-arrived entry must survive its own eviction check"


class TestSessionFeatureTrackerRestoreOrder:
    def test_round_trip_restores_ascending_order_for_both_dicts(self):
        with tempfile.TemporaryDirectory() as model_dir:
            source = SessionFeatureTracker(model_dir=model_dir)
            for i, ip in enumerate(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]):
                source._ip_last_seen[ip] = float(2000 + i)
            for i, session in enumerate(["sess-a", "sess-b", "sess-c", "sess-d", "sess-e"]):
                source._session_last_seen[session] = float(3000 + i)
            source.save()

            restored = SessionFeatureTracker(model_dir=model_dir)
            _assert_monotonically_non_decreasing(restored._ip_last_seen.items())
            _assert_monotonically_non_decreasing(restored._session_last_seen.items())
            assert next(iter(restored._ip_last_seen)) == "10.0.0.1"
            assert next(iter(restored._session_last_seen)) == "sess-a"

    def test_eviction_after_restart_drops_the_coldest_ip_and_session(self):
        with tempfile.TemporaryDirectory() as model_dir:
            source = SessionFeatureTracker(model_dir=model_dir)
            for i in range(SF_MAX_IPS):
                source._ip_last_seen[f"ip-{i}"] = float(i)
            for i in range(MAX_PERSISTED_SESSIONS):
                source._session_last_seen[f"sess-{i}"] = float(i)
            source.save()

            restored = SessionFeatureTracker(model_dir=model_dir)
            assert len(restored._ip_last_seen) == SF_MAX_IPS
            assert len(restored._session_last_seen) == MAX_PERSISTED_SESSIONS

            restored._touch(restored._ip_last_seen, "new-ip", float(SF_MAX_IPS), SF_MAX_IPS,
                             restored._state.ip_ports, restored._state.ip_failed_logins)
            assert "ip-0" not in restored._ip_last_seen, "_touch's own eviction must drop the coldest IP"
            assert "new-ip" in restored._ip_last_seen

            restored._touch(restored._session_last_seen, "new-sess", float(MAX_PERSISTED_SESSIONS),
                             MAX_PERSISTED_SESSIONS, restored._state.session_counts)
            assert "sess-0" not in restored._session_last_seen, "_touch's own eviction must drop the coldest session"
            assert "new-sess" in restored._session_last_seen


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
