"""
Fixes applied after the #61 audit (tracked in #62). Separate from
test_worker_audit.py, which characterizes defects found in the original
scaffold -- these tests characterize the corrected behavior instead, so a
regression back to the old behavior fails loudly here rather than silently
un-fixing something the audit already flagged.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import worker  # noqa: E402


class TestRedisIsOptionalAndBestEffort:
    """ml-worker/docker-compose.yml no longer runs a Redis service at all
    (#62) -- REDIS_URL defaults to empty, and write_anomaly() must never let
    a missing or failing broker take an Elasticsearch write down with it."""

    def test_write_anomaly_succeeds_with_no_redis_client(self):
        es = MagicMock()
        event = {"_id": "1", "_index": "honeypot-v2-test", "_source": {"@timestamp": "2026-07-31T00:00:00Z"}}
        scores = {"isolation_forest": 1.0, "lstm_ae": 1.0, "hbos": 1.0}  # composite well above THRESHOLD

        worker.write_anomaly(es, None, event, scores, "test explanation")

        es.index.assert_called_once()
        assert es.index.call_args.kwargs["index"] == worker.ANOMALY_INDEX

    def test_write_anomaly_survives_a_failing_redis_client(self):
        es = MagicMock()
        rdb = MagicMock()
        rdb.publish.side_effect = ConnectionError("redis is not there")
        event = {"_id": "2", "_index": "honeypot-v2-test", "_source": {"@timestamp": "2026-07-31T00:00:00Z"}}
        scores = {"isolation_forest": 1.0, "lstm_ae": 1.0, "hbos": 1.0}

        # Must not raise: the ES write already committed by the time
        # rdb.publish is attempted, and a notification failure is not a
        # reason to lose that.
        worker.write_anomaly(es, rdb, event, scores, "test explanation")

        es.index.assert_called_once()
        rdb.publish.assert_called_once()

    def test_below_threshold_events_never_reach_redis_or_es(self):
        es = MagicMock()
        rdb = MagicMock()
        event = {"_id": "3", "_index": "honeypot-v2-test", "_source": {}}
        scores = {"isolation_forest": 0.1, "hbos": 0.1, "lstm_ae": 0.0}  # composite well below THRESHOLD

        worker.write_anomaly(es, rdb, event, scores, "should not fire")

        es.index.assert_not_called()
        rdb.publish.assert_not_called()
