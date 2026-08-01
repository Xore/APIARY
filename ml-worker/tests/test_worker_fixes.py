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
import fixtures  # noqa: E402
import models.isolation_forest as iso_mod  # noqa: E402


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


class TestWriteAnomalyReadsTheRealSchema:
    """#62 task 33: write_anomaly() used the same broken flat lookups as the
    pre-fix extract_features() (src.get("src_ip"), src.get("dst_port"),
    src.get("proto")) -- a correctly-fired anomaly would still get written
    with src_ip=None, the one field an operator needs to act on it. Fixed to
    reuse the same per-sensor reads extract_features() uses."""

    def test_anomaly_document_gets_the_real_src_ip_and_port(self):
        es = MagicMock()
        event = {"_id": "1", "_index": "honeypot-v2-test", "_source": fixtures.COWRIE_LOGIN_FAILED["_source"]}
        scores = {"isolation_forest": 1.0, "lstm_ae": 1.0, "hbos": 1.0}

        worker.write_anomaly(es, None, event, scores, "test explanation")

        doc = es.index.call_args.kwargs["document"]
        assert doc["src_ip"] == "203.0.113.9"
        assert doc["dst_port"] == 22
        assert doc["proto"] == "tcp"


class TestBoundedRetrain:
    """#62 task 33: retrain() must never fit on more than MAX_TRAIN_SAMPLES
    regardless of how many sources the caller collected -- see the
    constant's comment in models/isolation_forest.py for the cost
    rationale (unbounded IsolationForest.fit()/HBOS.fit() cost on a busy
    honeypot's 24h retrain window)."""

    def test_retrain_fits_on_at_most_the_capped_sample_count(self, monkeypatch, tmp_path):
        monkeypatch.setattr(iso_mod, "MAX_TRAIN_SAMPLES", 5)
        model = iso_mod.IsoForestModel(model_dir=str(tmp_path))
        sources = [fixtures.COWRIE_LOGIN_FAILED["_source"]] * 50  # far over the patched cap

        fit_sample_counts = []
        orig_fit = iso_mod.IsolationForest.fit

        def spy_fit(self, X, *a, **kw):
            fit_sample_counts.append(X.shape[0])
            return orig_fit(self, X, *a, **kw)

        monkeypatch.setattr(iso_mod.IsolationForest, "fit", spy_fit)
        model.retrain(sources)

        assert fit_sample_counts == [5], "IsolationForest.fit() must never see more than MAX_TRAIN_SAMPLES rows"

    def test_fetch_new_events_stops_scrolling_once_max_total_is_reached(self):
        es = MagicMock()
        # 3 pages of 4 hits each; max_total=5 should stop after page 2 (8
        # collected, trimmed to 5) without ever requesting page 3.
        page = lambda n: {"_scroll_id": "sid", "hits": {"hits": [{"_id": str(i)} for i in range(n)]}}
        es.search.return_value = page(4)
        es.scroll.side_effect = [page(4), page(4)]

        events = worker.fetch_new_events(es, "honeypot-v2-*", "2026-07-31T00:00:00Z", page_size=4, max_total=5)

        assert len(events) == 5
        assert es.scroll.call_count == 1, "must stop after the first scroll page already exceeds max_total, not fetch a third page"
