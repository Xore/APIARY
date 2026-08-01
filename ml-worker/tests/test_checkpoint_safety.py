"""
#168: total-order checkpoints (timestamp + seen_ids-at-that-timestamp) and
idempotent ml-anomalies document IDs. See docs/ml-gpu-coordinated-roadmap.md
§1 for the original bug report this fixes: "timestamp-only checkpoints can
skip equal-timestamp events, duplicate findings after partial failures."

Run: python3 -m pytest ml-worker/tests/test_checkpoint_safety.py -v
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import worker  # noqa: E402
import fixtures  # noqa: E402


def _hit(id_, timestamp):
    return {"_id": id_, "_index": "honeypot-v2-test", "_source": {"@timestamp": timestamp}}


class TestAdvanceCheckpoint:
    def test_advances_to_the_max_timestamp_in_the_batch(self):
        events = [_hit("a", "2026-08-01T10:00:00Z"), _hit("b", "2026-08-01T10:00:05Z")]
        result = worker.advance_checkpoint(events, {"last_timestamp": "2026-08-01T09:00:00Z", "seen_ids": []})
        assert result["last_timestamp"] == "2026-08-01T10:00:05Z"

    def test_seen_ids_only_covers_the_new_max_timestamp_not_the_whole_batch(self):
        events = [
            _hit("a", "2026-08-01T10:00:00Z"),
            _hit("b", "2026-08-01T10:00:05Z"),
            _hit("c", "2026-08-01T10:00:05Z"),  # shares the max timestamp with b
        ]
        result = worker.advance_checkpoint(events, {"last_timestamp": "", "seen_ids": []})
        assert set(result["seen_ids"]) == {"b", "c"}, \
            "seen_ids must cover every doc AT the new max timestamp, and nothing strictly before it"

    def test_empty_batch_keeps_the_previous_checkpoint_unchanged(self):
        previous = {"last_timestamp": "2026-08-01T09:00:00Z", "seen_ids": ["x"]}
        assert worker.advance_checkpoint([], previous) == previous


class TestFetchNewEventsEqualTimestampSafety:
    """The actual bug (#168): a plain gt-since query permanently loses any
    sibling document sharing the checkpointed timestamp that wasn't in the
    batch the checkpoint was computed from."""

    def test_fetch_uses_inclusive_range_not_exclusive(self):
        es = MagicMock()
        page = lambda hits: {"_scroll_id": "sid", "hits": {"hits": hits}}
        es.search.return_value = page([])
        worker.fetch_new_events(es, "honeypot-v2-*", "2026-08-01T10:00:00Z")
        query = es.search.call_args.kwargs["body"]
        assert query["query"]["range"]["@timestamp"] == {"gte": "2026-08-01T10:00:00Z"}, \
            "must requery inclusively so a same-timestamp sibling can be re-seen and then filtered by exclude_ids"

    def test_exclude_ids_filters_out_already_processed_boundary_documents(self):
        es = MagicMock()
        boundary_ts = "2026-08-01T10:00:00Z"
        hits = [_hit("already-seen", boundary_ts), _hit("brand-new", boundary_ts)]
        es.search.return_value = {"_scroll_id": "sid", "hits": {"hits": hits}}
        es.scroll.return_value = {"_scroll_id": "sid", "hits": {"hits": []}}

        events = worker.fetch_new_events(es, "honeypot-v2-*", boundary_ts, exclude_ids={"already-seen"})

        ids = [e["_id"] for e in events]
        assert ids == ["brand-new"], \
            "a document sharing the checkpoint's exact timestamp but not yet processed must still be returned"

    def test_end_to_end_two_cycles_same_timestamp_sibling_is_not_lost(self):
        """The full bug scenario: cycle 1 sees one event at timestamp T and
        checkpoints past it. A sibling event that also has timestamp T
        (e.g. sub-second precision collision under load) is then queried in
        cycle 2 -- it must be returned, not silently dropped forever."""
        es = MagicMock()
        boundary_ts = "2026-08-01T10:00:00Z"

        # Cycle 1: only "first" exists at T so far.
        es.search.return_value = {"_scroll_id": "sid", "hits": {"hits": [_hit("first", boundary_ts)]}}
        es.scroll.return_value = {"_scroll_id": "sid", "hits": {"hits": []}}
        checkpoint = {"last_timestamp": "2026-08-01T09:00:00Z", "seen_ids": []}
        events = worker.fetch_new_events(es, "honeypot-v2-*", checkpoint["last_timestamp"],
                                          exclude_ids=set(checkpoint["seen_ids"]))
        checkpoint = worker.advance_checkpoint(events, checkpoint)
        assert checkpoint == {"last_timestamp": boundary_ts, "seen_ids": ["first"]}

        # Cycle 2: "second" has now landed with the SAME timestamp T.
        es.search.return_value = {"_scroll_id": "sid", "hits": {"hits": [
            _hit("first", boundary_ts), _hit("second", boundary_ts),
        ]}}
        events = worker.fetch_new_events(es, "honeypot-v2-*", checkpoint["last_timestamp"],
                                          exclude_ids=set(checkpoint["seen_ids"]))

        assert [e["_id"] for e in events] == ["second"], \
            "the equal-timestamp sibling must be seen in the next cycle, not lost"


class TestAnomalyDocIdIsDeterministic:
    def test_same_source_identity_produces_the_same_id(self):
        a = worker.anomaly_doc_id("honeypot-v2-2026.08.01", "evt-1")
        b = worker.anomaly_doc_id("honeypot-v2-2026.08.01", "evt-1")
        assert a == b

    def test_different_source_index_changes_the_id_even_with_the_same_event_id(self):
        # Auto-generated ES IDs are only unique within their own index.
        a = worker.anomaly_doc_id("honeypot-v2-2026.08.01", "evt-1")
        b = worker.anomaly_doc_id("suricata-v2-alert-2026.08.01", "evt-1")
        assert a != b

    def test_none_values_do_not_raise(self):
        worker.anomaly_doc_id(None, None)  # must not raise


class TestWriteAnomalyIsIdempotent:
    """#168: reprocessing the same source event (checkpoint replay,
    crash-retry) must overwrite the same ml-anomalies document, not create
    a second one with a random ES-assigned ID."""

    def test_write_anomaly_passes_a_deterministic_id(self):
        es = MagicMock()
        event = {"_id": "evt-1", "_index": "honeypot-v2-test", "_source": fixtures.COWRIE_LOGIN_FAILED["_source"]}
        scores = {"isolation_forest": 1.0, "lstm_ae": 1.0, "hbos": 1.0}

        worker.write_anomaly(es, None, event, scores, "test explanation")

        expected_id = worker.anomaly_doc_id("honeypot-v2-test", "evt-1")
        assert es.index.call_args.kwargs["id"] == expected_id

    def test_reprocessing_the_same_event_writes_the_same_id_twice(self):
        es = MagicMock()
        event = {"_id": "evt-1", "_index": "honeypot-v2-test", "_source": fixtures.COWRIE_LOGIN_FAILED["_source"]}
        scores = {"isolation_forest": 1.0, "lstm_ae": 1.0, "hbos": 1.0}

        worker.write_anomaly(es, None, event, scores, "first pass")
        worker.write_anomaly(es, None, event, scores, "replay after a crash")

        ids = [call.kwargs["id"] for call in es.index.call_args_list]
        assert ids[0] == ids[1], "a replayed event must overwrite the same document, not create a second one"
