#!/usr/bin/env python3
"""Tests for worker.py (#154 phase 5, first half): wiring
decode_correlate/campaign_correlator/criticality_rules against
Elasticsearch-shaped data for real, not just the corpus fixture.

Uses a minimal hand-rolled fake ES client (this repo has no existing
FakeElasticsearch helper in Python -- the dashboard's own e2e suite has a
JS one, fake-elasticsearch.mjs, for the same "no real ES in CI" reason;
this is that same idea, scoped to exactly the API surface worker.py
actually calls: search/scroll/clear_scroll/index/get). No network, no
real Elasticsearch needed to run these.
"""
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import criticality_rules as rules  # noqa: E402
import validate_corpus  # noqa: E402
import worker  # noqa: E402


class FakeElasticsearch:
    """Just enough of the elasticsearch-py client surface for worker.py:
    one search() that returns everything matching an index pattern (glob-
    style '*' only, this repo's own two real patterns' only wildcard
    shape) in one page -- no real pagination, since no test here needs
    more than a handful of documents at once. scroll() always signals
    "no more hits" on the first call, matching that. index() records
    writes for assertions instead of persisting anything."""

    def __init__(self, documents: dict):
        # {index_name: [{"_id": ..., "_source": {...}}, ...]}
        self._documents = documents
        self.indexed: list[dict] = []

    def _matches(self, index_name: str, pattern: str) -> bool:
        if pattern.endswith("*"):
            return index_name.startswith(pattern[:-1])
        return index_name == pattern

    def search(self, index, body, scroll=None):
        since = body["query"]["range"]["@timestamp"]["gte"]
        hits = []
        for index_name, docs in self._documents.items():
            if not self._matches(index_name, index):
                continue
            for doc in docs:
                if doc["_source"].get("@timestamp", "") >= since:
                    hits.append({"_id": doc["_id"], "_index": index_name, "_source": doc["_source"]})
        hits.sort(key=lambda h: h["_source"].get("@timestamp", ""))
        return {"_scroll_id": "fake-scroll-1", "hits": {"hits": hits}}

    def scroll(self, scroll_id, scroll=None):
        return {"_scroll_id": scroll_id, "hits": {"hits": []}}

    def clear_scroll(self, scroll_id):
        pass

    def index(self, index, document, id=None):
        self.indexed.append({"index": index, "id": id, "document": document})


def _cowrie_doc(doc_id, ts, session, src_ip, input_text):
    return {"_id": doc_id, "_source": {
        "@timestamp": ts, "eventid": "cowrie.command.input",
        "session": session, "src_ip": src_ip, "input": input_text,
        "username": "root", "password": "x", "dst_port": 22,
    }}


class TestFetchWindowEvents(unittest.TestCase):
    def test_maps_es_hit_shape_into_event_shape(self):
        es = FakeElasticsearch({"honeypot-v2-2026.02.09": [
            _cowrie_doc("realid1", "2026-02-09T04:01:00.123Z", "s1", "203.0.113.10", "id; env"),
        ]})
        events = worker.fetch_window_events(es, "honeypot-v2-*", "2026-02-01T00:00:00Z")
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertEqual(e["event_id"], "realid1")
        self.assertEqual(e["source_index"], "honeypot-v2-2026.02.09")
        self.assertEqual(e["raw"]["input"], "id; env")

    def test_skips_documents_with_no_timestamp(self):
        es = FakeElasticsearch({"honeypot-v2-2026.02.09": [
            {"_id": "no-ts", "_source": {"eventid": "cowrie.command.input", "input": "id"}},
        ]})
        events = worker.fetch_window_events(es, "honeypot-v2-*", "2026-02-01T00:00:00Z")
        self.assertEqual(events, [])

    def test_index_pattern_wildcard_matches_dated_indices_only(self):
        es = FakeElasticsearch({
            "honeypot-v2-2026.02.09": [_cowrie_doc("a", "2026-02-09T00:00:00Z", "s1", "203.0.113.1", "id")],
            "suricata-v2-2026.02.09": [_cowrie_doc("b", "2026-02-09T00:00:00Z", "s2", "203.0.113.2", "id")],
        })
        events = worker.fetch_window_events(es, "honeypot-v2-*", "2026-02-01T00:00:00Z")
        self.assertEqual([e["event_id"] for e in events], ["a"])


class TestNormalizeTimestamp(unittest.TestCase):
    def test_bare_z_suffix_passes_through(self):
        self.assertEqual(worker._normalize_timestamp("2026-02-09T04:01:00Z"), "2026-02-09T04:01:00Z")

    def test_fractional_seconds_are_truncated(self):
        self.assertEqual(worker._normalize_timestamp("2026-02-09T04:01:00.123456Z"), "2026-02-09T04:01:00Z")

    def test_numeric_utc_offset_is_normalized_to_z(self):
        self.assertEqual(worker._normalize_timestamp("2026-02-09T06:01:00+02:00"), "2026-02-09T04:01:00Z")

    def test_naive_timestamp_assumed_utc(self):
        # Real @timestamp fields are never naive in practice, but a
        # malformed document shouldn't crash the whole cycle over it.
        self.assertEqual(worker._normalize_timestamp("2026-02-09T04:01:00"), "2026-02-09T04:01:00Z")


class TestBuildCampaignVerdict(unittest.TestCase):
    def test_low_severity_campaign_yields_no_verdict(self):
        events_by_id = {
            "e1": {"event_id": "e1", "timestamp": "2026-02-09T00:00:00Z", "source_index": "honeypot-v2-x",
                   "raw": {"eventid": "cowrie.command.input", "input": "id; whoami", "session": "s1"}},
        }
        campaign = worker.corr.Campaign(event_ids=["e1"], identifiers={"session:s1"}, start="2026-02-09T00:00:00Z", end="2026-02-09T00:00:00Z")
        self.assertIsNone(worker.build_campaign_verdict(campaign, events_by_id))

    def test_high_severity_campaign_yields_full_verdict(self):
        events_by_id = {
            "e1": {"event_id": "e1", "timestamp": "2026-02-09T00:00:00Z", "source_index": "honeypot-v2-x",
                   "raw": {"eventid": "cowrie.command.input", "input": "cat /proc/self/environ", "session": "s1"}},
        }
        campaign = worker.corr.Campaign(event_ids=["e1"], identifiers={"session:s1"}, start="2026-02-09T00:00:00Z", end="2026-02-09T00:00:00Z")
        verdict = worker.build_campaign_verdict(campaign, events_by_id)
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict["severity"], "high")
        self.assertEqual(verdict["matched_categories"], ["sensitive-path-read"])
        self.assertEqual(verdict["event_count"], 1)
        self.assertEqual(len(verdict["events"]), 1)
        matched = verdict["events"][0]["matched_rules"][0]
        self.assertEqual(matched["rule"], "sensitive-path-read")
        self.assertTrue(matched["trust_boundary"])  # non-empty -- phase 5's own required field
        self.assertEqual(matched["decode_chain"], [])  # this rule never decodes anything

    def test_encoded_execution_verdict_surfaces_decode_chain_hashes(self):
        # #154 phase 5's own "decoded-artifact hashes" requirement, proven
        # through the worker's own real call sequence (RuleMatch ->
        # dataclasses.asdict), not just against criticality_rules.py directly.
        import base64
        import gzip
        blob = base64.b64encode(gzip.compress(b"id")).decode()
        events_by_id = {
            "e1": {"event_id": "e1", "timestamp": "2026-02-09T00:00:00Z", "source_index": "honeypot-v2-x",
                   "raw": {"eventid": "cowrie.command.input",
                           "input": f"python3 -c \"exec(gzip.decompress(base64.b64decode('{blob}')))\"", "session": "s1"}},
        }
        campaign = worker.corr.Campaign(event_ids=["e1"], identifiers={"session:s1"}, start="2026-02-09T00:00:00Z", end="2026-02-09T00:00:00Z")
        verdict = worker.build_campaign_verdict(campaign, events_by_id)
        chain = verdict["events"][0]["matched_rules"][0]["decode_chain"]
        self.assertTrue(chain)
        self.assertEqual(chain[0]["transform"], "base64")
        self.assertIn("gzip", [step["transform"] for step in chain])
        self.assertEqual(len(chain[-1]["output_sha256"]), 64)

    def test_campaign_id_is_deterministic(self):
        events_by_id = {
            "e1": {"event_id": "e1", "timestamp": "2026-02-09T00:00:00Z", "source_index": "x",
                   "raw": {"eventid": "cowrie.command.input", "input": "cat /proc/self/environ"}},
            "e2": {"event_id": "e2", "timestamp": "2026-02-09T00:01:00Z", "source_index": "x",
                   "raw": {"eventid": "cowrie.command.input", "input": "cat /proc/self/environ"}},
        }
        campaign_a = worker.corr.Campaign(event_ids=["e1", "e2"], identifiers=set(), start="x", end="y")
        campaign_b = worker.corr.Campaign(event_ids=["e2", "e1"], identifiers=set(), start="x", end="y")  # reversed order
        vid_a = worker.build_campaign_verdict(campaign_a, events_by_id)["campaign_id"]
        vid_b = worker.build_campaign_verdict(campaign_b, events_by_id)["campaign_id"]
        self.assertEqual(vid_a, vid_b)


class TestRunCycle(unittest.TestCase):
    def test_end_to_end_writes_only_escalating_campaigns(self):
        now = datetime.now(timezone.utc)
        ts_recent = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        es = FakeElasticsearch({
            "honeypot-v2-2026": [
                _cowrie_doc("high1", ts_recent, "sess-danger", "203.0.113.10", "cat /proc/self/environ"),
                _cowrie_doc("low1", ts_recent, "sess-benign", "198.51.100.1", "ls -la"),
            ],
        })
        written = worker.run_cycle(es)
        self.assertEqual(written, 1)
        self.assertEqual(len(es.indexed), 1)
        doc = es.indexed[0]
        self.assertEqual(doc["index"], worker.CAMPAIGN_INDEX)
        self.assertEqual(doc["document"]["severity"], "high")
        self.assertEqual([e["event_id"] for e in doc["document"]["events"]], ["high1"])

    def test_no_events_writes_nothing(self):
        es = FakeElasticsearch({})
        self.assertEqual(worker.run_cycle(es), 0)

    def test_never_raises_on_es_failure(self):
        class BrokenES(FakeElasticsearch):
            def search(self, *a, **kw):
                raise ConnectionError("es unreachable")
        # fetch_window_events itself catches and logs -- run_cycle should
        # complete with zero events, not propagate.
        self.assertEqual(worker.run_cycle(BrokenES({})), 0)


class TestTrustBoundaryCoverage(unittest.TestCase):
    def test_every_rule_has_a_trust_boundary_entry(self):
        # RuleMatch.rule strings use hyphens (see each rule's own
        # RuleMatch(...) call) -- read straight from source rather than
        # guessing a name-mangling transform from each function's own
        # rule_snake_case name is exact.
        import inspect
        emitted_names = set()
        for r in rules.ALL_RULES:
            source = inspect.getsource(r)
            for line in source.splitlines():
                if "RuleMatch(" in line:
                    name = line.split('RuleMatch("')[1].split('"')[0]
                    emitted_names.add(name)
        missing = emitted_names - set(rules.TRUST_BOUNDARIES)
        self.assertEqual(missing, set(), f"rule name(s) with no TRUST_BOUNDARIES entry: {missing}")


class TestFullPipelineAgainstRealCorpus(unittest.TestCase):
    """The actual point of this file: proves campaign_correlator.py and
    criticality_rules.py -- both already proven against the corpus
    independently, in their own test files -- produce the *same* real
    capstone finding when driven through worker.py's own
    correlate-then-score path (corr.correlate_campaigns +
    build_campaign_verdict), the exact call sequence run_cycle uses. Skips
    fetch_window_events/FakeElasticsearch entirely here since that
    ES-shape-mapping concern is already covered above -- this is purely
    about whether the pipeline wiring itself is correct."""

    @classmethod
    def setUpClass(cls):
        cls.events = validate_corpus.load_corpus()
        cls.events_by_id = {e["event_id"]: e for e in cls.events}

    def test_merged_campaign_still_reaches_critical_through_worker_wiring(self):
        campaigns = worker.corr.correlate_campaigns(self.events, window=worker.CORRELATION_WINDOW)
        verdicts = [v for c in campaigns if (v := worker.build_campaign_verdict(c, self.events_by_id)) is not None]
        critical = [v for v in verdicts if v["severity"] == "critical"]
        self.assertEqual(len(critical), 1)
        self.assertGreaterEqual(critical[0]["event_count"], 8)
        self.assertIn("corpus-017", [e["event_id"] for e in critical[0]["events"]])

    def test_benign_only_events_never_produce_a_verdict(self):
        benign_events = [e for e in self.events if e["is_benign"]]
        benign_by_id = {e["event_id"]: e for e in benign_events}
        campaigns = worker.corr.correlate_campaigns(benign_events, window=worker.CORRELATION_WINDOW)
        verdicts = [v for c in campaigns if (v := worker.build_campaign_verdict(c, benign_by_id)) is not None]
        self.assertEqual(verdicts, [])

    def test_correlation_window_matches_module_default(self):
        # If campaign_correlator.py's own default window ever changes,
        # this worker's CORRELATION_WINDOW constant needs to move with it
        # (or be deliberately different for a stated reason) -- catches
        # silent drift between the two rather than each just trusting the
        # other stayed in sync.
        import inspect
        sig = inspect.signature(worker.corr.correlate_campaigns)
        self.assertEqual(sig.parameters["window"].default, worker.CORRELATION_WINDOW)


if __name__ == "__main__":
    unittest.main()
