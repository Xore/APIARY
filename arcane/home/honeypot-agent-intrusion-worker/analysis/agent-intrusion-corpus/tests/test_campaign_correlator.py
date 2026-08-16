#!/usr/bin/env python3
"""Tests for campaign_correlator.py (#154 phase 2, second half).

Same two-group structure as test_decode_correlate.py: hand-built-fixture
unit tests for the mechanism in isolation, then end-to-end tests against
the real corpus proving it actually surfaces the specific correlation
#154 opens with -- isolated low-signal events from *different* sensors/
actors turning out to be one campaign once a shared identifier links them.
"""
import sys
import unittest
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import campaign_correlator as cc  # noqa: E402
import validate_corpus  # noqa: E402


def _event(event_id, ts, **raw):
    return {"event_id": event_id, "timestamp": ts, "raw": raw}


class TestExtractIdentifiers(unittest.TestCase):
    def test_session_and_src_ip(self):
        ids = cc.extract_identifiers({"session": "s1", "src_ip": "203.0.113.1"})
        self.assertEqual(ids, {"session:s1", "ip:203.0.113.1"})

    def test_host_counts_when_actor_is_unknown(self):
        ids = cc.extract_identifiers({"host": "192.0.2.50", "actor": "unknown"})
        self.assertEqual(ids, {"ip:192.0.2.50"})

    def test_host_counts_when_actor_absent(self):
        ids = cc.extract_identifiers({"host": "192.0.2.50"})
        self.assertEqual(ids, {"ip:192.0.2.50"})

    def test_host_excluded_for_named_actor(self):
        # A named, legitimate actor (admin, hp-autoheal, dependabot[bot],
        # ...) owning a host is real shared infrastructure, not identity
        # evidence -- see the module's own _NAMED_ACTORS rationale.
        ids = cc.extract_identifiers({"host": "192.0.2.1", "actor": "admin"})
        self.assertEqual(ids, set())

    def test_channel_extracted_from_input_field(self):
        ids = cc.extract_identifiers({"input": "curl -d 'type=stage&channel=c9f2&seq=1&data=X'"})
        self.assertEqual(ids, {"channel:c9f2"})

    def test_channel_extracted_from_payload_printable(self):
        ids = cc.extract_identifiers({"payload_printable": "type=exfil&channel=abcd&seq=1&data=X"})
        self.assertEqual(ids, {"channel:abcd"})

    def test_dest_ip_is_not_an_identifier(self):
        # Deliberate: dest_ip is usually the *target*, not the actor --
        # using it as a correlation key would merge unrelated flows that
        # happen to hit the same shared internal service.
        ids = cc.extract_identifiers({"dest_ip": "192.0.2.61"})
        self.assertEqual(ids, set())

    def test_no_identifiers_returns_empty_set(self):
        self.assertEqual(cc.extract_identifiers({"event": "something", "actor": "unknown"}), set())


class TestCorrelateCampaigns(unittest.TestCase):
    def test_shared_session_merges(self):
        events = [
            _event("e1", "2026-01-01T00:00:00Z", session="s1", src_ip="203.0.113.1"),
            _event("e2", "2026-01-01T00:05:00Z", session="s1", src_ip="203.0.113.1"),
        ]
        campaigns = cc.correlate_campaigns(events)
        self.assertEqual(len(campaigns), 1)
        self.assertEqual(set(campaigns[0].event_ids), {"e1", "e2"})

    def test_no_shared_identifier_stays_separate(self):
        events = [
            _event("e1", "2026-01-01T00:00:00Z", session="s1"),
            _event("e2", "2026-01-01T00:05:00Z", session="s2"),
        ]
        campaigns = cc.correlate_campaigns(events)
        self.assertEqual(len(campaigns), 2)

    def test_shared_identifier_outside_window_stays_separate(self):
        events = [
            _event("e1", "2026-01-01T00:00:00Z", src_ip="203.0.113.1"),
            _event("e2", "2026-01-10T00:00:00Z", src_ip="203.0.113.1"),  # 9 days later
        ]
        campaigns = cc.correlate_campaigns(events, window=timedelta(hours=72))
        self.assertEqual(len(campaigns), 2)

    def test_shared_identifier_inside_window_merges(self):
        events = [
            _event("e1", "2026-01-01T00:00:00Z", src_ip="203.0.113.1"),
            _event("e2", "2026-01-02T00:00:00Z", src_ip="203.0.113.1"),  # 24h later
        ]
        campaigns = cc.correlate_campaigns(events, window=timedelta(hours=72))
        self.assertEqual(len(campaigns), 1)

    def test_transitive_chain_across_different_identifier_types(self):
        # e1/e2 share a session; e2/e3 share nothing directly but e2 and
        # e3 both mention the same channel -- e1 should end up in the same
        # campaign as e3 even though e1 and e3 share no identifier of
        # their own. This is the exact multi-hop shape the real corpus
        # test below exercises for real.
        events = [
            _event("e1", "2026-01-01T00:00:00Z", session="s1"),
            _event("e2", "2026-01-01T00:05:00Z", session="s1", input="channel=zz99&seq=1"),
            _event("e3", "2026-01-01T00:10:00Z", payload_printable="channel=zz99&seq=1"),
        ]
        campaigns = cc.correlate_campaigns(events)
        self.assertEqual(len(campaigns), 1)
        self.assertEqual(set(campaigns[0].event_ids), {"e1", "e2", "e3"})

    def test_event_with_no_identifiers_is_a_singleton_campaign(self):
        events = [_event("e1", "2026-01-01T00:00:00Z", event="pull_request_opened", actor="unknown")]
        campaigns = cc.correlate_campaigns(events)
        self.assertEqual(len(campaigns), 1)
        self.assertEqual(campaigns[0].event_ids, ["e1"])

    def test_campaigns_sorted_by_start_time(self):
        events = [
            _event("e1", "2026-01-02T00:00:00Z", session="s2"),
            _event("e2", "2026-01-01T00:00:00Z", session="s1"),
        ]
        campaigns = cc.correlate_campaigns(events)
        self.assertEqual([c.start for c in campaigns], sorted(c.start for c in campaigns))


class TestAgainstRealCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = validate_corpus.load_corpus()
        cls.campaigns = cc.correlate_campaigns(cls.events)

    def _campaign_containing(self, event_id):
        for camp in self.campaigns:
            if event_id in camp.event_ids:
                return camp
        self.fail(f"{event_id} not found in any campaign")

    def test_every_corpus_event_appears_exactly_once(self):
        seen = [eid for camp in self.campaigns for eid in camp.event_ids]
        self.assertEqual(sorted(seen), sorted(e["event_id"] for e in self.events))
        self.assertEqual(len(seen), len(set(seen)))

    def test_session_001_actor_chain_merges_into_one_campaign(self):
        # corpus-001/002/010/011/013/014: recon through encoded_dropper_c2,
        # same cowrie session and source IP throughout.
        expected = {"corpus-001", "corpus-002", "corpus-010", "corpus-011", "corpus-013", "corpus-014"}
        camp = self._campaign_containing("corpus-001")
        self.assertEqual(set(camp.event_ids), expected)

    def test_channel_bridges_two_otherwise_unconnected_actor_identities(self):
        # The real point of this whole module: corpus-015/016 (honeypot
        # session, source IP 203.0.113.11) share no session or IP at all
        # with corpus-017/018/021/023 (internal workload, IP 192.0.2.50)
        # -- the *only* thing connecting them is a C2 channel ID
        # (c9f2) reused across a "stage" and an "exfil" message, exactly
        # the shape #154 opens with: isolated low-signal events that are
        # actually one campaign, detectable only by noticing the shared
        # channel, not by any single event being independently alarming.
        camp_stage = self._campaign_containing("corpus-015")
        camp_exfil = self._campaign_containing("corpus-017")
        self.assertIs(camp_stage, camp_exfil)
        self.assertIn("channel:c9f2", camp_stage.identifiers)
        self.assertIn("ip:203.0.113.11", camp_stage.identifiers)
        self.assertIn("ip:192.0.2.50", camp_stage.identifiers)
        # corpus-019/022 (persistence + cloud_k8s probe, same 192.0.2.50
        # workload via the host-with-unknown-actor fallback) should also
        # be swept into this same campaign.
        self.assertIn("corpus-019", camp_stage.event_ids)
        self.assertIn("corpus-022", camp_stage.event_ids)

    def test_benign_events_sharing_dashboard_host_do_not_merge(self):
        # corpus-005 (actor=admin), corpus-007 (WireGuard handshake), and
        # corpus-009 (actor=hp-autoheal) all mention host=192.0.2.1 (the
        # dashboard/management host itself) -- none should merge with each
        # other purely on that basis; a named actor owning a shared host
        # is not identity evidence (see extract_identifiers' own
        # docstring). Confirmed here against the real fixtures, not just
        # the synthetic unit test above.
        c5 = self._campaign_containing("corpus-005")
        c9 = self._campaign_containing("corpus-009")
        self.assertNotEqual(set(c5.event_ids), set(c9.event_ids))
        self.assertNotIn("corpus-009", c5.event_ids)
        self.assertNotIn("corpus-005", c9.event_ids)

    def test_documented_gap_fleet_siblings_on_different_hosts_stay_separate(self):
        # corpus-019 (host 192.0.2.50) and corpus-020 (host 192.0.2.51) are
        # the real campaign's own "fleet across multiple nodes" pattern --
        # deliberately on *different* hosts, so no shared stable ID exists
        # between them. This module only correlates on shared identifiers
        # (#154's own literal ask), not repeated-pattern similarity across
        # different infrastructure -- that would be a real, separate
        # capability (arguably phase 3 territory: "the same technique
        # fired on N different hosts within Y minutes" is itself a
        # criticality signal), not a bug in this one. Asserted explicitly
        # so this stays a documented, intentional scope boundary rather
        # than a silent gap a future reader has to rediscover.
        c19 = self._campaign_containing("corpus-019")
        self.assertNotIn("corpus-020", c19.event_ids)

    def test_documented_gap_mesh_pivot_ip_change_stays_separate(self):
        # corpus-023 (mesh enrollment, still src_ip 192.0.2.50 -- the
        # workload's own address) and corpus-024/025 (internal-connector
        # enumeration and the source-control breach, both from
        # 198.51.100.1 -- the *mesh* address that workload enrolled as)
        # are, per their own notes, "the same mesh identity" -- but that
        # identity claim spans a NAT/tunnel boundary (a workload's own IP
        # vs. the address it appears as once tunneled) this module has no
        # signal for. A real fix needs actual mesh-enrollment-event
        # correlation (matching an enrollment record's own workload-IP and
        # assigned-tunnel-IP fields), not a generic ID matcher -- out of
        # scope here, asserted so the gap is visible rather than assumed
        # away.
        c23 = self._campaign_containing("corpus-023")
        c24 = self._campaign_containing("corpus-024")
        self.assertIsNot(c23, c24)


if __name__ == "__main__":
    unittest.main()
