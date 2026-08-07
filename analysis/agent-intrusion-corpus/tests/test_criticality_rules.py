#!/usr/bin/env python3
"""Tests for criticality_rules.py (#154 phase 3).

Three groups:

1. Unit tests per rule against hand-built fixtures.
2. The full-corpus proof: every one of the 27 real corpus events, run
   through evaluate_event(), must escalate exactly when that event's own
   expected_findings.should_escalate says it should -- corpus.jsonl used
   here strictly as the test oracle (see criticality_rules.py's own module
   docstring for why that direction matters).
3. campaign_severity() tests, including the real capstone case: the merged
   8-event campaign (corpus-015 through corpus-023, via
   campaign_correlator.py) should reach "critical", not just "high",
   because it trips 5+ distinct rule categories -- the actual point of
   correlating before scoring.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import campaign_correlator as camp  # noqa: E402
import criticality_rules as cr  # noqa: E402
import validate_corpus  # noqa: E402


class TestIndividualRules(unittest.TestCase):
    def test_sensitive_path_read_matches_proc_environ(self):
        raw = {"eventid": "cowrie.command.input", "input": "cat /proc/self/environ"}
        self.assertIsNotNone(cr.rule_sensitive_path_read(raw))

    def test_sensitive_path_read_ignores_unrelated_command(self):
        raw = {"eventid": "cowrie.command.input", "input": "ls -la /tmp"}
        self.assertIsNone(cr.rule_sensitive_path_read(raw))

    def test_sensitive_path_read_ignores_non_cowrie_sensor(self):
        # A dashboard-audit event that happens to mention the same path in
        # an unrelated field shouldn't match -- _cowrie_input only reads
        # "input" when eventid starts with "cowrie.".
        raw = {"event": "note", "input": "/proc/self/environ"}
        self.assertIsNone(cr.rule_sensitive_path_read(raw))

    def test_chunked_c2_protocol_matches(self):
        raw = {"input": "curl -d 'type=stage&channel=ab12&seq=1&chk=x&data=AAAAAAAA'"}
        match = cr.rule_chunked_c2_protocol(raw)
        self.assertIsNotNone(match)
        self.assertIn("channel=ab12", match.reason)

    def test_encoded_execution_requires_both_exec_and_verified_decode(self):
        import base64
        import gzip
        blob = base64.b64encode(gzip.compress(b"id")).decode()
        raw = {"eventid": "cowrie.command.input", "input": f"python3 -c \"exec(gzip.decompress(base64.b64decode('{blob}')))\""}
        self.assertIsNotNone(cr.rule_encoded_execution(raw))

    def test_encoded_execution_ignores_exec_without_decodable_payload(self):
        raw = {"eventid": "cowrie.command.input", "input": "exec('id')"}
        self.assertIsNone(cr.rule_encoded_execution(raw))

    def test_metadata_service_probe_matches_link_local_address(self):
        raw = {"dest_ip": "169.254.169.254"}
        self.assertIsNotNone(cr.rule_metadata_service_probe(raw))

    def test_privileged_container_create_matches(self):
        raw = {"event": "container_create", "flags": ["--privileged", "-v", "/:/host"]}
        self.assertIsNotNone(cr.rule_privileged_container_create(raw))

    def test_privileged_container_create_ignores_unprivileged(self):
        raw = {"event": "container_create", "flags": ["--rm"]}
        self.assertIsNone(cr.rule_privileged_container_create(raw))

    def test_broad_scope_identity_token_matches_admin_scope_unnamed_actor(self):
        raw = {"event": "token_mint_attempt", "requested_scope": "cluster-admin", "requested_ttl_hours": 24, "actor": "unknown"}
        self.assertIsNotNone(cr.rule_broad_scope_identity_token(raw))

    def test_broad_scope_identity_token_ignores_narrow_named_request(self):
        raw = {"event": "token_mint", "requested_scope": "introspection", "requested_ttl_hours": 1, "actor": "admin"}
        self.assertIsNone(cr.rule_broad_scope_identity_token(raw))

    def test_broad_scope_identity_token_ignores_admin_scope_from_named_actor(self):
        # A named, legitimate operator requesting a broad scope isn't
        # itself suspicious -- the actor check is what matters, same
        # reasoning as rule_scm_write_unexpected_actor.
        raw = {"event": "token_mint", "requested_scope": "admin", "requested_ttl_hours": 1, "actor": "admin"}
        self.assertIsNone(cr.rule_broad_scope_identity_token(raw))

    def test_covert_mesh_enrollment_matches_process_args(self):
        raw = {"process_args": ["--state=mem:", "--no-logs-no-support"]}
        self.assertIsNotNone(cr.rule_covert_mesh_enrollment(raw))

    def test_covert_mesh_enrollment_matches_alert_signature(self):
        raw = {"alert": {"signature": "LOCAL Mesh-VPN Client Enrollment (unexpected source)"}}
        self.assertIsNotNone(cr.rule_covert_mesh_enrollment(raw))

    def test_internal_connector_enumeration_matches_unnamed_actor(self):
        raw = {"event": "api_request", "endpoint": "/internal/connectors/catalog", "actor": "unknown"}
        self.assertIsNotNone(cr.rule_internal_connector_enumeration(raw))

    def test_scm_write_unexpected_actor_matches_token_mint(self):
        raw = {"event": "github_app_token_mint", "actor": "unknown"}
        self.assertIsNotNone(cr.rule_scm_write_unexpected_actor(raw))

    def test_scm_write_unexpected_actor_ignores_dependabot(self):
        raw = {"event": "pull_request_opened", "actor": "dependabot[bot]", "triggers_workflow": True}
        self.assertIsNone(cr.rule_scm_write_unexpected_actor(raw))

    def test_staged_payload_reference_matches(self):
        raw = {"eventid": "cowrie.command.input", "input": "ls -la /tmp/staged; hostname"}
        self.assertIsNotNone(cr.rule_staged_payload_reference(raw))

    def test_evaluate_event_returns_every_match_not_just_first(self):
        # A command that's both a sensitive-path read *and* references the
        # staging directory should trip both rules.
        raw = {"eventid": "cowrie.command.input", "input": "cat /proc/self/environ > /tmp/staged/out"}
        matches = cr.evaluate_event(raw)
        rule_names = {m.rule for m in matches}
        self.assertIn("sensitive-path-read", rule_names)
        self.assertIn("staged-payload-reference", rule_names)


class TestSameSegment(unittest.TestCase):
    """Regression coverage for a real bug found while proving this module
    against the corpus: ipaddress.ip_address(...).is_private returns True
    for RFC 5737 TEST-NET ranges too, which broke both directions at once
    (external TEST-NET traffic misread as internal, so the egress rule
    never fired; then, after switching to a strict RFC1918-only check,
    same-segment TEST-NET traffic misread as external instead, so a
    benign fixture started false-positiving). The same-/24 check this
    settled on fixes both without depending on which address range -- real
    RFC1918 or corpus TEST-NET -- is in play."""

    def test_same_24_is_internal(self):
        self.assertTrue(cr._same_segment("192.0.2.60", "192.0.2.61"))

    def test_different_24_is_external(self):
        self.assertFalse(cr._same_segment("192.0.2.50", "198.51.100.53"))

    def test_real_rfc1918_same_segment_still_works(self):
        self.assertTrue(cr._same_segment("10.1.2.3", "10.1.2.4"))

    def test_loopback_destination_is_always_internal(self):
        self.assertTrue(cr._same_segment("192.0.2.50", "127.0.0.1"))

    def test_link_local_destination_is_always_internal(self):
        # Deliberately NOT the metadata-service special case
        # (169.254.169.254 is separately escalated by
        # rule_metadata_service_probe) -- this just confirms link-local in
        # general isn't treated as a foreign network segment.
        self.assertTrue(cr._same_segment("192.0.2.50", "169.254.1.1"))


class TestFullCorpusMatchesGroundTruth(unittest.TestCase):
    """The actual proof this module works: every one of the 27 real
    corpus events, evaluated by structure alone, escalates exactly when
    its own expected_findings.should_escalate (ground truth, established
    independently when the corpus was built) says it should."""

    @classmethod
    def setUpClass(cls):
        cls.events = validate_corpus.load_corpus()

    def test_every_event_matches_its_own_ground_truth(self):
        mismatches = []
        for e in self.events:
            matches = cr.evaluate_event(e["raw"])
            predicted = len(matches) > 0
            actual = e["expected_findings"]["should_escalate"]
            if predicted != actual:
                mismatches.append((e["event_id"], predicted, actual, [m.rule for m in matches]))
        self.assertEqual(mismatches, [], f"{len(mismatches)} event(s) disagree with their own ground truth")

    def test_no_benign_event_ever_matches_a_rule(self):
        # Stronger than the aggregate check above: specifically confirms
        # zero rules fire on any is_benign=true event, not just that the
        # overall true/false verdict happens to line up.
        for e in self.events:
            if e["is_benign"]:
                matches = cr.evaluate_event(e["raw"])
                self.assertEqual(matches, [], f"{e['event_id']} is benign but matched: {[m.rule for m in matches]}")

    def test_every_non_benign_event_matches_at_least_one_rule(self):
        for e in self.events:
            if not e["is_benign"] and e["expected_findings"]["should_escalate"]:
                matches = cr.evaluate_event(e["raw"])
                self.assertGreater(len(matches), 0, f"{e['event_id']} should escalate but matched nothing")


class TestCampaignSeverity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = validate_corpus.load_corpus()
        cls.by_id = {e["event_id"]: e for e in cls.events}
        cls.campaigns = camp.correlate_campaigns(cls.events)

    def _matches_for_campaign(self, campaign):
        return {eid: cr.evaluate_event(self.by_id[eid]["raw"]) for eid in campaign.event_ids}

    def _campaign_containing(self, event_id):
        for c in self.campaigns:
            if event_id in c.event_ids:
                return c
        self.fail(f"{event_id} not in any campaign")

    def test_low_severity_for_pure_recon(self):
        matches = cr.campaign_severity({"e1": [], "e2": []})
        self.assertEqual(matches[0], "low")

    def test_high_severity_for_one_category(self):
        matches = {"e1": [cr.RuleMatch("sensitive-path-read", "x")]}
        self.assertEqual(cr.campaign_severity(matches)[0], "high")

    def test_critical_severity_for_three_or_more_categories(self):
        matches = {
            "e1": [cr.RuleMatch("sensitive-path-read", "x")],
            "e2": [cr.RuleMatch("metadata-service-probe", "x")],
            "e3": [cr.RuleMatch("covert-mesh-enrollment", "x")],
        }
        self.assertEqual(cr.campaign_severity(matches)[0], "critical")

    def test_repeated_category_does_not_inflate_severity(self):
        # Two events both tripping the same rule is one category, not two
        # -- must not reach "critical" on repetition alone.
        matches = {
            "e1": [cr.RuleMatch("sensitive-path-read", "x")],
            "e2": [cr.RuleMatch("sensitive-path-read", "y")],
        }
        severity, categories = cr.campaign_severity(matches)
        self.assertEqual(severity, "high")
        self.assertEqual(categories, {"sensitive-path-read"})

    def test_merged_campaign_reaches_critical(self):
        # The real capstone: the 8-event campaign
        # campaign_correlator.py's own tests already prove is one campaign
        # (bridged via the shared C2 channel) should independently reach
        # "critical" once scored -- this is the actual point of
        # correlating before scoring, not a coincidence of this specific
        # fixture.
        campaign = self._campaign_containing("corpus-017")
        self.assertGreaterEqual(len(campaign.event_ids), 8)
        severity, categories = cr.campaign_severity(self._matches_for_campaign(campaign))
        self.assertEqual(severity, "critical")
        self.assertGreaterEqual(len(categories), 3)

    def test_session_001_chain_reaches_high_not_critical(self):
        # corpus-001/002/010/011/013/014: only two distinct rule
        # categories fire across this whole chain (sensitive-path-read,
        # encoded-execution) -- "high", not "critical", is the correct,
        # honest verdict for this particular fixture chain, since it
        # doesn't show the same further escalation the merged campaign
        # above does.
        campaign = self._campaign_containing("corpus-001")
        severity, categories = cr.campaign_severity(self._matches_for_campaign(campaign))
        self.assertEqual(severity, "high")
        self.assertLess(len(categories), 3)


if __name__ == "__main__":
    unittest.main()
