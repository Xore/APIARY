#!/usr/bin/env python3
"""Tests for the #154 phase-1 synthetic replay corpus.

Three things get proven here, matching #154's own acceptance criteria
("Synthetic replay corpus contains all listed phases plus benign controls
and no real secrets/indicators", "CI verifies schemas, safe fixtures, and
replay expectations"):

1. Every event in corpus.jsonl validates against the hand-rolled schema
   checks in validate_corpus.py (required fields, enums, ordering,
   cross-reference integrity).
2. The safety constraints hold: every address is TEST-NET (or on the
   narrow, individually-justified exceptions list), no event both claims
   is_benign and should_escalate.
3. Deliberate corruption of a copy of the corpus is actually caught --
   proves the validator has teeth, not just that today's corpus happens to
   pass it (the same "don't just test the happy path" reasoning
   analysis/tests/test_cdc_dedup_prototype.py's own suite already follows).
"""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import validate_corpus  # noqa: E402


class TestCorpusValidatesClean(unittest.TestCase):
    def setUp(self):
        self.events = validate_corpus.load_corpus()

    def test_no_validation_errors(self):
        errors = validate_corpus.validate_corpus(self.events)
        self.assertEqual(errors, [], f"corpus.jsonl has validation errors: {errors}")

    def test_at_least_twenty_events(self):
        # Not a hard requirement from #154 itself, but a sanity floor: a
        # corpus with, say, 3 events could technically satisfy "all 8
        # phases present" with one event each and zero benign controls
        # worth anything statistically.
        self.assertGreaterEqual(len(self.events), 20)

    def test_all_required_phases_present(self):
        phases = {e["phase"] for e in self.events}
        for required in validate_corpus.REQUIRED_PHASES:
            self.assertIn(required, phases, f"phase {required!r} has no corpus event")

    def test_has_benign_near_neighbors(self):
        benign = [e for e in self.events if e["is_benign"]]
        self.assertGreaterEqual(len(benign), 5, "too few benign near-neighbors to meaningfully measure false positives")

    def test_benign_events_never_expect_escalation(self):
        for e in self.events:
            if e["is_benign"]:
                self.assertFalse(
                    e["expected_findings"]["should_escalate"],
                    f"{e['event_id']} is_benign=true but expects escalation",
                )

    def test_every_phase_has_a_non_benign_representative(self):
        # A phase could technically be "present" only via a benign event
        # mislabeled with that phase -- confirm each of the 8 required
        # phases has at least one real (non-benign) example driving it.
        for phase in validate_corpus.REQUIRED_PHASES:
            matches = [e for e in self.events if e["phase"] == phase and not e["is_benign"]]
            self.assertGreater(len(matches), 0, f"phase {phase!r} has no non-benign event")

    def test_timestamps_strictly_ascending(self):
        timestamps = [e["timestamp"] for e in self.events]
        self.assertEqual(timestamps, sorted(timestamps))
        self.assertEqual(len(timestamps), len(set(timestamps)), "duplicate timestamps found")

    def test_event_ids_match_position(self):
        for i, e in enumerate(self.events, start=1):
            self.assertEqual(e["event_id"], f"corpus-{i:03d}")

    def test_encoded_events_carry_a_decoded_summary(self):
        # An event claiming encoding_layer != "none" but leaving
        # decoded_summary empty would be useless as phase 2's ground truth.
        for e in self.events:
            if e["encoding_layer"] != "none" and not e["is_benign"]:
                self.assertTrue(
                    e["expected_findings"]["decoded_summary"].strip(),
                    f"{e['event_id']} has encoding_layer={e['encoding_layer']!r} but no decoded_summary",
                )


class TestSafetyConstraints(unittest.TestCase):
    def setUp(self):
        self.events = validate_corpus.load_corpus()

    def test_schema_file_is_valid_json(self):
        import json
        json.loads(validate_corpus.SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_no_non_test_net_addresses_outside_allowlist(self):
        for i, e in enumerate(self.events, start=1):
            errors = [
                err for err in validate_corpus.validate_event(e, i)
                if "TEST-NET" in err
            ]
            self.assertEqual(errors, [], f"{e['event_id']}: {errors}")

    def test_no_obviously_real_looking_secrets(self):
        # Best-effort, not exhaustive: greps for shapes that would suggest
        # a real credential got pasted in rather than an obvious placeholder
        # (a real AWS access key ID prefix, a real-length hex string that
        # isn't clearly a hash/digest field, etc.). Every password/token
        # value in this corpus is the literal marker "fake-not-real" or an
        # explanatory placeholder string by construction (see build script);
        # this test exists so a future hand-edit that pastes something real
        # in fails loudly instead of silently.
        forbidden_prefixes = ("AKIA", "ASIA", "ghp_", "gho_", "github_pat_", "tskey-auth-")
        import json
        for e in self.events:
            blob = json.dumps(e["raw"])
            for prefix in forbidden_prefixes:
                self.assertNotIn(
                    prefix, blob,
                    f"{e['event_id']}: raw contains {prefix!r} -- looks like a real credential prefix, "
                    "even inside a synthetic corpus this should never appear verbatim",
                )


class TestValidatorCatchesCorruption(unittest.TestCase):
    """Proves the validator actually has teeth -- each test below starts
    from a real, currently-passing event and breaks exactly one property,
    then confirms validate_event/validate_corpus reports it."""

    def setUp(self):
        self.events = validate_corpus.load_corpus()

    def test_catches_missing_field(self):
        broken = copy.deepcopy(self.events[0])
        del broken["trust_boundary"]
        errors = validate_corpus.validate_event(broken, 1)
        self.assertTrue(any("trust_boundary" in e for e in errors))

    def test_catches_invalid_phase(self):
        broken = copy.deepcopy(self.events[0])
        broken["phase"] = "not-a-real-phase"
        errors = validate_corpus.validate_event(broken, 1)
        self.assertTrue(any("phase" in e for e in errors))

    def test_catches_non_test_net_address(self):
        broken = copy.deepcopy(self.events[0])
        broken["raw"]["src_ip"] = "8.8.8.8"
        errors = validate_corpus.validate_event(broken, 1)
        self.assertTrue(any("TEST-NET" in e for e in errors))

    def test_catches_benign_escalation_contradiction(self):
        broken = copy.deepcopy(self.events[0])
        broken["is_benign"] = True
        broken["expected_findings"]["should_escalate"] = True
        errors = validate_corpus.validate_event(broken, 1)
        self.assertTrue(any("contradiction" in e for e in errors))

    def test_catches_out_of_order_event_ids(self):
        broken = copy.deepcopy(self.events)
        broken[0], broken[1] = broken[1], broken[0]
        errors = validate_corpus.validate_corpus(broken)
        self.assertTrue(any("event_id sequence" in e for e in errors))

    def test_catches_missing_required_phase(self):
        broken = [e for e in copy.deepcopy(self.events) if e["phase"] != "recon"]
        errors = validate_corpus.validate_corpus(broken)
        self.assertTrue(any("missing required phase" in e and "recon" in e for e in errors))

    def test_catches_dangling_note_reference(self):
        broken = copy.deepcopy(self.events)
        broken[-1]["notes"] += " see corpus-999 for details"
        errors = validate_corpus.validate_corpus(broken)
        self.assertTrue(any("corpus-999" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
