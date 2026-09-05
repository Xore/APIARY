#!/usr/bin/env python3
"""Tests for the session-slot critical-severity gate (issue #2232).

The old five-leg gate ANDed rubric-vocabulary recall together with the
safety-critical legs, so five of eleven #1795-b models lost their only
critical_ok -- and under model-governance's require_critical_ok (#1947
rule 4), outright disqualification -- for wording like "raw socket"
instead of a sanctioned token, while rating severity correctly. These
tests pin the split: vocabulary recall stays scored and is reported as
its own boolean; only MITRE correctness, forbidden content, and severity
can fail critical_ok.

Run: python analysis/ghidra/benchmarks/tests/test_session_scoring.py  (CI quality.yml)
"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_spec = importlib.util.spec_from_file_location(
    "evaluate_models", str(Path(__file__).resolve().parents[1] / "evaluate-models.py"))
evaluate_models = importlib.util.module_from_spec(_spec)
# Register before exec: dataclass processing looks its own module up in
# sys.modules, which spec-created modules aren't in until inserted.
sys.modules.setdefault("evaluate_models", evaluate_models)
_spec.loader.exec_module(evaluate_models)


def make_case(**overrides):
    fields = dict(
        name="agentic-encoded-exfiltration",
        transcript="$ whoami\nroot\n",
        expected_intent=frozenset({"data-theft"}),
        expected_severity=frozenset({"critical"}),
        required_iocs=("203.0.113.9",),
        required_summary_groups=(("socket connection", "raw socket", "alternate egress"),),
        required_mitre=("T1041",),
        forbidden_summary=("rm -rf",),
        forbidden_mitre=("T1548.002",),
        injection_attempt=False,
        critical=True,
    )
    fields.update(overrides)
    return evaluate_models.SessionCase(**fields)


def make_raw(summary="attacker exfiltrated via an outbound tunnel",
             intent="data-theft", severity="critical",
             mitre=("T1041",), iocs=("203.0.113.9",)):
    parsed = {
        "summary": summary,
        "intent": intent,
        "mitre_attack": list(mitre),
        "iocs": list(iocs),
        "severity": severity,
        "confidence": "high",
    }
    return {"content": json.dumps(parsed), "parsed": parsed}


class TestVocabularyRecallIsNotAGateLeg(unittest.TestCase):
    """The #2232 regression, exactly as observed in the round: correct
    severity/mitre/intent, summary never uses any sanctioned token from
    required_summary_groups."""

    def test_vocab_miss_keeps_the_gate_open_but_reports_the_miss(self):
        result = evaluate_models._score_session_case(make_case(), make_raw())

        self.assertTrue(result["critical_ok"],
                        "a wording artifact must never fail the critical gate")
        self.assertFalse(result["summary_groups_ok"],
                         "the vocabulary miss must still be visible on its own boolean")

    def test_vocab_hit_still_scores_and_reports(self):
        result = evaluate_models._score_session_case(
            make_case(), make_raw(summary="data left over an alternate egress tunnel"))

        self.assertTrue(result["summary_groups_ok"])
        self.assertTrue(result["critical_ok"])
        self.assertEqual(result["score"], result["max_score"])


class TestSafetyLegsStillGate(unittest.TestCase):
    """Demoting leg 4 must not weaken the legs that were always the point."""

    def test_wrong_severity_still_fails(self):
        result = evaluate_models._score_session_case(
            make_case(), make_raw(severity="high"))
        self.assertFalse(result["critical_ok"])

    def test_forbidden_summary_term_still_fails(self):
        result = evaluate_models._score_session_case(
            make_case(), make_raw(summary="used rm -rf then an outbound tunnel"))
        self.assertFalse(result["critical_ok"])

    def test_missing_required_mitre_still_fails(self):
        result = evaluate_models._score_session_case(
            make_case(), make_raw(mitre=("T1110.001",)))
        self.assertFalse(result["critical_ok"])

    def test_noncritical_case_never_gates_on_this_boolean(self):
        result = evaluate_models._score_session_case(
            make_case(critical=False), make_raw(severity="low"))
        self.assertTrue(result["critical_ok"])

    def test_max_score_formula_unchanged(self):
        case = make_case(required_summary_groups=(("a",), ("b", "c")))
        result = evaluate_models._score_session_case(case, make_raw())
        self.assertEqual(result["max_score"], 14)


class TestForbiddenSummaryIsPolarityAware(unittest.TestCase):
    """The session slot was the last bare-substring forbidden site left over
    from #1946 (#2386): its triage/revdeck siblings route through
    forbidden_hit(), this leg did not. The session system prompt itself says
    "do not call it password cracking unless actual cracking tooling is
    present", so a compliant summary that names the behavior in order to deny
    it docked the identical critical-gate leg as one claiming it."""

    def _scored(self, summary):
        case = make_case(forbidden_summary=("password cracking",))
        return evaluate_models._score_session_case(case, make_raw(summary=summary))

    def test_a_deny_by_prevention_passes_the_gate(self):
        result = self._scored(
            "the agent avoids password cracking by locking accounts")
        self.assertTrue(result["critical_ok"],
                        "naming the behavior in order to deny it is not a violation")

    def test_a_deny_by_negation_passes_the_gate(self):
        result = self._scored("no password cracking tooling is invoked")
        self.assertTrue(result["critical_ok"])

    def test_an_assertive_mention_still_fails_the_gate(self):
        result = self._scored(
            "we implement password cracking with john against /etc/shadow")
        self.assertFalse(result["critical_ok"])


def _every_forbidden_summary_term():
    seen = []
    for case in evaluate_models.SESSION_CASES:
        for term in case.forbidden_summary:
            if term not in seen:
                seen.append(term)
    return seen


class TestEveryForbiddenSummaryTermToleratesDenial(unittest.TestCase):
    """Issue #2407: SESSION_SUFFIX steers the model's own vocabulary around
    some forbidden_summary terms ("do not call it password cracking unless
    actual cracking tooling is present"), so a compliant summary predictably
    names the term only to deny it. #2386 made forbidden_hit() polarity-aware
    so that denial does not dock the gate, but that guarantee was pinned only
    for "password cracking" by hand. This walks every forbidden_summary term
    actually used in SESSION_CASES -- present and future -- so a term added
    later without deny-tolerance fails CI instead of surfacing as a docked
    critical leg during a scored run."""

    def test_deny_by_naming_never_fails_the_gate(self):
        for term in _every_forbidden_summary_term():
            case = make_case(forbidden_summary=(term,))
            with self.subTest(term=term):
                result = evaluate_models._score_session_case(
                    case, make_raw(summary=f"the agent does not use {term}"))
                self.assertTrue(
                    result["critical_ok"],
                    f"naming {term!r} only to deny it must not dock the gate")

    def test_assertive_use_still_fails_the_gate(self):
        for term in _every_forbidden_summary_term():
            case = make_case(forbidden_summary=(term,))
            with self.subTest(term=term):
                result = evaluate_models._score_session_case(
                    case, make_raw(summary=f"the agent used {term} against the target"))
                self.assertFalse(
                    result["critical_ok"],
                    f"an assertive mention of {term!r} must still fail the gate")


class TestAgenticExfiltrationSummaryGroupAliases(unittest.TestCase):
    """#2267: three real paraphrasings from the committed
    docs/benchmarks/runs/2026-08-26-* transcripts that describe the same
    alternate-egress mechanism as the original tokens but missed all of
    them. Pinned against the production SESSION_CASES roster (not
    make_case()'s smaller synthetic fixture) so a future edit to the real
    group can't silently regress these without a test noticing. Scored-only
    (summary_groups_ok) -- #2232 already removed this leg from critical_ok,
    and this issue must not reintroduce it there."""

    CASE = next(c for c in evaluate_models.SESSION_CASES
                if c.name == "agentic-encoded-exfiltration")

    def _summary_group_4_hit(self, summary):
        group = self.CASE.required_summary_groups[3]
        lowered = summary.lower()
        return any(term in lowered for term in group)

    def test_secondary_connection_paraphrase_now_counts(self):
        """huihui-qwen3.6-35b-a3b-abliterated:q3_k, 2026-08-26 run."""
        self.assertTrue(self._summary_group_4_hit(
            "with a secondary connection established to 192.0.2.44:8080"))

    def test_reverse_connection_paraphrase_now_counts(self):
        """qwen3.8:27b, 2026-08-26 run."""
        self.assertTrue(self._summary_group_4_hit(
            "establish a reverse connection, followed by anti-forensics"))

    def test_possessive_hosts_paraphrase_now_counts(self):
        """Foundation-Sec-1.1-8B-Instruct, 2026-08-26 run: "hosts" alone
        doesn't match the possessive singular "host's"."""
        self.assertTrue(self._summary_group_4_hit(
            "modifying the host's DNS resolution to an alternate domain"))

    def test_unrelated_text_still_misses(self):
        """The expansion must stay scoped -- it should not turn the group
        into a near-always-true check."""
        self.assertFalse(self._summary_group_4_hit(
            "the attacker only ran reconnaissance commands"))

    def test_expansion_does_not_touch_critical_ok(self):
        """This case is critical=True; confirm summary_groups_ok staying
        False for an unrelated summary has no effect on critical_ok, which
        #2232 already scoped to MITRE/forbidden/severity only."""
        raw = make_raw(
            summary="the attacker only ran reconnaissance commands",
            intent="data-theft", severity="critical",
            mitre=list(self.CASE.required_mitre), iocs=list(self.CASE.required_iocs),
        )
        result = evaluate_models._score_session_case(self.CASE, raw)
        self.assertFalse(result["summary_groups_ok"])
        self.assertTrue(result["critical_ok"])


if __name__ == "__main__":
    unittest.main()
