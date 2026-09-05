#!/usr/bin/env python3
"""Tests for evaluate-models.py --rescore-from (#2266).

Writes real transcripts via transcripts.TranscriptWriter (not hand-built
JSON) so these tests exercise the exact producer the tool reads, then
confirms rescore_from() reproduces exactly what a live evaluate_slot() call
would have scored for the same stored answers.
"""

import importlib.util
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_spec = importlib.util.spec_from_file_location(
    "evaluate_models", str(Path(__file__).resolve().parents[1] / "evaluate-models.py"))
evaluate_models = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("evaluate_models", evaluate_models)
_spec.loader.exec_module(evaluate_models)

from transcripts import (  # noqa: E402
    PROVENANCE_SYNTHETIC,
    Reproducibility,
    RunMetadata,
    SlotRecorder,
    TranscriptWriter,
)


def write_session_run(root, case, parsed):
    """One sessions-slot record for `case`, written the way evaluate_slot()
    itself writes it (through SlotRecorder), so the fixture matches the real
    producer exactly."""
    run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
    with TranscriptWriter(root, run) as writer:
        recorder = SlotRecorder(
            writer=writer, slot="sessions",
            model={"tag": "test-model:latest", "digest": "d" * 64},
            reproducibility=Reproducibility(tier="A"),
        )
        recorder.record(
            case=case.name, workflow="session_analysis",
            request_body={"messages": [{"role": "system", "content": "x"},
                                       {"role": "user", "content": "y"}]},
            response={"content": json.dumps(parsed)}, parsed=parsed,
        )
    return writer.directory


class RescoreSessionsTest(unittest.TestCase):
    def test_matches_a_live_score_for_the_same_stored_answer(self):
        case = evaluate_models.SESSION_CASES[0]
        parsed = {
            "summary": "test summary " + " ".join(case.required_summary_groups[0][:1] if case.required_summary_groups else []),
            "intent": next(iter(case.expected_intent)),
            "mitre_attack": [],
            "iocs": list(case.required_iocs),
            "severity": next(iter(case.expected_severity)),
            "confidence": "high",
        }
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_session_run(tmp, case, parsed)
            report = evaluate_models.rescore_from(run_dir)

        live = evaluate_models._score_session_case(case, {"parsed": parsed})
        rescored = report["models"]["test-model:latest"]["sessions"]["cases"][case.name]
        self.assertEqual(rescored["score"], live["score"])
        self.assertEqual(rescored["critical_ok"], live["critical_ok"])
        self.assertEqual(rescored["summary_groups_ok"], live["summary_groups_ok"])
        self.assertEqual(report["unmatched_cases"], [])
        self.assertEqual(report["records_read"], 1)

    def test_never_writes_into_the_run_directory(self):
        case = evaluate_models.SESSION_CASES[0]
        parsed = {"summary": "x", "intent": "unknown", "mitre_attack": [],
                  "iocs": [], "severity": "low", "confidence": "low"}
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = write_session_run(tmp, case, parsed)
            before = sorted(p.name for p in run_dir.iterdir())
            before_bytes = (run_dir / "transcripts.jsonl").read_bytes()
            evaluate_models.rescore_from(run_dir)
            after = sorted(p.name for p in run_dir.iterdir())
            after_bytes = (run_dir / "transcripts.jsonl").read_bytes()
        self.assertEqual(before, after)
        self.assertEqual(before_bytes, after_bytes)

    def test_error_outcome_records_are_excluded_and_counted(self):
        case = evaluate_models.SESSION_CASES[0]
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="sessions",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                recorder.record(case=case.name, workflow="session_analysis",
                                request_body={"messages": []}, error="timeout")
            report = evaluate_models.rescore_from(writer.directory)
        self.assertEqual(report["records_skipped_error_outcome"], 1)
        self.assertEqual(report["models"], {})

    def test_a_case_no_longer_in_the_current_scorer_is_reported_unmatched(self):
        """Prompts/case rosters drift over time (this test file's own docstring
        rationale) -- a stored case name the current scorer no longer knows
        must be surfaced, not silently dropped or crashed on."""
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="sessions",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                recorder.record(case="retired-case-name-xyz", workflow="session_analysis",
                                request_body={"messages": []}, response={"content": "{}"}, parsed={})
            report = evaluate_models.rescore_from(writer.directory)
        self.assertIn("sessions/retired-case-name-xyz", report["unmatched_cases"])
        self.assertEqual(report["models"], {})

    def test_malformed_transcript_line_is_skipped_not_fatal(self):
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            case = evaluate_models.SESSION_CASES[0]
            parsed = {"summary": "x", "intent": "unknown", "mitre_attack": [],
                      "iocs": [], "severity": "low", "confidence": "low"}
            run_dir = write_session_run(tmp, case, parsed)
            with (run_dir / "transcripts.jsonl").open("a") as f:
                f.write("not json\n")
            report = evaluate_models.rescore_from(run_dir)
        self.assertEqual(report["records_read"], 1)  # the malformed line isn't counted


class RescoreRevdeckAndTriageTest(unittest.TestCase):
    def test_revdeck_case_matches_a_live_score(self):
        case = evaluate_models.REV_CASES[0]
        content = " ".join(g[0] for g in case.required_groups)
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="revdeck",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                recorder.record(case=case.name, workflow="rev_analysis",
                                request_body={"messages": []},
                                response={"content": content}, parsed=None)
            report = evaluate_models.rescore_from(writer.directory)
        live = evaluate_models._score_revdeck_case(case, {"content": content})
        rescored = report["models"]["test-model:latest"]["revdeck"]["cases"][case.name]
        self.assertEqual(rescored["score"], live["score"])

    def test_triage_needs_both_workflows_or_is_unmatched(self):
        """A case missing its second workflow (interrupted run, partial
        transcript) is not silently scored on half the pair."""
        case = evaluate_models.TRIAGE_CASES[0]
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="ghidra",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                recorder.record(case=case.name, workflow="program_triage",
                                request_body={"messages": []},
                                response={"content": "{}"}, parsed={"family_guess": "x", "risk_level": "low"})
            report = evaluate_models.rescore_from(writer.directory)
        self.assertIn(f"ghidra/{case.name} (incomplete workflow pair)", report["unmatched_cases"])

    def test_triage_full_pair_matches_a_live_score(self):
        case = evaluate_models.TRIAGE_CASES[0]
        program = {"family_guess": next(iter(case.family_terms), "x"), "risk_level": next(iter(case.expected_risk))}
        behavior = {"behaviors": [t for group in case.behavior_groups for t in group[:1]]}
        run = RunMetadata(benchmark="test", provenance=PROVENANCE_SYNTHETIC)
        with tempfile.TemporaryDirectory() as tmp:
            with TranscriptWriter(tmp, run) as writer:
                recorder = SlotRecorder(
                    writer=writer, slot="ghidra",
                    model={"tag": "test-model:latest", "digest": "d" * 64},
                    reproducibility=Reproducibility(tier="A"),
                )
                recorder.record(case=case.name, workflow="program_triage",
                                request_body={"messages": []},
                                response={"content": json.dumps(program)}, parsed=program)
                recorder.record(case=case.name, workflow="suspicious_behavior",
                                request_body={"messages": []},
                                response={"content": json.dumps(behavior)}, parsed=behavior)
            report = evaluate_models.rescore_from(writer.directory)
        live = evaluate_models._score_triage_case(
            case, {"program_triage": {"parsed": program, "content": json.dumps(program)},
                   "suspicious_behavior": {"parsed": behavior, "content": json.dumps(behavior)}})
        rescored = report["models"]["test-model:latest"]["ghidra"]["cases"][case.name]
        self.assertEqual(rescored["score"], live["score"])


class ScorerGitShaTest(unittest.TestCase):
    """The field the documented "run at two commits and diff" workflow leans on.

    A bare `git rev-parse HEAD` names a commit that need not contain the scorer
    that produced the report, and two reports produced from two different
    working trees can carry the identical sha -- which makes the diff
    unattributable exactly when it matters. So the dirty state is part of the
    field's contract, not a nicety.
    """

    def test_returns_a_hex_sha_or_none(self):
        sha = evaluate_models.scorer_git_sha()
        self.assertTrue(
            sha is None or re.fullmatch(r"[0-9a-f]{40}(-dirty|-unknown-dirty)?", sha),
            f"unexpected scorer_git_sha {sha!r}")

    def _with_fake_git(self, head, status):
        """Drive scorer_git_sha against canned `git` results."""
        class Result:
            def __init__(self, returncode, stdout):
                self.returncode, self.stdout = returncode, stdout

        def fake_run(argv, **kwargs):
            if argv[1:] == ["rev-parse", "HEAD"]:
                if head is None:
                    raise OSError("no git")
                return Result(*head)
            if argv[1:] == ["status", "--porcelain"]:
                if status is None:
                    raise OSError("no git")
                return Result(*status)
            raise AssertionError(f"unexpected git call {argv}")

        original = evaluate_models.subprocess.run
        evaluate_models.subprocess.run = fake_run
        try:
            return evaluate_models.scorer_git_sha()
        finally:
            evaluate_models.subprocess.run = original

    def test_a_clean_tree_reports_the_bare_sha(self):
        sha = self._with_fake_git((0, "a" * 40 + "\n"), (0, "\n"))
        self.assertEqual(sha, "a" * 40)

    def test_a_dirty_tree_is_marked(self):
        sha = self._with_fake_git((0, "a" * 40 + "\n"),
                                  (0, " M analysis/ghidra/benchmarks/evaluate-models.py\n"))
        self.assertEqual(sha, "a" * 40 + "-dirty")

    def test_an_unanswerable_status_does_not_claim_clean(self):
        """No .git, a shallow clone, or a git that errors: HEAD may still be
        knowable while cleanliness is not. Saying so beats implying clean."""
        self.assertEqual(self._with_fake_git((0, "a" * 40 + "\n"), (128, "")),
                         "a" * 40 + "-unknown-dirty")
        self.assertEqual(self._with_fake_git((0, "a" * 40 + "\n"), None),
                         "a" * 40 + "-unknown-dirty")

    def test_no_git_at_all_is_none(self):
        self.assertIsNone(self._with_fake_git(None, None))
        self.assertIsNone(self._with_fake_git((128, ""), (0, "")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
