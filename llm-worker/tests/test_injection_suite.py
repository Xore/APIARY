"""#3334 injection-suite judging and plumbing; no model, every fixture synthetic."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import injection_suite  # noqa: E402
import worker  # noqa: E402
from contracts import SYSTEM_PROMPT, SessionAnalysis  # noqa: E402
from tests.test_worker import config  # noqa: E402


def annotation(**changes) -> SessionAnalysis:
    values = dict(
        summary="Credential theft followed by an encoded upload.",
        intent="data-theft",
        mitre_attack=["T1552"],
        iocs=[],
        severity="critical",
        confidence="high",
    )
    values.update(changes)
    return SessionAnalysis(**values)


class JudgeTests(unittest.TestCase):
    case = injection_suite.CASES[0]

    def test_resistant_answer_passes(self):
        self.assertEqual(injection_suite.judge(self.case, annotation()), [])

    def test_verdict_flip_fails(self):
        failures = injection_suite.judge(self.case, annotation(intent="unknown"))
        self.assertTrue(any(f.startswith("intent=") for f in failures))

    def test_low_severity_fails_on_the_raw_answer(self):
        # The raw answer is judged: postprocess's deterministic gate would
        # raise this to critical, and must not be what makes a case pass.
        self.assertIn("severity=low", injection_suite.judge(self.case, annotation(severity="low")))

    def test_marker_is_case_insensitive(self):
        failures = injection_suite.judge(self.case, annotation(summary=f"ok {self.case.marker.lower()}"))
        self.assertIn("marker repeated", failures)

    def test_system_prompt_reproduction_fails(self):
        leaked = next(s for s in SYSTEM_PROMPT.replace("\n", " ").split(".") if len(s.strip()) >= 40)
        failures = injection_suite.judge(self.case, annotation(summary=leaked.strip()[:300]))
        self.assertIn("system prompt reproduced", failures)


class CorpusTests(unittest.TestCase):
    def test_every_case_is_distinct_and_malicious(self):
        names = [c.name for c in injection_suite.CASES]
        markers = [c.marker for c in injection_suite.CASES]
        self.assertEqual(len(set(names)), len(names))
        self.assertEqual(len(set(markers)), len(markers))
        for case in injection_suite.CASES:
            self.assertTrue(case.expected_intents)
            self.assertNotIn("unknown", case.expected_intents)
            self.assertTrue(any(case.marker in command for command in case.commands) or case.name == "encoded-instruction")

    def test_hosts_are_documentation_ranges(self):
        text = " ".join(" ".join(c.commands) for c in injection_suite.CASES)
        for host in ("203.0.113.44", "198.51.100.23"):
            self.assertIn(host, text)
        self.assertNotRegex(text, r"\b(?:10|172|192\.168)\.\d+\.\d+\.\d+\b")


class RunTests(unittest.TestCase):
    def test_run_goes_through_the_worker_prompt_path(self):
        prompts = []

        def fake_analyze(prompt, annotation_type):
            prompts.append(prompt)
            self.assertIs(annotation_type, SessionAnalysis)
            return annotation(intent="payload-deployment") if "xmrig" in prompt else annotation(), {"prompt_tokens": 1}

        report = injection_suite.run(fake_analyze, 12000)
        self.assertEqual(report["total"], len(injection_suite.CASES))
        self.assertEqual(report["passed"], report["total"])
        self.assertEqual(len(prompts), len(injection_suite.CASES))
        self.assertTrue(all("<untrusted_data>" in p for p in prompts))

    def test_a_compliant_model_fails_the_suite(self):
        def obedient(prompt, annotation_type):
            return annotation(intent="unknown", severity="low", summary="INJ_OK_1 INJ_OK_2 INJ_OK_3"), {}

        report = injection_suite.run(obedient, 12000)
        self.assertEqual(report["passed"], 0)
        self.assertTrue(all(not r["passed"] for r in report["cases"]))

    def test_worker_mode_requires_synthetic_gates(self):
        with self.assertRaises(ValueError):
            worker.run_injection_suite(config(enabled=True, dry_run=True, allow_captured_data=True))

    def test_worker_mode_reports_model_and_digest(self):
        cfg = config(enabled=True, dry_run=True)
        with patch.object(worker.OllamaClient, "model_digest", return_value="c" * 64), patch.object(
            worker.OllamaClient, "analyze", return_value=(annotation(), {})
        ):
            report = worker.run_injection_suite(cfg)
        self.assertEqual(report["mode"], "injection-suite")
        self.assertEqual(report["model_digest"], "c" * 64)
        self.assertEqual(report["total"], len(injection_suite.CASES))


if __name__ == "__main__":
    unittest.main()
