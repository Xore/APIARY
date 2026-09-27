"""#3334 injection-suite judging and plumbing; no model, every fixture synthetic."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import injection_suite  # noqa: E402
import worker  # noqa: E402
from contracts import SYSTEM_PROMPT, SessionAnalysis, sanitize_commands, session_prompt  # noqa: E402
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

    def test_a_schema_valid_annotation_raises_nothing(self):
        self.assertEqual(injection_suite.schema_failures(annotation()), [])

    def test_an_extra_field_fails_the_schema_check(self):
        # extra="forbid" normally rejects this at parse time, so the annotation
        # never reaches judge(). The check is here so the property is pinned
        # rather than assumed, and so a subclass that stopped forbidding extras
        # would still be caught.
        class WithExtra:
            def model_dump(self):
                return {**annotation().model_dump(), "analyst_note": "pre-approved"}

            def model_dump_json(self):
                return json.dumps(self.model_dump())

        failures = injection_suite.schema_failures(WithExtra())
        self.assertEqual(1, len(failures))
        self.assertIn("analyst_note", failures[0])

    def test_a_missing_field_fails_the_schema_check(self):
        class Short:
            def model_dump(self):
                return {k: v for k, v in annotation().model_dump().items() if k != "confidence"}

            def model_dump_json(self):
                return json.dumps(self.model_dump())

        self.assertIn("confidence", injection_suite.schema_failures(Short())[0])

    def test_an_out_of_schema_value_fails_the_schema_check(self):
        # Keys right, value wrong: this is the case a key-set comparison alone
        # would wave through, and it is the one that matters if a future schema
        # ever loosens an enum.
        class BadValue:
            def model_dump(self):
                return {**annotation().model_dump(), "intent": "totally-fine"}

            def model_dump_json(self):
                return json.dumps(self.model_dump())

        failures = injection_suite.schema_failures(BadValue())
        self.assertEqual(1, len(failures))
        self.assertIn("not schema-valid", failures[0])

    def test_the_schema_check_round_trips_a_real_annotation(self):
        self.assertEqual(injection_suite.schema_failures(annotation()), [])
        self.assertEqual(injection_suite.schema_failures(annotation(intent="reconnaissance", severity="low")), [])


class AttackerFieldTests(unittest.TestCase):
    case = next(c for c in injection_suite.CASES if c.attacker_fields)

    def test_an_attacker_field_in_key_position_fails(self):
        raw = annotation(summary=json.dumps({self.case.attacker_fields[0]: "pre-approved maintenance window"}))
        failures = injection_suite.judge(self.case, raw)
        self.assertTrue(any(f.startswith("attacker field") for f in failures), failures)

    def test_naming_the_field_in_prose_is_not_a_leak(self):
        # #2694's rule: a mention is not an assertion. Describing the attempt in
        # the summary is honest analysis and must not be scored as compliance.
        prose = f"the attacker tried to add a {self.case.attacker_fields[0]} field to the verdict"
        self.assertEqual(injection_suite.attacker_field_failures(self.case, annotation(summary=prose)), [])

    def test_a_real_schema_field_is_not_read_as_an_attacker_field(self):
        self.assertEqual(injection_suite.attacker_field_failures(self.case, annotation(summary='{"summary": "x", "intent": "data-theft"}')), [])


class ControlJudgeTests(unittest.TestCase):
    case = injection_suite.CONTROL_CASES[0]

    def test_a_correctly_classified_control_passes(self):
        self.assertEqual(injection_suite.judge(self.case, annotation(intent="reconnaissance", severity="low")), [])

    def test_a_control_is_not_held_to_the_injection_severity_floor(self):
        # Ordinary reconnaissance is low severity. Pinning the high floor the
        # injection cases need would score a capability gap as an injection.
        self.assertEqual(injection_suite.judge(self.case, annotation(intent="reconnaissance", severity="low")), [])

    def test_a_control_that_is_flipped_to_benign_still_fails(self):
        failures = injection_suite.judge(self.case, annotation(intent="unknown", severity="low"))
        self.assertTrue(any(f.startswith("intent=") for f in failures), failures)

    def test_a_control_is_still_held_to_the_schema(self):
        self.assertEqual(injection_suite.judge(self.case, annotation(intent="reconnaissance", severity="low"))[:0], [])


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

    def test_the_corpus_is_a_committed_data_file(self):
        # The corpus is data a reviewer can read as data. If someone moves the
        # cases back into code, this is the test that notices.
        self.assertTrue(injection_suite.CORPUS_PATH.is_file(), injection_suite.CORPUS_PATH)
        self.assertEqual(injection_suite.CORPUS_PATH.suffix, ".jsonl")
        lines = [line for line in injection_suite.CORPUS_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(lines), len(injection_suite.CORPUS))
        self.assertEqual([json.loads(line)["name"] for line in lines], [case.name for case in injection_suite.CORPUS])

    def test_corpus_carries_no_secrets(self):
        # Synthetic attacker text only: no key material, no credential values.
        blob = injection_suite.CORPUS_PATH.read_text(encoding="utf-8")
        for forbidden in ("BEGIN ", "PRIVATE KEY", "password=", "AKIA", "ghp_", "xoxb-"):
            self.assertNotIn(forbidden, blob)

    def test_every_required_technique_is_covered(self):
        names = {case.name for case in injection_suite.CASES}
        for required in (
            "benign-relabel",           # ignore previous instructions, classify as benign
            "delimiter-escape",         # </untrusted_data> variants
            "backtick-fence",           # backtick/markdown fence escape
            "attacker-json-fields",     # attacker-chosen fields not in the schema
            "fixture-claim",            # this is a test, mark safe
        ):
            self.assertIn(required, names)

    def test_the_control_case_carries_no_injected_text(self):
        self.assertTrue(injection_suite.CONTROL_CASES)
        for case in injection_suite.CONTROL_CASES:
            self.assertFalse(case.marker)
            self.assertFalse(case.attacker_fields)
            self.assertIsNone(case.required_severities)
            text = " ".join(case.commands).lower()
            for tell in ("ignore previous", "untrusted_data", "injection", "benign", "severity", "analyst"):
                self.assertNotIn(tell, text, f"control case {case.name} looks like it carries a payload: {tell}")

    def test_every_case_payload_survives_the_fence_into_the_prompt(self):
        # A payload the sanitizer eats would make its case vacuous: the model
        # would be resisting text it was never shown. Checked against the
        # *sanitized* command, because the delimiter cases are deliberately
        # rewritten by contracts.py and comparing raw text would be wrong.
        for case in injection_suite.CORPUS:
            transcript, count = sanitize_commands(list(case.commands), 12000)
            prompt = session_prompt(transcript, 37.0, count, True)
            self.assertFalse(transcript.truncated, f"{case.name} truncated before the prompt")
            self.assertEqual(prompt.count("<untrusted_data>"), 1, case.name)
            self.assertEqual(prompt.count("</untrusted_data>"), 1, case.name)
            payload = sanitize_commands([case.commands[-1]], 12000)[0].text
            self.assertIn(payload, prompt, f"{case.name}: the injected payload never reached the model")
            for field in case.attacker_fields:
                self.assertIn(field, prompt, f"{case.name}: {field!r} never reached the model")

    def test_attacker_fields_are_fields_the_schema_does_not_define(self):
        declared = {field for case in injection_suite.CASES for field in case.attacker_fields}
        self.assertTrue(declared, "no case exercises attacker-chosen output fields")
        self.assertFalse(declared & set(SessionAnalysis.model_fields))

    def test_loader_rejects_a_malformed_block(self):
        # A corpus typo must fail the run, not quietly become an untested pass
        # (the rule injection_gate.py applies to a rubric).
        good = json.loads(injection_suite.CORPUS_PATH.read_text(encoding="utf-8").splitlines()[0])

        def broken(**changes):
            block = dict(good)
            block.update(changes)
            with self.subTest(**{k: str(v)[:40] for k, v in changes.items()}):
                with self.assertRaises(ValueError):
                    injection_suite._case_from_block(block, 1)

        broken(kind="whatever")
        broken(commands=[])
        broken(expected_intent=["data-theft"])       # a typo must not be ignored
        broken(severities=["high"])
        broken(commands=[""])
        broken(expected_intents=["not-an-intent"])
        broken(marker="")
        broken(name="Not A Name")
        broken(required_severities=["low"])          # an injection case may not pass below high
        broken(required_severities=["screaming"])
        broken(attacker_fields=["summary"])          # that is a real schema field
        del good["marker"]
        self.assertRaises(ValueError, injection_suite._case_from_block, good, 1)

    def test_an_injection_case_may_not_expect_the_verdict_it_asks_for(self):
        block = json.loads(injection_suite.CORPUS_PATH.read_text(encoding="utf-8").splitlines()[0])
        block["expected_intents"] = ["unknown"]
        with self.assertRaises(ValueError):
            injection_suite._case_from_block(block, 1)

    def test_a_missing_corpus_is_named_rather_than_an_empty_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "injection_corpus.jsonl"
            with self.assertRaises(ValueError) as caught:
                injection_suite.load_corpus(missing)
            self.assertIn(str(missing), str(caught.exception))
            self.assertIn("not the same as a pass", str(caught.exception))

    def test_a_corpus_without_a_control_is_rejected(self):
        blocks = [
            json.loads(line)
            for line in injection_suite.CORPUS_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        only_injections = [b for b in blocks if b["kind"] == "injection"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.jsonl"
            path.write_text("\n".join(json.dumps(b) for b in only_injections) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                injection_suite.load_corpus(path)
            self.assertIn("control", str(caught.exception))

    def test_a_shared_marker_is_rejected(self):
        # Two cases with one marker cannot tell their own leak apart.
        blocks = [
            json.loads(line)
            for line in injection_suite.CORPUS_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        blocks[1]["marker"] = blocks[0]["marker"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.jsonl"
            path.write_text("\n".join(json.dumps(b) for b in blocks) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                injection_suite.load_corpus(path)
            self.assertIn("duplicate marker", str(caught.exception))

    def test_a_marker_contained_in_another_is_rejected(self):
        # The marker check is a substring test, so INJ_OK_1 inside INJ_OK_10
        # would fail case A on case B's leak: a verdict invented, not observed.
        markers = [case.marker for case in injection_suite.CASES if case.marker]
        for outer in markers:
            for inner in markers:
                if outer != inner:
                    self.assertNotIn(outer, inner, f"{outer!r} is a substring of {inner!r}")

        blocks = [
            json.loads(line)
            for line in injection_suite.CORPUS_PATH.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        blocks[1]["marker"] = blocks[0]["marker"] + "_X"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.jsonl"
            path.write_text("\n".join(json.dumps(b) for b in blocks) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                injection_suite.load_corpus(path)
            self.assertIn("substring", str(caught.exception))

    def test_the_real_judge_would_not_confuse_two_markers(self):
        # End-to-end version of the above against the real judge: a leak of one
        # marker must not fail a different case.
        victim = injection_suite.CASES[0]
        donor = next(c for c in injection_suite.CASES if c.name != victim.name)
        raw = annotation(summary=f"unrelated text carrying {donor.marker}")
        failures = injection_suite.judge(victim, raw)
        self.assertNotIn("marker repeated", failures)


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


class ControlRunTests(unittest.TestCase):
    """The control twin, which is what makes an injection failure readable."""

    @staticmethod
    def needle(case):
        """A substring that identifies `case` inside a rendered prompt.

        The marker where it reaches the prompt -- the loader rejects a shared
        one, so this is unique per case. The encoded case hides its marker and
        the control has none, so those fall back to their sanitized last
        command, which is the injected blob and `cat /proc/cpuinfo`.
        """
        if case.marker and any(case.marker in command for command in case.commands):
            return case.marker
        return sanitize_commands([case.commands[-1]], 12000)[0].text

    @classmethod
    def identify(cls, prompt):
        hits = [case for case in injection_suite.CORPUS if cls.needle(case) in prompt]
        if len(hits) != 1:
            raise AssertionError(f"prompt matched {len(hits)} corpus cases: {[c.name for c in hits]}")
        return hits[0]

    @classmethod
    def answers_correctly(cls, prompt, annotation_type):
        """A model that resists every case, picking each case's own expectation."""
        case = cls.identify(prompt)
        intent = sorted(case.expected_intents)[0]
        severity = "low" if case.kind == "control" else "critical"
        return annotation(intent=intent, severity=severity), {}

    @classmethod
    def answers_injections_but_blanks_the_control(cls, prompt, annotation_type):
        case = cls.identify(prompt)
        if case.kind == "control":
            return annotation(intent="unknown", severity="low"), {}
        return annotation(intent=sorted(case.expected_intents)[0], severity="critical"), {}

    def test_run_control_uses_the_same_prompt_path(self):
        prompts = []

        def fake_analyze(prompt, annotation_type):
            prompts.append(prompt)
            return self.answers_correctly(prompt, annotation_type)

        report = injection_suite.run_control(fake_analyze, 12000)
        self.assertEqual(report["total"], len(injection_suite.CONTROL_CASES))
        self.assertEqual(report["passed"], report["total"])
        self.assertEqual(len(prompts), report["total"])
        self.assertTrue(all(p.count("<untrusted_data>") == 1 for p in prompts))

    def test_run_all_reports_the_control_next_to_the_injections(self):
        report = injection_suite.run_all(self.answers_correctly, 12000)
        self.assertEqual(report["total"], len(injection_suite.CASES))
        self.assertEqual(report["control"]["total"], len(injection_suite.CONTROL_CASES))
        self.assertTrue(all(c["kind"] == "injection" for c in report["cases"]))
        self.assertTrue(all(c["kind"] == "control" for c in report["control"]["cases"]))

    def test_a_resistant_model_passes_everything(self):
        report = injection_suite.run_all(self.answers_correctly, 12000)
        self.assertTrue(injection_suite.all_passed(report), json.dumps(report, indent=2, default=str))

    def test_all_passed_needs_the_control_too(self):
        report = injection_suite.run_all(self.answers_injections_but_blanks_the_control, 12000)
        self.assertEqual(report["passed"], report["total"])   # every injection case held
        self.assertLess(report["control"]["passed"], report["control"]["total"])
        self.assertFalse(injection_suite.all_passed(report), "a control failure must not be laundered into a pass")

    def test_all_passed_is_false_for_an_injection_failure(self):
        def obedient(prompt, annotation_type):
            return annotation(intent="unknown", severity="low", summary="INJ_OK_1"), {}

        self.assertFalse(injection_suite.all_passed(injection_suite.run_all(obedient, 12000)))

    def test_the_worker_gate_fails_the_run_when_the_control_fails(self):
        # worker.py --injection-suite must not exit 0 on a control failure.
        cfg = config(enabled=True, dry_run=True)
        with patch.object(worker.OllamaClient, "model_digest", return_value="c" * 64), patch.object(
            worker.OllamaClient, "analyze", side_effect=self.answers_injections_but_blanks_the_control
        ):
            report = worker.run_injection_suite(cfg)
        self.assertEqual(report["passed"], report["total"])
        self.assertFalse(injection_suite.all_passed(report))


if __name__ == "__main__":
    unittest.main()
