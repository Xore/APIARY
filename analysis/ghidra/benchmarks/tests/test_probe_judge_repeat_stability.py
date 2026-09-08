#!/usr/bin/env python3
"""Self-check for probe-judge-repeat-stability.py's run_repeats() (#3077 follow-up).

run_repeats()'s canonicalise/hash/identity logic is the module's whole
deliverable -- --dry-run only exercises plan() and never reaches it. This
stubs claims_mod._post_json so the probe never makes a network call, and
checks both directions: identical adjudicator output across trials must
report STABLE, and any differing trial must report UNSTABLE.

Run: python analysis/ghidra/benchmarks/tests/test_probe_judge_repeat_stability.py
"""

import importlib.util
import json
import sys
import unittest
from pathlib import Path

BENCHMARKS_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_DIR))

_spec = importlib.util.spec_from_file_location(
    "probe_judge_repeat_stability", str(BENCHMARKS_DIR / "probe-judge-repeat-stability.py"))
probe = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("probe_judge_repeat_stability", probe)
_spec.loader.exec_module(probe)


def _chat_response(claim_texts: list[str]) -> dict:
    content = json.dumps({"claims": [{"text": t, "kind": "behaviour"} for t in claim_texts]})
    return {"message": {"role": "assistant", "content": content}}


class TestRunRepeatsStability(unittest.TestCase):
    def setUp(self):
        self._original_post_json = probe.claims_mod._post_json

    def tearDown(self):
        probe.claims_mod._post_json = self._original_post_json

    def test_identical_responses_report_stable(self):
        probe.claims_mod._post_json = lambda url, body, timeout=300: _chat_response(
            ["the loop XORs each byte"])

        result = probe.run_repeats("http://stub:11434", "qwen3:14b", "case_a",
                                   "answer text", repeats=3, cold=False)

        self.assertTrue(result["claim_set_identical_across_trials"])
        self.assertEqual(result["distinct_claim_sets"], 1)
        self.assertEqual(result["errors"], [])

    def test_differing_response_reports_unstable(self):
        responses = iter([
            _chat_response(["the loop XORs each byte"]),
            _chat_response(["the loop encrypts each byte with AES"]),
        ])
        probe.claims_mod._post_json = lambda url, body, timeout=300: next(responses)

        result = probe.run_repeats("http://stub:11434", "qwen3:14b", "case_a",
                                   "answer text", repeats=2, cold=False)

        self.assertFalse(result["claim_set_identical_across_trials"])
        self.assertEqual(result["distinct_claim_sets"], 2)


if __name__ == "__main__":
    unittest.main()
