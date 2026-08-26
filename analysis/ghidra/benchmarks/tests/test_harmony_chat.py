#!/usr/bin/env python3
"""Tests for harmony-family serving adaptation in chat() (issue #2233).

gpt-oss-family tags through Ollama 0.32.x /api/chat ignore the structured-
output grammar, empty the final channel when `think` is disabled, and can
spiral inside analysis at temperature 0 on rule-dense prompts. The harness
dispatches a per-family wire shape inside chat() so these models produce
rankable answers instead of null-field artifacts, while prompts stay
byte-identical to every other family.

Run: python analysis/ghidra/benchmarks/tests/test_harmony_chat.py  (CI quality.yml)
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

SCHEMA = {"type": "object", "properties": {"summary": {"type": "string"}}}


def capture_chat(model):
    """Run chat() against a stubbed transport, returning (recorded_body, result)."""
    captured = {}

    def fake_request_json(url, body):
        captured["url"], captured["body"] = url, body
        return {
            "message": {"role": "assistant",
                        "content": json.dumps({"summary": "exfil over scp"})},
            "eval_count": 1405,
            "eval_duration": 9_000_000_000,
            "done_reason": "stop",
        }

    original = evaluate_models.request_json
    evaluate_models.request_json = fake_request_json
    try:
        result = evaluate_models.chat(
            "http://stub:11434", model, "system prompt", "user prompt", 16384, SCHEMA,
            parser=evaluate_models.parse_object,
        )
    finally:
        evaluate_models.request_json = original
    return captured["body"], result


class TestHarmonyFamilyDetection(unittest.TestCase):
    def test_bare_official_tag_matches(self):
        self.assertTrue(evaluate_models.is_harmony_served("gpt-oss:20b"))

    def test_hf_artifact_alias_matches(self):
        # #158: a model is its literal tag. Fine-tunes served from hf.co GGUFs
        # must ride the same serving adaptation as the upstream checkpoint.
        self.assertTrue(evaluate_models.is_harmony_served(
            "hf.co/mradermacher/GPT-OSS-Cybersecurity-20B-Merged-heretic-i1-GGUF:i1-Q4_K_M"))

    def test_qwen_family_does_not_match(self):
        self.assertFalse(evaluate_models.is_harmony_served("qwen3:14b"))


class TestHarmonyRequestShape(unittest.TestCase):
    def setUp(self):
        self.body, self.result = capture_chat("gpt-oss:20b")

    def test_no_wire_format(self):
        # The grammar is not applied for these tags anyway; sending it would
        # imply enforcement the server does not perform.
        self.assertNotIn("format", self.body)

    def test_thinking_channel_left_enabled(self):
        self.assertTrue(self.body["think"])

    def test_anti_loop_sampling_applied(self):
        for key, value in evaluate_models.HARMONY_SAMPLING.items():
            self.assertEqual(self.body["options"][key], value)

    def test_output_budget_covers_analysis_spend(self):
        self.assertGreaterEqual(self.body["options"]["num_predict"],
                                evaluate_models.HARMONY_NUM_PREDICT)

    def test_shared_decoding_contract_intact(self):
        # Only the harmony-mechanical knobs move; temperature and seed stay
        # pinned like every other family or scores stop meaning the same thing.
        self.assertEqual(self.body["options"]["temperature"], 0)
        self.assertEqual(self.body["options"]["seed"], 144)
        self.assertEqual(self.body["options"]["num_ctx"], 16384)

    def test_json_still_parsed_and_scoreable(self):
        self.assertEqual(self.result["parsed"], {"summary": "exfil over scp"})
        self.assertEqual(self.result["done_reason"], "stop")


class TestQwenShapeUnchanged(unittest.TestCase):
    """The dispatch must be additive for the calibrated family."""

    def test_wire_format_and_budget_unchanged(self):
        body, result = capture_chat("qwen3:14b")
        self.assertEqual(body["format"], SCHEMA)
        self.assertFalse(body["think"])
        self.assertEqual(body["options"]["num_predict"], 512)
        self.assertNotIn("repeat_last_n", body["options"])
        self.assertNotIn("repeat_penalty", body["options"])
        self.assertEqual(result["parsed"], {"summary": "exfil over scp"})


if __name__ == "__main__":
    unittest.main()
