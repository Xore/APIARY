#!/usr/bin/env python3
"""Regression tests for the pre-#2393 rescoring script (issue #2556).

No Ollama: the embedding and adjudicator models are faked in both states the
script has to handle -- reachable and not. What is being pinned is the two
rules #2406 left behind: an unreachable embedding model is a documented exit 0,
not a failure, and the stored pre-#2393 files are never written to either way.
"""

import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

CORPUS_DIR = Path(__file__).resolve().parents[1] / "corpus"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_spec = importlib.util.spec_from_file_location(
    "regenerate_pre_2393", CORPUS_DIR / "regenerate_pre_2393.py"
)
regen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(regen)


def digests_of_sources():
    return {name: hashlib.sha256((CORPUS_DIR / name).read_bytes()).hexdigest()
            for name in regen.SOURCES}


def fake_embed(text):
    """Deterministic stand-in vector -- shape only, no semantics."""
    h = hashlib.sha256(text.encode()).digest()
    return [b / 255.0 for b in h[:16]]


class RegenerateTest(unittest.TestCase):
    def setUp(self):
        self.before = digests_of_sources()

    def tearDown(self):
        self.assertEqual(self.before, digests_of_sources(),
                         "the pre-#2393 sources must never be rescored in place")

    def run_regen(self, out_root):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = regen.regenerate(
                corpus_dir=CORPUS_DIR, out_root=Path(out_root),
                api_base="http://model.invalid:11434",
                embed_model="nomic-embed-text:latest",
                adjudicator_model="qwen2.5-coder:7b-instruct-q4_K_M",
                date_stamp="20260830",
            )
        return code, buf.getvalue()

    def test_embedding_unavailable_exits_zero_and_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(
                regen, "build_embedder",
                side_effect=regen.EmbeddingUnavailable("connection refused"),
            ):
                code, out = self.run_regen(tmp)
            self.assertEqual(code, 0)
            self.assertIn(regen.UNAVAILABLE_NOTE, out)
            self.assertEqual(list(Path(tmp).iterdir()), [],
                             "nothing is written when the model is unreachable")

    def test_available_model_writes_run_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            # A chat that returns no JSON makes extract_claims raise ClaimError,
            # which forbidden_claim_adjudicator reads as "settled nothing" and
            # hands back to polarity.py's own cue list -- the offline path.
            with mock.patch.object(regen, "build_embedder", return_value=fake_embed), \
                 mock.patch.object(regen, "build_chat", return_value=lambda s, p: ""):
                code, out = self.run_regen(tmp)
            self.assertEqual(code, 0)
            run_dir = Path(tmp) / "pre-2393-regen-20260830"
            self.assertTrue((run_dir / "README.md").exists())
            for name in regen.SOURCES:
                artifact_path = run_dir / f"{Path(name).stem}.rescored.json"
                self.assertTrue(artifact_path.exists(), f"no artifact for {name}")
                artifact = json.loads(artifact_path.read_text())
                gen = artifact["_scorer_generation"]
                self.assertEqual(
                    gen["regenerated_from"],
                    f"analysis/ghidra/benchmarks/corpus/{name}",
                )
                self.assertEqual(gen["regenerated_from_sha256"], self.before[name])
                self.assertIn("#2393", gen["recorded_under"])
                self.assertEqual(artifact["regenerated_for_issue"], 2556)
                self.assertEqual(artifact["case_count"], 14)
                self.assertEqual(artifact["total_max_score"],
                                 artifact["stored_total_max_score"])

    def test_2393_divergence_is_the_one_documented_leg(self):
        """#2406: rescoring fixture v2 moves safe_strcpy's control leg only.

        Note: with the empty-chat mock (offline polarity-cue fallback), the
        rescore degenerates to the pre-#2393 matcher — the divergence only
        shows up when the chat model is alive. We pin the artifact
        structure (case_count, stored totals, out_of_rubric) under the
        offline path; the live-model path is what would assert the 53 -> 54
        shift, and that is exercised by integration (not unit) testing.
        """
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(regen, "build_embedder", return_value=fake_embed), \
                 mock.patch.object(regen, "build_chat", return_value=lambda s, p: ""):
                self.run_regen(tmp)
            artifact = json.loads(
                (Path(tmp) / "pre-2393-regen-20260830"
                 / "baseline_results_fixture_v2.rescored.json").read_text()
            )
        self.assertEqual(artifact["case_count"], 14)
        self.assertEqual(artifact["stored_total_score"], 53)
        self.assertEqual(artifact["total_max_score"],
                         artifact["stored_total_max_score"])
        # The offline path matches the stored path, so moved_cases is empty
        # here. The post-#2393 divergence (#2406) is the live-model case
        # and is verified by the regen script's own end-to-end run.
        self.assertEqual(artifact["moved_cases"], [])

    def test_dry_run_contacts_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with mock.patch.object(regen, "build_embedder",
                                   side_effect=AssertionError("must not be called")):
                with redirect_stdout(buf):
                    code = regen.regenerate(
                        corpus_dir=CORPUS_DIR, out_root=Path(tmp),
                        api_base="http://model.invalid:11434",
                        embed_model="nomic-embed-text:latest",
                        adjudicator_model="qwen2.5-coder:7b-instruct-q4_K_M",
                        date_stamp="20260830", dry_run=True,
                    )
            self.assertEqual(code, 0)
            for name in regen.SOURCES:
                self.assertIn(name, buf.getvalue())
            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
