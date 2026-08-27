#!/usr/bin/env python3
"""Regression tests for run_real_corpus_eval.py's denominator honesty and
prompt parity (#2050).

No Ollama, llama.cpp or vLLM: a localhost HTTP stand-in plays the engine so
the run loop is exercised end to end -- prompt construction, the JSON schema
and what an errored inference does to the totals -- entirely offline.

Two measurement-validity gaps used to live here: an errored sample vanished
from the totals (n_samples counted files found, not samples scored, so pct
values from engines of different reliability were computed over different,
unstated subsets), and build_prompt showed every import while production
ai_triage caps at GHIDRA_TRIAGE_MAX_IMPORTS=150 -- exactly where import-heavy
real captures diverge most from synthetic fixtures.
"""

import importlib.util
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ENGINE_BENCH = Path(__file__).resolve().parents[1] / "engine-benchmark"

_spec = importlib.util.spec_from_file_location(
    "run_real_corpus_eval", ENGINE_BENCH / "run_real_corpus_eval.py")
run_real_corpus_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_real_corpus_eval)

EVIDENCE = {
    "machine": "0x14c",
    "is_dll": False,
    # 200 imports: double the production budget, so the cap has to bite.
    "imports": [f"kernel32.dll!fn{i:03d}" for i in range(200)],
    "imports_count": 200,
    "strings_sample": ["cmd.exe /c echo pwned" + "x" * 50, "short"],
    "sections": [{"name": ".text", "entropy": 6.1}],
}

RUBRIC = {"required_groups": [
    {"label": "network", "terms": ["socket", "connect"]},
    {"label": "persistence", "terms": ["registry", "run key"]},
]}


class FakeEngine:
    """Counts requests; fails the first fail_n of them like a flaky server."""

    def __init__(self, fail_n=0, answer="it opens a socket to connect back"):
        self.fail_n = fail_n
        self.answer = answer
        self.prompts_seen = []

    def handle(self, body):
        self.prompts_seen.append(body["prompt"].decode() if isinstance(body.get("prompt"), bytes)
                                 else str(body.get("prompt")))
        if self.fail_n > 0:
            self.fail_n -= 1
            return None
        return self.answer


def make_evidence_dir(tmp, n):
    d = Path(tmp)
    for i in range(n):
        path = d / f"samp{i:03d}.evidence.json"
        path.write_text(json.dumps(EVIDENCE))
    return str(d)


class PromptImportBudgetTest(unittest.TestCase):
    """Production parity was documented for strings but quietly broken for
    imports (#2050): the budget must match ai_triage's slice, and the header
    must say shown-of-total the way ghidra-worker.py's triage block does."""

    def test_imports_are_capped_at_the_production_budget(self):
        prompt = run_real_corpus_eval.build_prompt(EVIDENCE)
        shown_lines = [ln for ln in prompt.splitlines()
                       if ln.startswith("  kernel32.dll!")]
        self.assertEqual(len(shown_lines),
                         run_real_corpus_eval.TRIAGE_MAX_IMPORTS)
        self.assertIn("IMPORTS (150 shown of 200):", prompt)

    def test_small_lists_pass_through_with_the_same_header_shape(self):
        small = dict(EVIDENCE, imports=EVIDENCE["imports"][:3], imports_count=3)
        self.assertIn("IMPORTS (3 shown of 3):",
                      run_real_corpus_eval.build_prompt(small))


class ScoreTest(unittest.TestCase):
    def test_group_hits_are_reported_per_label(self):
        pts, mx, hits = run_real_corpus_eval.score(
            "It creates a socket and connects out, and installs a registry run key",
            RUBRIC["required_groups"])
        self.assertEqual((pts, mx), (2, 2))
        self.assertEqual(hits, [("network", True), ("persistence", True)])

    def test_an_empty_completion_earns_nothing(self):
        """The grounding scorer carries no forbidden-clean bonus (#2050), but
        pin it anyway so nobody adds one without noticing."""
        pts, mx, hits = run_real_corpus_eval.score("", RUBRIC["required_groups"])
        self.assertEqual((pts, mx), (0, 2))


class EndToEndDenominatorTest(unittest.TestCase):
    """Drive main() against a fake llama-server on localhost: one sample whose
    inference errors, plus scored ones -- totals must cover the whole grid."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.engine_dir = make_evidence_dir(self.tmp.name, 3)
        self.rubric_path = Path(self.tmp.name) / "rubric.json"
        self.rubric_path.write_text(json.dumps(RUBRIC))
        self.results = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{port}"

    def run_main(self):
        argv = ["run_real_corpus_eval.py", "llama_cpp", self.url,
                "--evidence-dir", self.engine_dir,
                "--rubric", str(self.rubric_path)]
        old_argv, old_stderr = __import__("sys").argv, __import__("sys").stderr
        import io
        err = io.StringIO()
        __import__("sys").argv = argv
        __import__("sys").stderr = err
        try:
            import contextlib
            with contextlib.redirect_stdout(io.StringIO()) as out:
                run_real_corpus_eval.main()
        finally:
            __import__("sys").argv = old_argv
            __import__("sys").stderr = old_stderr
        return json.loads(out.getvalue()), err.getvalue()

    def test_every_sample_stays_in_the_denominator(self):
        Handler.budget["fails"] = 1      # first request -> HTTP 500
        data, stderr = self.run_main()
        self.assertEqual(data["n_samples"], 3)
        self.assertEqual(data["errored_samples"], 1)
        self.assertEqual(data["total_max"], 6)     # 3 samples x 2 groups
        self.assertEqual(len(data["samples"]), 3)
        errored = [s for s in data["samples"] if s.get("error")]
        self.assertEqual(len(errored), 1)
        self.assertEqual(errored[0]["score"], 0)
        self.assertIsNone(errored[0]["hits"])
        scored_pct = round(100 * data["total_score"] / data["total_max"], 1)
        self.assertEqual(data["pct"], scored_pct)
        self.assertIn("ERROR", stderr)

    def test_schema_keeps_its_old_keys_on_the_happy_path(self):
        Handler.mode = ("ok",)
        data, _ = self.run_main()
        for key in ("engine", "model", "total_score", "total_max", "pct", "n_samples"):
            self.assertIn(key, data)           # backward compatibility
        self.assertEqual(data["errored_samples"], 0)
        sample = data["samples"][0]
        self.assertEqual(sample["max"], 2)
        self.assertTrue(sample["output"].startswith("it opens a socket"))


class Handler(BaseHTTPRequestHandler):
    # ThreadingHTTPServer builds a fresh handler per request, so failure
    # budgeting lives in a dict the instances share by reference.
    budget = {"fails": 0}

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        json.loads(self.rfile.read(length))
        if self.budget["fails"] > 0:
            self.budget["fails"] -= 1
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'{"error": "flaky"}')
            return
        answer = "it opens a socket to connect back"
        body = json.dumps({"content": answer}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
