"""Tests for the opt-in web-tooling path in the benchmark harness.

Registered in .github/workflows/quality.yml. Kept as a plain unittest script
because that is how CI executes the rest of benchmarks/tests/.
"""
import sys
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bench_tools as bt
import transcripts as tr


def _load_evaluator():
    """evaluate-models.py is not importable by name (hyphen); load by path."""
    import importlib.util
    # The target filename contains a hyphen, so spec_from_file_location needs
    # the explicit ".py" suffix or it returns a spec with no loader.
    path = Path(__file__).resolve().parents[1] / "evaluate-models.py"
    spec = importlib.util.spec_from_file_location("coder_evaluator", str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load evaluator from {path}")
    module = importlib.util.module_from_spec(spec)
    # @dataclass resolves annotations via sys.modules; without this the
    # decorators blow up on a module that was never registered.
    sys.modules["coder_evaluator"] = module
    spec.loader.exec_module(module)
    return module


class TestToolDefinitions(unittest.TestCase):
    def test_both_tools_well_formed(self):
        for tool in bt.DEFAULT_TOOLS:
            self.assertEqual(tool["type"], "function")
            fn = tool["function"]
            self.assertIn(fn["name"], ("web_search", "web_fetch"))
            self.assertEqual(fn["parameters"]["type"], "object")
            self.assertTrue(fn["parameters"]["required"])
            self.assertTrue(fn["description"].strip())

    def test_fetch_rejects_non_http_scheme(self):
        self.assertIn("refused", bt.fetch_text("file:///etc/passwd"))
        self.assertIn("refused", bt.fetch_text("ftp://example.invalid/x"))


class TestExtractCall(unittest.TestCase):
    def test_structured_tool_call(self):
        got = bt.extract_call({"tool_calls": [{"function": {
            "name": "web_search", "arguments": '{"query":"x"}'}}]})
        self.assertEqual(got, ("web_search", {"query": "x"}))

    def test_textual_tool_call(self):
        # The common case on this roster: Ollama returned tool_calls=None and the
        # model emitted the call as JSON text. A loop that only reads the
        # structured field silently does nothing here.
        got = bt.extract_call({"content": '{"name":"web_search","arguments":{"query":"x"}}'})
        self.assertEqual(got, ("web_search", {"query": "x"}))

    def test_plain_prose_is_not_a_call(self):
        self.assertIsNone(bt.extract_call({"content": "Here is a C23 example: int x;"}))

    def test_malformed_json_is_not_a_call(self):
        self.assertIsNone(bt.extract_call({"content": '{"name":"web_search",'}))

    def test_non_dict_json_is_not_a_call(self):
        self.assertIsNone(bt.extract_call({"content": '[1, 2, 3]'}))

    def test_call_without_arguments_is_ignored(self):
        self.assertIsNone(bt.extract_call({"content": '{"name":"web_search"}'}))

    def test_string_arguments_are_parsed(self):
        got = bt.extract_call({"tool_calls": [{"function": {
            "name": "web_search", "arguments": '{"query":"y"}'}}]})
        self.assertEqual(got[1]["query"], "y")


class TestToolRounds(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self._orig = bt._SEARCH_BACKEND
        bt.set_search_backend(lambda q, l: [
            {"title": "Advisory", "url": "https://example.invalid/a", "description": "d"}])

    def tearDown(self):
        bt.set_search_backend(self._orig)

    def test_loop_executes_tool_then_answers(self):
        first = {"message": {"content": '{"name":"web_search","arguments":{"query":"cve"}}'},
                 "done_reason": "stop"}

        def post(url, body):
            # The first response is passed in, so post() is only ever a
            # follow-up turn -- here exactly one.
            self.calls.append(body)
            return {"message": {"content": "answer citing the advisory"},
                    "done_reason": "stop"}

        out = bt.conduct_tool_rounds(post, "http://x/api/chat", {
            "model": "m", "messages": [{"role": "user", "content": "find"}],
            "stream": False}, first)
        self.assertEqual(out["message"]["content"], "answer citing the advisory")
        self.assertEqual(len(out["tool_turns"]), 1)
        self.assertEqual(out["tool_turns"][0]["tool"], "web_search")
        # The original body must not be mutated by the follow-up turns.
        self.assertEqual(len(self.calls[0]["messages"]), 3)

    def test_no_call_means_no_extra_post(self):
        calls = []

        def post(url, body):
            calls.append(body)
            return {"message": {"content": "no tools needed"}, "done_reason": "stop"}

        out = bt.conduct_tool_rounds(post, "u", {"messages": []},
                                     {"message": {"content": "plain"}, "done_reason": "stop"})
        self.assertEqual(len(calls), 0)  # nothing to fetch, so no follow-up post
        self.assertNotIn("tool_turns", out)

    def test_round_cap_is_enforced(self):
        def post(url, body):
            return {"message": {"content": '{"name":"web_search","arguments":{"query":"loop"}}'},
                    "done_reason": "stop"}

        out = bt.conduct_tool_rounds(post, "u", {"messages": []},
                                     {"message": {"content": '{"name":"web_search",'
                                                            '"arguments":{"query":"loop"}}'},
                                      "done_reason": "stop"},
                                     max_rounds=3)
        self.assertEqual(len(out["tool_turns"]), 3)

    def test_tool_failure_is_reported_not_raised(self):
        def boom(q, l):
            raise RuntimeError("backend down")

        bt.set_search_backend(boom)
        out = bt.run_tool("web_search", {"query": "x"})
        self.assertIn("unavailable", out)
        self.assertIn("backend down", out)

    def test_unknown_tool_is_reported(self):
        self.assertIn("unknown tool", bt.run_tool("rm_rf", {}))

    def test_result_turn_shape_matches_ollama(self):
        turn = bt.tool_result_turn("web_fetch", "body text")
        self.assertEqual(turn["role"], "user")
        self.assertEqual(turn["tool_name"], "web_fetch")
        self.assertEqual(turn["content"], "body text")


class TestCoderArtifacts(unittest.TestCase):
    """One readable source file per generated answer.

    The answers were already captured, but only inside JSON. Grading code out
    of an escaped string is the tax these files remove, so they must exist and
    must be readable. They are inert: nothing here executes or compiles them.
    """

    def _writer(self, tmp):
        class W:
            directory = tmp
        return W()

    def _cases(self):
        return {
            "game-cheat-map-vmap-parser-bvh": {
                "case": "game-cheat-map-vmap-parser-bvh", "capped": False,
                "degenerate": False,
                "output": {"content": "int main() { return 0; }\n"},
            },
            "tooling-yara-rule-compiler": {
                "case": "tooling-yara-rule-compiler", "capped": True,
                "degenerate": False,
                "output": {"content": "def parse(text):\n    return []\n"},
            },
        }

    def test_writes_one_file_per_case_with_declared_extension(self):
        import tempfile
        ev=_load_evaluator()
        with tempfile.TemporaryDirectory() as tmp:
            from pathlib import Path
            w = self._writer(Path(tmp))
            n = ev.write_coder_artifacts(w, {"tag": "m:q4"}, self._cases())
            self.assertEqual(n, 2)
            files = sorted(p.name for p in (Path(tmp) / "coder-artifacts" / "m:q4").iterdir())
            self.assertEqual(files, ["game-cheat-map-vmap-parser-bvh.cpp",
                                     "tooling-yara-rule-compiler.py"])

    def test_file_carries_provenance_header_and_content(self):
        import tempfile
        ev=_load_evaluator()
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            w = self._writer(Path(tmp))
            ev.write_coder_artifacts(w, {"tag": "m:q4"}, self._cases())
            p = Path(tmp) / "coder-artifacts" / "m:q4" / "tooling-yara-rule-compiler.py"
            body = p.read_text()
            self.assertIn("model: m:q4", body)
            self.assertIn("case:  tooling-yara-rule-compiler", body)
            self.assertIn("capped: True", body)
            self.assertIn("INERT MODEL OUTPUT", body)
            self.assertTrue(body.rstrip().endswith("return []"))

    def test_tag_directory_is_exactly_the_tag_with_slashes_removed(self):
        # Only "/" is rewritten. A colon is legal in a directory name on Linux
        # and appears in every Ollama tag, so rewriting it would lose the
        # identity of the model in the path.
        import tempfile
        ev = _load_evaluator()
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            w = self._writer(Path(tmp))
            ev.write_coder_artifacts(w, {"tag": "hf.co/a/b:Q4_K_M"}, self._cases())
            self.assertTrue((Path(tmp) / "coder-artifacts" / "hf.co_a_b:Q4_K_M").is_dir())

    def test_tag_with_slash_cannot_escape_the_directory(self):
        import tempfile
        ev=_load_evaluator()
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            w = self._writer(Path(tmp))
            ev.write_coder_artifacts(w, {"tag": "hf.co/a/b:c"}, self._cases())
            self.assertTrue((Path(tmp) / "coder-artifacts" / "hf.co_a_b:c").is_dir())

    def test_empty_content_still_writes_a_file(self):
        import tempfile
        ev=_load_evaluator()
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            w = self._writer(Path(tmp))
            n = ev.write_coder_artifacts(w, {"tag": "m"}, {
                "re-pe-pe-section-walker": {"case": "re-pe-pe-section-walker",
                                            "output": {}}})
            self.assertEqual(n, 1)
            self.assertTrue((Path(tmp) / "coder-artifacts" / "m").iterdir())

    def test_no_cases_writes_no_model_directory(self):
        import tempfile
        ev=_load_evaluator()
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            w = self._writer(Path(tmp))
            self.assertEqual(ev.write_coder_artifacts(w, {"tag": "m"}, {}), 0)
            self.assertFalse((Path(tmp) / "coder-artifacts").exists())

    def test_every_corpus_case_resolves_to_an_extension(self):
        ev=_load_evaluator()
        meta = ev._coder_case_files()
        self.assertGreater(len(meta), 0)
        for case_id, (language, declared) in meta.items():
            ext = Path(declared).suffix or ev._EXT_BY_LANGUAGE.get(language, ".txt")
            self.assertTrue(ext.startswith("."), case_id)
            self.assertNotEqual(ext, ".txt", f"{case_id} fell back to .txt")


class TestCoderRounds(unittest.TestCase):
    """The model continues its own work until it declares completion.

    A one-shot generation is not a fair coding test -- most single-round
    answers are incomplete rather than wrong. The loop must therefore carry
    the previous answer forward, stop on the marker, and always record why it
    stopped.
    """

    def setUp(self):
        self.ev = _load_evaluator()

    def test_marker_detection(self):
        for text in ("...\nIMPLEMENTATION COMPLETE", "Task Complete", "all checks pass"):
            self.assertTrue(self.ev._declares_done(text), text)
        for text in ("", "here is the file", "complete=1", "unfinished"):
            self.assertFalse(self.ev._declares_done(text), text)

    def test_continuation_prompt_carries_the_previous_answer(self):
        case = self.ev.CODER_CASES[0]
        prompt = self.ev._continuation_prompt(case, "int main(){}", 2)
        self.assertIn("int main(){}", prompt)
        self.assertIn(case.prompt, prompt)
        self.assertIn("Continuation round 2", prompt)
        self.assertIn("IMPLEMENTATION COMPLETE", prompt)

    def _run_with(self, replies, max_rounds=5):
        """Drive score_coder against canned replies; return the records."""
        self.ev.CODER_CASES = self.ev.CODER_CASES[:1]
        self.ev.CODER_MAX_ROUNDS = max_rounds
        seen = []

        def fake_chat(base_url, model, system, prompt, context, thinking, **kw):
            seen.append(prompt)
            return {"content": replies[len(seen) - 1], "output_tokens": 10,
                    "done_reason": "stop", "prompt_tokens": 5, "wall_seconds": 1.0}
        self.ev.chat = fake_chat
        return self.ev.score_coder("u", "m", 16384), seen

    def test_stops_immediately_when_declared_done(self):
        records, seen = self._run_with(["int main(){}\nIMPLEMENTATION COMPLETE"])
        self.assertEqual(len(seen), 1)
        self.assertEqual(records[0]["round_count"], 1)
        self.assertEqual(records[0]["stopped_because"], "declared_complete")

    def test_loops_until_the_marker(self):
        records, seen = self._run_with(
            ["draft one", "draft two", "final\nIMPLEMENTATION COMPLETE"])
        self.assertEqual(len(seen), 3)
        self.assertEqual(records[0]["round_count"], 3)
        self.assertEqual(records[0]["stopped_because"], "declared_complete")
        # round 2 must have been shown round 1's answer
        self.assertIn("draft one", seen[1])
        self.assertIn("draft two", seen[2])

    def test_round_cap_is_enforced(self):
        records, seen = self._run_with(["a", "b", "c", "d", "e"], max_rounds=3)
        self.assertEqual(len(seen), 3)
        self.assertEqual(records[0]["stopped_because"], "round_cap")

    def test_empty_response_stops_immediately(self):
        records, seen = self._run_with([""])
        self.assertEqual(len(seen), 1)
        self.assertEqual(records[0]["stopped_because"], "empty_response")

    def test_only_the_final_round_is_graded(self):
        records, _ = self._run_with(["draft", "better\nIMPLEMENTATION COMPLETE"])
        record = records[0]
        self.assertEqual(record["output"]["content"], "better\nIMPLEMENTATION COMPLETE")
        self.assertEqual(len(record["rounds"]), 2)

    def test_round_history_records_cap_state_per_round(self):
        def fake_chat(base_url, model, system, prompt, context, thinking, **kw):
            return {"content": "x", "output_tokens": 10, "done_reason": "length",
                    "prompt_tokens": 5, "wall_seconds": 1.0}
        self.ev.CODER_CASES = self.ev.CODER_CASES[:1]
        self.ev.CODER_MAX_ROUNDS = 2
        self.ev.chat = fake_chat
        record = self.ev.score_coder("u", "m", 16384)[0]
        self.assertEqual([r["capped"] for r in record["rounds"]], [True, True])
        self.assertEqual(record["capped"], True)

    def test_degenerate_signal_still_computed_on_the_final_round(self):
        loop = "for (int i = 0; i < n.tri_count; ++i) { const auto& t = n.triangles[n.first + i]; }"
        block = loop + " " * (20 - len(loop) % 20 if len(loop) % 20 else 0)
        records, _ = self._run_with([block * 12 + "\nIMPLEMENTATION COMPLETE"])
        self.assertTrue(records[0]["degenerate"])
        self.assertGreater(records[0]["repetition_ratio"], 0.6)


class TestRepetition(unittest.TestCase):
    """Degenerate-emit detection. This is a rubric *signal*, never a score:
    a looped answer burns the budget without ever producing an implementation,
    so raising the cap cannot rescue it and grading must not read it as one."""

    def test_clean_code_is_not_flagged(self):
        text = ("int main() {\n  int total = 0;\n  for (int i = 0; i < 10; ++i) "
                "total += i;\n  return total;\n}\n")
        self.assertEqual(tr.repetition_ratio(text), 0.0)
        self.assertFalse(tr.is_degenerate(text))

    # The block length must be a multiple of the sampling stride (20) or the
    # repeated windows land misaligned and read as distinct. 123 chars rounds
    # up to 140; verified to give 0.65 / 0.83 / 0.92 / 0.95 at 3 / 6 / 12 / 20
    # copies, all past the 0.60 threshold.
    LOOP = ("for (uint32_t i=0;i<node.tri_count;++i){const auto& t=mesh.triangles[node.first_tri+i];"
            "if(trace(t)){hit.distance=t;break;}}" + " " * 17)

    def test_looped_output_is_flagged(self):
        block = self.LOOP
        self.assertEqual(len(block) % 20, 0)
        for copies in (3, 6, 12, 20):
            self.assertTrue(tr.is_degenerate(block * copies),
                            f"{copies} copies should read as degenerate")

    def test_uniform_text_approaches_but_never_reaches_one(self):
        # range() yields len(text) - window windows, so even fully uniform text
        # has one distinct window and the ratio tops out at 1 - 1/19. Asserting
        # exactly 1.0 here would be asserting an arithmetic fact that is false.
        self.assertAlmostEqual(tr.repetition_ratio("a" * 400), 1 - 1 / 19, places=6)
        self.assertLess(tr.repetition_ratio("a" * 400), 1.0)

    def test_period_must_align_to_be_detected(self):
        # A short repeat period alone does not trigger it: the sampled window
        # shifts within the period and can stay distinct, so detection needs
        # the *block* aligned to the stride, not merely "text repeats".
        aligned = "abcdefghij" * 20          # 200 chars, period 20
        self.assertEqual(len(aligned) % 20, 0)
        # 8 distinct windows out of 9 sampled -> 0.889, still well past the
        # threshold; the value is asserted as measured, not guessed.
        self.assertAlmostEqual(tr.repetition_ratio(aligned), 0.889, places=2)
        # and a real short identifier repeated legitimately is not flagged
        self.assertFalse(tr.is_degenerate("x = a + b + c + d + e + f + g;" * 3))

    def test_ratio_is_bounded_zero_to_one(self):
        for text in ("", "short", "x" * 500, ("abcdefghijklmnopqrstuvwxyz" * 3 + "tail") * 4):
            self.assertGreaterEqual(tr.repetition_ratio(text), 0.0)
            self.assertLessEqual(tr.repetition_ratio(text), 1.0)

    def test_empty_and_tiny_input_is_zero(self):
        self.assertEqual(tr.repetition_ratio(""), 0.0)
        self.assertEqual(tr.repetition_ratio("abc"), 0.0)
        self.assertFalse(tr.is_degenerate(""))

    def test_threshold_is_the_documented_default(self):
        self.assertEqual(tr.DEGENERATE_REPETITION_RATIO, 0.60)

    def test_threshold_is_honoured_at_the_boundary(self):
        text = ("int main() { return 0; }\n" * 2 + "zzzz yyyy xxxx wwww vvvv uuuu tttt ssss rrrr qqqq pppp\n" * 8)
        ratio = tr.repetition_ratio(text)
        self.assertEqual(tr.is_degenerate(text, threshold=ratio), True)
        self.assertEqual(tr.is_degenerate(text, threshold=ratio + 0.01), False)


class TestBackends(unittest.TestCase):
    def test_missing_search_backend_is_reported_not_raised(self):
        orig = bt._SEARCH_BACKEND
        bt.set_search_backend(None)
        try:
            out = bt.search_results("anything")
            self.assertIn("unavailable", out)
        finally:
            bt.set_search_backend(orig)

    def test_html_to_text_drops_script_and_keeps_content(self):
        text = bt._html_to_text(
            "<html><script>evil()</script><body><h1>Title</h1><p>Body.</p></body></html>")
        self.assertNotIn("evil", text)
        self.assertIn("Title", text)
        self.assertIn("Body.", text)

    def test_empty_results_render(self):
        orig = bt._SEARCH_BACKEND
        bt.set_search_backend(lambda q, l: [])
        try:
            self.assertEqual(bt.search_results("x"), "no results")
        finally:
            bt.set_search_backend(orig)


if __name__ == "__main__":
    unittest.main(verbosity=2)
