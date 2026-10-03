"""Tests for the opt-in web-tooling path in the benchmark harness.

Registered in .github/workflows/quality.yml. Kept as a plain unittest script
because that is how CI executes the rest of benchmarks/tests/.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bench_tools as bt
import transcripts as tr


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
