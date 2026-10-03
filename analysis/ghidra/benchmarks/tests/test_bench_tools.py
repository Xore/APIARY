"""Tests for the opt-in web-tooling path in the benchmark harness.

Registered in .github/workflows/quality.yml. Kept as a plain unittest script
because that is how CI executes the rest of benchmarks/tests/.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bench_tools as bt


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
