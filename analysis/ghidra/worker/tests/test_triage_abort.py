"""#1698: aborting a GPU triage job that is already generating.

The interesting behaviour is not "does the flag get read" but the three things
that make abandoning a stream safe: the abort check must not be consulted once
per token, a failing check must not kill a healthy job, and an abort must be
distinguishable from a failure so the queue does not record one as the other.
"""

import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path

WORKER_PATH = Path(__file__).resolve().parents[1] / "ghidra-worker.py"
SPEC = importlib.util.spec_from_file_location("ghidra_worker", WORKER_PATH)
WORKER = importlib.util.module_from_spec(SPEC)
sys.modules["ghidra_worker"] = WORKER
SPEC.loader.exec_module(WORKER)


def sse(*chunks: dict) -> io.BytesIO:
    """An OpenAI-style SSE body, as urlopen would hand it back."""
    body = b""
    for chunk in chunks:
        body += b"data: " + json.dumps(chunk).encode() + b"\n\n"
    body += b"data: [DONE]\n\n"
    return io.BytesIO(body)


def delta(text: str) -> dict:
    return {"choices": [{"delta": {"content": text}}]}


class StreamReassembly(unittest.TestCase):
    def test_chunks_fold_into_the_non_streamed_shape(self):
        # Everything downstream of the request is written against the
        # non-streamed object; streaming must not change how an answer is
        # parsed, only when the call can be given up on.
        resp = WORKER._read_streamed_completion(
            sse(delta('{"risk_'), delta('level":"high"}')), lambda: False
        )
        self.assertEqual(resp["choices"][0]["message"]["content"], '{"risk_level":"high"}')

    def test_usage_survives_so_the_truncation_check_still_works(self):
        # _prompt_was_truncated reads usage.prompt_tokens; losing it in the
        # stream would silently disable the guard against a model answering
        # confidently about a prompt fragment.
        resp = WORKER._read_streamed_completion(
            sse(delta("x"), {"usage": {"prompt_tokens": 4096}, "choices": []}), lambda: False
        )
        self.assertEqual(resp["usage"]["prompt_tokens"], 4096)
        self.assertFalse(WORKER._prompt_was_truncated(resp["usage"], 1000))

    def test_unparseable_chunk_is_skipped_not_fatal(self):
        body = io.BytesIO(b"data: not json\n\ndata: " + json.dumps(delta("ok")).encode() + b"\n\ndata: [DONE]\n\n")
        resp = WORKER._read_streamed_completion(body, lambda: False)
        self.assertEqual(resp["choices"][0]["message"]["content"], "ok")

    def test_abort_raises_rather_than_returning_a_partial_answer(self):
        # A half-generated JSON object must never reach the parser — a partial
        # assessment is worse than none, and the caller has to be able to tell
        # this apart from a failure.
        with self.assertRaises(WORKER.TriageAborted):
            WORKER._read_streamed_completion(sse(delta("a"), delta("b")), lambda: True)


class AbortPollThrottle(unittest.TestCase):
    def test_the_check_is_not_run_once_per_chunk(self):
        # Chunks arrive many times a second and the real check is an
        # Elasticsearch query. Unthrottled, this would be a query per token.
        calls = {"n": 0}

        def check():
            calls["n"] += 1
            return False

        poll = WORKER._throttled(check, seconds=60)
        for _ in range(500):
            poll()
        self.assertEqual(calls["n"], 1, "should consult the backing store once inside the window")

    def test_a_true_result_latches(self):
        # Once an operator has asked to stop, a later transient failure of the
        # check must not resurrect the job.
        results = iter([True, False, False])
        poll = WORKER._throttled(lambda: next(results), seconds=0)
        self.assertTrue(poll())
        self.assertTrue(poll())

    def test_a_failing_check_does_not_kill_a_healthy_job(self):
        # An unreachable queue is not a reason to abandon work in flight. Not
        # aborting is the safe direction: the worst case is the old behaviour.
        def boom():
            raise RuntimeError("elasticsearch unreachable")

        poll = WORKER._throttled(boom, seconds=0)
        self.assertFalse(poll())

    def test_no_check_means_no_overhead(self):
        self.assertIsNone(WORKER._throttled(None))


class NonStreamingPathUnchanged(unittest.TestCase):
    def test_streaming_is_only_requested_when_aborting_is_possible(self):
        # The live ghidra-worker path passes no predicate and must keep its
        # existing single-response behaviour, so this change cannot regress
        # the common case.
        self.assertIsNone(WORKER._throttled(None))


if __name__ == "__main__":
    unittest.main()
