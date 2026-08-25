#!/usr/bin/env python3
"""Tests for the benchmark transcript record (issue #1805).

These assert the properties the claim-pool scoring depends on: that the prompt
is stored as sent, that a failure is stored rather than dropped, that a stored
transcript is never rewritten, and that captured real-data transcripts cannot
land inside the repository.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from transcripts import (  # noqa: E402
    PROVENANCE_CAPTURED,
    PROVENANCE_SYNTHETIC,
    REPO_ROOT,
    SCHEMA_VERSION,
    Reproducibility,
    RunMetadata,
    SlotRecorder,
    TranscriptWriter,
    sha256_json,
)

MODEL = {"tag": "qwen3:14b", "digest": "abc123", "quantization": "Q4_K_M"}
BODY = {
    "model": "qwen3:14b",
    "messages": [
        {"role": "system", "content": "system text"},
        {"role": "user", "content": "user text with EVIDENCE"},
    ],
    "options": {"temperature": 0, "num_ctx": 16384, "num_predict": 512, "seed": 144},
}


def read_records(writer):
    return [json.loads(line) for line in writer.path.read_text().splitlines()]


class TranscriptWriterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def writer(self, provenance=PROVENANCE_SYNTHETIC, **kwargs):
        return TranscriptWriter(
            self.root, RunMetadata(benchmark="test", provenance=provenance, **kwargs)
        )

    def test_stores_the_prompt_as_sent(self):
        """The literal request body is the record, so the prompt never has to be
        rebuilt from the fixtures to be read back."""
        with self.writer() as writer:
            writer.record(
                slot="ghidra", case="ransomware-like", workflow="program_triage",
                model=MODEL, request_body=BODY,
                reproducibility=Reproducibility(tier="B"),
                response={"content": "raw answer", "wall_seconds": 1.5, "output_tokens": 42},
                parsed={"family_guess": "ransomware"},
            )
        record = read_records(writer)[0]
        self.assertEqual(record["request"]["system_prompt"], "system text")
        self.assertEqual(record["request"]["user_prompt"], "user text with EVIDENCE")
        self.assertEqual(record["request"]["body"], BODY)
        self.assertEqual(record["request"]["body_sha256"], sha256_json(BODY))
        self.assertEqual(record["response"]["raw"], "raw answer")
        self.assertTrue(record["response"]["parse_ok"])
        self.assertEqual(record["model"]["digest"], "abc123")
        self.assertEqual(record["reproducibility"]["tier"], "B")
        self.assertEqual(record["schema_version"], SCHEMA_VERSION)
        self.assertEqual(record["outcome"], "ok")
        self.assertEqual(record["claim_ids"], [])

    def test_failures_are_recorded_not_dropped(self):
        """A refusal or timeout is a measurement -- for a derestricted round it
        is *the* measurement."""
        with self.writer() as writer:
            writer.record(
                slot="revdeck", case="process-injection", workflow=None,
                model=MODEL, request_body=BODY,
                reproducibility=Reproducibility(),
                error="TimeoutError: timed out",
            )
        record = read_records(writer)[0]
        self.assertEqual(record["outcome"], "error")
        self.assertEqual(record["error"], "TimeoutError: timed out")
        self.assertIsNone(record["response"]["raw"])
        self.assertFalse(record["response"]["parse_ok"])

    def test_unparsable_response_keeps_the_raw_text(self):
        """A JSON-parse failure is itself a measured outcome, so the raw text is
        stored alongside the parse result rather than instead of it."""
        with self.writer() as writer:
            writer.record(
                slot="sessions", case="cryptomining", workflow="session_analysis",
                model=MODEL, request_body=BODY,
                reproducibility=Reproducibility(),
                response={"content": "I cannot help with that."},
                parsed=None,
            )
        record = read_records(writer)[0]
        self.assertEqual(record["outcome"], "ok")
        self.assertEqual(record["response"]["raw"], "I cannot help with that.")
        self.assertFalse(record["response"]["parse_ok"])

    def test_one_line_per_call_and_run_summary_is_hashed(self):
        writer = self.writer()
        for case in ("a", "b", "c"):
            writer.record(
                slot="ghidra", case=case, workflow="program_triage", model=MODEL,
                request_body=BODY, reproducibility=Reproducibility(),
                response={"content": case},
            )
        summary = writer.close()
        self.assertEqual(len(read_records(writer)), 3)
        self.assertEqual(summary["record_count"], 3)
        self.assertIsNotNone(summary["transcripts_sha256"])
        run = json.loads((writer.directory / "run.json").read_text())
        self.assertEqual(run["record_count"], 3)
        self.assertEqual(run["benchmark"], "test")

    def test_a_stored_transcript_is_never_rewritten(self):
        """A misconfigured run is superseded by a new one, never edited -- later
        scores depend on the original text."""
        first = self.writer()
        first.record(
            slot="ghidra", case="a", workflow=None, model=MODEL, request_body=BODY,
            reproducibility=Reproducibility(), response={"content": "x"},
        )
        first.close()
        run_id = first.run.run_id
        with self.assertRaises(ValueError) as caught:
            TranscriptWriter(
                self.root,
                RunMetadata(benchmark="test", run_id=run_id, started_at=first.run.started_at),
            )
        self.assertIn("never rewritten", str(caught.exception))

    def test_supersedes_is_carried_in_the_run_record(self):
        writer = self.writer(supersedes="20260101T000000Z-deadbeef")
        summary = writer.close()
        self.assertEqual(summary["supersedes"], "20260101T000000Z-deadbeef")

    def test_captured_provenance_may_not_be_written_into_the_repo(self):
        """Real session transcripts carry attacker IPs and payloads; the split is
        enforced here rather than left to reviewer vigilance."""
        with self.assertRaises(ValueError) as caught:
            TranscriptWriter(
                REPO_ROOT / "docs" / "benchmarks" / "runs",
                RunMetadata(benchmark="test", provenance=PROVENANCE_CAPTURED),
            )
        self.assertIn("refusing to write captured-data transcripts", str(caught.exception))

    def test_captured_provenance_is_allowed_outside_the_repo(self):
        writer = TranscriptWriter(
            self.root, RunMetadata(benchmark="test", provenance=PROVENANCE_CAPTURED)
        )
        self.addCleanup(writer.close)
        self.assertEqual(writer.directory.stat().st_mode & 0o777, 0o700)

    def test_synthetic_provenance_is_allowed_inside_the_repo(self):
        writer = self.writer()
        writer.close()
        self.assertTrue(writer.path.exists())

    def test_unknown_tier_and_provenance_are_rejected(self):
        with self.assertRaises(ValueError):
            Reproducibility(tier="Z")
        with self.assertRaises(ValueError):
            RunMetadata(benchmark="test", provenance="whatever")

    def test_directory_name_is_date_prefixed(self):
        run = RunMetadata(benchmark="test", started_at="2026-08-25T12:00:00Z", run_id="abcd")
        self.assertEqual(run.directory_name, "2026-08-25-abcd")


class SlotRecorderTest(unittest.TestCase):
    def test_no_writer_is_a_silent_no_op(self):
        recorder = SlotRecorder(
            writer=None, slot="ghidra", model=MODEL, reproducibility=Reproducibility()
        )
        self.assertIsNone(
            recorder.record(case="a", workflow=None, request_body=BODY, response={"content": "x"})
        )

    def test_records_carry_the_slot_model_and_tier_it_was_built_with(self):
        """Bundling these on the recorder is what stops a slot recording a
        different model than the one it evaluated."""
        with tempfile.TemporaryDirectory() as tmp:
            writer = TranscriptWriter(tmp, RunMetadata(benchmark="test"))
            recorder = SlotRecorder(
                writer=writer, slot="sessions", model=MODEL,
                reproducibility=Reproducibility(tier="C", claim_pool_version="pool-v3"),
            )
            recorder.record(case="recon", workflow="session_analysis", request_body=BODY,
                            response={"content": "answer"}, parsed={"intent": "reconnaissance"})
            writer.close()
            record = read_records(writer)[0]
        self.assertEqual(record["slot"], "sessions")
        self.assertEqual(record["model"], MODEL)
        self.assertEqual(record["reproducibility"]["tier"], "C")
        self.assertEqual(record["reproducibility"]["claim_pool_version"], "pool-v3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
