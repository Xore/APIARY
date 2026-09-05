#!/usr/bin/env python3
"""Tests for adjudicated claim-pool scoring (issue #1805).

No Ollama: the embedder is stubbed so deduplication and scoring are exercised
deterministically. These cover the properties that decide whether a claim-pool
score can be believed -- that the adjudicator cannot be a contestant, that
rephrasing earns nothing, that unadjudicated claims never silently count, and
that the pool version moves when a verdict does.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from claims import (  # noqa: E402
    POOL_SCHEMA_VERSION,
    VERDICT_FALSE,
    VERDICT_PENDING,
    VERDICT_TRUE,
    VERDICT_UNSUPPORTED,
    AdjudicationConfig,
    Claim,
    ClaimError,
    _post_json,
    adjudicate_deterministic,
    adjudicate_pool,
    apply_rulings,
    canonical,
    cosine,
    load_pool,
    load_transcripts,
    merge_into_pool,
    pool_version,
    save_pool,
    score_model,
)

# A stub embedder: claims sharing a leading token embed identically, so
# "semantic duplicate" is deterministic and obvious in the test.
VECTORS = {
    "xor": [1.0, 0.0, 0.0],
    "loop": [0.0, 1.0, 0.0],
    "risk": [0.0, 0.0, 1.0],
}


def stub_embed(text: str) -> list[float]:
    head = canonical(text).split()[0]
    return VECTORS.get(head, [0.5, 0.5, 0.5])


class AdjudicatorExclusionTest(unittest.TestCase):
    def test_a_contestant_cannot_adjudicate_its_own_round(self):
        """Silent circularity: the scores still look fine, so this is enforced
        rather than documented."""
        with self.assertRaises(ClaimError) as caught:
            AdjudicationConfig(adjudicator_tag="qwen3:14b",
                               scored_models=("qwen3:14b", "qwen2.5-coder:7b"))
        self.assertIn("circular", str(caught.exception))

    def test_an_outside_model_is_accepted(self):
        config = AdjudicationConfig(adjudicator_tag="qwen3:14b",
                                    scored_models=("qwen2.5-coder:7b",))
        self.assertEqual(config.adjudicator_tag, "qwen3:14b")


class CanonicalTest(unittest.TestCase):
    def test_collapses_only_meaningless_differences(self):
        self.assertEqual(canonical("  XORs  every byte. "), "xors every byte")
        self.assertEqual(canonical("XORs every byte"), canonical("xors every byte."))

    def test_keeps_genuinely_different_text_apart(self):
        self.assertNotEqual(canonical("xors every byte"), canonical("xors every word"))


class CosineTest(unittest.TestCase):
    def test_identical_vectors(self):
        self.assertAlmostEqual(cosine([1.0, 0.0], [1.0, 0.0]), 1.0)

    def test_orthogonal_vectors(self):
        self.assertAlmostEqual(cosine([1.0, 0.0], [0.0, 1.0]), 0.0)

    def test_zero_vector_is_not_a_division_error(self):
        self.assertEqual(cosine([0.0, 0.0], [1.0, 0.0]), 0.0)


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.pool: list[Claim] = []

    def merge(self, texts, model, case="xor_decode_loop"):
        claims = [Claim(case=case, text=t) for t in texts]
        return merge_into_pool(self.pool, claims, stub_embed, model=model, run_id="r1")

    def test_a_new_claim_is_added_with_provenance(self):
        stats = self.merge(["xor every byte with a key"], "model-a")
        self.assertEqual(stats, {"new": 1, "merged": 0})
        self.assertEqual(self.pool[0].made_by, ["model-a"])
        self.assertEqual(self.pool[0].first_seen["model"], "model-a")
        self.assertEqual(self.pool[0].first_seen["run_id"], "r1")

    def test_rephrasing_the_same_claim_earns_nothing(self):
        """A model must not gain by saying the same thing differently."""
        self.merge(["xor every byte with a key"], "model-a")
        stats = self.merge(["xor each byte using a single-byte key"], "model-b")
        self.assertEqual(stats, {"new": 0, "merged": 1})
        self.assertEqual(len(self.pool), 1)
        self.assertEqual(self.pool[0].made_by, ["model-a", "model-b"])

    def test_the_same_model_twice_is_not_counted_twice(self):
        self.merge(["xor every byte"], "model-a")
        self.merge(["xor each byte"], "model-a")
        self.assertEqual(self.pool[0].made_by, ["model-a"])

    def test_a_genuinely_different_claim_stays_separate(self):
        self.merge(["xor every byte with a key"], "model-a")
        self.merge(["loop is bounded by the length argument"], "model-b")
        self.assertEqual(len(self.pool), 2)

    def test_claims_do_not_merge_across_cases(self):
        self.merge(["xor every byte"], "model-a", case="xor_decode_loop")
        self.merge(["xor every byte"], "model-b", case="checksum_rotate")
        self.assertEqual(len(self.pool), 2)


class AdjudicationTest(unittest.TestCase):
    def test_ground_truth_match_promotes_to_true(self):
        claim = Claim(case="c", text="xor every byte with a key")
        self.assertTrue(adjudicate_deterministic(claim, "xor each byte, symmetric", stub_embed))

    def test_never_rules_false_on_absence(self):
        """Absence from a one-paragraph summary is not evidence a claim is
        wrong, so the cheap rung only ever promotes to true."""
        claim = Claim(case="c", text="risk is elevated for this sample")
        self.assertFalse(adjudicate_deterministic(claim, "xor each byte", stub_embed))
        self.assertEqual(claim.verdict, VERDICT_PENDING)

    def test_empty_ground_truth_settles_nothing(self):
        self.assertFalse(adjudicate_deterministic(Claim(case="c", text="xor bytes"), "", stub_embed))

    def test_unsettled_claims_go_to_the_review_queue(self):
        pool = [Claim(case="c", text="risk is elevated"), Claim(case="c", text="xor every byte")]
        rubric = {"c": {"ground_truth": "xor each byte, symmetric"}}
        with tempfile.TemporaryDirectory() as tmp:
            queue = Path(tmp) / "review.json"
            counts = adjudicate_pool(pool, rubric, stub_embed, review_queue=queue)
            rows = json.loads(queue.read_text())
        self.assertEqual(counts[VERDICT_TRUE], 1)
        self.assertEqual(counts[VERDICT_PENDING], 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["text"], "risk is elevated")
        self.assertIn("ground_truth", rows[0])

    def test_human_rulings_are_applied_and_attributed(self):
        pool = [Claim(case="c", text="risk is elevated")]
        with tempfile.TemporaryDirectory() as tmp:
            rulings = Path(tmp) / "ruled.json"
            rulings.write_text(json.dumps([
                {"claim_id": pool[0].claim_id, "verdict": VERDICT_FALSE, "note": "benign control"}
            ]))
            self.assertEqual(apply_rulings(pool, rulings), 1)
        self.assertEqual(pool[0].verdict, VERDICT_FALSE)
        self.assertEqual(pool[0].verdict_source, "human")
        self.assertEqual(pool[0].verdict_note, "benign control")

    def test_a_placeholder_ruling_is_ignored(self):
        pool = [Claim(case="c", text="risk is elevated")]
        with tempfile.TemporaryDirectory() as tmp:
            rulings = Path(tmp) / "ruled.json"
            rulings.write_text(json.dumps([
                {"claim_id": pool[0].claim_id, "verdict": "<< true | false | unsupported >>"}
            ]))
            self.assertEqual(apply_rulings(pool, rulings), 0)
        self.assertEqual(pool[0].verdict, VERDICT_PENDING)


class ScoringTest(unittest.TestCase):
    def build(self):
        return [
            Claim(case="c", text="a", verdict=VERDICT_TRUE, made_by=["A", "B"]),
            Claim(case="c", text="b", verdict=VERDICT_TRUE, made_by=["A"]),
            Claim(case="c", text="c", verdict=VERDICT_TRUE, made_by=["B"]),
            Claim(case="c", text="d", verdict=VERDICT_FALSE, made_by=["A"]),
            Claim(case="c", text="e", verdict=VERDICT_PENDING, made_by=["A"]),
        ]

    def test_coverage_precision_unique_and_missed(self):
        pool = self.build()
        a = score_model(pool, "A")
        # 3 true claims in the pool; A made 2 of them.
        self.assertEqual(a["coverage"], round(2 / 3, 3))
        # A has 3 adjudicated claims (a, b, d); 2 are true.
        self.assertEqual(a["precision"], round(2 / 3, 3))
        self.assertEqual(a["unique_true"], 1)   # "b"
        self.assertEqual(a["missed_true"], 1)   # "c"
        self.assertEqual(a["false"], 1)
        self.assertEqual(a["unadjudicated"], 1)

    def test_unadjudicated_claims_never_count_as_correct(self):
        """A thin pool must look thin, not flattering."""
        pool = [Claim(case="c", text="x", verdict=VERDICT_PENDING, made_by=["A"])]
        result = score_model(pool, "A")
        self.assertIsNone(result["coverage"])
        self.assertIsNone(result["precision"])
        self.assertEqual(result["unadjudicated"], 1)

    def test_verbosity_is_penalised_by_precision(self):
        """Padding hits more claims but lowers precision -- the brake the
        keyword scorer lacked."""
        pool = [Claim(case="c", text="a", verdict=VERDICT_TRUE, made_by=["A", "B"])]
        pool += [Claim(case="c", text=f"pad{i}", verdict=VERDICT_FALSE, made_by=["B"])
                 for i in range(4)]
        self.assertEqual(score_model(pool, "A")["precision"], 1.0)
        self.assertEqual(score_model(pool, "B")["precision"], 0.2)

    def test_unsupported_is_tracked_apart_from_false(self):
        pool = [Claim(case="c", text="x", verdict=VERDICT_UNSUPPORTED, made_by=["A"])]
        result = score_model(pool, "A")
        self.assertEqual(result["unsupported"], 1)
        self.assertEqual(result["false"], 0)


class PoolVersionTest(unittest.TestCase):
    def test_version_changes_when_a_verdict_changes(self):
        """Coverage is a fraction of the pool, so a report that does not name
        the version is unreadable a round later."""
        pool = [Claim(case="c", text="a", verdict=VERDICT_PENDING)]
        before = pool_version(pool)
        pool[0].verdict = VERDICT_TRUE
        self.assertNotEqual(before, pool_version(pool))

    def test_version_is_stable_for_the_same_content(self):
        a = [Claim(case="c", text="a", verdict=VERDICT_TRUE)]
        b = [Claim(case="c", text="a", verdict=VERDICT_TRUE)]
        self.assertEqual(pool_version(a), pool_version(b))

    def test_version_changes_on_a_merge_only_round(self):
        """#2031: a round that adds zero new claims and only appends to
        made_by (a later model's every claim happens to merge into existing
        ones) still moves unique_true/missed_true for earlier models, so the
        version must move too -- identical claim_id:verdict pairs are not
        enough to call two pools the same."""
        pool: list[Claim] = []
        merge_into_pool(pool, [Claim(case="c", text="xor every byte with a key")],
                        stub_embed, model="model-a", run_id="r1")
        before = pool_version(pool)
        merge_into_pool(pool, [Claim(case="c", text="xor each byte using a key")],
                        stub_embed, model="model-b", run_id="r2")
        self.assertEqual(pool[0].made_by, ["model-a", "model-b"])
        self.assertNotEqual(before, pool_version(pool))

    def test_version_is_idempotent_across_a_pure_rerun(self):
        """Re-running extraction on the same transcripts must not itself move
        the version -- only a real content change should."""
        pool: list[Claim] = []
        merge_into_pool(pool, [Claim(case="c", text="xor every byte with a key")],
                        stub_embed, model="model-a", run_id="r1")
        first = pool_version(pool)
        merge_into_pool(pool, [Claim(case="c", text="xor every byte with a key")],
                        stub_embed, model="model-a", run_id="r1")
        self.assertEqual(first, pool_version(pool))

    def test_save_and_load_round_trip(self):
        pool = [Claim(case="c", text="a", verdict=VERDICT_TRUE, made_by=["A"])]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pool.json"
            version = save_pool(path, pool, {"round": "test"})
            loaded, data = load_pool(path)
        self.assertEqual(data["pool_version"], version)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].verdict, VERDICT_TRUE)
        self.assertEqual(loaded[0].made_by, ["A"])
        self.assertEqual(loaded[0].claim_id, pool[0].claim_id)


class ReviewQueueFreshnessTest(unittest.TestCase):
    """#2417: the review queue stamps each row with the rubric's ground_truth
    at generation time, and a rubric correction (#2384) can retire that text
    while the queue keeps quoting it -- the next adjudication pass would then
    rule on claims against a mechanism the repo says is wrong. The invariant:
    every quoted ground truth equals the live rubric's, or the rubric change
    lands together with a restamped queue."""

    BENCH_DIR = Path(__file__).resolve().parents[1]
    QUEUE = BENCH_DIR.parents[2] / "docs" / "benchmarks" / "claim-pools" / "tier-a-v1-review-queue.json"
    RUBRIC = BENCH_DIR / "corpus" / "rev_cases_v2_rubric.json"

    def test_every_row_quotes_the_current_rubric_ground_truth(self):
        queue = json.loads(self.QUEUE.read_text())
        rubric = json.loads(self.RUBRIC.read_text())["cases"]
        stale = [
            (row["claim_id"], row["case"]) for row in queue
            if row.get("ground_truth") != (rubric.get(row["case"]) or {}).get("ground_truth")
        ]
        self.assertEqual(stale, [],
                         f"queue rows quoting retired ground truth: {stale}")

    def test_retired_narrative_is_kept_only_as_an_explicit_annotation(self):
        """Fidelity: the pre-correction text survives inside a
        ground_truth_superseded note (superseded-but-annotated), never as the
        row's operative quote."""
        queue = json.loads(self.QUEUE.read_text())
        for row in queue:
            if row.get("ground_truth_superseded") is not None:
                self.assertNotEqual(row["ground_truth_superseded"].get("previous_text"),
                                    row["ground_truth"],
                                    f"{row['claim_id']}: supersession recorded but quote unchanged")


class SchemaVersionTest(unittest.TestCase):
    """#2032 item 4: a schema mismatch must fail with a message naming both
    versions, not a bare TypeError from deep inside Claim construction."""

    def test_mismatched_schema_version_raises_with_both_versions_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pool.json"
            path.write_text(json.dumps({"schema_version": "some-other-v9", "claims": []}))
            with self.assertRaises(ClaimError) as caught:
                load_pool(path)
        self.assertIn("some-other-v9", str(caught.exception))
        self.assertIn(POOL_SCHEMA_VERSION, str(caught.exception))

    def test_missing_schema_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pool.json"
            path.write_text(json.dumps({"claims": []}))
            with self.assertRaises(ClaimError):
                load_pool(path)

    def test_matching_schema_version_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pool.json"
            save_pool(path, [Claim(case="c", text="a")], {})
            claims, _ = load_pool(path)
        self.assertEqual(len(claims), 1)


class ApplyRulingsUnmatchedIdTest(unittest.TestCase):
    """#2032 item 3: an unmatched claim_id must be visible, not silently
    dropped -- "applied N" alone gives no denominator."""

    def test_unmatched_claim_id_is_reported(self):
        pool = [Claim(case="c", text="risk is elevated")]
        with tempfile.TemporaryDirectory() as tmp:
            rulings = Path(tmp) / "ruled.json"
            rulings.write_text(json.dumps([
                {"claim_id": "not-a-real-id", "verdict": VERDICT_TRUE},
                {"claim_id": pool[0].claim_id, "verdict": VERDICT_FALSE},
            ]))
            import io
            from contextlib import redirect_stderr
            buf = io.StringIO()
            with redirect_stderr(buf):
                applied = apply_rulings(pool, rulings)
        self.assertEqual(applied, 1)
        self.assertIn("not-a-real-id", buf.getvalue())


class ReviewQueueFreshnessPreservationTest(unittest.TestCase):
    """#2032 item 2: a regenerated queue must not clobber rows a human has
    already filled in."""

    def test_a_filled_row_survives_regeneration(self):
        pool = [Claim(case="c", text="risk is elevated"), Claim(case="c", text="xor every byte")]
        rubric = {"c": {"ground_truth": "unrelated sentence"}}
        with tempfile.TemporaryDirectory() as tmp:
            queue = Path(tmp) / "review.json"
            adjudicate_pool(pool, rubric, stub_embed, review_queue=queue)
            rows = json.loads(queue.read_text())
            # a human fills in one row
            rows[0]["verdict"] = VERDICT_TRUE
            rows[0]["note"] = "confirmed by hand"
            queue.write_text(json.dumps(rows))

            # extraction re-runs (e.g. a new transcript merged); pool still
            # has these same two claims pending, so the queue regenerates
            pool2 = [Claim(case="c", text="risk is elevated"), Claim(case="c", text="xor every byte")]
            adjudicate_pool(pool2, rubric, stub_embed, review_queue=queue)
            regenerated = {r["claim_id"]: r for r in json.loads(queue.read_text())}
        filled_id = rows[0]["claim_id"]
        self.assertEqual(regenerated[filled_id]["verdict"], VERDICT_TRUE)
        self.assertEqual(regenerated[filled_id]["note"], "confirmed by hand")


class LoadTranscriptsTest(unittest.TestCase):
    """#2032 item 5: a malformed line must not crash the whole load, and the
    error must name the file and line."""

    def test_malformed_line_is_skipped_with_file_and_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            (run_dir / "transcripts.jsonl").write_text(
                '{"case": "a", "run_id": "r1"}\n'
                "not json at all\n"
                '{"case": "b", "run_id": "r1"}\n'
            )
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                records = load_transcripts(run_dir)
        self.assertEqual(len(records), 2)
        self.assertIn("transcripts.jsonl:2", buf.getvalue())


class PostJsonRetryTest(unittest.TestCase):
    """#2032 item 1: a transient failure must be retried, not lost."""

    def test_retries_then_succeeds(self):
        import urllib.error

        calls = {"n": 0}

        class FakeResponse:
            def __init__(self, body):
                self.body = body

            def read(self):
                return self.body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=None):
            calls["n"] += 1
            if calls["n"] < 3:
                raise urllib.error.URLError("connection reset")
            return FakeResponse(b'{"ok": true}')

        import claims as claims_module
        original = claims_module.urllib.request.urlopen
        original_sleep = claims_module.time.sleep
        claims_module.urllib.request.urlopen = fake_urlopen
        claims_module.time.sleep = lambda _s: None
        try:
            result = _post_json("http://example.invalid/x", {"a": 1}, timeout=5)
        finally:
            claims_module.urllib.request.urlopen = original
            claims_module.time.sleep = original_sleep
        self.assertEqual(result, {"ok": True})
        self.assertEqual(calls["n"], 3)

    def test_exhausting_retries_raises_claim_error(self):
        import urllib.error

        def always_fails(req, timeout=None):
            raise urllib.error.URLError("connection reset")

        import claims as claims_module
        original = claims_module.urllib.request.urlopen
        original_sleep = claims_module.time.sleep
        claims_module.urllib.request.urlopen = always_fails
        claims_module.time.sleep = lambda _s: None
        try:
            with self.assertRaises(ClaimError):
                _post_json("http://example.invalid/x", {"a": 1}, timeout=5, retries=2)
        finally:
            claims_module.urllib.request.urlopen = original
            claims_module.time.sleep = original_sleep


class IncrementalSaveTest(unittest.TestCase):
    """#2032 item 1: the pool is written after every record, not once at the end.

    The acceptance criterion is "killing Ollama mid-merge costs at most one
    record of progress", which is a property of *where* the save call sits --
    moving it back out of the loop leaves every other test green. So this pins
    the call site directly: a counting spy over `claims.save_pool` driving the
    real extraction loop, asserting one save per successful record and that the
    file on disk actually holds each record's claims as it goes.

    No Ollama: the embedder is the module's stub convention and the adjudicator
    chat is a canned JSON response, so nothing leaves the process.
    """

    def _run_main(self, records, tmp):
        import claims as claims_module

        run_dir = Path(tmp) / "run"
        run_dir.mkdir(exist_ok=True)
        (run_dir / "transcripts.jsonl").write_text(
            "\n".join(json.dumps(r) for r in records) + "\n"
        )
        pool_path = Path(tmp) / "pool.json"

        # One distinct claim per transcript, keyed off the answer text, so the
        # pool grows by exactly one on every record instead of deduplicating.
        def fake_post_json(url, body, *, timeout, retries=3):
            answer = body["messages"][-1]["content"]
            text = answer.rsplit("\n\n", 1)[-1].strip()
            return {"message": {"content": json.dumps(
                {"claims": [{"text": text, "kind": "behaviour"}]})}}

        saves = []
        original_save = claims_module.save_pool

        def counting_save(path, pool, meta):
            version = original_save(path, pool, meta)
            saves.append(json.loads(path.read_text()))
            return version

        original_argv = sys.argv
        original_embedder = claims_module.ollama_embedder
        original_post = claims_module._post_json
        claims_module.save_pool = counting_save
        claims_module.ollama_embedder = lambda api_base, model=None: stub_embed
        claims_module._post_json = fake_post_json
        sys.argv = ["claims.py", str(run_dir), "--pool", str(pool_path),
                    "--adjudicator", "adjudicator:test"]
        try:
            import io
            from contextlib import redirect_stdout
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = claims_module.main()
        finally:
            sys.argv = original_argv
            claims_module.save_pool = original_save
            claims_module.ollama_embedder = original_embedder
            claims_module._post_json = original_post
        self.assertEqual(rc, 0)
        return saves, pool_path

    def test_the_pool_is_written_once_per_record(self):
        records = [
            {"case": "xor_decode_loop", "model": {"tag": "m:test"}, "run_id": "r1",
             "outcome": "ok", "response": {"raw": "xor claim one"}},
            {"case": "xor_decode_loop", "model": {"tag": "m:test"}, "run_id": "r1",
             "outcome": "ok", "response": {"raw": "loop claim two"}},
            {"case": "linked_list_sum", "model": {"tag": "m:test"}, "run_id": "r1",
             "outcome": "ok", "response": {"raw": "risk claim three"}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            saves, pool_path = self._run_main(records, tmp)

        # 3 in-loop saves + the single final save after adjudication.
        self.assertEqual(len(saves), len(records) + 1)
        # After the Nth record the file already holds N claims -- a crash at
        # that point costs the (N+1)th record only.
        self.assertEqual([len(s["claims"]) for s in saves[:-1]], [1, 2, 3])

    def test_a_skipped_record_does_not_save(self):
        """Only *successful* records cost a write -- a malformed or non-ok
        record is skipped before the save, so the count tracks real progress."""
        records = [
            {"case": "xor_decode_loop", "model": {"tag": "m:test"}, "run_id": "r1",
             "outcome": "ok", "response": {"raw": "xor claim one"}},
            {"case": "xor_decode_loop", "model": {"tag": "m:test"}, "run_id": "r1",
             "outcome": "timeout", "response": {"raw": ""}},
            {"model": {"tag": "m:test"}, "run_id": "r1",
             "outcome": "ok", "response": {"raw": "loop claim two"}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            saves, _ = self._run_main(records, tmp)
        self.assertEqual(len(saves), 2)  # one record + the final save

    def test_a_crashed_run_does_not_mark_the_next_pool_partial(self):
        """`extraction_in_progress` is only true of the file a crashed run left
        behind. `meta` is reloaded from that file on the next run and
        `meta.update()` never removes keys, so without an explicit clear the
        flag would stick to every later pool, complete ones included."""
        records = [
            {"case": "xor_decode_loop", "model": {"tag": "m:test"}, "run_id": "r1",
             "outcome": "ok", "response": {"raw": "xor claim one"}},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            saves, pool_path = self._run_main(records, tmp)
            # the in-loop write marks the pool partial ...
            self.assertTrue(saves[0]["meta"].get("extraction_in_progress"))
            # ... and the final write of the same run clears it.
            self.assertNotIn("extraction_in_progress", saves[-1]["meta"])

            # Simulate the crashed-run state: the partial meta is what a second
            # run loads. It must not survive that run's clean completion.
            partial = json.loads(pool_path.read_text())
            partial["meta"]["extraction_in_progress"] = True
            pool_path.write_text(json.dumps(partial, indent=2, sort_keys=True))
            saves2, _ = self._run_main(records, tmp)
        self.assertNotIn("extraction_in_progress", saves2[-1]["meta"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
