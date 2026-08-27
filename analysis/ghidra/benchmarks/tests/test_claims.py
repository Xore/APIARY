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
    VERDICT_FALSE,
    VERDICT_PENDING,
    VERDICT_TRUE,
    VERDICT_UNSUPPORTED,
    AdjudicationConfig,
    Claim,
    ClaimError,
    adjudicate_deterministic,
    adjudicate_pool,
    apply_rulings,
    canonical,
    cosine,
    load_pool,
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
