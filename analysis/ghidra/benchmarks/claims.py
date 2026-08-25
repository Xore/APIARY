#!/usr/bin/env python3
"""Adjudicated claim-pool scoring for the benchmark (issue #1805).

## Why the rubric score is not enough

Both existing scorers are substring matching -- `any(term in joined for term in
group)` against a fixed keyword list per case. Four consequences, all bad:

1. It rewards saying the word, not understanding it. "The loop iterates" scores
   the same as a correct account of the bounds check.
2. It cannot credit a correct insight nobody pre-listed. A model noticing that
   the XOR primitive is symmetric -- true, useful for triage, and stated in the
   case's own `ground_truth` -- earns nothing.
3. It cannot express "A found what B missed" at all, since that comparison only
   exists if it was enumerated in advance.
4. Verbosity wins: more synonyms hit more groups, and `forbidden` is empty on
   most cases, so padding is nearly free.

The irony is that `ground_truth` -- the actual semantic description -- sits in
the rubric and is not used for scoring at all.

Measured evidence that this matters, from #1805-e: Tier B beat Tier A by
+1.17 of 69 while **8 of 14 cases moved in both directions and cancelled**. The
aggregate says "+1.17"; what actually happened is that the model saw a
format-string bug it had missed and lost a file-persistence detail it had held.
A single number cannot carry that, which is what this module exists to fix.

## The scheme

1. **Decompose** each answer into atomic, individually checkable claims.
2. **Pool** across models per case, deduplicated *semantically* -- a model must
   not gain by rephrasing itself.
3. **Adjudicate each distinct claim once**, against ground truth, cheapest check
   first: the executable semantic harness where one applies, then the case's
   `ground_truth` prose, then a human ruling on the remainder.
4. **Score each model against the adjudicated pool**: coverage, precision,
   unique contribution, missed-by.
5. The pre-authored `required_groups` stays as a **floor**, not a ceiling: miss
   it and you still fail, however many novel claims you made.

Verdicts are `true`, `false`, or `unsupported` -- the last meaning plausible but
not derivable from what the model was shown. That is the hallucination signal
and is tracked separately from being wrong.

## Two rules enforced in code rather than trusted

**The adjudicator may not be a model in the round.** A candidate grading its own
novel claims is circular, and the failure is silent -- the scores still look
fine. `AdjudicationConfig` refuses to construct if the adjudicator tag appears
among the scored models.

**The pool is frozen and versioned.** Coverage is defined as a fraction of the
pool, so an unfrozen pool means a model's score moves because a *later* model
found something new. Old rounds are rescored against the frozen pool from their
stored transcripts (#1944), which is the whole reason those transcripts exist.

## What this module does not do

It does not decide verdicts by itself where the evidence is thin. Claims that no
deterministic check and no ground-truth match can settle are written to a review
queue with their provenance, and they stay `unadjudicated` -- excluded from every
score -- until a human rules. A pool that quietly guesses is worse than a small
pool, because the guess is invisible in the resulting number.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Iterable

BENCHMARKS_DIR = Path(__file__).resolve().parent
CORPUS_DIR = BENCHMARKS_DIR / "corpus"

POOL_SCHEMA_VERSION = "apiary-claim-pool-v1"

VERDICT_TRUE = "true"
VERDICT_FALSE = "false"
VERDICT_UNSUPPORTED = "unsupported"
VERDICT_PENDING = "unadjudicated"
VERDICTS = (VERDICT_TRUE, VERDICT_FALSE, VERDICT_UNSUPPORTED, VERDICT_PENDING)

# Cosine similarity above which two claims are the same claim. Deliberately
# high: merging two genuinely different observations is worse than carrying a
# near-duplicate, because a merge silently deletes one model's finding while a
# duplicate only costs a little precision. Tuned to keep "encrypts each byte"
# and "XORs every byte" together while keeping "loops over the buffer" apart.
DEDUP_THRESHOLD = 0.86

EXTRACTION_SYSTEM = """You split reverse-engineering analyses into atomic claims.

An atomic claim is one thing that can independently be true or false: a single
behavioural assertion, one evidence citation, one risk judgement, or one
recommended next step. Split compound sentences. Drop hedging and restate each
claim as a plain assertion. Never add anything the text does not say, and never
merge two assertions into one.

Return a single JSON object and nothing else:
  {"claims": [{"text": string, "kind": string}, ...]}

kind is one of: behaviour, evidence, risk, next_step."""


class ClaimError(RuntimeError):
    pass


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def canonical(text: str) -> str:
    """Cheap normalisation before the expensive semantic comparison.

    Only collapses things that are never a real difference in meaning -- case,
    whitespace, trailing punctuation. Anything subtler is left to the embedding,
    because a lexical rule that decides two claims are identical is exactly the
    substring matching this module replaces.
    """
    text = re.sub(r"\s+", " ", text.strip().lower())
    return text.rstrip(" .;:!")


@dataclass
class Claim:
    case: str
    text: str
    kind: str = "behaviour"
    verdict: str = VERDICT_PENDING
    verdict_source: str | None = None
    verdict_note: str | None = None
    # Which run/model first produced this claim, and everyone who has since made
    # it. Provenance is why a post-hoc addition can never be mistaken for a
    # pre-authored rubric entry.
    first_seen: dict[str, Any] = field(default_factory=dict)
    made_by: list[str] = field(default_factory=list)

    @property
    def claim_id(self) -> str:
        return _sha256(f"{self.case}|{canonical(self.text)}")[:16]

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["claim_id"] = self.claim_id
        return data


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    return 0.0 if not na or not nb else dot / (na * nb)


def ollama_embedder(api_base: str, model: str = "nomic-embed-text:latest") -> Callable[[str], list[float]]:
    """Embeddings from the local Ollama, for semantic deduplication.

    Local by contract, like every other model call in this stack. The model is
    already deployed for `llm-search`, so this adds no new dependency.
    """
    cache: dict[str, list[float]] = {}
    base = api_base.rstrip("/")
    if base.endswith("/v1"):
        base = base[: -len("/v1")]

    def embed(text: str) -> list[float]:
        key = canonical(text)
        if key in cache:
            return cache[key]
        body = json.dumps({"model": model, "input": key}).encode()
        req = urllib.request.Request(f"{base}/api/embed", data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=120) as response:
            payload = json.loads(response.read())
        vectors = payload.get("embeddings") or ([payload["embedding"]] if "embedding" in payload else [])
        if not vectors:
            raise ClaimError(f"no embedding returned for {key[:60]!r}")
        cache[key] = vectors[0]
        return cache[key]

    return embed


@dataclass
class AdjudicationConfig:
    """Who adjudicates, and the guarantee that it is not a contestant."""

    adjudicator_tag: str
    scored_models: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.adjudicator_tag in self.scored_models:
            raise ClaimError(
                f"{self.adjudicator_tag} is being scored in this round and cannot also "
                "adjudicate it -- a candidate grading its own novel claims is circular. "
                "Pick a model outside the round, or adjudicate by hand."
            )


def extract_claims(answer: str, case: str, *, chat: Callable[[str, str], str]) -> list[Claim]:
    """Decompose one answer into atomic claims via the adjudicator model."""
    raw = chat(EXTRACTION_SYSTEM, f"Case: {case}\n\nAnalysis to split:\n\n{answer}")
    start, end = raw.find("{"), raw.rfind("}")
    if start < 0 or end <= start:
        raise ClaimError(f"extractor returned no JSON object for {case}: {raw[:200]!r}")
    try:
        parsed = json.loads(raw[start:end + 1])
    except ValueError as exc:
        raise ClaimError(f"extractor JSON did not parse for {case}: {exc}") from exc
    claims = []
    for item in parsed.get("claims", []):
        text = (item.get("text") or "").strip()
        if text:
            claims.append(Claim(case=case, text=text, kind=item.get("kind") or "behaviour"))
    return claims


def merge_into_pool(pool: list[Claim], incoming: Iterable[Claim], embed: Callable[[str], list[float]],
                    *, model: str, run_id: str, threshold: float = DEDUP_THRESHOLD) -> dict[str, int]:
    """Add a model's claims to the pool, merging semantic duplicates.

    Deduplication is by meaning, not string: "encrypts each byte" and "XORs every
    byte" are one claim, and a model must not gain from rephrasing itself. An
    exact canonical match short-circuits the embedding call.
    """
    stats = {"new": 0, "merged": 0}
    by_case: dict[str, list[Claim]] = {}
    for claim in pool:
        by_case.setdefault(claim.case, []).append(claim)

    for claim in incoming:
        siblings = by_case.setdefault(claim.case, [])
        match = next((s for s in siblings if canonical(s.text) == canonical(claim.text)), None)
        if match is None and siblings:
            vector = embed(claim.text)
            best, score = None, 0.0
            for sibling in siblings:
                similarity = cosine(vector, embed(sibling.text))
                if similarity > score:
                    best, score = sibling, similarity
            if best is not None and score >= threshold:
                match = best
        if match is not None:
            if model not in match.made_by:
                match.made_by.append(model)
            stats["merged"] += 1
            continue
        claim.made_by = [model]
        claim.first_seen = {"model": model, "run_id": run_id,
                            "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        siblings.append(claim)
        pool.append(claim)
        stats["new"] += 1
    return stats


def adjudicate_deterministic(claim: Claim, ground_truth: str, embed: Callable[[str], list[float]],
                             *, threshold: float = 0.80) -> bool:
    """Cheapest rung: does the case's own ground_truth already assert this?

    Only ever promotes a claim to `true`. It never rules anything false, because
    absence from a one-paragraph summary is not evidence that a claim is wrong --
    the ground_truth is a description, not an exhaustive enumeration. Everything
    it cannot settle goes to a human.
    """
    if not ground_truth:
        return False
    return cosine(embed(claim.text), embed(ground_truth)) >= threshold


def adjudicate_pool(pool: list[Claim], rubric: dict[str, Any], embed: Callable[[str], list[float]],
                    *, review_queue: Path | None = None) -> dict[str, int]:
    """Run the adjudication ladder over every pending claim."""
    counts = {VERDICT_TRUE: 0, VERDICT_FALSE: 0, VERDICT_UNSUPPORTED: 0, VERDICT_PENDING: 0}
    pending = []
    for claim in pool:
        if claim.verdict != VERDICT_PENDING:
            counts[claim.verdict] += 1
            continue
        ground_truth = (rubric.get(claim.case) or {}).get("ground_truth", "")
        if adjudicate_deterministic(claim, ground_truth, embed):
            claim.verdict = VERDICT_TRUE
            claim.verdict_source = "ground_truth-match"
            counts[VERDICT_TRUE] += 1
            continue
        counts[VERDICT_PENDING] += 1
        pending.append(claim)

    if review_queue is not None and pending:
        review_queue.parent.mkdir(parents=True, exist_ok=True)
        rows = [{"claim_id": c.claim_id, "case": c.case, "text": c.text, "kind": c.kind,
                 "first_seen": c.first_seen, "made_by": c.made_by,
                 "ground_truth": (rubric.get(c.case) or {}).get("ground_truth", ""),
                 "verdict": "<< true | false | unsupported >>"} for c in pending]
        review_queue.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    return counts


def apply_rulings(pool: list[Claim], rulings: Path) -> int:
    """Fold a completed human review file back into the pool."""
    rows = json.loads(rulings.read_text())
    by_id = {c.claim_id: c for c in pool}
    applied = 0
    for row in rows:
        verdict = (row.get("verdict") or "").strip()
        if verdict not in (VERDICT_TRUE, VERDICT_FALSE, VERDICT_UNSUPPORTED):
            continue
        claim = by_id.get(row.get("claim_id"))
        if claim is None:
            continue
        claim.verdict = verdict
        claim.verdict_source = "human"
        claim.verdict_note = row.get("note")
        applied += 1
    return applied


def score_model(pool: list[Claim], model: str) -> dict[str, Any]:
    """Score one model against the adjudicated pool.

    - coverage: of all true claims, what fraction this model made. Recall of
      real findings.
    - precision: of this model's adjudicated claims, what fraction were true.
      The verbosity and hallucination brake -- without it, "mentions more"
      trivially wins.
    - unique: true claims no other model made. This is the number the whole
      revision is about.
    - missed: true claims others made and this one did not. The more actionable
      half when choosing a production model.

    Unadjudicated claims are excluded from every figure rather than assumed
    either way, and are reported so a thin pool is visible rather than flattering.
    """
    true_claims = [c for c in pool if c.verdict == VERDICT_TRUE]
    mine = [c for c in pool if model in c.made_by]
    mine_true = [c for c in mine if c.verdict == VERDICT_TRUE]
    mine_adjudicated = [c for c in mine if c.verdict != VERDICT_PENDING]
    unique = [c for c in mine_true if c.made_by == [model]]
    missed = [c for c in true_claims if model not in c.made_by]
    return {
        "model": model,
        "claims_made": len(mine),
        "coverage": round(len(mine_true) / len(true_claims), 3) if true_claims else None,
        "precision": round(len(mine_true) / len(mine_adjudicated), 3) if mine_adjudicated else None,
        "unique_true": len(unique),
        "unique_examples": [c.text for c in unique[:5]],
        "missed_true": len(missed),
        "missed_examples": [c.text for c in missed[:5]],
        "false": sum(1 for c in mine if c.verdict == VERDICT_FALSE),
        "unsupported": sum(1 for c in mine if c.verdict == VERDICT_UNSUPPORTED),
        "unadjudicated": sum(1 for c in mine if c.verdict == VERDICT_PENDING),
    }


def pool_version(pool: list[Claim]) -> str:
    """A content hash over adjudicated claims: the pool's identity.

    Stated in every report next to the Ghidra cache key. Coverage is a fraction
    of this set, so a report that does not name the version is unreadable a round
    later.
    """
    payload = sorted(f"{c.claim_id}:{c.verdict}" for c in pool)
    return _sha256("|".join(payload))[:16]


def save_pool(path: Path, pool: list[Claim], meta: dict[str, Any]) -> str:
    version = pool_version(pool)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema_version": POOL_SCHEMA_VERSION,
        "pool_version": version,
        "frozen_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "meta": meta,
        "claims": [c.as_dict() for c in pool],
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return version


def load_pool(path: Path) -> tuple[list[Claim], dict[str, Any]]:
    data = json.loads(path.read_text())
    claims = []
    for row in data.get("claims", []):
        row.pop("claim_id", None)
        claims.append(Claim(**row))
    return claims, data


def load_transcripts(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "transcripts.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("runs", nargs="+", type=Path, help="committed transcript run directories")
    parser.add_argument("--pool", type=Path, required=True, help="claim pool JSON to build or extend")
    parser.add_argument("--adjudicator", default="qwen3:14b",
                        help="model that extracts claims; must not be scored in this round")
    parser.add_argument("--api-base", default="http://127.0.0.1:11434")
    parser.add_argument("--review-queue", type=Path, help="write unadjudicated claims here for a human")
    parser.add_argument("--rulings", type=Path, help="apply a completed review file, then rescore")
    args = parser.parse_args()

    rubric = json.loads((CORPUS_DIR / "rev_cases_v2_rubric.json").read_text())["cases"]
    embed = ollama_embedder(args.api_base)

    records = []
    for run in args.runs:
        records.extend(load_transcripts(run))
    scored_models = tuple(sorted({r["model"]["tag"] for r in records}))
    AdjudicationConfig(adjudicator_tag=args.adjudicator, scored_models=scored_models)

    pool: list[Claim] = []
    meta: dict[str, Any] = {}
    if args.pool.exists():
        pool, previous = load_pool(args.pool)
        meta = previous.get("meta", {})
        print(f"loaded pool {previous.get('pool_version')} with {len(pool)} claims")

    if args.rulings:
        applied = apply_rulings(pool, args.rulings)
        print(f"applied {applied} human rulings")
    else:
        def chat(system: str, prompt: str) -> str:
            body = json.dumps({
                "model": args.adjudicator,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": prompt}],
                "stream": False, "think": False, "format": "json",
                "options": {"temperature": 0, "seed": 144, "num_ctx": 8192, "num_predict": 1024},
            }).encode()
            req = urllib.request.Request(f"{args.api_base.rstrip('/')}/api/chat", data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=300) as response:
                return json.loads(response.read()).get("message", {}).get("content", "")

        totals = {"new": 0, "merged": 0}
        for record in records:
            if record.get("outcome") != "ok" or not record["response"].get("raw"):
                continue
            try:
                claims = extract_claims(record["response"]["raw"], record["case"], chat=chat)
            except ClaimError as exc:
                print(f"  extract failed {record['case']} ({record['model']['tag']}): {exc}")
                continue
            stats = merge_into_pool(pool, claims, embed,
                                    model=record["model"]["tag"], run_id=record["run_id"])
            totals["new"] += stats["new"]
            totals["merged"] += stats["merged"]
            print(f"  {record['case']:24s} {record['model']['tag']:34s} "
                  f"+{stats['new']} new, {stats['merged']} merged")
        print(f"\n{totals['new']} new claims, {totals['merged']} merged into existing")

    counts = adjudicate_pool(pool, rubric, embed, review_queue=args.review_queue)
    print(f"verdicts: {counts}")

    meta.update({"scored_models": list(scored_models), "adjudicator": args.adjudicator,
                 "runs": [str(r) for r in args.runs]})
    version = save_pool(args.pool, pool, meta)
    print(f"pool {version} saved to {args.pool} ({len(pool)} claims)")

    print("\nper-model scores against the frozen pool:")
    for model in scored_models:
        result = score_model(pool, model)
        print(f"  {result['model']}")
        print(f"    coverage={result['coverage']} precision={result['precision']} "
              f"unique_true={result['unique_true']} missed_true={result['missed_true']} "
              f"unadjudicated={result['unadjudicated']}")
    if args.review_queue and counts[VERDICT_PENDING]:
        print(f"\n{counts[VERDICT_PENDING]} claims need a human ruling: {args.review_queue}")
        print("Scores above exclude them; they are not assumed true or false.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
