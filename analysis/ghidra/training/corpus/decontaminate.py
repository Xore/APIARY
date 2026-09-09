#!/usr/bin/env python3
"""Decontamination scan (issue #3082, plan §6.1): proves 0 overlap between
corpus-v1 training samples and the benchmark's own test set before any
round-7 score is quoted.

Protected material -- must not leak into a training sample above the
near-duplicate threshold:
  - the 17 benchmark corpus programs' C source (analysis/ghidra/benchmarks/corpus/src/*.c)
  - their rubric ground_truth prose and required_groups/forbidden phrases
    (analysis/ghidra/benchmarks/corpus/rev_cases_v2_rubric.json) -- a phrase also
    found in --background's reference corpus is generic scoring vocabulary,
    not a leak, and is not protected (#3146)
  - the adjudicated claim pool's claim text (docs/benchmarks/claim-pools/tier-a-v1.json)
  - transcripts under docs/benchmarks/runs/ (optional, --transcripts; can be large)
  - a live tierb-cache directory of decompiled variants (host-only, --tierb-cache; not committed here)

Two independent checks:
  1. exact hash -- normalised whitespace/case, sha256
  2. near-duplicate -- word-shingle Jaccard overlap above --threshold

# ponytail: exact shingle sets are O(protected_docs x samples); fine at this
# corpus's scale (dozens of protected docs, low thousands of samples). Swap
# for MinHash bucketing if either side grows past a few thousand documents.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from schema import Record, iter_jsonl  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[4]
BENCH_CORPUS_DIR = REPO_ROOT / "analysis" / "ghidra" / "benchmarks" / "corpus"
CLAIM_POOL_PATH = REPO_ROOT / "docs" / "benchmarks" / "claim-pools" / "tier-a-v1.json"
TRANSCRIPTS_DIR = REPO_ROOT / "docs" / "benchmarks" / "runs"

SHINGLE_SIZE = 8
JACCARD_THRESHOLD = 0.5
REPORT_SCHEMA_VERSION = "corpus-v1-decontamination-1"


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def sha256_of(text: str) -> str:
    return hashlib.sha256(normalize(text).encode()).hexdigest()


def shingles(text: str, n: int = SHINGLE_SIZE) -> set[str]:
    words = normalize(text).split()
    if len(words) < n:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}


def jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


@dataclass
class ProtectedDoc:
    source: str  # e.g. "corpus-src:xor_decode_loop.c"
    kind: str    # "source" | "ground_truth" | "phrase" | "claim" | "transcript"
    text: str


def _walk_strings(obj) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v)


def _background_phrase_texts(background_corpus: Optional[Path]) -> Optional[list[str]]:
    """Normalised text of every file under a reference corpus of unprotected,
    definitely-not-test-set material. None means no reference corpus was
    supplied (or it doesn't exist) -- the signal to fall back to protecting
    every multi-word phrase, same as before #3146 existed."""
    if not background_corpus or not background_corpus.is_dir():
        return None
    texts = [normalize(f.read_text(errors="replace"))
             for f in sorted(background_corpus.rglob("*")) if f.is_file()]
    return texts or None


def load_protected_corpus(*, tierb_cache: Optional[Path] = None, transcripts: bool = False,
                           background_corpus: Optional[Path] = None) -> list[ProtectedDoc]:
    docs: list[ProtectedDoc] = []

    src_dir = BENCH_CORPUS_DIR / "src"
    for c_file in sorted(src_dir.glob("*.c")):
        docs.append(ProtectedDoc(f"corpus-src:{c_file.name}", "source", c_file.read_text()))

    background = _background_phrase_texts(background_corpus)

    def is_generic(phrase: str) -> bool:
        # No reference corpus -- can't tell generic from specific, so protect
        # everything (#3146: never silently weaken the scan).
        return background is not None and any(normalize(phrase) in t for t in background)

    rubric_path = BENCH_CORPUS_DIR / "rev_cases_v2_rubric.json"
    if rubric_path.exists():
        rubric = json.loads(rubric_path.read_text())["cases"]
        for case_name, case in rubric.items():
            gt = case.get("ground_truth")
            if gt:
                docs.append(ProtectedDoc(f"rubric-ground-truth:{case_name}", "ground_truth", gt))
            for group in case.get("required_groups", []):
                for phrase in group:
                    # lone common words are too noisy to protect; a multi-word
                    # phrase that also shows up in the background corpus is
                    # generic scoring vocabulary, not an identifying leak (#3146)
                    if len(phrase.split()) >= 2 and not is_generic(phrase):
                        docs.append(ProtectedDoc(f"rubric-phrase:{case_name}", "phrase", phrase))
            for term in case.get("forbidden", []):
                if len(term.split()) >= 2 and not is_generic(term):
                    docs.append(ProtectedDoc(f"rubric-forbidden:{case_name}", "phrase", term))

    if CLAIM_POOL_PATH.exists():
        pool = json.loads(CLAIM_POOL_PATH.read_text())
        for claim in pool.get("claims", []):
            text = claim.get("text")
            if text:
                docs.append(ProtectedDoc(f"claim-pool:{claim.get('claim_id', '?')}", "claim", text))

    if transcripts and TRANSCRIPTS_DIR.exists():
        for f in TRANSCRIPTS_DIR.rglob("*.json"):
            try:
                data = json.loads(f.read_text())
            except (json.JSONDecodeError, OSError):
                continue
            for value in _walk_strings(data):
                if len(value) > 40:  # skip ids/timestamps/short fields
                    docs.append(ProtectedDoc(f"transcript:{f.relative_to(TRANSCRIPTS_DIR)}", "transcript", value))

    if tierb_cache and tierb_cache.exists():
        for f in sorted(tierb_cache.rglob("*")):
            if f.is_file():
                try:
                    docs.append(ProtectedDoc(f"tierb-cache:{f.name}", "source", f.read_text()))
                except (UnicodeDecodeError, OSError):
                    continue

    return docs


@dataclass
class Hit:
    sample_id: str
    sample_slice: str
    protected_source: str
    kind: str  # "exact" | "near_duplicate" | "phrase"
    score: Optional[float] = None


def _sample_text(rec: Record) -> Optional[str]:
    parts = [p for p in (rec.prompt, rec.completion) if p]
    return "\n".join(parts) if parts else None


def scan_samples(records: list[Record], protected: list[ProtectedDoc], *,
                  threshold: float = JACCARD_THRESHOLD) -> list[Hit]:
    hashable = [d for d in protected if d.kind != "phrase"]
    protected_hashes = {sha256_of(d.text): d for d in hashable}
    protected_shingle_docs = [(d, shingles(d.text)) for d in hashable]
    phrase_docs = [d for d in protected if d.kind == "phrase"]

    hits: list[Hit] = []
    for rec in records:
        text = _sample_text(rec)
        if not text:
            continue
        norm = normalize(text)

        h = sha256_of(text)
        if h in protected_hashes:
            hits.append(Hit(rec.id, rec.slice, protected_hashes[h].source, "exact"))
            continue  # exact hit already the worst case; no need for the rest

        sample_shingles = shingles(text)
        best: Optional[tuple[float, ProtectedDoc]] = None
        for doc, doc_shingles in protected_shingle_docs:
            score = jaccard(sample_shingles, doc_shingles)
            if score >= threshold and (best is None or score > best[0]):
                best = (score, doc)
        if best:
            hits.append(Hit(rec.id, rec.slice, best[1].source, "near_duplicate", round(best[0], 4)))
            continue

        for doc in phrase_docs:
            if doc.text.lower() in norm:
                hits.append(Hit(rec.id, rec.slice, doc.source, "phrase"))

    return hits


def build_report(records: list[Record], hits: list[Hit], protected: list[ProtectedDoc], *,
                  threshold: float) -> dict:
    per_slice: dict[str, dict[str, int]] = {}
    for r in records:
        per_slice.setdefault(r.slice, {"samples": 0, "hits": 0})["samples"] += 1
    for h in hits:
        per_slice.setdefault(h.sample_slice, {"samples": 0, "hits": 0})["hits"] += 1
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "threshold": threshold,
        "shingle_size": SHINGLE_SIZE,
        "protected_documents": len(protected),
        "samples_scanned": len(records),
        "total_hits": len(hits),
        "pass": len(hits) == 0,
        "per_slice": per_slice,
        "hits": [asdict(h) for h in hits],
    }


def run(manifests: list[Path], *, tierb_cache: Optional[Path], transcripts: bool,
        threshold: float, out: Path, background_corpus: Optional[Path] = None) -> dict:
    records: list[Record] = []
    for m in manifests:
        records.extend(iter_jsonl(m))
    protected = load_protected_corpus(tierb_cache=tierb_cache, transcripts=transcripts,
                                       background_corpus=background_corpus)
    hits = scan_samples(records, protected, threshold=threshold)
    report = build_report(records, hits, protected, threshold=threshold)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True))
    return report


_XOR_SOURCE = """/* Decodes a buffer in place using a single byte XOR key. Loop, crypto-like
 * primitive. Category: loop plus crypto-like primitive. */
void xor_decode(unsigned char *buf, unsigned long len, unsigned char key) {
    for (unsigned long i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}
"""  # near-duplicate (reworded comment, identical loop) of
# analysis/ghidra/benchmarks/corpus/src/xor_decode_loop.c


def _fixture_records() -> list[Record]:
    return [
        Record(id="fx-clean-1", slice="S3", family="dispatch-table", source_path="fixture",
               prompt="A command dispatcher indexes into a table of three no-argument handlers.",
               completion="It validates the index bound before calling the handler, otherwise no-ops."),
        Record(id="fx-clean-2", slice="S6", family="cpt-text", source_path="fixture",
               prompt="Session opened a reverse shell over TCP port 4444 using a netcat one-liner."),
        Record(id="fx-contaminated", slice="S3", family="encoding-loop", source_path="fixture",
               prompt=_XOR_SOURCE),
    ]


def run_fixture(out: Path) -> dict:
    """The tiny, synthetic, end-to-end proof the acceptance criteria ask for:
    a real protected corpus, a handful of records, one of them a deliberate
    near-duplicate of xor_decode_loop.c, scanned with the exact same code
    path `run()` uses. Not the full corpus -- proof that the flow works."""
    records = _fixture_records()
    protected = load_protected_corpus()
    hits = scan_samples(records, protected)
    report = build_report(records, hits, protected, threshold=JACCARD_THRESHOLD)
    report["fixture"] = True
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True))
    return report


def demo() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        report = run_fixture(Path(td) / "report.json")
        assert report["samples_scanned"] == 3, report
        assert report["total_hits"] == 1, report
        assert report["pass"] is False, report
        assert report["hits"][0]["sample_id"] == "fx-contaminated"
        assert report["hits"][0]["kind"] in ("exact", "near_duplicate", "phrase")
        assert (Path(td) / "report.json").exists()

    # a clean-only run must pass
    clean = _fixture_records()[:2]
    protected = load_protected_corpus()
    hits = scan_samples(clean, protected)
    assert hits == [], hits

    print("decontaminate.py demo: ok (1/3 fixture samples correctly caught, clean subset passes)")
    _demo_background_discrimination()


def _demo_background_discrimination() -> None:
    """#3146: a required_groups/forbidden phrase that also shows up in an
    unprotected reference corpus must not block otherwise-clean decompiler
    text, while ground truth and a phrase absent from that corpus still must."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        background_dir = Path(td) / "background"
        background_dir.mkdir()
        (background_dir / "notes.txt").write_text(
            "This note only ever discusses control flow in the abstract."
        )

        protected = load_protected_corpus(background_corpus=background_dir)
        assert not any(d.kind == "phrase" and d.text == "control flow" for d in protected)
        assert any(d.kind == "phrase" and d.text == "not attacker-controlled" for d in protected)

        rubric = json.loads((BENCH_CORPUS_DIR / "rev_cases_v2_rubric.json").read_text())["cases"]
        records = [
            Record(id="fx-generic", slice="S3", family="calib-prefilter", source_path="fixture",
                   prompt=None, completion="The control flow here is a simple three-way branch."),
            Record(id="fx-ground-truth", slice="S3", family="calib-prefilter", source_path="fixture",
                   prompt=None, completion=rubric["xor_decode_loop"]["ground_truth"]),
            Record(id="fx-specific", slice="S3", family="calib-prefilter", source_path="fixture",
                   prompt=None, completion="Argument zero is not attacker-controlled in this path."),
        ]
        hits = {h.sample_id: h for h in scan_samples(records, protected)}
        assert "fx-generic" not in hits, hits.get("fx-generic")
        assert hits["fx-ground-truth"].kind == "exact", hits["fx-ground-truth"]
        assert hits["fx-specific"].kind == "phrase", hits["fx-specific"]

    print("decontaminate.py demo: background-corpus phrase discrimination ok (#3146)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("manifests", nargs="*", type=Path, help="corpus-v1 *_manifest.jsonl files to scan")
    parser.add_argument("--tierb-cache", type=Path, default=None, help="host-only decompiled-variant cache dir")
    parser.add_argument("--transcripts", action="store_true", help="also load docs/benchmarks/runs/ (slow)")
    parser.add_argument("--background", type=Path, default=None,
                         help="reference corpus dir of unprotected text; a required_groups/forbidden "
                              "phrase found there is generic and is not protected (#3146)")
    parser.add_argument("--threshold", type=float, default=JACCARD_THRESHOLD)
    parser.add_argument("--out", type=Path, default=Path("decontamination-report.json"))
    parser.add_argument("--fixture", action="store_true", help="run the built-in tiny fixture instead of --manifests")
    args = parser.parse_args()

    if args.fixture:
        report = run_fixture(args.out)
    elif args.manifests:
        report = run(args.manifests, tierb_cache=args.tierb_cache, transcripts=args.transcripts,
                      threshold=args.threshold, out=args.out, background_corpus=args.background)
    else:
        parser.error("give at least one manifest, or pass --fixture")
        return 2

    print(f"scanned {report['samples_scanned']} samples against {report['protected_documents']} "
          f"protected documents: {report['total_hits']} hits -> {args.out}")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    if len(sys.argv) > 1:
        sys.exit(main())
    demo()
