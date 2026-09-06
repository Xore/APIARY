#!/usr/bin/env python3
"""S6 cpt-text: raw domain text for continued pretraining, pooled from
whatever other slices already exist -- decompiler output (S2/S3), sanitised
session transcripts (S1), REx86 text (S4), public RE corpora (issue #3082).

No teacher, no labels: CPT trains on the text itself. The one rule that
matters here is the same one everywhere else -- a record whose slice is
S1/S2 (captured, not built in this repo) must never reach a text shard this
script writes, so `extract_text` re-checks `slices.guard_not_built_here`
itself rather than trusting that the caller already filtered.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from schema import Record, write_jsonl  # noqa: E402
from slices import SLICES_BY_ID, guard_not_built_here  # noqa: E402


def extract_text(record: Record) -> Optional[str]:
    guard_not_built_here(record.slice)  # raises for S1/S2 -- see module docstring
    parts = [p for p in (record.prompt, record.completion) if p]
    if not parts:
        return None
    return "\n".join(parts)


def build_cpt_shards(records: list[Record], out_dir: Path, *, shard_chars: int = 100_000) -> list[Record]:
    out_dir.mkdir(parents=True, exist_ok=True)
    shards: list[Record] = []
    buf: list[str] = []
    buf_ids: list[str] = []
    buf_len = 0
    shard_index = 0

    def flush():
        nonlocal buf, buf_ids, buf_len, shard_index
        if not buf:
            return
        text = "\n\n".join(buf)
        path = out_dir / f"s6_shard_{shard_index:04d}.txt"
        path.write_text(text)
        shards.append(Record(
            id=f"s6-shard-{shard_index}",
            slice="S6",
            family="cpt-text",
            source_path=str(path.relative_to(out_dir.parent)) if out_dir.parent in path.parents else str(path),
            meta={"source_ids": list(buf_ids), "char_count": len(text),
                  "sha256": hashlib.sha256(text.encode()).hexdigest()},
        ))
        shard_index += 1
        buf, buf_ids, buf_len = [], [], 0

    for rec in records:
        text = extract_text(rec)
        if text is None:
            continue
        buf.append(text)
        buf_ids.append(rec.id)
        buf_len += len(text)
        if buf_len >= shard_chars:
            flush()
    flush()

    write_jsonl(out_dir / "s6_manifest.jsonl", shards)
    return shards


def demo() -> None:
    import tempfile
    from slices import NotBuiltHereError

    good = [
        Record(id="s3-a", slice="S3", family="dispatch-table", source_path="a.c",
               prompt="decompiled text of a", completion="handler dispatch summary"),
        Record(id="s4-b", slice="S4", family="qa", source_path="rex86.zip",
               prompt="what does xor do", completion="zeroes the register"),
    ]
    with tempfile.TemporaryDirectory() as td:
        shards = build_cpt_shards(good, Path(td))
        assert len(shards) == 1, shards
        assert (Path(td) / "s6_shard_0000.txt").exists()

    bad = [Record(id="s1-x", slice="S1", family="session", source_path="x", prompt="captured session text")]
    try:
        with tempfile.TemporaryDirectory() as td:
            build_cpt_shards(bad, Path(td))
    except NotBuiltHereError:
        pass
    else:
        raise AssertionError("S1 text should never reach a CPT shard")

    print("generate_s6.py demo: ok")


if __name__ == "__main__":
    demo()
