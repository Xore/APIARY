#!/usr/bin/env python3
"""The one JSONL record schema shared by every corpus-v1 slice (#3082).

One schema, not six, because decontaminate.py and the dev split have to walk
every slice the same way. Slice-specific data lives in `meta`.

    id            str   stable, unique within the slice
    slice         str   one of slices.SliceId
    family        str   slice-specific bucket (behaviour family, source corpus, ...)
    source_path   str   relative path to the underlying source artefact (.c, transcript, ...)
    prompt        str | None   task text given to the teacher/student; None if not yet built
                              (e.g. S3 needs host-side Ghidra decompilation first)
    completion    str | None   teacher label; None until labelled
    meta          dict  slice-specific extras (toolchain, opt level, split id, ...)

Every generator in this package writes records through `write_jsonl` /
`iter_jsonl` so the shape can't drift between slices.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional

SCHEMA_VERSION = "corpus-v1-record-1"


@dataclass
class Record:
    id: str
    slice: str
    family: str
    source_path: str
    prompt: Optional[str] = None
    completion: Optional[str] = None
    meta: dict[str, Any] = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def write_jsonl(path: Path, records: list[Record]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for r in records:
            f.write(json.dumps(r.to_json(), sort_keys=True) + "\n")


def iter_jsonl(path: Path) -> Iterator[Record]:
    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            d.pop("schema_version", None)
            yield Record(**d)


def demo() -> None:
    import tempfile

    recs = [
        Record(id="a-1", slice="S3", family="xor-like", source_path="a.c", meta={"opt": "O0"}),
        Record(id="a-2", slice="S3", family="dispatch", source_path="b.c", prompt="p", completion="c"),
    ]
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "sample.jsonl"
        write_jsonl(p, recs)
        got = list(iter_jsonl(p))
        assert got == recs, got
    print("schema.py demo: ok")


if __name__ == "__main__":
    demo()
