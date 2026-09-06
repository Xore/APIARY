#!/usr/bin/env python3
"""S4 revdeck-rex86: convert Zenodo 15420461 (REx86, CC-BY-4.0, 5981 entries:
intent / Q&A / complete-the-code / comments) into the corpus-v1 schema
(issue #3082).

Already public, already licensed for this -- no teacher call, no filtering
beyond the schema conversion. The one thing the plan and #847 both flag:
check REx86's own internal split before it goes anywhere near training, so a
row that REx86 itself reserved for evaluation doesn't end up in `train`. This
script does not fetch or unzip the dataset (network access and the archive
are an operator step); it converts whatever JSON records are handed to it,
one per REx86 entry, and stamps `meta.rex86_internal_split` from whatever
split field the source recorded so the check in #847 has something to read.

Usage: generate_s4.py <rex86_entries.json> <out_dir>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from schema import Record, write_jsonl  # noqa: E402

TASK_KINDS = {"intent", "qa", "complete_code", "comment"}


def convert_entries(entries: list[dict]) -> list[Record]:
    records = []
    for i, entry in enumerate(entries):
        task = entry.get("task", "intent")
        if task not in TASK_KINDS:
            raise ValueError(f"entry {i}: unknown REx86 task kind {task!r}")
        prompt = entry.get("input") or entry.get("question") or entry.get("code")
        completion = entry.get("output") or entry.get("answer") or entry.get("comment")
        if prompt is None or completion is None:
            raise ValueError(f"entry {i}: missing prompt/completion for task {task!r}")
        records.append(Record(
            id=f"s4-{entry.get('id', i)}",
            slice="S4",
            family=task,
            source_path=entry.get("source_path", "rex86.zip"),
            prompt=prompt,
            completion=completion,
            meta={
                "rex86_internal_split": entry.get("split"),  # #847: verify before use
                "license": "CC-BY-4.0",
                "zenodo": "15420461",
            },
        ))
    return records


def demo() -> None:
    import tempfile

    fixture = [
        {"id": "1", "task": "intent", "input": "mov eax, ebx", "output": "copy ebx into eax"},
        {"id": "2", "task": "qa", "question": "what does xor eax,eax do?", "answer": "zeroes eax", "split": "train"},
        {"id": "3", "task": "complete_code", "code": "push ebp\n???", "output": "mov ebp, esp"},
        {"id": "4", "task": "comment", "input": "call malloc", "comment": "heap allocation", "split": "test"},
    ]
    records = convert_entries(fixture)
    assert len(records) == 4
    assert records[1].meta["rex86_internal_split"] == "train"
    assert records[3].meta["rex86_internal_split"] == "test"
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "s4_manifest.jsonl"
        write_jsonl(p, records)
        assert p.exists()
    print(f"generate_s4.py demo: ok ({len(records)} entries)")


if __name__ == "__main__":
    if len(sys.argv) == 3:
        entries = json.loads(Path(sys.argv[1]).read_text())
        out_dir = Path(sys.argv[2])
        records = convert_entries(entries)
        write_jsonl(out_dir / "s4_manifest.jsonl", records)
        print(f"wrote {len(records)} entries to {out_dir / 's4_manifest.jsonl'}")
    else:
        demo()
