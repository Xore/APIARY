#!/usr/bin/env python3
"""Regression test for #2645: hp-extracted-file-importer OOM crashloop.

Two bugs in analysis/extracted-file-importer.py, both visible in the same
production log:

1. read_files_log() re-read and re-parsed *every* byte of *every*
   files*.log (rotated ones included, never deleted) on every single
   IMPORT_INTERVAL cycle. That on-disk corpus only grows across a day, so
   the transient `records` list built each cycle grew right along with it
   -- independent of how many of those records were new, already shipped,
   or skipped for being oversized. CPython/glibc do not reliably hand that
   transient memory back to the OS, so resident memory crept upward in
   step with total log volume, matching the reported rss trend
   (200 -> 203 -> 249 -> 254 MB across one day) until the 256 MiB cgroup
   limit OOM-killed the process. The fix tracks a per-file byte offset so
   each cycle only reads what was appended since the last one.

2. Any Zeek-extracted artefact over MAX_BYTES (16 MiB) was skipped with a
   log line and never indexed in any form -- not deferred, not queued, not
   recorded. The fix ships a metadata-only document (sha256 computed via a
   streaming, fixed-window read so the oversized file is never buffered
   whole) so the artefact's existence is auditable instead of silently
   vanishing.
"""
import gc
import importlib.util
import json
import sys
import tracemalloc
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
IMPORTER_PATH = REPO_ROOT / "arcane" / "home" / "honeypot-elk" / "analysis" / "extracted-file-importer.py"

_spec = importlib.util.spec_from_file_location("extracted_file_importer_2645", str(IMPORTER_PATH))
importer = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("extracted_file_importer_2645", importer)
_spec.loader.exec_module(importer)


def _write_files_log(path: Path, n: int, size_bytes: int, extract_dir: Path, name_prefix: str):
    """n files.log rows, each pointing at a real on-disk artefact of
    size_bytes so find_extracted() resolves them like Zeek's own output."""
    extract_dir.mkdir(parents=True, exist_ok=True)
    lines = []
    for i in range(n):
        fname = f"{name_prefix}{i}.bin"
        (extract_dir / fname).write_bytes(b"\x41" * size_bytes)
        lines.append(json.dumps({
            "extracted": fname,
            "fuid": f"F{name_prefix}{i}",
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "mime_type": "application/octet-stream",
            "source": "HTTP",
            "uid": f"C{name_prefix}{i}",
            "id.orig_h": "10.0.0.1",
            "id.orig_p": 4444,
            "id.resp_h": "10.0.0.2",
            "id.resp_p": 80,
        }))
    path.write_text("\n".join(lines) + "\n")


@pytest.fixture
def env(tmp_path, monkeypatch):
    logs = tmp_path / "zeek"
    extract = tmp_path / "zeek-extract"
    logs.mkdir()
    extract.mkdir()
    monkeypatch.setattr(importer, "FILES_LOG_DIR", logs)
    monkeypatch.setattr(importer, "EXTRACT_DIR", extract)
    # Never actually talk to Elasticsearch in this test.
    monkeypatch.setattr(importer, "already_indexed", lambda sha256: False)
    shipped_docs = []
    monkeypatch.setattr(importer, "es_post", lambda path, body, content_type="application/json": (
        shipped_docs.append(json.loads(body)) or {}
    ))
    return {"logs": logs, "extract": extract, "shipped": shipped_docs}


def test_offsets_bound_reparsing_of_skipped_files(env):
    """A second cycle over an unchanged, already-scanned files.log must
    parse zero new records -- the #2645 bug re-parsed everything, every
    cycle, forever."""
    _write_files_log(env["logs"] / "files.log", 500, size_bytes=100, extract_dir=env["extract"], name_prefix="a")
    offsets = {}
    first_pass = importer.read_files_log(offsets)
    assert len(first_pass) == 500

    second_pass = importer.read_files_log(offsets)
    assert second_pass == [], "an unchanged files.log must not be re-parsed on the next cycle"

    # Now simulate Zeek appending one more row: only that one must come back.
    with (env["logs"] / "files.log").open("a") as handle:
        (env["extract"] / "anew.bin").write_bytes(b"\x41" * 100)
        handle.write(json.dumps({"extracted": "anew.bin", "fuid": "Fnew"}) + "\n")
    third_pass = importer.read_files_log(offsets)
    assert len(third_pass) == 1


def test_memory_bounded_across_many_skipped_files(env, monkeypatch):
    """Simulates a day of Zeek rotating in new files.log segments, each full
    of artefacts this importer skips (oversized, over MAX_BYTES). The
    #2645 bug re-read the *entire accumulated* log corpus every cycle, so
    a later cycle -- with many prior segments behind it -- cost far more
    than an early one even though it is doing the same amount of new work.
    With the offset fix, each cycle's cost tracks only what is new in that
    cycle, so peak memory must stay flat as the historical corpus grows."""
    monkeypatch.setattr(importer, "MAX_BYTES", 4096)
    state = {"seen": set(), "offsets": {}}
    per_cycle_records = 40
    cycles = 12

    peaks = []
    for cycle in range(cycles):
        _write_files_log(
            env["logs"] / f"files_{cycle:03d}.log", per_cycle_records,
            size_bytes=importer.MAX_BYTES + 100, extract_dir=env["extract"],
            name_prefix=f"c{cycle}_",
        )
        gc.collect()
        tracemalloc.start()
        importer.import_once(state)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)

    # Every cycle adds the same amount of new work, so with the fix peak
    # memory in the last cycle (corpus = 12 prior segments) should be
    # close to the first cycle's (corpus = 0 prior segments), not
    # proportional to how many segments have piled up behind it.
    baseline = sum(peaks[:3]) / 3
    assert peaks[-1] < 3 * baseline + 200_000, (
        f"peak per-cycle memory grew with accumulated log history: {peaks}"
    )


def test_oversized_artifact_is_not_silently_discarded(env):
    """A >MAX_BYTES artefact must be indexed as a metadata-only record, not
    dropped with no trace."""
    over_cap = importer.MAX_BYTES + 1
    _write_files_log(env["logs"] / "files.log", 1, size_bytes=over_cap, extract_dir=env["extract"], name_prefix="huge")
    state = {"seen": set(), "offsets": {}}
    shipped = importer.import_once(state)

    assert shipped == 1
    assert len(env["shipped"]) == 1
    doc = env["shipped"][0]
    assert doc["file"]["oversized"] is True
    assert doc["file"]["size"] == over_cap
    assert "bytes" not in doc["file"], "oversized artefact bytes must never be shipped"
    assert doc["file"]["hash"]["sha256"], "an oversized artefact must still be identifiable by hash"


def test_oversized_hash_never_buffers_whole_file(env, monkeypatch):
    """hash_file() must read in fixed windows, not path.read_bytes() the
    whole (potentially huge) artefact."""
    size = importer.MAX_BYTES + 4096
    big = env["extract"] / "onefile.bin"
    big.write_bytes(b"\x42" * size)

    def _forbidden_read_bytes(self):
        raise AssertionError("hash_file() must not buffer the whole file")

    monkeypatch.setattr(Path, "read_bytes", _forbidden_read_bytes)
    digest = importer.hash_file(big, chunk_size=4096)
    assert len(digest) == 64
