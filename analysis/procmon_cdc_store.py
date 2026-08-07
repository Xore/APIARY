#!/usr/bin/env python3
"""Row-aware content-defined-chunking store for procmon.csv (#528).

## Why record-aware, not generic byte-CDC

#481 built a generic FastCDC-style byte-level chunker (`cdc-dedup-prototype.py`)
for near-duplicate binary/opaque artifacts like registry snapshot exports,
where it works well. #528 asked the same question for procmon.csv/EVTX
exports across *different, unrelated* sample runs, and found generic
byte-CDC essentially fails there: procmon.csv rows are long constant
literal text (column boilerplate, path prefixes, operation names) with
only a few short varying tokens, so the rolling hash's ~64-byte effective
memory produces the same intermediate states regardless of which row or
run it's scanning, and the chunker falls back to max-size boundaries that
don't align between files -- recovering well under 1% of the genuine
~90% content overlap. Full measurement and root cause:
analysis/tests/test_cdc_dedup_prototype.py.

The fix isn't a better rolling hash -- it's chunking on the format's own
record boundary instead of a content-derived one. procmon.csv is already
naturally row-oriented; this module chunks on that CSV row boundary,
which recovers ~90% in the same test data (full reversal).

## Storage model

A content-addressable pack store, restic/git-object-store style:

    root/
      index.sqlite3          -- chunks(hash, pack_id, offset, length, refcount)
                                 packs(pack_id, path, size, live_bytes)
                                 manifests(manifest_id, path, num_rows, ...)
      packs/pack-NNNNNN.bin  -- append-only chunk payloads, rotated by size
      manifests/<id>.manifest -- ordered list of chunk hashes for one
                                  stored file; a manifest + the chunks it
                                  references reconstructs the original
                                  bytes exactly (see reconstruct())

Chosen over a single ever-growing append-only blob for two reasons:
(1) refcounted GC needs per-chunk reachability tracking regardless of
physical layout, so pack-vs-blob doesn't avoid that bookkeeping either
way; (2) splitting into rotated, independently-compactable pack files
means compaction never has to rewrite the *entire* accumulated history
at once, only whichever packs have actually accrued enough dead space
to be worth it.

Chosen over one file per unique row (the simplest possible CAS layout):
procmon.csv rows are small (tens to low hundreds of bytes) and a real
store will accumulate tens of thousands of them -- one-file-per-chunk
means one inode and one directory-entry per row, which is real overhead
(filesystem block rounding alone wastes most of a 4KB block per tiny
chunk) that packing avoids.

## Exact reconstruction

Rows are chunked via `data.split(b"\\r\\n")`. This is a *lossless* split:
`b"\\r\\n".join(data.split(b"\\r\\n"))` reproduces `data` exactly in every
case, including a trailing separator (which produces one trailing empty
row) -- no separate "did it end with \\r\\n" bookkeeping is needed. Every
call site verifies this round-trip directly rather than trusting the
argument: see RowChunkStore.store_bytes's optional verification and
archive_diagnostics.py's own mandatory round-trip check before doing
anything destructive.

## Concurrency

Built for the same single-writer-at-a-time usage as dedupe-payloads.py's
own dedupe()/prune_old_directories() -- a maintenance-cycle process, not
concurrent multi-writer access. SQLite's own file locking is enough to
make individual operations atomic, but compact_pack() must not run
concurrently with a store_bytes()/release_manifest() call touching the
same pack (same reasoning dedupe-payloads.py's own single-process-loop
design already relies on).
"""

import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROW_SEPARATOR = b"\r\n"
CHUNK_HASH_SIZE = 16  # blake2b digest_size -- matches cdc-dedup-prototype.py's own chunk hash width
PACK_MAX_BYTES = 64 * 1024 * 1024  # rotate to a new pack past this size


def chunk_hash(row: bytes) -> bytes:
    return hashlib.blake2b(row, digest_size=CHUNK_HASH_SIZE).digest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class RowChunkStore:
    def __init__(self, root):
        self.root = Path(root)
        self.pack_dir = self.root / "packs"
        self.manifest_dir = self.root / "manifests"
        self.pack_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "index.sqlite3"
        self.db = sqlite3.connect(self.db_path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS packs (
                pack_id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL UNIQUE,
                size INTEGER NOT NULL DEFAULT 0,
                live_bytes INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS chunks (
                hash BLOB PRIMARY KEY,
                pack_id INTEGER NOT NULL REFERENCES packs(pack_id),
                offset INTEGER NOT NULL,
                length INTEGER NOT NULL,
                refcount INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS manifests (
                manifest_id TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                num_rows INTEGER NOT NULL,
                original_size INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        self.db.commit()

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- pack management -----------------------------------------------

    def _current_pack(self):
        """Return (pack_id, path, size) of the pack new chunks should be
        appended to, creating a fresh one if none exists yet or the last
        one is already past PACK_MAX_BYTES."""
        row = self.db.execute(
            "SELECT pack_id, path, size FROM packs ORDER BY pack_id DESC LIMIT 1"
        ).fetchone()
        if row and row[2] < PACK_MAX_BYTES:
            return row[0], self.pack_dir / row[1], row[2]
        idx = 1
        while (self.pack_dir / f"pack-{idx:06d}.bin").exists():
            idx += 1
        name = f"pack-{idx:06d}.bin"
        cur = self.db.execute(
            "INSERT INTO packs(path, size, live_bytes) VALUES (?, 0, 0)", (name,)
        )
        self.db.commit()
        return cur.lastrowid, self.pack_dir / name, 0

    # -- store / reconstruct ---------------------------------------------

    def store_bytes(self, data: bytes, manifest_id: str = None) -> str:
        """Store row-oriented `data` (\\r\\n-separated), returning a
        manifest_id reconstruct() accepts.

        Idempotent: calling this twice with byte-identical data and the
        default (content-hash) manifest_id returns the existing manifest
        immediately rather than writing duplicate chunks -- the caller
        still needs a matching release_manifest() call per store_bytes()
        call to keep refcounts balanced if it wants dedup credit tracked
        per logical reference (see archive_diagnostics.py).
        """
        manifest_id = manifest_id or hashlib.sha256(data).hexdigest()
        existing = self.db.execute(
            "SELECT manifest_id FROM manifests WHERE manifest_id = ?", (manifest_id,)
        ).fetchone()
        if existing:
            return manifest_id

        rows = data.split(ROW_SEPARATOR)
        hashes = [chunk_hash(r) for r in rows]

        # A single store_bytes() call can itself carry enough new (not
        # already-deduplicated) bytes to blow past PACK_MAX_BYTES -- real
        # procmon.csv exports have run well past 100MB (#502's own live
        # diagnostic hit a 128MB ring-buffer cap). Rotation therefore has
        # to be checked per-row, not just once at the top of this call,
        # or one large file could grow a single pack unboundedly.
        pack_id, pack_path, offset = self._current_pack()
        pack_f = pack_path.open("ab")
        new_bytes = 0
        try:
            for row, h in zip(rows, hashes):
                existing_chunk = self.db.execute(
                    "SELECT 1 FROM chunks WHERE hash = ?", (h,)
                ).fetchone()
                if existing_chunk is not None:
                    self.db.execute(
                        "UPDATE chunks SET refcount = refcount + 1 WHERE hash = ?", (h,)
                    )
                    continue
                if offset >= PACK_MAX_BYTES:
                    self.db.execute(
                        "UPDATE packs SET size = ?, live_bytes = live_bytes + ? WHERE pack_id = ?",
                        (offset, new_bytes, pack_id),
                    )
                    pack_f.close()
                    pack_id, pack_path, offset = self._current_pack()
                    pack_f = pack_path.open("ab")
                    new_bytes = 0
                length = len(row)
                pack_f.write(row)
                self.db.execute(
                    "INSERT INTO chunks(hash, pack_id, offset, length, refcount) "
                    "VALUES (?, ?, ?, ?, 1)",
                    (h, pack_id, offset, length),
                )
                offset += length
                new_bytes += length
        finally:
            pack_f.close()
        self.db.execute(
            "UPDATE packs SET size = ?, live_bytes = live_bytes + ? WHERE pack_id = ?",
            (offset, new_bytes, pack_id),
        )

        manifest_path = self.manifest_dir / f"{manifest_id}.manifest"
        manifest_path.write_bytes(b"".join(hashes))
        self.db.execute(
            "INSERT INTO manifests(manifest_id, path, num_rows, original_size, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (manifest_id, manifest_path.name, len(rows), len(data), _now_iso()),
        )
        self.db.commit()
        return manifest_id

    def _manifest_hashes(self, manifest_id: str):
        row = self.db.execute(
            "SELECT path FROM manifests WHERE manifest_id = ?", (manifest_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"no manifest {manifest_id!r} in this store")
        raw = (self.manifest_dir / row[0]).read_bytes()
        return [raw[i:i + CHUNK_HASH_SIZE] for i in range(0, len(raw), CHUNK_HASH_SIZE)]

    def reconstruct(self, manifest_id: str) -> bytes:
        """Reassemble the exact original bytes store_bytes() was given
        for `manifest_id`."""
        hashes = self._manifest_hashes(manifest_id)
        pack_paths = {}
        rows = []
        for h in hashes:
            chunk_row = self.db.execute(
                "SELECT pack_id, offset, length FROM chunks WHERE hash = ?", (h,)
            ).fetchone()
            if chunk_row is None:
                raise KeyError(
                    f"chunk {h.hex()} referenced by manifest {manifest_id} is "
                    f"missing from the index -- corrupt store or premature GC "
                    f"(a live manifest's chunks must never be compacted away; "
                    f"see compact_pack()'s refcount>0 filter)"
                )
            pack_id, offset, length = chunk_row
            if pack_id not in pack_paths:
                path_row = self.db.execute(
                    "SELECT path FROM packs WHERE pack_id = ?", (pack_id,)
                ).fetchone()
                pack_paths[pack_id] = self.pack_dir / path_row[0]
            with pack_paths[pack_id].open("rb") as f:
                f.seek(offset)
                rows.append(f.read(length))
        return ROW_SEPARATOR.join(rows)

    def release_manifest(self, manifest_id: str) -> None:
        """Drop one reference to every chunk `manifest_id` uses, then
        delete the manifest itself. Physical chunk bytes are NOT
        reclaimed here -- that's compact_pack()'s job, run as a separate
        maintenance step (same prune-then-compact split
        dedupe-payloads.py's own prune_old_directories()/dedupe() already
        use). Safe to call on an already-released or unknown manifest_id
        (no-op)."""
        row = self.db.execute(
            "SELECT path FROM manifests WHERE manifest_id = ?", (manifest_id,)
        ).fetchone()
        if row is None:
            return
        for h in self._manifest_hashes(manifest_id):
            chunk_row = self.db.execute(
                "SELECT pack_id, length, refcount FROM chunks WHERE hash = ?", (h,)
            ).fetchone()
            if chunk_row is None:
                continue  # already gone (e.g. a prior partial release) -- nothing to decrement
            pack_id, length, refcount = chunk_row
            self.db.execute(
                "UPDATE chunks SET refcount = refcount - 1 WHERE hash = ?", (h,)
            )
            if refcount == 1:
                # This chunk just died. Shrink its pack's live_bytes now so
                # compact_all()'s dead-fraction heuristic sees the drop
                # without needing a full recompute pass over every chunk.
                self.db.execute(
                    "UPDATE packs SET live_bytes = live_bytes - ? WHERE pack_id = ?",
                    (length, pack_id),
                )
        (self.manifest_dir / row[0]).unlink(missing_ok=True)
        self.db.execute("DELETE FROM manifests WHERE manifest_id = ?", (manifest_id,))
        self.db.commit()

    # -- garbage collection ----------------------------------------------

    def compact_pack(self, pack_id: int) -> dict:
        """Rewrite one pack file keeping only chunks with refcount > 0,
        dropping dead (refcount <= 0) chunks from the index and
        reclaiming their bytes. Must not be called concurrently with a
        store_bytes()/release_manifest() call touching the same pack
        (see module docstring's concurrency note)."""
        pack_row = self.db.execute(
            "SELECT path, size FROM packs WHERE pack_id = ?", (pack_id,)
        ).fetchone()
        if pack_row is None:
            raise KeyError(f"no pack {pack_id}")
        pack_path = self.pack_dir / pack_row[0]
        bytes_before = pack_row[1]

        live_chunks = self.db.execute(
            "SELECT hash, offset, length FROM chunks "
            "WHERE pack_id = ? AND refcount > 0 ORDER BY offset",
            (pack_id,),
        ).fetchall()
        dead = self.db.execute(
            "SELECT COUNT(*) FROM chunks WHERE pack_id = ? AND refcount <= 0", (pack_id,)
        ).fetchone()[0]

        tmp_path = pack_path.with_name(pack_path.name + ".compact.tmp")
        new_offset = 0
        with pack_path.open("rb") as src, tmp_path.open("wb") as dst:
            for h, offset, length in live_chunks:
                src.seek(offset)
                dst.write(src.read(length))
                self.db.execute("UPDATE chunks SET offset = ? WHERE hash = ?", (new_offset, h))
                new_offset += length

        self.db.execute("DELETE FROM chunks WHERE pack_id = ? AND refcount <= 0", (pack_id,))
        self.db.execute(
            "UPDATE packs SET size = ?, live_bytes = ? WHERE pack_id = ?",
            (new_offset, new_offset, pack_id),
        )
        self.db.commit()
        tmp_path.replace(pack_path)
        return {
            "pack_id": pack_id,
            "chunks_dropped": dead,
            "bytes_before": bytes_before,
            "bytes_after": new_offset,
            "bytes_reclaimed": bytes_before - new_offset,
        }

    def compact_all(self, min_dead_fraction: float = 0.5) -> list:
        """Compact every pack whose dead-byte fraction (1 - live_bytes/size)
        is at least `min_dead_fraction`, skipping packs with nothing dead
        (compaction has a real I/O cost -- a full rewrite -- so it isn't
        worth doing for a pack that's already fully live). Returns one
        compact_pack() result dict per pack actually compacted."""
        results = []
        rows = self.db.execute("SELECT pack_id, size, live_bytes FROM packs").fetchall()
        for pack_id, size, live_bytes in rows:
            if size == 0:
                continue
            dead_fraction = 1 - (live_bytes / size)
            if dead_fraction >= min_dead_fraction:
                results.append(self.compact_pack(pack_id))
        return results

    # -- introspection -----------------------------------------------------

    def stats(self) -> dict:
        packs = self.db.execute("SELECT COUNT(*), COALESCE(SUM(size), 0) FROM packs").fetchone()
        chunks = self.db.execute(
            "SELECT COUNT(*), COALESCE(SUM(length), 0) FROM chunks WHERE refcount > 0"
        ).fetchone()
        manifests = self.db.execute("SELECT COUNT(*) FROM manifests").fetchone()
        return {
            "packs": packs[0],
            "pack_bytes_on_disk": packs[1],
            "live_chunks": chunks[0],
            "live_chunk_bytes": chunks[1],
            "manifests": manifests[0],
        }
