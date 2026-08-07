"""Tests for procmon_cdc_store.py (#528)."""

import importlib.util
import random
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "procmon_cdc_store.py"
SPEC = importlib.util.spec_from_file_location("procmon_cdc_store", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules["procmon_cdc_store"] = MODULE
SPEC.loader.exec_module(MODULE)


def _procmon_row(i: int) -> bytes:
    return (
        f'"9:14:{i % 60:02d}.{i % 1000:04d} AM","proc{i % 5}.exe",{1000 + i},'
        f'"ReadFile","C:\\Windows\\System32\\path{i % 50}","SUCCESS","Detail {i}"'
    ).encode()


def _make_csv(rows: list) -> bytes:
    header = b'"Time","Process","PID","Operation","Path","Result","Detail"'
    return b"\r\n".join([header] + rows)


class RoundTripTest(unittest.TestCase):
    def test_store_and_reconstruct_is_byte_exact(self, tmp_path=None):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            store = MODULE.RowChunkStore(Path(tmp) / "store")
            rows = [_procmon_row(i) for i in range(500)]
            data = _make_csv(rows)
            manifest_id = store.store_bytes(data)
            self.assertEqual(store.reconstruct(manifest_id), data)

    def test_trailing_separator_round_trips(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            store = MODULE.RowChunkStore(Path(tmp) / "store")
            data = b"row1\r\nrow2\r\nrow3\r\n"  # trailing \r\n -> one trailing empty row
            manifest_id = store.store_bytes(data)
            self.assertEqual(store.reconstruct(manifest_id), data)

    def test_empty_bytes_round_trips(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            store = MODULE.RowChunkStore(Path(tmp) / "store")
            manifest_id = store.store_bytes(b"")
            self.assertEqual(store.reconstruct(manifest_id), b"")

    def test_unknown_manifest_raises(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            store = MODULE.RowChunkStore(Path(tmp) / "store")
            with self.assertRaises(KeyError):
                store.reconstruct("does-not-exist")


class DedupTest(unittest.TestCase):
    def test_second_identical_file_shares_every_chunk(self):
        """The actual #528 payoff: storing a second, unrelated-but-mostly-
        overlapping run's procmon.csv should not re-store the shared rows.
        Measured via the index directly (live_chunk_bytes), not just
        round-trip correctness."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            store = MODULE.RowChunkStore(Path(tmp) / "store")
            rng = random.Random(7)
            noise = [_procmon_row(i) for i in range(900)]

            def run(unique_start):
                rows = list(noise)
                unique = [
                    f'"9:15:00.0000 AM","malware.exe",{9000 + i},"RegSetValue",'
                    f'"HKLM\\Run\\evil{i}","SUCCESS","Type: REG_SZ"'.encode()
                    for i in range(unique_start, unique_start + 100)
                ]
                for row in unique:
                    rows.insert(rng.randrange(len(rows) + 1), row)
                return _make_csv(rows)

            data1 = run(0)
            data2 = run(1000)  # same noise, different unique rows

            store.store_bytes(data1)
            stats_after_first = store.stats()
            store.store_bytes(data2)
            stats_after_second = store.stats()

            # Second run adds ~100 new unique rows' worth of bytes, not a
            # second full copy of the ~900 shared noise rows.
            new_bytes = stats_after_second["live_chunk_bytes"] - stats_after_first["live_chunk_bytes"]
            self.assertLess(new_bytes, len(data2) * 0.3)

            # And both still reconstruct exactly regardless of sharing.
            m1 = MODULE.hashlib.sha256(data1).hexdigest()
            m2 = MODULE.hashlib.sha256(data2).hexdigest()
            self.assertEqual(store.reconstruct(m1), data1)
            self.assertEqual(store.reconstruct(m2), data2)

    def test_storing_same_content_twice_is_idempotent(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            store = MODULE.RowChunkStore(Path(tmp) / "store")
            data = _make_csv([_procmon_row(i) for i in range(50)])
            m1 = store.store_bytes(data)
            stats1 = store.stats()
            m2 = store.store_bytes(data)
            stats2 = store.stats()
            self.assertEqual(m1, m2)
            self.assertEqual(stats1["manifests"], stats2["manifests"])


class GarbageCollectionTest(unittest.TestCase):
    def test_release_then_compact_reclaims_orphaned_chunk_bytes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            store = MODULE.RowChunkStore(Path(tmp) / "store")
            data = _make_csv([_procmon_row(i) for i in range(300)])
            manifest_id = store.store_bytes(data)
            before = store.stats()
            self.assertGreater(before["live_chunk_bytes"], 0)

            store.release_manifest(manifest_id)
            results = store.compact_all(min_dead_fraction=0.0)
            self.assertTrue(results)  # something was compacted

            after = store.stats()
            self.assertEqual(after["live_chunk_bytes"], 0)
            self.assertEqual(after["manifests"], 0)
            with self.assertRaises(KeyError):
                store.reconstruct(manifest_id)

    def test_compact_preserves_chunks_still_referenced_by_another_manifest(self):
        """Two files sharing rows; releasing one must not break the other's
        reconstruction, even after compaction physically rewrites the pack."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            store = MODULE.RowChunkStore(Path(tmp) / "store")
            shared = [_procmon_row(i) for i in range(200)]
            data1 = _make_csv(shared + [b"unique-to-1"])
            data2 = _make_csv(shared + [b"unique-to-2"])
            m1 = store.store_bytes(data1)
            m2 = store.store_bytes(data2)

            store.release_manifest(m1)
            store.compact_all(min_dead_fraction=0.0)

            # m1's own unique row is gone, but m2 (which shares most rows
            # with m1) must still reconstruct byte-exact.
            self.assertEqual(store.reconstruct(m2), data2)
            with self.assertRaises(KeyError):
                store.reconstruct(m1)

    def test_compact_all_skips_packs_below_dead_fraction_threshold(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            store = MODULE.RowChunkStore(Path(tmp) / "store")
            data = _make_csv([_procmon_row(i) for i in range(100)])
            store.store_bytes(data)
            # Nothing released -- 0% dead. A high threshold should compact
            # nothing since there's no dead space to reclaim yet.
            results = store.compact_all(min_dead_fraction=0.5)
            self.assertEqual(results, [])


class PackRotationTest(unittest.TestCase):
    def test_pack_rotates_past_the_size_limit(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            store = MODULE.RowChunkStore(Path(tmp) / "store")
            original_max = MODULE.PACK_MAX_BYTES
            MODULE.PACK_MAX_BYTES = 2048  # force rotation quickly
            try:
                # Enough distinct (non-deduplicating) rows to exceed the
                # tiny pack limit above and force at least a second pack.
                rows = [f"unique-row-{i}-{'x' * 40}".encode() for i in range(200)]
                data = _make_csv(rows)
                manifest_id = store.store_bytes(data)
                self.assertEqual(store.reconstruct(manifest_id), data)
                pack_count = store.db.execute("SELECT COUNT(*) FROM packs").fetchone()[0]
                self.assertGreater(pack_count, 1)
            finally:
                MODULE.PACK_MAX_BYTES = original_max


if __name__ == "__main__":
    unittest.main()
