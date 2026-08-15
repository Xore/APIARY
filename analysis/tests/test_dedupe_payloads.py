import importlib.util
import os
import tempfile
import unittest
from datetime import date
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "dedupe-payloads.py"
SPEC = importlib.util.spec_from_file_location("dedupe_payloads", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DedupePayloadsTest(unittest.TestCase):
    def test_duplicate_paths_share_an_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / "a.bin", root / "b.bin"
            first.write_bytes(b"same payload")
            second.write_bytes(b"same payload")
            result = MODULE.dedupe([root], root / "state.json")
            self.assertEqual(result["duplicates_linked"], 1)
            self.assertEqual(first.stat().st_ino, second.stat().st_ino)
            self.assertEqual(second.read_bytes(), b"same payload")

    def test_already_hardlinked_names_are_hashed_once(self):
        # #1380: three names sharing one inode (as a previous dedupe pass, or
        # pre-existing hardlinks, would leave them) should cost one digest()
        # call, not three.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second, third = root / "a.bin", root / "b.bin", root / "c.bin"
            first.write_bytes(b"same payload")
            os.link(first, second)
            os.link(first, third)
            calls = []
            original_digest = MODULE.digest

            def counting_digest(path):
                calls.append(path)
                return original_digest(path)

            MODULE.digest = counting_digest
            try:
                result = MODULE.dedupe([root], root / "state.json")
            finally:
                MODULE.digest = original_digest
            self.assertEqual(len(calls), 1)
            self.assertEqual(result["files_hashed"], 1)
            self.assertEqual(result["paths_examined"], 3)
            self.assertEqual(result["duplicates_linked"], 0)
            self.assertEqual(result["bytes_hashed"], len(b"same payload"))

    def test_two_separate_inode_groups_with_same_content_still_link(self):
        # Distinct physical files (not yet linked to each other) with equal
        # content must still be discovered and linked -- grouping by inode
        # must not stop cross-inode-group discovery.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            group_a1, group_a2 = root / "a1.bin", root / "a2.bin"
            group_b = root / "b.bin"
            group_a1.write_bytes(b"same payload")
            os.link(group_a1, group_a2)
            group_b.write_bytes(b"same payload")
            result = MODULE.dedupe([root], root / "state.json")
            self.assertEqual(result["files_hashed"], 2)
            self.assertEqual(result["duplicates_linked"], 1)
            self.assertEqual(group_a1.stat().st_ino, group_b.stat().st_ino)


class PruneOldDirectoriesTest(unittest.TestCase):
    def test_removes_only_directories_past_retention(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old, recent = root / "2026-06-01", root / "2026-07-25"
            old.mkdir()
            recent.mkdir()
            (old / "capture-1").write_bytes(b"stale bistream")
            (recent / "capture-2").write_bytes(b"fresh bistream")
            result = MODULE.prune_old_directories(root, retention_days=30, today=date(2026, 7, 31))
            self.assertEqual(result["directories_removed"], 1)
            self.assertGreater(result["bytes_removed"], 0)
            self.assertFalse(old.exists())
            self.assertTrue(recent.exists())
            self.assertTrue((recent / "capture-2").exists())

    def test_ignores_non_date_directories_and_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            odd = root / "not-a-date"
            odd.mkdir()
            (odd / "whatever").write_bytes(b"x")
            stray_file = root / "2020-01-01"  # a file, not a directory, despite the name
            stray_file.write_bytes(b"x")
            result = MODULE.prune_old_directories(root, retention_days=30, today=date(2026, 7, 31))
            self.assertEqual(result["directories_removed"], 0)
            self.assertTrue(odd.exists())
            self.assertTrue(stray_file.exists())

    def test_zero_retention_days_disables_pruning(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "2020-01-01").mkdir()
            result = MODULE.prune_old_directories(root, retention_days=0, today=date(2026, 7, 31))
            self.assertEqual(result["directories_removed"], 0)
            self.assertTrue((root / "2020-01-01").exists())

    def test_missing_root_is_a_no_op(self):
        result = MODULE.prune_old_directories(Path("/does/not/exist"), retention_days=30)
        self.assertEqual(result, {"directories_removed": 0, "bytes_removed": 0})


if __name__ == "__main__":
    unittest.main()
