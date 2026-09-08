#!/usr/bin/env python3
"""Pin backup-freshness-check.py's own logic (REVIEW-A/#3025): the newest
matching archive's mtime, EMPTY for a readable-but-empty dir, and a
rejected argument for anything outside the one allowed backup directory --
never a filename or listing on stdout."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "backup-freshness-check.py"

_spec = importlib.util.spec_from_file_location("backup_freshness_check", SCRIPT)
bfc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bfc)


class BackupFreshnessCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        patcher = mock.patch.object(bfc, "ALLOWED_DIRS", (self.path,))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _touch(self, name: str, age_hours: float) -> None:
        f = self.path / name
        f.write_bytes(b"x")
        mtime = time.time() - age_hours * 3600
        os.utime(f, (mtime, mtime))

    def _run(self, *args: str) -> tuple[int, str]:
        with mock.patch("sys.argv", ["backup-freshness-check.py", *args]):
            out = []
            with mock.patch("builtins.print", side_effect=lambda s, file=None: out.append(s)):
                code = bfc.main()
        return code, (out[0] if out else "")

    def test_empty_dir_prints_empty(self) -> None:
        code, out = self._run(str(self.path), "*.tar.gz.gpg")
        self.assertEqual(code, 0)
        self.assertEqual(out, "EMPTY")

    def test_only_newest_matching_archive_counts(self) -> None:
        self._touch("apiary-essentials-old.tar.gz.gpg", age_hours=120)
        self._touch("apiary-essentials-new.tar.gz.gpg", age_hours=1)
        self._touch("unrelated-file.txt", age_hours=0)
        code, out = self._run(str(self.path), "apiary-essentials-*.tar.gz.gpg")
        self.assertEqual(code, 0)
        age_hours = (time.time() - float(out)) / 3600
        self.assertLess(age_hours, 2)

    def test_path_outside_allowed_dirs_is_rejected(self) -> None:
        outside = self.path / "not-allowed"
        outside.mkdir()
        code, _ = self._run(str(outside), "*.tar.gz.gpg")
        self.assertEqual(code, 2)

    def test_missing_directory_is_rejected(self) -> None:
        code, _ = self._run(str(self.path / "does-not-exist"), "*.tar.gz.gpg")
        self.assertEqual(code, 2)

    def test_glob_traversal_is_rejected(self) -> None:
        # REVIEW-A live finding: sys.argv[1] is checked against ALLOWED_DIRS
        # but sys.argv[2] reached target.glob() unvalidated -- confirmed
        # live to return /etc/shadow's mtime via "../../../etc/shadow".
        code, _ = self._run(str(self.path), "../../../etc/shadow")
        self.assertEqual(code, 2)

    def test_glob_with_path_separator_is_rejected(self) -> None:
        code, _ = self._run(str(self.path), "subdir/*.gpg")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
