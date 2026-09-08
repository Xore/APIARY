#!/usr/bin/env python3
"""Pin backup-staleness-watch.py's newest_archive_age_hours() (#3025): a
genuinely empty destination and a genuinely stale archive must both read as
staleness, a fresh archive must not, and a *read failure* (REVIEW-A: EACCES
on the real 0700 backup dir) must raise CouldNotCheck rather than being
silently reported as either.

newest_archive_age_hours() shells out to the privileged
backup-freshness-check.py helper via `sudo -n` (the whole point of the
fix -- the real destination directory is unreadable to the runner user), so
these tests fake that subprocess boundary rather than touching real
permissions."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "backup-staleness-watch.py"

_spec = importlib.util.spec_from_file_location("backup_staleness_watch", SCRIPT)
bsw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bsw)


class _Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class NewestArchiveAgeTest(unittest.TestCase):
    def _mock_helper(self, result: _Result):
        return mock.patch.object(bsw.subprocess, "run", return_value=result)

    def test_empty_directory_is_none(self) -> None:
        with self._mock_helper(_Result(0, "EMPTY\n")):
            self.assertIsNone(bsw.newest_archive_age_hours(Path("/mnt/usb-recovery/apiary-backups")))

    def test_fresh_archive_is_reported(self) -> None:
        newest = bsw.time.time() - 2 * 3600
        with self._mock_helper(_Result(0, f"{newest!r}\n")):
            age = bsw.newest_archive_age_hours(Path("/mnt/usb-recovery/apiary-backups"))
        self.assertIsNotNone(age)
        self.assertLess(age, 48)

    def test_stale_archive_is_reported(self) -> None:
        newest = bsw.time.time() - 120 * 3600
        with self._mock_helper(_Result(0, f"{newest!r}\n")):
            age = bsw.newest_archive_age_hours(Path("/mnt/usb-recovery/apiary-backups"))
        self.assertIsNotNone(age)
        self.assertGreater(age, 48)

    def test_permission_denied_raises_could_not_check_not_staleness(self) -> None:
        # REVIEW-A/#3025: the actual bug -- a helper/sudo failure (EACCES on
        # the real 0700 dir, before this fix) must never be read as "no
        # archive found" and must never silently return None either.
        with self._mock_helper(_Result(1, "", "PermissionError: [Errno 13] ...")):
            with self.assertRaises(bsw.CouldNotCheck):
                bsw.newest_archive_age_hours(Path("/mnt/usb-recovery/apiary-backups"))

    def test_unexpected_helper_output_raises_could_not_check(self) -> None:
        with self._mock_helper(_Result(0, "garbage\n")):
            with self.assertRaises(bsw.CouldNotCheck):
                bsw.newest_archive_age_hours(Path("/mnt/usb-recovery/apiary-backups"))


if __name__ == "__main__":
    unittest.main()
