"""Tests for archive_diagnostics.py (#528)."""

import importlib.util
import sys
import tempfile
import time
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

STORE_PATH = Path(__file__).resolve().parent.parent / "procmon_cdc_store.py"
STORE_SPEC = importlib.util.spec_from_file_location("procmon_cdc_store", STORE_PATH)
STORE_MODULE = importlib.util.module_from_spec(STORE_SPEC)
sys.modules["procmon_cdc_store"] = STORE_MODULE
STORE_SPEC.loader.exec_module(STORE_MODULE)

MODULE_PATH = Path(__file__).resolve().parent.parent / "archive_diagnostics.py"
SPEC = importlib.util.spec_from_file_location("archive_diagnostics", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _make_diagnostics_zip(path: Path, procmon_csv: bytes = b"row1\r\nrow2\r\n", extra_files=None):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        if procmon_csv is not None:
            zf.writestr("procmon.csv", procmon_csv)
        zf.writestr("metadata.json", b'{"job": "abc123"}')
        for name, content in (extra_files or {}).items():
            zf.writestr(name, content)


class ArchiveRoundTripTest(unittest.TestCase):
    def test_archive_then_rehydrate_restores_exact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            zip_path = tmp / "job1.diagnostics.zip"
            # Realistically sized (~1000 rows): a handful of tiny rows
            # would leave the JSON stub (manifest_id, hashes, timestamp --
            # a couple hundred bytes on its own) no smaller than the
            # member it replaces, which would make bytes_reclaimed > 0
            # assert on an unrealistic fixture rather than the real
            # zip-archival mechanism this test means to cover.
            original_csv = b"\r\n".join(
                f'"9:14:{i % 60:02d} AM","proc{i % 5}.exe",{1000 + i},'
                f'"ReadFile","C:\\Windows\\System32\\path{i % 50}","SUCCESS","Detail {i}"'.encode()
                for i in range(1000)
            )
            _make_diagnostics_zip(zip_path, procmon_csv=original_csv)

            store = STORE_MODULE.RowChunkStore(tmp / "store")
            result = MODULE.archive_one(zip_path, store)
            self.assertIn("manifest_id", result)
            self.assertGreater(result["bytes_reclaimed"], 0)

            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
                self.assertNotIn("procmon.csv", names)
                self.assertIn("procmon.csv.dedup-manifest-ref", names)
                self.assertIn("metadata.json", names)  # untouched member survives

            rehydrate_result = MODULE.rehydrate_one(zip_path, store)
            self.assertEqual(rehydrate_result["rehydrated_bytes"], len(original_csv))

            with zipfile.ZipFile(zip_path) as zf:
                self.assertEqual(zf.read("procmon.csv"), original_csv)
                self.assertNotIn("procmon.csv.dedup-manifest-ref", zf.namelist())
                self.assertEqual(zf.read("metadata.json"), b'{"job": "abc123"}')

    def test_archiving_twice_is_a_noop_the_second_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            zip_path = tmp / "job1.diagnostics.zip"
            _make_diagnostics_zip(zip_path)
            store = STORE_MODULE.RowChunkStore(tmp / "store")

            MODULE.archive_one(zip_path, store)
            second = MODULE.archive_one(zip_path, store)
            self.assertEqual(second.get("skipped"), "already archived")

    def test_zip_with_no_procmon_csv_is_skipped_not_erred(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            zip_path = tmp / "job1.diagnostics.zip"
            _make_diagnostics_zip(zip_path, procmon_csv=None)
            store = STORE_MODULE.RowChunkStore(tmp / "store")

            result = MODULE.archive_one(zip_path, store)
            self.assertEqual(result.get("skipped"), "no procmon.csv member")

    def test_rehydrate_detects_a_tampered_store(self):
        """If the chunk store's reconstruction somehow no longer matches
        what was recorded at archive time, rehydrate must refuse to write
        a silently-wrong file rather than trust the store blindly."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            zip_path = tmp / "job1.diagnostics.zip"
            _make_diagnostics_zip(zip_path, procmon_csv=b"row1\r\nrow2\r\nrow3\r\n")
            store = STORE_MODULE.RowChunkStore(tmp / "store")
            MODULE.archive_one(zip_path, store)

            # Corrupt the stub's recorded hash to simulate a mismatch.
            with zipfile.ZipFile(zip_path) as zf:
                stub = zf.read("procmon.csv.dedup-manifest-ref")
            import json
            stub_obj = json.loads(stub)
            stub_obj["original_sha256"] = "0" * 64
            tmp_zip = zip_path.with_suffix(".rewrite.tmp")
            with zipfile.ZipFile(zip_path) as src, zipfile.ZipFile(tmp_zip, "w") as dst:
                for info in src.infolist():
                    if info.filename == "procmon.csv.dedup-manifest-ref":
                        dst.writestr(info, json.dumps(stub_obj).encode())
                    else:
                        dst.writestr(info, src.read(info.filename))
            tmp_zip.replace(zip_path)

            with self.assertRaises(RuntimeError):
                MODULE.rehydrate_one(zip_path, store)


class FindArchivableTest(unittest.TestCase):
    def test_respects_age_cutoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            old_zip = tmp / "old.diagnostics.zip"
            new_zip = tmp / "new.diagnostics.zip"
            _make_diagnostics_zip(old_zip)
            _make_diagnostics_zip(new_zip)

            old_time = time.time() - 40 * 86400
            import os
            os.utime(old_zip, (old_time, old_time))

            found = list(MODULE.find_archivable(tmp, after_days=30))
            self.assertEqual(found, [old_zip])

    def test_ignores_non_diagnostics_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "job1.json").write_text("{}")
            found = list(MODULE.find_archivable(tmp, after_days=0))
            self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
