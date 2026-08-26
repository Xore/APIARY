"""Tests for archive_diagnostics.py (#528).

RehydrateCliAndSummaryTest (#1988) additionally covers main()'s command
surface: rehydrate failures print the same {"path", "error"} JSON lines
archive does and exit non-zero instead of dumping tracebacks, and the
archive summary counts archived work separately from skips.
"""

import contextlib
import importlib.util
import io
import json
import os
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


class ArchiveFailureDisciplineTest(unittest.TestCase):
    """#1987: archive_one() stores the manifest (and holds every chunk's
    refcount) before anything destructive happens. Both failure paths
    below used to leak that manifest permanently -- compact_pack() only
    reclaims refcount<=0 chunks, so orphaned manifests looked live to
    stats() forever. Verify-before-destroy must cover the destroy *and*
    the bookkeeping."""

    def _pre_stats(self, store):
        s = store.stats()
        return s["manifests"], s["live_chunk_bytes"]

    def test_reconstruct_failure_releases_the_stored_manifest(self):
        # A chunk vanished from the index between store_bytes() and
        # reconstruct(): the round-trip verification raise path (#1987
        # hole 1). The manifest must go back, or its chunks are stranded.
        real_reconstruct = STORE_MODULE.RowChunkStore.reconstruct

        def broken(self, manifest_id):
            raise KeyError("no such chunk in packs")

        STORE_MODULE.RowChunkStore.reconstruct = broken
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp = Path(tmp)
                zip_path = tmp / "job1.diagnostics.zip"
                original_csv = b"\r\n".join(
                    f'"9:{i % 60:02d} AM","proc.exe",{1000 + i},"ReadFile","C:\\x","OK","d"'.encode()
                    for i in range(500)
                )
                _make_diagnostics_zip(zip_path, procmon_csv=original_csv)
                store = STORE_MODULE.RowChunkStore(tmp / "store")

                before = self._pre_stats(store)
                with self.assertRaises(KeyError):
                    MODULE.archive_one(zip_path, store)
                after = store.stats()
                self.assertEqual(after["manifests"], before[0],
                                 "manifest left stored with nothing pointing at it")
                self.assertEqual(after["live_chunk_bytes"], before[1],
                                 "chunk refcounts leaked by the failed archive")

                # The zip itself was never touched by any pass.
                with zipfile.ZipFile(zip_path) as zf:
                    self.assertIn("procmon.csv", zf.namelist())
        finally:
            STORE_MODULE.RowChunkStore.reconstruct = real_reconstruct

    def test_zip_mutated_between_reads_aborts_with_nothing_stored(self):
        # #1987 hole 2: the verified bytes come from open #1 of the zip;
        # the destructive rewrite copies members from a second open. If
        # the file changed in between, promoting the rewrite silently
        # drops whatever the concurrent writer added (including new
        # procmon.csv content, while the stub pins the OLD bytes in the
        # store). archive_one() must detect the divergence and abort
        # before tmp_path.replace(), releasing the stored manifest.
        import unittest.mock
        import types

        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            zip_path = tmp / "job1.diagnostics.zip"
            _make_diagnostics_zip(zip_path, procmon_csv=b"ORIGINAL ROWS\r\n" * 400)

            # What a concurrent writer leaves behind between the reads:
            # different procmon.csv content AND an extra member.
            mutated = tmp / ".concurrent.zip"
            with zipfile.ZipFile(mutated, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("procmon.csv", b"TAMPERED NEW CONTENT\r\n" * 400)
                zf.writestr("metadata.json", b'{"job": "abc123"}')
                zf.writestr("sneaky-late-member.txt", b"written mid-archive")

            reads = {"count": 0}
            real_zipfile_cls = zipfile.ZipFile

            class FlippingOnFirstReadClose(real_zipfile_cls):
                """Replay of the race: when the verification read handle
                (open #1) closes, swap the on-disk zip for the writer's
                version, so the copy loop's open (#2) sees different
                bytes than were verified."""

                def __init__(self, file, mode="r", *args, **kw):
                    super().__init__(file, mode, *args, **kw)
                    self._is_target_read = (
                        mode == "r" and str(file) == str(zip_path))

                def __exit__(self, *exc):
                    out = super().__exit__(*exc)
                    if self._is_target_read:
                        reads["count"] += 1
                        if reads["count"] == 1:
                            mutated.replace(zip_path)
                    return out

            shim = types.SimpleNamespace(
                ZipFile=FlippingOnFirstReadClose,
                ZIP_DEFLATED=zipfile.ZIP_DEFLATED)

            store = STORE_MODULE.RowChunkStore(tmp / "store")
            before = self._pre_stats(store)
            # The copy pass now reads different members than open #1
            # verified; the divergence must be detected before replace.
            with unittest.mock.patch.object(MODULE, "zipfile", shim):
                with self.assertRaises(RuntimeError):
                    MODULE.archive_one(zip_path, store)

            after = store.stats()
            self.assertEqual(after["manifests"], before[0],
                             "manifest left stored after the aborted archive")
            self.assertEqual(after["live_chunk_bytes"], before[1],
                             "chunk refcounts leaked by the aborted archive")

            # No mixture ever took zip_path's place: the surviving bytes
            # are the concurrent writer's, complete with its new member.
            with zipfile.ZipFile(zip_path) as zf:
                names = zf.namelist()
                self.assertIn("sneaky-late-member.txt", names)
                self.assertIn("procmon.csv", names)
                self.assertNotIn("procmon.csv.dedup-manifest-ref", names)
            residue = [p.name for p in tmp.iterdir()
                       if p.name.endswith(".archiving.tmp")]
            self.assertEqual(residue, [], "aborted pass left .archiving.tmp behind")

    def test_no_tmp_residue_after_a_failed_archive(self):
        real_reconstruct = STORE_MODULE.RowChunkStore.reconstruct

        def broken(self, manifest_id):
            raise RuntimeError("store io exploded mid-verify")

        STORE_MODULE.RowChunkStore.reconstruct = broken
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp = Path(tmp)
                zip_path = tmp / "job1.diagnostics.zip"
                _make_diagnostics_zip(zip_path)
                store = STORE_MODULE.RowChunkStore(tmp / "store")
                with self.assertRaises(RuntimeError):
                    MODULE.archive_one(zip_path, store)
                residue = [p.name for p in tmp.iterdir()
                           if p.name.endswith(".archiving.tmp")]
                self.assertEqual(residue, [], "failed pass left .archiving.tmp behind")
        finally:
            STORE_MODULE.RowChunkStore.reconstruct = real_reconstruct


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


class RehydrateCliAndSummaryTest(unittest.TestCase):
    """#1988: main()'s error convention and summary semantics."""

    def _run_main(self, argv):
        """Drive MODULE.main() with argv/stdout swapped out; return its
        exit code and everything it printed (stdout, as JSON lines)."""
        out = io.StringIO()
        old_argv = sys.argv
        sys.argv = ["archive_diagnostics.py"] + argv
        try:
            with contextlib.redirect_stdout(out):
                rc = MODULE.main()
        finally:
            sys.argv = old_argv
        return rc, [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]

    def test_rehydrate_truncated_stub_errors_as_json_with_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            zip_path = tmp / "job1.diagnostics.zip"
            _make_diagnostics_zip(zip_path, procmon_csv=None,
                                  extra_files={"procmon.csv.dedup-manifest-ref": b"{not json"})
            rc, lines = self._run_main(
                ["rehydrate", "--store-dir", str(tmp / "store"), "--zip", str(zip_path)])
            self.assertEqual(rc, 1)
            self.assertEqual(len(lines), 1)
            self.assertEqual(lines[0]["path"], str(zip_path))
            self.assertIn("error", lines[0])

    def test_rehydrate_stub_missing_keys_errors_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            zip_path = tmp / "job2.diagnostics.zip"
            stub = json.dumps({"manifest_id": "no-such-manifest",
                               "original_sha256": "0" * 64}).encode()
            _make_diagnostics_zip(zip_path, procmon_csv=None,
                                  extra_files={"procmon.csv.dedup-manifest-ref": stub})
            rc, lines = self._run_main(
                ["rehydrate", "--store-dir", str(tmp / "store"), "--zip", str(zip_path)])
            # Manifest absent from the (empty) store: the store's KeyError
            # surfaces through the same JSON shape, not a traceback.
            self.assertEqual(rc, 1)
            self.assertEqual(lines[0]["path"], str(zip_path))
            self.assertIn("no-such-manifest", lines[0]["error"])

    def test_rehydrate_success_still_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            zip_path = tmp / "job3.diagnostics.zip"
            original = b"row\r\n" * 50
            _make_diagnostics_zip(zip_path, procmon_csv=original)
            store = STORE_MODULE.RowChunkStore(tmp / "store")
            MODULE.archive_one(zip_path, store)
            rc, lines = self._run_main(
                ["rehydrate", "--store-dir", str(tmp / "store"), "--zip", str(zip_path)])
            self.assertEqual(rc, 0)
            self.assertEqual(lines[0]["rehydrated_bytes"], len(original))

    def test_archive_summary_splits_archived_from_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            results = tmp / "results"
            results.mkdir()
            archived_zip = results / "jobA.diagnostics.zip"
            no_member_zip = results / "jobB.diagnostics.zip"
            already_archived_zip = results / "jobC.diagnostics.zip"
            # Realistically sized (~300 rows): the JSON stub is a few
            # hundred bytes on its own, so a two-row member would make the
            # "archived" zip *grow* and bytes_reclaimed go negative --
            # asserting on a broken fixture rather than real behaviour.
            archived_csv = b"\r\n".join(
                b'"9:14:00 AM","proc.exe",1000,"ReadFile",'
                b'"C:\\Windows\\System32\\x","SUCCESS","Detail"'
                for _ in range(300))
            _make_diagnostics_zip(archived_zip, procmon_csv=archived_csv)  # present: archived
            _make_diagnostics_zip(no_member_zip, procmon_csv=None)    # no member: skipped
            _make_diagnostics_zip(already_archived_zip, procmon_csv=None,
                                  extra_files={"procmon.csv.dedup-manifest-ref": b"{}"})
            old = time.time() - 40 * 86400   # past the --after-days cutoff
            for p in (archived_zip, no_member_zip, already_archived_zip):
                os.utime(p, (old, old))

            rc, lines = self._run_main(
                ["archive", "--results-dir", str(results),
                 "--store-dir", str(tmp / "store"), "--after-days", "30"])
            self.assertEqual(rc, 0)
            summary = lines[-1]
            self.assertTrue(summary["summary"])
            self.assertEqual(summary["zips_processed"], 1)
            self.assertEqual(summary["zips_skipped"], 2)
            self.assertEqual(summary["zips_errored"], 0)
            self.assertGreater(summary["bytes_reclaimed"], 0)


if __name__ == "__main__":
    unittest.main()
