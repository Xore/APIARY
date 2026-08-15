#!/usr/bin/env python3
"""Test dionaea/log_rotation_patch.py (#1389) against representative fixtures.

Builds fixture files from the patch module's own OLD_CLASS/OLD_IMPORT
constants -- the exact text apply_patch() expects to find, confirmed
live against the real vendored dionaea/lib/dionaea/python/dionaea/
log_json.py and log_incident.py (both files share an identical
FileHandler class) rather than guessed -- so there is no separate copy
of that text to drift out of sync with the patch itself.

Usage: dionaea/tests/test_log_rotation_patch.py
"""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlparse

MODULE_PATH = Path(__file__).resolve().parent.parent / "log_rotation_patch.py"
SPEC = importlib.util.spec_from_file_location("log_rotation_patch", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def make_fixture(path: Path):
    path.write_text(
        "from urllib.parse import urlparse\n"
        "import json\n"
        "\n"
        "class LoaderError(Exception):\n"
        "    pass\n"
        "\n"
        + MODULE.OLD_CLASS
        + "\n"
    )


class ApplyPatchTest(unittest.TestCase):
    def test_patches_a_fresh_fixture(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "log_json.py"
            make_fixture(target)
            msg = MODULE.apply_patch(target)
            self.assertIn("added self-rotation", msg)
            patched = target.read_text()
            self.assertIn(MODULE.MARKER, patched)
            self.assertIn("import os", patched)
            compile(patched, str(target), "exec")  # still valid Python

    def test_second_run_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "log_json.py"
            make_fixture(target)
            MODULE.apply_patch(target)
            once = target.read_text()
            msg = MODULE.apply_patch(target)
            self.assertIn("already patched", msg)
            self.assertEqual(target.read_text(), once)

    def test_refuses_to_patch_when_class_body_does_not_match(self):
        # An upstream dionaea release changing FileHandler's shape must fail
        # the build loudly, not silently apply a patch against text that no
        # longer means what it did (same discipline ftp_patch.py's own
        # `text.count(OLD) != 1` check already follows).
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "log_json.py"
            target.write_text("class FileHandler(object):\n    pass\n")
            with self.assertRaises(SystemExit):
                MODULE.apply_patch(target)


class PatchedFileHandlerBehaviorTest(unittest.TestCase):
    """Exercises the ACTUAL patched class body (not a reimplementation) by
    exec'ing NEW_CLASS with stub dependencies -- the same approach used to
    find the timestamp-collision bug test_rapid_rotation_within_one_second_
    does_not_collide now guards against."""

    def _file_handler_class(self):
        ns = {"urlparse": urlparse, "json": json, "os": os, "LoaderError": Exception}
        exec(MODULE.NEW_CLASS, ns)
        return ns["FileHandler"]

    def _read_all_records(self, d):
        seen = []
        for name in os.listdir(d):
            with open(os.path.join(d, name)) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        seen.append(json.loads(line)["n"])
        return seen

    def test_rotates_without_losing_or_duplicating_lines(self):
        FileHandler = self._file_handler_class()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "dionaea.json")
            os.environ["DIONAEA_LOG_MAX_BYTES"] = "10"
            try:
                fh = FileHandler("file://" + path)
                n = 30
                for i in range(n):
                    fh.submit({"n": i})
            finally:
                fh.fp.close()
                del os.environ["DIONAEA_LOG_MAX_BYTES"]
            self.assertEqual(sorted(self._read_all_records(d)), list(range(n)))

    def test_rapid_rotation_within_one_second_does_not_collide(self):
        # Regression test for the real bug found while validating this patch
        # live: two rotations landing in the same wall-clock second used to
        # silently replace the first rotated file via os.rename, losing
        # everything in it.
        FileHandler = self._file_handler_class()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "dionaea.json")
            os.environ["DIONAEA_LOG_MAX_BYTES"] = "1"
            try:
                fh = FileHandler("file://" + path)
                n = 40
                for i in range(n):
                    fh.submit({"n": i})
            finally:
                fh.fp.close()
                del os.environ["DIONAEA_LOG_MAX_BYTES"]
            got = sorted(self._read_all_records(d))
            self.assertEqual(got, list(range(n)), f"lost data across {len(os.listdir(d))} files")

    def test_zero_max_bytes_never_rotates(self):
        FileHandler = self._file_handler_class()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "dionaea.json")
            os.environ["DIONAEA_LOG_MAX_BYTES"] = "0"
            try:
                fh = FileHandler("file://" + path)
                for i in range(20):
                    fh.submit({"n": i})
            finally:
                fh.fp.close()
                del os.environ["DIONAEA_LOG_MAX_BYTES"]
            rotated = [f for f in os.listdir(d) if f != "dionaea.json"]
            self.assertEqual(rotated, [])

    def test_reopening_against_an_existing_large_file_seeds_size_from_disk(self):
        # A worker restart right before the threshold must not reset the
        # rotation countdown to 0 -- otherwise the file keeps growing well
        # past max across restarts.
        FileHandler = self._file_handler_class()
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "dionaea.json")
            with open(path, "w") as f:
                f.write('{"pre-existing": true}\n')
            os.environ["DIONAEA_LOG_MAX_BYTES"] = "1"
            try:
                fh = FileHandler("file://" + path)
                self.assertGreater(fh.size, 0)
                fh.submit({"n": 99})
            finally:
                fh.fp.close()
                del os.environ["DIONAEA_LOG_MAX_BYTES"]
            rotated = [f for f in os.listdir(d) if f.startswith("dionaea.json.")]
            self.assertEqual(len(rotated), 1)


if __name__ == "__main__":
    unittest.main()
