#!/usr/bin/env python3
"""Test conpot/json_log_rotation_patch.py (#2892) against representative fixtures.

Builds a fixture file from the patch module's own OLD_CLASS/OLD_IMPORT
constants -- the exact text apply_patch() expects to find, confirmed live
against the real vendored
conpot/core/loggers/json_log.py in the pinned dtagdevsec/conpot:24.04.1
image, same approach test_log_rotation_patch.py uses for dionaea (#1389) --
so there is no separate copy of that text to drift out of sync with the
patch itself.

Usage: conpot/tests/test_json_log_rotation_patch.py
"""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "json_log_rotation_patch.py"
SPEC = importlib.util.spec_from_file_location("json_log_rotation_patch", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def make_fixture(path: Path):
    path.write_text(MODULE.OLD_IMPORT + "\n\n\n" + MODULE.OLD_CLASS + "\n")


class ApplyPatchTest(unittest.TestCase):
    def test_patches_a_fresh_fixture(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "json_log.py"
            make_fixture(target)
            msg = MODULE.apply_patch(target)
            self.assertIn("added self-rotation", msg)
            patched = target.read_text()
            self.assertIn(MODULE.MARKER, patched)
            self.assertIn("import os", patched)
            compile(patched, str(target), "exec")  # still valid Python

    def test_second_run_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "json_log.py"
            make_fixture(target)
            MODULE.apply_patch(target)
            once = target.read_text()
            msg = MODULE.apply_patch(target)
            self.assertIn("already patched", msg)
            self.assertEqual(target.read_text(), once)

    def test_patched_logger_self_rotates(self):
        """The behavioural half dionaea's test doesn't cover: run the
        patched JsonLogger against a fixture package layout and confirm it
        actually closes/renames/reopens once max_bytes is exceeded, rather
        than just checking the patch applies syntactically."""
        import shutil
        import sys

        with tempfile.TemporaryDirectory() as d:
            pkg_root = Path(d) / "pkg"
            loggers_dir = pkg_root / "conpot" / "core" / "loggers"
            loggers_dir.mkdir(parents=True)
            (pkg_root / "conpot" / "__init__.py").touch()
            (pkg_root / "conpot" / "core" / "__init__.py").touch()
            (loggers_dir / "__init__.py").touch()
            (loggers_dir / "helpers.py").write_text(
                "def json_default(o):\n    return str(o)\n"
            )
            target = loggers_dir / "json_log.py"
            make_fixture(target)
            MODULE.apply_patch(target)

            sys.path.insert(0, str(pkg_root))
            try:
                # Fresh import each run: unittest may re-run this module in
                # the same interpreter, and a stale cached copy would hide
                # a real regression in the patched rotation logic.
                for mod_name in list(sys.modules):
                    if mod_name.startswith("conpot"):
                        del sys.modules[mod_name]
                from conpot.core.loggers.json_log import JsonLogger

                logfile = str(pkg_root / "conpot.json")
                os.environ["CONPOT_JSON_LOG_MAX_BYTES"] = "50"
                try:
                    logger = JsonLogger(logfile, "sensor1", None)
                    from datetime import datetime, timezone

                    for i in range(10):
                        logger.log({
                            "timestamp": datetime.now(timezone.utc),
                            "id": str(i),
                            "remote": ("1.2.3.4", 1111),
                            "local": ("5.6.7.8", 22),
                            "data_type": "test",
                            "data": {"request": "x", "response": "y"},
                        })
                finally:
                    del os.environ["CONPOT_JSON_LOG_MAX_BYTES"]

                generations = sorted(pkg_root.glob("conpot.json.*"))
                self.assertGreater(
                    len(generations), 0,
                    "expected at least one rotated generation once max_bytes "
                    "was exceeded, found none -- rotation did not fire",
                )
                self.assertTrue(
                    (pkg_root / "conpot.json").exists(),
                    "expected the live path to be reopened after rotation",
                )
            finally:
                sys.path.remove(str(pkg_root))


if __name__ == "__main__":
    unittest.main()
