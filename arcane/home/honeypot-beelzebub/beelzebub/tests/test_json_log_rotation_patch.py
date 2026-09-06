#!/usr/bin/env python3
"""Test beelzebub/json_log_rotation_patch.py (#2892) against representative fixtures.

Same approach as galah/tests/test_json_log_rotation_patch.py (#2892), the
other Go target: build a fixture file from the patch module's own
OLD_IMPORTS/OLD_BUILD_LOGGER constants -- the exact text apply_patch()
expects to find -- so there is no separate copy of that text to drift out
of sync with the patch itself.

The behavioural half extracts the patch's added rotatingWriter type into a
standalone Go program and actually `go run`s it, confirming the patched
writer really closes/renames/reopens once BEELZEBUB_JSON_LOG_MAX_BYTES is
exceeded and keeps the owning Builder's logsFile pointed at the live
generation -- not just that the patched source is syntactically plausible.
Skipped (not failed) if no `go` toolchain is on PATH, so this still runs
somewhere without silently asserting nothing.

Usage: beelzebub/tests/test_json_log_rotation_patch.py
"""
import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "json_log_rotation_patch.py"
SPEC = importlib.util.spec_from_file_location("json_log_rotation_patch", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def make_fixture(path: Path):
    path.write_text(MODULE.OLD_IMPORTS + ")\n\n" + MODULE.OLD_BUILD_LOGGER + "\treturn nil\n}\n")


class ApplyPatchTest(unittest.TestCase):
    def test_patches_a_fresh_fixture(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "builder.go"
            make_fixture(target)
            msg = MODULE.apply_patch(target)
            self.assertIn("added self-rotation", msg)
            patched = target.read_text()
            self.assertIn(MODULE.MARKER, patched)
            self.assertIn("rotatingWriter", patched)
            self.assertIn("BEELZEBUB_JSON_LOG_MAX_BYTES", patched)

    def test_second_run_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "builder.go"
            make_fixture(target)
            MODULE.apply_patch(target)
            once = target.read_text()
            msg = MODULE.apply_patch(target)
            self.assertIn("already patched", msg)
            self.assertEqual(target.read_text(), once)

    def test_patched_writer_self_rotates(self):
        """Behavioural half: extract the added rotatingWriter type into a
        standalone Go program and run it for real, same as galah's
        test_patched_writer_self_rotates."""
        go = shutil.which("go")
        if not go:
            self.skipTest("no go toolchain on PATH")

        # Everything the patch adds ahead of the (unchanged-signature)
        # buildLogger() -- the rotatingWriter type plus constructor/methods.
        added = MODULE.NEW_BUILD_LOGGER.split("func (b *Builder) buildLogger(")[0]
        self.assertIn("rotatingWriter", added)
        self.assertNotIn("buildLogger", added)

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "go.mod").write_text("module rotatingwritertest\n\ngo 1.23\n")
            main_go = root / "main.go"
            main_go.write_text(
                "package main\n\n"
                "import (\n"
                '\t"fmt"\n'
                '\t"os"\n'
                '\t"path/filepath"\n'
                '\t"strconv"\n'
                '\t"time"\n'
                ")\n\n"
                "// stand-in for internal/builder.Builder -- only the field\n"
                "// rotatingWriter touches is needed here.\n"
                "type Builder struct {\n"
                "\tlogsFile *os.File\n"
                "}\n\n"
                + added
                + "\n"
                "func main() {\n"
                "\tdir, err := os.MkdirTemp(\"\", \"rotwtest\")\n"
                "\tif err != nil { panic(err) }\n"
                "\tos.Setenv(\"BEELZEBUB_JSON_LOG_MAX_BYTES\", \"50\")\n"
                "\tpath := filepath.Join(dir, \"beelzebub.json\")\n"
                "\tf, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)\n"
                "\tif err != nil { panic(err) }\n"
                "\towner := &Builder{logsFile: f}\n"
                "\tw := newRotatingWriter(path, f, owner)\n"
                "\tfor i := 0; i < 10; i++ {\n"
                "\t\tif _, err := w.Write([]byte(fmt.Sprintf(\"line-%d-%s\\n\", i, time.Now()))); err != nil {\n"
                "\t\t\tpanic(err)\n"
                "\t\t}\n"
                "\t}\n"
                "\tmatches, _ := filepath.Glob(path + \".[0-9]*\")\n"
                "\tif len(matches) == 0 {\n"
                "\t\tpanic(\"expected at least one rotated generation, found none\")\n"
                "\t}\n"
                "\tif _, err := os.Stat(path); err != nil {\n"
                "\t\tpanic(\"expected live path to exist after rotation: \" + err.Error())\n"
                "\t}\n"
                "\tif owner.logsFile != w.file {\n"
                "\t\tpanic(\"owner.logsFile was not kept in sync with the current generation\")\n"
                "\t}\n"
                "\t_ = strconv.Itoa(len(matches))\n"
                "\tfmt.Println(\"OK\", len(matches), \"rotated generation(s)\")\n"
                "}\n"
            )
            result = subprocess.run(
                [go, "run", "."],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(
                result.returncode, 0,
                "go run failed:\nstdout: {}\nstderr: {}".format(
                    result.stdout, result.stderr
                ),
            )
            self.assertIn("OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
