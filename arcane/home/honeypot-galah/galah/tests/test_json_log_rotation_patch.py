#!/usr/bin/env python3
"""Test galah/json_log_rotation_patch.py (#2892) against representative fixtures.

Same approach as
conpot/tests/test_json_log_rotation_patch.py (#2892) and
dionaea's own test_log_rotation_patch.py (#1389): build a fixture file from
the patch module's own OLD_IMPORTS/OLD_NEW_FUNC constants -- the exact text
apply_patch() expects to find -- so there is no separate copy of that text
to drift out of sync with the patch itself.

Because galah is Go rather than Python, this also does something those two
don't need to: extract the patch's added rotatingWriter type into a
standalone Go program and actually `go build`/run it, confirming the
patched writer really closes/renames/reopens once GALAH_JSON_LOG_MAX_BYTES
is exceeded -- not just that the patched source is syntactically
plausible. Skipped (not failed) if no `go` toolchain is on PATH, so this
still runs somewhere without silently asserting nothing.

Usage: galah/tests/test_json_log_rotation_patch.py
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
    path.write_text(MODULE.OLD_IMPORTS + "\n\n" + MODULE.OLD_NEW_FUNC + "\n")


class ApplyPatchTest(unittest.TestCase):
    def test_patches_a_fresh_fixture(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "logger.go"
            make_fixture(target)
            msg = MODULE.apply_patch(target)
            self.assertIn("added self-rotation", msg)
            patched = target.read_text()
            self.assertIn(MODULE.MARKER, patched)
            self.assertIn("rotatingWriter", patched)
            self.assertIn("GALAH_JSON_LOG_MAX_BYTES", patched)

    def test_second_run_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "logger.go"
            make_fixture(target)
            MODULE.apply_patch(target)
            once = target.read_text()
            msg = MODULE.apply_patch(target)
            self.assertIn("already patched", msg)
            self.assertEqual(target.read_text(), once)

    def test_patched_writer_self_rotates(self):
        """Behavioural half: extract the added rotatingWriter type into a
        standalone Go program and run it for real, same intent as
        conpot's test_patched_logger_self_rotates but via `go run` since
        this patch's target language is Go, not Python."""
        go = shutil.which("go")
        if not go:
            self.skipTest("no go toolchain on PATH")

        # Everything the patch adds ahead of the (unchanged-signature) New()
        # function -- the rotatingWriter type plus its constructor/methods.
        marker_line = "// --- {} ---\n".format(MODULE.MARKER)
        added = MODULE.NEW_NEW_FUNC.split("// New creates a new Logger instance")[0]
        self.assertIn("rotatingWriter", added)
        self.assertNotIn("func New(", added)

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
                "// stand-in for internal/logger.Logger -- only the field\n"
                "// rotatingWriter touches is needed here.\n"
                "type Logger struct {\n"
                "\tEventFile *os.File\n"
                "}\n\n"
                + added
                + "\n"
                "func main() {\n"
                "\tdir, err := os.MkdirTemp(\"\", \"rotwtest\")\n"
                "\tif err != nil { panic(err) }\n"
                "\tos.Setenv(\"GALAH_JSON_LOG_MAX_BYTES\", \"50\")\n"
                "\tpath := filepath.Join(dir, \"event_log.json\")\n"
                "\tf, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)\n"
                "\tif err != nil { panic(err) }\n"
                "\towner := &Logger{EventFile: f}\n"
                "\tw := newRotatingWriter(path, f, owner)\n"
                "\tfor i := 0; i < 10; i++ {\n"
                "\t\tif _, err := w.Write([]byte(fmt.Sprintf(\"line-%d-%s\\n\", i, time.Now()))); err != nil {\n"
                "\t\t\tpanic(err)\n"
                "\t\t}\n"
                "\t}\n"
                "\tmatches, _ := filepath.Glob(path + \".*\")\n"
                "\tif len(matches) == 0 {\n"
                "\t\tpanic(\"expected at least one rotated generation, found none\")\n"
                "\t}\n"
                "\tif _, err := os.Stat(path); err != nil {\n"
                "\t\tpanic(\"expected live path to exist after rotation: \" + err.Error())\n"
                "\t}\n"
                "\tif owner.EventFile != w.file {\n"
                "\t\tpanic(\"owner.EventFile was not kept in sync with the current generation\")\n"
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
