#!/usr/bin/env python3
"""Test sentrypeer/json_log_rotation_patch.py (#2892) against representative fixtures.

Same approach as the other three json_log_rotation_patch.py tests
(beelzebub, conpot, galah): build a fixture file from the patch module's
own OLD_IMPORTS/OLD_FUNC constants -- the exact text apply_patch() expects
to find -- so there is no separate copy of that text to drift out of sync
with the patch itself.

The behavioural half extracts the patch's two added functions
(json_log_max_bytes/rotate_json_log_if_needed) into a standalone cargo
crate depending only on chrono (already a sentrypeer_rust dependency) and
actually `cargo run`s it, confirming the patched writer really
renames/reopens once SENTRYPEER_JSON_LOG_MAX_BYTES is exceeded -- not just
that the patched source is syntactically plausible. Skipped (not failed)
if no `cargo` toolchain is on PATH, or if `cargo`'s offline resolve can't
find a cached chrono crate, so this still runs somewhere without silently
asserting nothing.

Usage: sentrypeer/tests/test_json_log_rotation_patch.py
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
    path.write_text(MODULE.OLD_IMPORTS + "\n\n" + MODULE.OLD_FUNC + "\n")


class ApplyPatchTest(unittest.TestCase):
    def test_patches_a_fresh_fixture(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "json_logger.rs"
            make_fixture(target)
            msg = MODULE.apply_patch(target)
            self.assertIn("added self-rotation", msg)
            patched = target.read_text()
            self.assertIn(MODULE.MARKER, patched)
            self.assertIn("rotate_json_log_if_needed", patched)
            self.assertIn("SENTRYPEER_JSON_LOG_MAX_BYTES", patched)

    def test_second_run_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "json_logger.rs"
            make_fixture(target)
            MODULE.apply_patch(target)
            once = target.read_text()
            msg = MODULE.apply_patch(target)
            self.assertIn("already patched", msg)
            self.assertEqual(target.read_text(), once)

    def test_patched_writer_self_rotates(self):
        """Behavioural half: extract the added rotate_json_log_if_needed /
        json_log_max_bytes functions into a standalone cargo crate and run
        it for real, same intent as beelzebub/galah's `go run` tests but
        via `cargo run` since this patch's target is Rust, not Go."""
        cargo = shutil.which("cargo")
        if not cargo:
            self.skipTest("no cargo toolchain on PATH")

        # Everything the patch adds ahead of the (unchanged-signature)
        # json_log_bad_actor_rs() -- the two free functions, no FFI needed.
        added = MODULE.NEW_FUNC.split("#[unsafe(no_mangle)]")[0]
        self.assertIn("rotate_json_log_if_needed", added)
        self.assertNotIn("pub(crate) unsafe extern", added)

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text(
                "[package]\n"
                'name = "srotest"\n'
                'version = "0.1.0"\n'
                'edition = "2021"\n\n'
                "[dependencies]\n"
                'chrono = "0.4.45"\n'
            )
            (root / "src" / "added.rs").write_text(added)
            (root / "src" / "main.rs").write_text(
                "use chrono::Utc;\n"
                "use std::fs::{self, OpenOptions};\n"
                "use std::io::Write;\n"
                "use std::path::Path;\n\n"
                'include!("added.rs");\n\n'
                "fn main() {\n"
                "    let dir = std::env::temp_dir()\n"
                '        .join(format!("srotest-run-{}", std::process::id()));\n'
                "    fs::create_dir_all(&dir).unwrap();\n"
                '    let path = dir.join("sentrypeer.json");\n'
                "    let path_str = path.to_str().unwrap();\n"
                "    unsafe {\n"
                '        std::env::set_var("SENTRYPEER_JSON_LOG_MAX_BYTES", "50");\n'
                "    }\n\n"
                "    for i in 0..10 {\n"
                "        rotate_json_log_if_needed(path_str);\n"
                "        let mut f = OpenOptions::new()\n"
                "            .append(true)\n"
                "            .create(true)\n"
                "            .open(&path)\n"
                "            .unwrap();\n"
                '        writeln!(f, "line-{}-{}", i, Utc::now()).unwrap();\n'
                "    }\n\n"
                "    let mut generations = 0;\n"
                "    for entry in fs::read_dir(&dir).unwrap() {\n"
                "        let entry = entry.unwrap();\n"
                "        let name = entry.file_name().into_string().unwrap();\n"
                '        if name.starts_with("sentrypeer.json.") {\n'
                "            generations += 1;\n"
                "        }\n"
                "    }\n\n"
                "    if generations == 0 {\n"
                '        panic!("expected at least one rotated generation, found none");\n'
                "    }\n"
                "    if !path.exists() {\n"
                '        panic!("expected live path to exist after rotation");\n'
                "    }\n"
                '    println!("OK {} rotated generation(s)", generations);\n'
                "}\n"
            )
            result = subprocess.run(
                [cargo, "run", "--offline", "--quiet"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0 and "--offline" in result.stderr:
                self.skipTest(
                    "cargo has no cached chrono crate for --offline resolve:\n"
                    + result.stderr
                )
            self.assertEqual(
                result.returncode, 0,
                "cargo run failed:\nstdout: {}\nstderr: {}".format(
                    result.stdout, result.stderr
                ),
            )
            self.assertIn("OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
