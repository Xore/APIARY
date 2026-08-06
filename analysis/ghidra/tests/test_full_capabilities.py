#!/usr/bin/env python3
"""Exercise full_capabilities.py (#800) against the real pipeline source
tree -- not fixtures, since the whole point of this script is that its
inventory stays accurate as the real files change.

Usage: analysis/ghidra/tests/test_full_capabilities.py
"""
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "full_capabilities.py"

fails = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        fails.append(label)


def run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *args],
                           capture_output=True, text=True, timeout=10)


def test_show_finds_known_gates():
    result = run("--env-file", "/nonexistent-on-purpose")
    check(result.returncode == 0, "show exits 0 against a real (missing) env file")
    check("REVDECK_API_BASE" in result.stdout, "discovers REVDECK_API_BASE from ghidra-worker.py")
    check("STATICTOOLS_API_BASE" in result.stdout, "discovers STATICTOOLS_API_BASE")
    check("CAPA_SIGS_DIR" in result.stdout, "discovers CAPA_SIGS_DIR from statictools/server.py")
    # REVDECK_API_BASE's own code default is "" -- the established
    # "empty disables it" convention this pipeline already follows.
    off_section = result.stdout.split("OFF (")[1] if "OFF (" in result.stdout else ""
    check("REVDECK_API_BASE" in off_section, "REVDECK_API_BASE is classified OFF with no env file present")


def test_preset_all_on_then_minimal():
    with tempfile.TemporaryDirectory() as tmp:
        env_file = Path(tmp) / "env"
        env_file.write_text("GHIDRA_API_BASE=http://127.0.0.1:9090\n")

        run("--env-file", str(env_file), "--preset", "all-on")
        contents = env_file.read_text()
        check("REVDECK_API_BASE=http://127.0.0.1:19500" in contents, "all-on sets REVDECK_API_BASE")
        check("STATICTOOLS_API_BASE=http://127.0.0.1:9091" in contents, "all-on sets STATICTOOLS_API_BASE")
        check("GHIDRA_API_BASE=http://127.0.0.1:9090" in contents, "all-on preserves an unrelated pre-existing line")

        run("--env-file", str(env_file), "--preset", "minimal")
        contents = env_file.read_text()
        check("REVDECK_API_BASE=\n" in contents, "minimal clears REVDECK_API_BASE back to empty")


def test_set_overrides_existing_line_in_place():
    with tempfile.TemporaryDirectory() as tmp:
        env_file = Path(tmp) / "env"
        env_file.write_text("# a comment\nREVDECK_API_BASE=http://old:1\nOTHER=kept\n")

        run("--env-file", str(env_file), "--set", "REVDECK_API_BASE=http://new:2")
        lines = env_file.read_text().splitlines()
        check(lines[0] == "# a comment", "comment lines are left untouched")
        check("REVDECK_API_BASE=http://new:2" in lines, "an existing assignment is replaced in place, not duplicated")
        check("OTHER=kept" in lines, "unrelated existing assignments survive")
        check(lines.count("REVDECK_API_BASE=http://new:2") == 1, "no duplicate line is appended")


if __name__ == "__main__":
    test_show_finds_known_gates()
    test_preset_all_on_then_minimal()
    test_set_overrides_existing_line_in_place()
    if fails:
        print(f"\n{len(fails)} check(s) failed: {fails}")
        sys.exit(1)
    print("\nall checks passed")
