#!/usr/bin/env python3
"""Exercise full_capabilities.py (#800) against the real pipeline source
tree -- not fixtures, since the whole point of this script is that its
inventory stays accurate as the real files change.

#2064 adds two enforce-what-you-claim layers here:

* a census-parity check -- an independently-written scan of the same six
  SOURCE_FILES must find exactly the names the module's own extraction
  finds, so the docstring's accuracy claim is enforced rather than
  aspirational (the original narrow assignment shape hid 8 of 59 real
  reads); and
* apply() write-safety checks -- the env file must land atomically
  (systemd reads it as EnvironmentFile=) with stale duplicates collapsed,
  since last-one-wins semantics used to let a leftover line outrank a
  fresh rewrite indefinitely.

Usage: analysis/ghidra/tests/test_full_capabilities.py
"""
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "full_capabilities.py"
sys.path.insert(0, str(SCRIPT.parent))
import full_capabilities as fc  # noqa: E402

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


# --- #2391: defaults resets every inventoried override, not just gates ----

def _any_non_gate_tunable():
    """A real inventoried non-gate name (GHIDRA_TRIAGE_TIMEOUT & friends):
    whatever it is today, it must not survive 'back to source defaults'."""
    return next(name for name, meta in sorted(fc.inventory().items()) if not meta["gate"])


def test_preset_defaults_removes_every_inventoried_override():
    with tempfile.TemporaryDirectory() as tmp:
        env_file = Path(tmp) / "env"
        tunable = _any_non_gate_tunable()
        env_file.write_text(
            f"# operator experiment\n{tunable}=60\n"
            "REVDECK_API_BASE=http://127.0.0.1:19500\nOPERATORS_PRIVATE_NOTE=keepme\n"
        )

        result = run("--env-file", str(env_file), "--preset", "defaults")
        contents = env_file.read_text().splitlines()
        check(result.returncode == 0, "defaults exits 0")
        check(f"{tunable}=60" not in contents,
              f"non-gate tunable {tunable} is removed, not stranded (#2391)")
        check("REVDECK_API_BASE=http://127.0.0.1:19500" not in contents,
              "a gate override is still removed")
        check("OPERATORS_PRIVATE_NOTE=keepme" in contents,
              "names no pipeline source reads are left alone")
        check("# operator experiment" in contents, "comment lines survive the reset")
        check(tunable in result.stdout and "REVDECK_API_BASE" in result.stdout,
              "the removal report names what was actually removed")


def test_preset_all_on_then_defaults_is_a_clean_reset():
    with tempfile.TemporaryDirectory() as tmp:
        env_file = Path(tmp) / "env"
        run("--env-file", str(env_file), "--preset", "all-on")
        run("--env-file", str(env_file), "--preset", "defaults")
        contents = env_file.read_text()
        for key in ("STATICTOOLS_API_BASE", "GHIDRA_TRIAGE_API_BASE", "REVDECK_API_BASE"):
            check(key not in contents, f"defaults cancels all-on's {key} cleanly")
        check(not Path(tmp).joinpath(".env.tmp").exists(), "no temp residue after defaults")


def test_preset_defaults_with_nothing_to_remove_reports_honestly():
    with tempfile.TemporaryDirectory() as tmp:
        env_file = Path(tmp) / "env"
        # No line belongs to an inventoried name: only a hand-written key no
        # pipeline source reads plus comments/blank lines.
        env_file.write_text("# notes\nOPERATORS_PRIVATE_NOTE=keepme\n\n")
        result = run("--env-file", str(env_file), "--preset", "defaults")
        check(result.returncode == 0, "defaults on an override-free file exits 0")
        check(env_file.read_text() == "# notes\nOPERATORS_PRIVATE_NOTE=keepme\n\n",
              "nothing was removed when no inventoried override existed")
        check("no pipeline-managed overrides" in result.stdout,
              "the report says honestly when nothing was pipeline-managed")


def test_reset_path_is_atomic_under_write_failure():
    # The reset writes through the same #2064 tmp+os.replace machinery as
    # apply(); a crash mid-write must leave the operator's file untouched.
    with tempfile.TemporaryDirectory() as tmp:
        env_file = Path(tmp) / "env"
        env_file.write_text("REVDECK_API_BASE=http://old\nOTHER=kept\n")
        original = env_file.read_text()

        real_replace = os.replace
        def exploding_replace(src, dst):
            raise OSError(28, "simulated ENOSPC")
        os.replace = exploding_replace
        try:
            fc.reset(env_file, {"REVDECK_API_BASE": {}, "GHOST": {}})
        except OSError:
            pass
        else:
            fails.append("reset() did not propagate the simulated rename failure")
        finally:
            os.replace = real_replace

        check(env_file.read_text() == original, "original env file untouched after failed reset write")
        check(not (Path(tmp) / ".env.tmp").exists(), "no temp residue after failed reset write")


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


# --- #2064: inventory coverage -------------------------------------------

HISTORICAL_MISSES = [
    # The 8 census misses behind #2064 -- one per miss class, kept explicit
    # so deleting any of them from the sources fails loudly rather than
    # quietly shrinking the gate's reach back toward its old blind spot.
    ("GHIDRA_REQUEST_DIR", "analysis/ghidra/worker/ghidra-worker.py"),
    ("GHIDRA_RESULTS_DIR", "analysis/ghidra/worker/ghidra-worker.py"),
    ("GHIDRA_SAMPLES_DIR", "analysis/ghidra/worker/ghidra-worker.py"),
    ("GHIDRA_COWRIE_DOWNLOADS_DIR", "analysis/ghidra/worker/ghidra-worker.py"),
    ("GHIDRA_LOCK", "analysis/ghidra/worker/ghidra-worker.py"),
    ("GHIDRA_DATA_DIR", "analysis/ghidra/service/server.py"),
    ("GHIDRA_QUERY_TIMEOUT_SECONDS", "analysis/ghidra/service/server.py"),
    ("HOME", "analysis/ghidra/service/export_json.py"),
]

CENSUS_RE = re.compile(r'''os\.(?:environ\.get|getenv)\(\s*["']([A-Z][A-Z0-9_]*)["']''')


def census_names():
    """Independent scan of the same six SOURCE_FILES: strips '#' comment
    lines so documented examples can't inflate either side, then collects
    every literal read opening it finds. Written against the module rather
    than through it on purpose -- if extraction ever regresses to missing a
    shape again, this function is what still sees it."""
    names = set()
    for path in fc.SOURCE_FILES:
        body = "\n".join(
            line for line in path.read_text().splitlines()
            if not line.strip().startswith("#")
        )
        names |= set(CENSUS_RE.findall(body))
    return names


def test_inventory_matches_independent_census():
    inv = fc.inventory()
    names = census_names()
    check(not names - set(inv),
          f"census finds {sorted(names - set(inv))} that inventory misses")
    check(not set(inv) - names,
          f"inventory inventories {sorted(set(inv) - names)} that no source actually reads")


def test_historical_misses_attributed_to_their_own_file():
    inv = fc.inventory()
    for name, source in HISTORICAL_MISSES:
        check(name in inv, f"{name} discovered at all (#2064)")
        meta = inv.get(name)
        if meta:
            check(meta["source"] == source,
                  f"{name} attributed to {source}, got {meta['source']} "
                  "(first-seen file must be where the read really lives)")


def test_show_lists_the_eight():
    result = run("--env-file", "/nonexistent-on-purpose")
    for name, _source in HISTORICAL_MISSES:
        check(name in result.stdout, f"show() output lists {name}")


def test_extraction_shapes_on_synthetic_file(tmpdir=None):
    """Hermetic unit for every miss class from #2064, independent of whether
    the real sources keep carrying examples of each."""
    with tempfile.TemporaryDirectory() as tmp:
        probe = Path(tmp) / "probe.py"
        probe.write_text('''
# wrapped-path one-liner
REQUEST = Path(os.environ.get("PROBE_REQUEST", "/req"))
# multi-line site keeps attribution even though the name sits below the fold
RESULTS = Path(os.environ.get(
    "PROBE_RESULTS", "/res"))
_TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "2"))
out = args[0] if args else os.path.join(os.environ.get("PROBE_HOME", "/tmp"), "x")
FOO=os.getenv("PROBE_BARE")
''')
        found = {}
        for name, default, description, _src in fc.extract(probe):
            found.setdefault(name, (default, description))
        check(set(found) == {"PROBE_REQUEST", "PROBE_RESULTS",
                             "PROBE_TIMEOUT", "PROBE_HOME", "PROBE_BARE"},
              f"all five synthetic shapes extracted, got {sorted(found)}")
        check(found.get("PROBE_REQUEST", ("", ""))[1] == "wrapped-path one-liner",
              f"Path()-wrapped shape keeps its comment, got {found.get('PROBE_REQUEST')}")
        check(found.get("PROBE_RESULTS", ("", ""))[1].endswith("below the fold"),
              f"multi-line site attributes preceding comment, got {found.get('PROBE_RESULTS')}")


def test_apply_collapses_stale_duplicates():
    # EnvironmentFile= semantics: the LAST occurrence of a key wins. Before
    # #2064 apply() rewrote only the first line, so a stale duplicate below
    # it kept outranking every rewrite forever.
    with tempfile.TemporaryDirectory() as tmp:
        env_file = Path(tmp) / "env"
        env_file.write_text(
            "GHIDRA_API_BASE=http://old:1\nOTHER=kept\nGHIDRA_API_BASE=http://stale:9\n")

        run("--env-file", str(env_file), "--set", "GHIDRA_API_BASE=http://new:2")
        lines = env_file.read_text().splitlines()
        check(lines.count("GHIDRA_API_BASE=http://new:2") == 1,
              f"exactly one assignment survives, got {lines}")
        check(lines == ["GHIDRA_API_BASE=http://new:2", "OTHER=kept"],
              f"duplicate is dropped, unrelated lines keep order: {lines}")


def test_apply_preserves_file_mode_on_rewrite():
    with tempfile.TemporaryDirectory() as tmp:
        env_file = Path(tmp) / "env"
        env_file.write_text("REVDECK_API_BASE=http://old\n")
        os.chmod(env_file, 0o600)

        run("--env-file", str(env_file), "--set", "REVDECK_API_BASE=http://new")
        check(stat.S_IMODE(env_file.stat().st_mode) == 0o600,
              "atomic rewrite keeps 0600 -- a widened mode would leak overrides")


def test_apply_is_atomic_under_write_failure():
    # Simulate the crash window the plain write_text version had: if the
    # process dies mid-write (or rename fails), the operator's env file must
    # be byte-identical to before and no .env.tmp residue may remain.
    with tempfile.TemporaryDirectory() as tmp:
        env_file = Path(tmp) / "env"
        env_file.write_text("REVDECK_API_BASE=http://old\n")
        original = env_file.read_text()

        real_replace = os.replace
        def exploding_replace(src, dst):
            raise OSError(28, "simulated ENOSPC")
        os.replace = exploding_replace
        try:
            fc.apply(env_file, {"REVDECK_API_BASE": "http://new"})
        except OSError:
            pass
        else:
            fails.append("apply() did not propagate the simulated rename failure")
        finally:
            os.replace = real_replace

        check(env_file.read_text() == original, "original env file untouched after failed write")
        check(not (Path(tmp) / ".env.tmp").exists(), "no temp residue after failed write")


if __name__ == "__main__":
    test_show_finds_known_gates()
    test_preset_all_on_then_minimal()
    test_preset_defaults_removes_every_inventoried_override()
    test_preset_all_on_then_defaults_is_a_clean_reset()
    test_preset_defaults_with_nothing_to_remove_reports_honestly()
    test_reset_path_is_atomic_under_write_failure()
    test_set_overrides_existing_line_in_place()
    test_inventory_matches_independent_census()
    test_historical_misses_attributed_to_their_own_file()
    test_show_lists_the_eight()
    test_extraction_shapes_on_synthetic_file()
    test_apply_collapses_stale_duplicates()
    test_apply_preserves_file_mode_on_rewrite()
    test_apply_is_atomic_under_write_failure()
    if fails:
        print(f"\n{len(fails)} check(s) failed: {fails}")
        sys.exit(1)
    print("\nall checks passed")
