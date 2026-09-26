"""The published sizing table must match what the compose files declare (#3328).

A hand-written sizing table is wrong the first time somebody edits a `cpus:`
line. Recompute it here instead, so CI fails on the commit that introduces the
drift rather than on an operator discovering it.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
README = ROOT / "docs" / "deploy-profiles" / "README.md"
SIZING = ROOT / "scripts" / "deploy-profile-sizing.py"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))


def test_sizing_script_runs():
    out = subprocess.run(
        [sys.executable, str(SIZING)], capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert "full:" in out.stdout


def test_readme_table_matches_compose_files():
    """Every row the README publishes must equal the recomputed value."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("sizing", SIZING)
    sizing = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sizing)

    readme = README.read_text(encoding="utf-8")
    rows = re.findall(
        r"^\| `([a-z-]+)` \| (\d+) \| ([\d.]+) \| ([\d.]+) GiB \|$",
        readme, re.MULTILINE)
    assert rows, "no sizing table rows found in the README -- the table moved or lost its format"

    for profile, stacks, cpus, gib in rows:
        text = (sizing.PROFILES / f"{profile}.txt").read_text(encoding="utf-8")
        entries = sizing.profile_entries(sizing.PROFILES / f"{profile}.txt")
        total_cpus = total_mem = 0
        for entry in entries:
            compose = sizing.stack_for(entry)
            if compose is None:
                continue
            c, m = sizing.declared_limits(
                compose.read_text(encoding="utf-8", errors="replace"))
            total_cpus += c
            total_mem += m
        assert int(stacks) == len(entries), (
            f"{profile}: README says {stacks} stacks, profile lists {len(entries)}")
        assert float(cpus) == round(total_cpus, 1), (
            f"{profile}: README says {cpus} cpus, compose files declare "
            f"{total_cpus:g}")
        assert abs(float(gib) - total_mem / 1024**3) < 0.05, (
            f"{profile}: README says {gib} GiB, compose files declare "
            f"{total_mem / 1024**3:.1f} GiB")
        del text


def test_es_heap_is_not_counted_as_a_mem_limit():
    """The 6g ES heap is a JVM setting, not a mem_limit; the doc says so."""
    readme = README.read_text(encoding="utf-8")
    assert "ES_JAVA_OPTS=-Xms6g -Xmx6g" in readme
    compose = ROOT / "arcane" / "home" / "honeypot-elk" / "compose.yml"
    assert "-Xmx6g" in compose.read_text(encoding="utf-8")
