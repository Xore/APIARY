#!/usr/bin/env python3
"""Regression test for #2301: reports-scheduler and user-retention-sweep
are implemented in worker.rs::spawn_enabled, and the issue claimed neither
was wired into any service's WORKER_LOOPS anywhere.

That claim was true only for arcane/home/honeypot-dashboard/compose.yml.
The #1622 split (2026-08-19, a week before #2301 was filed on 2026-08-26)
moved backend-service into its own honeypot-dashboard-backend stack and
carried WORKER_LOOPS=user-retention-sweep,reports-scheduler with it — both
loops, and the quarantine/isolation hardening built for them
(isolate::cycle / isolate::item, SCHEDULE_QUARANTINE_FAILURES), are already
live on that single-instance tier. #2301's audit never looked at the
sibling file.

Because main.rs calls worker::spawn_enabled() unconditionally for every
apiary-backend process, WORKER_LOOPS is the only gate — so the fix this
test locks in is narrower than the issue's own suggested fix ("append both
loop names to backend-worker's WORKER_LOOPS too"): reports-scheduler is a
non-atomic read-due-definitions -> render -> mark_scheduled_run sequence,
and user-retention-sweep is a read-modify-write of a single ES doc, so a
*second* concurrent consumer would race the first exactly the way #2110
already had to fix once for payload-inventory (see
honeypot-dashboard/compose.yml's own history comment on that incident).
Each loop must stay wired in exactly one place — not zero, and not two or
more.
"""
import pathlib
import re
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
HOME_DIR = REPO_ROOT / "arcane" / "home"
BACKEND_SRC = HOME_DIR / "honeypot-dashboard" / "backend-service" / "src"
WORKER_RS = BACKEND_SRC / "worker.rs"
ISOLATE_RS = BACKEND_SRC / "isolate.rs"
MAIN_RS = BACKEND_SRC / "main.rs"

LOOP_NAMES = ("reports-scheduler", "user-retention-sweep")

WORKER_LOOPS_ENV_RE = re.compile(r"WORKER_LOOPS=([^\s\"'${}]+)")


def _compose_files():
    files = sorted(HOME_DIR.glob("*/compose.yml"))
    assert files, f"no compose.yml files found under {HOME_DIR}"
    return files


def _worker_loops_entries():
    """(path, [loop names]) for every real WORKER_LOOPS= environment line
    across every arcane/home/*/compose.yml stack. Comment lines are
    skipped so a prose mention of WORKER_LOOPS=<loop> in an explanatory
    comment can't be mistaken for a real consumer."""
    entries = []
    for path in _compose_files():
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            match = WORKER_LOOPS_ENV_RE.search(stripped)
            if not match:
                continue
            loops = [name.strip() for name in match.group(1).split(",") if name.strip()]
            if loops:
                entries.append((path, loops))
    return entries


def _consumers_of(loop_name, entries):
    return [path for path, loops in entries if loop_name in loops]


def _window_after(text, needle, source, size=900):
    index = text.find(needle)
    assert index != -1, f"{needle!r} not found in {source}"
    return text[index : index + size]


def test_compose_files_discovered():
    assert len(_compose_files()) >= 5


def test_worker_rs_exists():
    assert WORKER_RS.exists(), f"worker.rs not found at {WORKER_RS}"


@pytest.mark.parametrize("loop_name", LOOP_NAMES)
def test_loop_implemented_in_spawn_enabled(loop_name):
    text = WORKER_RS.read_text(encoding="utf-8")
    assert f'"{loop_name}" => {{' in text, (
        f"spawn_enabled no longer has a match arm for {loop_name!r} -- has "
        "the loop been renamed or removed?"
    )


@pytest.mark.parametrize("loop_name", LOOP_NAMES)
def test_loop_enabled_in_at_least_one_worker_loops_env(loop_name):
    entries = _worker_loops_entries()
    consumers = _consumers_of(loop_name, entries)
    assert consumers, (
        f"{loop_name!r} is implemented in worker.rs::spawn_enabled but does "
        f"not appear in any WORKER_LOOPS= environment entry under "
        f"{HOME_DIR}/*/compose.yml -- the loop (and its quarantine/isolation "
        "hardening) never runs (#2301)"
    )


@pytest.mark.parametrize("loop_name", LOOP_NAMES)
def test_loop_not_double_wired(loop_name):
    entries = _worker_loops_entries()
    consumers = _consumers_of(loop_name, entries)
    assert len(consumers) <= 1, (
        f"{loop_name!r} is wired into WORKER_LOOPS in more than one stack "
        f"({[str(p.relative_to(REPO_ROOT)) for p in consumers]}) -- two "
        "concurrent consumers would race the same non-atomic ES "
        "read-modify-write (the #2110 payload-inventory failure mode)"
    )


MATCH_ARM_TARGETS = {
    "user-retention-sweep": "retention_sweep_loop",
    "reports-scheduler": "reports_scheduler_loop",
}


@pytest.mark.parametrize("loop_name,fn_name", MATCH_ARM_TARGETS.items())
def test_match_arm_dispatches_to_loop_fn(loop_name, fn_name):
    text = WORKER_RS.read_text(encoding="utf-8")
    window = _window_after(text, f'"{loop_name}" => {{', "worker.rs")
    assert fn_name in window, (
        f"the {loop_name!r} match arm in spawn_enabled no longer spawns "
        f"{fn_name}"
    )


CYCLE_CALLS = {
    "retention_sweep_loop": (
        "user-retention-sweep",
        "async fn retention_sweep_loop(state: AppState) {",
    ),
    "reports_scheduler_loop": (
        "reports-scheduler",
        "async fn reports_scheduler_loop(state: AppState) {",
    ),
}


@pytest.mark.parametrize("fn_name,pair", CYCLE_CALLS.items())
def test_loop_fn_wraps_tick_in_isolate_cycle(fn_name, pair):
    loop_name, signature = pair
    text = WORKER_RS.read_text(encoding="utf-8")
    window = _window_after(text, signature, "worker.rs")
    assert f'crate::isolate::cycle("{loop_name}"' in window, (
        f"{fn_name} no longer wraps its tick in crate::isolate::cycle -- a "
        "panic inside one tick would take the whole loop down instead of "
        "being isolated (#2181)"
    )


def test_reports_scheduler_tick_isolates_each_definition():
    text = WORKER_RS.read_text(encoding="utf-8")
    window = _window_after(
        text, "async fn reports_scheduler_tick(state: &AppState) {", "worker.rs"
    )
    assert "crate::isolate::item(" in window, (
        "reports_scheduler_tick no longer isolates each definition's render "
        "individually -- one poisoned definition could block every sibling "
        "definition due the same tick (#2181)"
    )


def test_isolate_module_implements_cycle_and_item():
    assert ISOLATE_RS.exists(), f"isolate.rs not found at {ISOLATE_RS}"
    text = ISOLATE_RS.read_text(encoding="utf-8")
    assert re.search(r"async\s+fn\s+cycle", text), "isolate::cycle is missing"
    assert re.search(r"async\s+fn\s+item", text), "isolate::item is missing"


def test_main_calls_spawn_enabled_unconditionally():
    """WORKER_LOOPS is meant to be the only gate for any given process:
    main() must call spawn_enabled without a role/mode check that could
    exempt a particular binary invocation (e.g. the request-serving one)
    from ever reading it -- otherwise wiring a loop into a service's
    WORKER_LOOPS would not be sufficient to actually run it."""
    assert MAIN_RS.exists(), f"main.rs not found at {MAIN_RS}"
    text = MAIN_RS.read_text(encoding="utf-8")
    assert "worker::spawn_enabled(state.clone())" in text


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
