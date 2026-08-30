#!/usr/bin/env python3
"""Regression test for #2707.

disk-space-check.sh (arcane/home/honeypot-utilities/analysis/) alerted once
per *bind-mounted path*, never once per physical filesystem. On the home
server, honeypot-logs (/logs) and honeypot-state (/state) are both
bind-mounts of the same host directory tree (/opt/stacks/apiary), so a
single low-free-space condition on that one filesystem fired 2-3
near-identical WARNING lines -- same percent_free, same avail/total -- with
nothing telling the operator which of the bind mounts actually held the
bytes. That's noise a spike can hide in: the monitor's signal didn't
distinguish "three mounts, one real filesystem" from "three independent
filesystems all in trouble at once".

The fix (check_path/report_hits in disk-space-check.sh) records each
checked path's df hit instead of alerting immediately, then groups hits by
df's "source" column (the backing device -- read from `df -Pk`'s first
field rather than GNU-only `df --output=source`, staying consistent with
the file's existing busybox/Alpine portability constraint) before writing
to the alert log. Paths sharing a device collapse into a single alert
naming all of their labels plus a "top_contributor" (largest by `du`) so
the next real spike points straight at a directory instead of an
unexplained duplicate percentage.

This test runs the real script against two directories carved out of the
same tmp filesystem (so df reports one shared source for both, exactly
like /logs and /state on the home server) and asserts exactly one alert
line comes out, naming both labels and picking the larger directory as the
top contributor.
"""
import json
import os
import pathlib
import subprocess
import sys
import time

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "arcane/home/honeypot-utilities/analysis/disk-space-check.sh"

SH_BIN = "/bin/sh"


def _script_text():
    return SCRIPT.read_text(encoding="utf-8")


def test_script_exists():
    assert SCRIPT.exists(), f"{SCRIPT} not found"


def test_script_groups_hits_before_alerting():
    text = _script_text()
    assert "report_hits" in text, (
        "check_path hits must be grouped by filesystem in a separate pass "
        "(report_hits) instead of alerting immediately per path"
    )


def test_script_names_a_top_contributor():
    text = _script_text()
    assert "top_contributor" in text, (
        "the grouped alert must name the largest checked path in the group "
        "so an operator isn't left comparing N identical percentages by hand"
    )
    assert "du -sk" in text, "top contributor must be sized with du, not guessed"


@pytest.mark.skipif(not pathlib.Path(SH_BIN).exists(), reason="no /bin/sh available")
def test_two_bindmounts_of_the_same_filesystem_collapse_to_one_alert(tmp_path):
    logs_dir = tmp_path / "logs"
    state_dir = tmp_path / "state"
    logs_dir.mkdir()
    state_dir.mkdir()

    # state_dir gets far more bytes than logs_dir -- top_contributor must
    # name "honeypot-state", not just whichever label happened to be
    # checked first.
    (logs_dir / "small.log").write_bytes(b"x" * 1024)
    (state_dir / "big.bin").write_bytes(b"y" * (1024 * 1024))

    out_file = tmp_path / "disk-space.json"

    env = dict(os.environ)
    env.update(
        {
            "DISK_CHECK_PATHS": f"honeypot-logs={logs_dir}:honeypot-state={state_dir}",
            # Real free-space percentage on the test runner's filesystem is
            # unknown and irrelevant here -- force every check to be "low"
            # so the grouping/top-contributor logic always fires.
            "DISK_WARN_PERCENT_FREE": "100",
            "DISK_SPACE_LOG": str(out_file),
            "ELASTICSEARCH_URL": "http://127.0.0.1:1",
            "START_DELAY": "0",
            "CHECK_INTERVAL": "3600",
        }
    )

    proc = subprocess.Popen(
        [SH_BIN, str(SCRIPT)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            if out_file.exists() and out_file.read_text(encoding="utf-8").strip():
                break
            time.sleep(0.2)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

    assert out_file.exists(), "disk-space-check.sh produced no alert log at all"
    lines = [ln for ln in out_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1, (
        "two bind-mounts of the same filesystem must collapse into exactly "
        f"one alert line, got {len(lines)}: {lines}"
    )

    record = json.loads(lines[0])
    disk = record["disk"]
    assert "honeypot-logs" in disk["labels"]
    assert "honeypot-state" in disk["labels"]
    assert disk["top_contributor"]["label"] == "honeypot-state", (
        "top_contributor must name the larger of the grouped paths, got "
        f"{disk['top_contributor']!r}"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
