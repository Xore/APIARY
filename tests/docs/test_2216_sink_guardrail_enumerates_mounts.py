#!/usr/bin/env python3
"""Regression test for #2216 acceptance criterion 4: the retention-parity
guardrail must "fail when a new stack adds an uncovered one."

The first cut of scripts/check-json-sink-retention-parity.py could not. It
compared its hand-written ROWS ledger against log-maintenance.sh and nothing
else, so it only ever caught drift in the halves an author had already
remembered to touch. A brand-new stack that bind-mounts a log directory,
appends a .json sink into it forever, adds no pruner line and no ledger row
-- precisely the drift the guard exists to stop -- passed green, and so did
moving a -name glob onto a neighbouring directory's find line, which leaves
a directory unpruned while every glob string still appears somewhere in the
file.

Both cases are pinned here, run against a throwaway repo root assembled from
symlinks so the real tree is never mutated:

1. the real tree passes (a guard that fails on everything guards nothing);
2. a synthetic unrotated/unpruned/unledgered stack fails, naming the mount;
3. a glob attached to the wrong directory's find line fails, naming the
   directory left with no pruner.
"""
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-json-sink-retention-parity.py"
STACKS = REPO_ROOT / "arcane" / "home"
MAINTENANCE = STACKS / "honeypot-utilities" / "analysis" / "log-maintenance.sh"

# The shape every one of the nine #2216 writers had before the fix: one
# O_APPEND handle opened at startup, held for the process lifetime.
UNROTATED_WRITER = """package main

import "os"

func main() {
\tf, _ := os.OpenFile("/var/log/honeypot/newsink.json",
\t\tos.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
\t_, _ = f.Write([]byte("{}\\n"))
}
"""

NEW_STACK_COMPOSE = """services:
  newsink:
    build: ./newsink
    volumes:
      - /opt/stacks/apiary/logs/newsink:/var/log/honeypot
"""


def build_root(tmp_path: pathlib.Path, *, maintenance_text: str | None = None,
               extra_stack: dict[str, str] | None = None) -> pathlib.Path:
    """A throwaway repo root the checker can resolve itself against.

    Every real stack is symlinked in rather than copied, so the enumeration
    sees the true fleet at native speed; only the pieces a case needs to
    change are materialised as real files.
    """
    root = tmp_path / "repo"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, root / "scripts" / SCRIPT.name)

    home = root / "arcane" / "home"
    home.mkdir(parents=True)
    for stack in sorted(STACKS.iterdir()):
        if not stack.is_dir():
            continue
        if stack.name == "honeypot-utilities" and maintenance_text is not None:
            local = home / stack.name
            (local / "analysis").mkdir(parents=True)
            (local / "analysis" / "log-maintenance.sh").write_text(maintenance_text)
            shutil.copy(stack / "compose.yml", local / "compose.yml")
        else:
            (home / stack.name).symlink_to(stack)

    for relative, text in (extra_stack or {}).items():
        target = home / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)

    return root


def run(root: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(root / "scripts" / SCRIPT.name)],
        capture_output=True, text=True, check=False,
    )


def test_the_real_tree_passes(tmp_path):
    result = run(build_root(tmp_path))
    assert result.returncode == 0, result.stderr
    assert "all accounted for" in result.stdout


def test_a_new_stack_with_an_uncovered_sink_fails(tmp_path):
    # The reviewer's constructed case, verbatim: compose bind mount, a
    # writer that never rotates, no pruner line, no ledger row.
    root = build_root(tmp_path, extra_stack={
        "honeypot-newsink/compose.yml": NEW_STACK_COMPOSE,
        "honeypot-newsink/newsink/main.go": UNROTATED_WRITER,
    })
    result = run(root)

    assert result.returncode == 1, result.stdout
    assert "unledgered log mount" in result.stderr
    assert "/logs/newsink" in result.stderr


def test_a_glob_on_the_wrong_directorys_find_line_fails(tmp_path):
    # tftp-relay's glob moved onto /logs/dicompot's line. The string is
    # still present in the file -- a whole-file substring test stays green
    # -- but /logs/tftp-relay now has no pruner at all.
    original = MAINTENANCE.read_text()
    starved = "  find /logs/tftp-relay -maxdepth 1 -name 'sessions.json.[0-9]*'"
    assert starved in original, "the tftp-relay prune line moved; update this test"
    moved = original.replace(
        starved,
        "  find /logs/tftp-relay -maxdepth 1 -name 'unrelated.json.[0-9]*'",
    ).replace(
        "find /logs/dicompot -maxdepth 1 -name 'dicompot.json.[0-9]*'",
        "find /logs/dicompot -maxdepth 1 -name 'dicompot.json.[0-9]*' "
        "-o -name 'sessions.json.[0-9]*'",
    )
    assert "'sessions.json.[0-9]*'" in moved, "the glob must still be in the file"

    result = run(build_root(tmp_path, maintenance_text=moved))

    assert result.returncode == 1, result.stdout
    assert "pruner half missing" in result.stderr
    assert "/logs/tftp-relay" in result.stderr


def test_a_retired_stack_takes_its_ledger_entry_with_it(tmp_path):
    # wordpot (#2469) is why: a ledger nobody prunes keeps describing a
    # fleet that no longer exists. Dropping a mounted stack must fail until
    # its entry goes too.
    root = build_root(tmp_path)
    retired = root / "arcane" / "home" / "honeypot-endlessh"
    retired.unlink()

    result = run(root)

    assert result.returncode == 1, result.stdout
    assert "stale ledger entry" in result.stderr
    assert "/logs/endlessh" in result.stderr


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
