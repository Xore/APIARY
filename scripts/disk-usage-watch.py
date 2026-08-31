#!/usr/bin/env python3
"""Alarm when the runner host's `/var` filesystem crosses a dangerous
usage threshold (#2743).

2026-08-31: `/var` (device /dev/sdd1, 1.8T -- backs /var/lib/docker, so
every CI container, image build and Arcane stack on the homeserver) reached
96% full. Two Elasticsearch-backed CI legs failed with
`unavailable_shards_exception: primary shard is not active` -- the same
test passed on the same host at the same commit once `docker builder
prune -af` reclaimed 179GB of buildkit cache (0 active entries) and took
/var to 89%. Nothing reported the 96% figure; it was invisible until it
broke a test that looked like flake. This is a dedicated check rather than
folding into ci-queue-watch.py: that script already gained a runner-
capacity report in this same batch of fixes (#2744), and a second,
unrelated concern piling onto the same function across two independent
worktrees/PRs risked a needless merge collision.

Design mirrors ci-queue-watch.py's proven shape (#2499):
- A single open `disk-usage-alarm`-labeled issue at a time: a sweep that
  finds continued high usage appends to it; a sweep that finds usage back
  under threshold closes it with the recovery evidence.
- The threshold (DISK_USAGE_WARN_PERCENT, default 90) sits below the 96%
  this issue was filed over and above the 89% a full buildkit prune
  reached -- a sweep that fires has real headroom concern, not routine
  noise from ordinary build/pull churn.
- Runs `df` directly on the box being measured (this script is meant to
  run as a step on the self-hosted homeserver-backed runner itself, not
  over SSH from elsewhere) -- no separate credential or network path to
  the thing it's measuring.

Usage:
  scripts/disk-usage-watch.py [--dry-run] [--path /var] [--warn-percent 90]
  --dry-run prints the would-be action and exits (no issue writes).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

LABEL = "disk-usage-alarm"
REPO = os.environ.get("GITHUB_REPOSITORY", "")


def fail(msg: str) -> "None":
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def gh(*args: str) -> str:
    out = subprocess.run(["gh", *args], capture_output=True, text=True)
    if out.returncode != 0:
        fail(f"gh {' '.join(args[:2])} failed: {out.stderr.strip()}")
    return out.stdout


def disk_usage(path: str) -> tuple[int, str, str]:
    """Returns (used_percent, size_human, avail_human) for `path`'s filesystem.

    Refuses to read a failed `df` as healthy -- same fatal-on-empty
    discipline ci-queue-watch.py uses for its own run listing: a broken
    check must not silently report "fine".
    """
    out = subprocess.run(
        ["df", "-h", "--output=pcent,size,avail", path],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        fail(f"df {path} failed: {out.stderr.strip()}")
    lines = [l for l in out.stdout.splitlines() if l.strip()]
    if len(lines) < 2:
        fail(f"df {path} returned no data row -- refusing to read this as healthy")
    pcent, size, avail = lines[1].split()
    if not pcent.endswith("%"):
        fail(f"df {path} returned an unparseable percent field: {pcent!r}")
    return int(pcent.rstrip("%")), size, avail


def open_alarm_issue() -> str:
    out = gh(
        "issue", "list", "-R", REPO, "--state", "open",
        "--label", LABEL, "--json", "number", "--jq", ".[0].number // \"\"",
    ).strip()
    return out or ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default="/var")
    ap.add_argument("--warn-percent", type=int, default=90)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    used_pct, size, avail = disk_usage(args.path)
    host = os.environ.get("RUNNER_NAME") or os.uname().nodename
    print(f"{args.path} on {host}: {used_pct}% used, {size} total, {avail} available")

    if used_pct < args.warn_percent:
        print(f"healthy: below the {args.warn_percent}% threshold")
        if args.dry_run:
            return 0
        if not REPO:
            fail("GITHUB_REPOSITORY must be set")
        open_issue = open_alarm_issue()
        if open_issue:
            now = datetime.now(timezone.utc).strftime("%FT%TZ")
            gh(
                "issue", "close", open_issue, "-R", REPO,
                "--comment",
                f"Recovered as of {now}: {args.path} on {host} is now "
                f"{used_pct}% used ({avail} available), below the "
                f"{args.warn_percent}% threshold. Closing; the next sweep "
                "over threshold reopens.",
            )
            print(f"closed disk-usage-alarm issue #{open_issue} (recovered)")
        return 0

    print(f"ALARM: {used_pct}% >= {args.warn_percent}% threshold")
    now = datetime.now(timezone.utc).strftime("%FT%TZ")
    body = (
        f"Sweep at {now}: `{args.path}` on `{host}` is **{used_pct}%** used "
        f"({avail} available of {size} total) -- at or above the "
        f"{args.warn_percent}% warning threshold.\n\n"
        "Context: #2743 -- this filesystem backs `/var/lib/docker` (every CI "
        "container, image build, and Arcane stack). It reached 96% once "
        "before with no warning and broke Elasticsearch-backed CI legs "
        "(`unavailable_shards_exception`); `docker builder prune -af` "
        "reclaimed 179GB of buildkit cache with zero active entries. Check "
        "`docker system df -v` for the current breakdown before assuming "
        "the same cause -- do not run `docker volume prune` or delete any "
        "volume without auditing first; this host's volumes may hold real "
        "captured honeypot data that exists nowhere else.\n"
    )

    if args.dry_run:
        print(f"--- dry run: would open/update {LABEL} issue with the body above")
        return 0
    if not REPO:
        fail("GITHUB_REPOSITORY must be set")

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
        fh.write(body)
        body_path = Path(fh.name)

    subprocess.run(
        ["gh", "label", "create", LABEL, "-R", REPO,
         "-d", "Runner-host disk usage alarm (scripts/disk-usage-watch.py)",
         "--color", "D93F0B"],
        capture_output=True, text=True,
    )
    open_issue = open_alarm_issue()
    if open_issue:
        gh("issue", "comment", open_issue, "-R", REPO, "--body-file", str(body_path))
        print(f"appended to disk-usage-alarm issue #{open_issue}")
    else:
        gh(
            "issue", "create", "-R", REPO, "--title",
            f"ops: {args.path} on the homeserver at or above {args.warn_percent}% (#2743 watch)",
            "--label", LABEL, "--body-file", str(body_path),
        )
        print("opened disk-usage-alarm issue")
    body_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
