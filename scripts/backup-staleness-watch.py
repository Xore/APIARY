#!/usr/bin/env python3
"""Alarm when the essentials backup has gone stale (#3025).

2026-09-01: a homeserver rebuild wiped `apiary-backup-essentials.timer` along
with everything else under /etc/systemd/system and /usr/local/libexec. The
backup silently stopped producing archives for 4 days -- nobody noticed until
an unrelated #1609 audit happened to check. `scripts/backup-essentials.sh
--check` already detects this (newest archive on any of its three
destinations older than MAX_AGE_HOURS), but nothing ever *runs* --check on a
schedule and turns a failure into something visible.

Deliberately does NOT re-run or wrap backup-essentials.sh --check: that
script's own logic is workstation-local (DEST_LOCAL_USB/DEST_LOCAL_DISK are
paths on the backup host, not this runner) and reaches the server leg over
`ssh $HOMESERVER_SSH` -- which is redundant and pointless when this watcher
already runs ON the homeserver runner. Instead this checks the one backup leg
that is local to the box this script actually runs on: `DEST_SERVER_USB`
(scripts/backup-essentials.sh's own default,
/mnt/usb-recovery/apiary-backups), the same directory backup-essentials.sh
itself writes to over SSH from the workstation.

This covers the incident that prompted #3025: backup-essentials.sh produces
all three destinations from a single script run on the workstation, so if
the pipeline stops, the server-USB leg goes stale in lockstep with the other
two -- there is no failure mode where the workstation legs keep updating
while this one alone falls behind. It does NOT independently monitor the two
workstation-local destinations; doing that would need a new SSH credential
from this CI runner to the workstation, which is a real credential/blast-
radius increase this fix does not introduce. If the workstation legs and the
server leg ever diverge (e.g. the workstation fans out to USB/disk but its
SSH push to the server leg alone starts failing), that gap is not covered
here.

Design mirrors disk-usage-watch.py's proven shape (#2743) exactly:
- A single open `backup-staleness-alarm`-labeled issue at a time: a sweep
  that finds continued staleness appends to it; a sweep that finds a fresh
  archive again closes it with the recovery evidence.
- Runs directly against the filesystem it measures, on the self-hosted
  homeserver runner -- no separate credential or network path.

REVIEW-A/#3025: `/mnt/usb-recovery/apiary-backups` is `drwx------ xore
xore`; the runner user cannot read it at all. A direct `Path.glob()`
against it silently returns zero matches on EACCES instead of raising, so
the first version of this watcher read "permission denied" as "no archive
found" and alarmed every 6 hours against three healthy archives. Fixed by
reading through a narrow root-run helper
(scripts/backup-freshness-check.py, sudoers grant in
scripts/github-ci-runner/install-ci-runner.sh) that returns only a bare
mtime or `EMPTY` -- same privilege-boundary shape as
scripts/compose-project-state.py. A failed read now raises `CouldNotCheck`
and exits 1 without ever opening or touching the alarm issue.

Usage:
  scripts/backup-staleness-watch.py [--dry-run] [--path DIR] [--max-age-hours N]
  --dry-run prints the would-be action and exits (no issue writes).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

LABEL = "backup-staleness-alarm"
REPO = os.environ.get("GITHUB_REPOSITORY", "")
GLOB = "apiary-essentials-*.tar.gz.gpg"
FRESHNESS_HELPER = "/opt/github-ci-runner-helpers/backup-freshness-check.py"


def fail(msg: str) -> "None":
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def gh(*args: str) -> str:
    out = subprocess.run(["gh", *args], capture_output=True, text=True)
    if out.returncode != 0:
        fail(f"gh {' '.join(args[:2])} failed: {out.stderr.strip()}")
    return out.stdout


class CouldNotCheck(Exception):
    """The backup dir could not be read at all this sweep (permission
    denied, helper missing, ...) -- distinct from "checked and it's
    stale/empty". Never treated as staleness by the caller."""


def newest_archive_age_hours(path: Path) -> float | None:
    """Age in hours of the newest matching archive under `path`, or None if
    the directory is genuinely empty of matching archives (checked
    successfully). Raises CouldNotCheck if the read itself failed --
    REVIEW-A/#3025: `path.is_dir()` and `path.glob()` silently return
    False/empty on EACCES rather than raising, so a straight local read
    against the 0700 `xore`-owned backup dir was reading "permission
    denied" as "no archive found" and alarming staleness every 6 hours
    against three healthy archives (verified live). Read through the
    privileged helper (scripts/backup-freshness-check.py, granted via
    sudoers -- see scripts/github-ci-runner/install-ci-runner.sh) instead
    of a direct filesystem read, exactly like compose-drift-watch.py does
    for the root-owned stack dirs it can't read either."""
    out = subprocess.run(
        # REVIEW-A non-blocking: absolute path, matching the sudoers grant
        # itself (/usr/bin/python3 ...) and compose-drift-watch.py's own
        # privileged-helper call -- works today via secure_path, but a bare
        # "python3" is one PATH change away from silently resolving to
        # something the grant never intended.
        ["sudo", "-n", "/usr/bin/python3", FRESHNESS_HELPER, str(path), GLOB],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise CouldNotCheck(out.stderr.strip() or f"helper exited {out.returncode}")
    result = out.stdout.strip()
    if result == "EMPTY":
        return None
    try:
        newest = float(result)
    except ValueError:
        raise CouldNotCheck(f"unexpected helper output: {result!r}")
    return (time.time() - newest) / 3600


def open_alarm_issue() -> str:
    out = gh(
        "issue", "list", "-R", REPO, "--state", "open",
        "--label", LABEL, "--json", "number", "--jq", ".[0].number // \"\"",
    ).strip()
    return out or ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--path", default="/mnt/usb-recovery/apiary-backups")
    ap.add_argument("--max-age-hours", type=int, default=48)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    host = os.environ.get("RUNNER_NAME") or os.uname().nodename
    try:
        age_h = newest_archive_age_hours(Path(args.path))
    except CouldNotCheck as e:
        # Never alarm on a read failure -- that would be the exact bug
        # this fix closes, just moved one level up. Exit non-zero so a
        # broken helper/sudoers grant is still visible in CI, but as a
        # job failure, never as a false staleness alarm/issue.
        print(f"note: could not check {args.path} on {host}: {e}", file=sys.stderr)
        return 1

    if age_h is not None and age_h <= args.max_age_hours:
        print(f"{args.path} on {host}: newest archive is {age_h:.1f}h old, "
              f"below the {args.max_age_hours}h threshold")
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
                f"Recovered as of {now}: newest archive under {args.path} on "
                f"{host} is now {age_h:.1f}h old, below the "
                f"{args.max_age_hours}h threshold. Closing; the next sweep "
                "over threshold reopens.",
            )
            print(f"closed backup-staleness-alarm issue #{open_issue} (recovered)")
        return 0

    reason = (
        f"no {GLOB} found under {args.path} (missing/unmounted/empty)"
        if age_h is None else
        f"newest archive is {age_h:.1f}h old"
    )
    print(f"ALARM: {reason}, threshold {args.max_age_hours}h")
    now = datetime.now(timezone.utc).strftime("%FT%TZ")
    body = (
        f"Sweep at {now} on `{host}`: {reason} under `{args.path}` -- at or "
        f"above the {args.max_age_hours}h staleness threshold.\n\n"
        "Context: #3025 -- a 2026-09-01 homeserver rebuild wiped "
        "`apiary-backup-essentials.timer` and the essentials backup silently "
        "stopped for 4 days before anyone noticed. This only checks the "
        "server-USB leg (`DEST_SERVER_USB` in `scripts/backup-essentials.sh`), "
        "local to this runner; the two workstation-local legs are not "
        "independently monitored here (would need a new SSH credential from "
        "this runner to the workstation). Since backup-essentials.sh produces "
        "all three destinations from one script run, staleness here means the "
        "whole pipeline stopped. First check whether "
        "`apiary-backup-essentials.timer` is still enabled on the backup "
        "host (`systemctl status apiary-backup-essentials.timer`) -- a "
        "rebuild there wipes it again. Re-run "
        "`scripts/install-backup-essentials.sh` on the backup host if it's "
        "not.\n"
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
         "-d", "Essentials backup staleness alarm (scripts/backup-staleness-watch.py)",
         "--color", "D93F0B"],
        capture_output=True, text=True,
    )
    open_issue = open_alarm_issue()
    if open_issue:
        gh("issue", "comment", open_issue, "-R", REPO, "--body-file", str(body_path))
        print(f"appended to backup-staleness-alarm issue #{open_issue}")
    else:
        gh(
            "issue", "create", "-R", REPO, "--title",
            f"ops: essentials backup stale (>{args.max_age_hours}h) on the server-USB leg (#3025 watch)",
            "--label", LABEL, "--body-file", str(body_path),
        )
        print("opened backup-staleness-alarm issue")
    body_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
