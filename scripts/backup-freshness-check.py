#!/usr/bin/env python3
"""Narrow root-run helper for backup-staleness-watch.py (REVIEW-A/#3025).

`/mnt/usb-recovery/apiary-backups` is `drwx------ xore xore` -- the
`github-ci-runner` system user cannot list it at all. `Path.glob()` on an
unreadable directory silently returns zero matches instead of raising, so
the watcher was reading "permission denied" as "no archive found" and
alarming staleness every 6 hours against three healthy archives sitting
right there (verified live, REVIEW-A). Widening group membership or mode
bits on the real backup directory was rejected for the same reason
compose-project-state.py rejected it for `.env` files: this is the same
directory `backup-essentials.sh` writes the *only* copy of decrypted-at-
rest-adjacent essentials archives to, and it should stay closed to every
account except `xore` and root.

Instead: root reads the directory (mirroring compose-project-state.py's
pattern exactly) and the ONLY thing that ever leaves this process on
stdout is the newest matching archive's mtime, as a bare epoch float, or
the literal string `EMPTY` if the directory is readable but holds no
matching archive. No filename, no byte size, no listing of any other file
in the directory -- an attacker who can only run this helper learns "how
stale is the backup", nothing about what the backup contains or is named.

Granted to `github-ci-runner` via a sudoers NOPASSWD entry restricted to
this exact script path (scripts/github-ci-runner/install-ci-runner.sh),
not a general root shell or group membership.

Usage (normally invoked by backup-staleness-watch.py via `sudo -n`, not by
hand):
  sudo python3 scripts/backup-freshness-check.py <dir> <glob>
Exit 0 on success (prints an epoch float or EMPTY), 1 on a missing/non-dir
path, 2 on a rejected argument.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Real backup destination only -- matches backup-staleness-watch.py's own
# --path default. A path outside this is refused before touching the
# filesystem, so this root-run helper can't be pointed at an arbitrary
# root-owned directory elsewhere on the host even though sudoers itself
# allows any trailing argument.
ALLOWED_DIRS = (Path("/mnt/usb-recovery/apiary-backups"),)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: backup-freshness-check.py <dir> <glob>", file=sys.stderr)
        return 2

    try:
        target = Path(sys.argv[1]).resolve(strict=True)
    except OSError as e:
        print(f"refusing: cannot resolve {sys.argv[1]!r}: {e}", file=sys.stderr)
        return 2

    if target not in ALLOWED_DIRS:
        print(f"refusing: {target} is outside the known backup dirs {ALLOWED_DIRS}", file=sys.stderr)
        return 2

    glob = sys.argv[2]
    if "/" in glob or ".." in glob:
        print(f"refusing: glob {glob!r} must not contain '/' or '..'", file=sys.stderr)
        return 2

    if not target.is_dir():
        print(f"refusing: {target} is not a directory", file=sys.stderr)
        return 1

    newest = max((f.stat().st_mtime for f in target.glob(glob)), default=None)
    print("EMPTY" if newest is None else repr(newest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
