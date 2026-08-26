#!/usr/bin/env python3
"""Roll back an ml-worker model to a previously retained version (#65,
docs/ml-worker-plan.md §11.3).

ml-worker has no HTTP control surface -- a deliberate, pure background
poller -- so this is a standalone script an operator runs inside the
container:

    docker exec <container> python3 rollback.py isoforest <timestamp>

It repoints current_<name>.<ext> to the requested still-retained version
(one of the last MAX_RETAINED_VERSIONS accepted retrains, per
models/lifecycle.py's pruning). Takes effect on the worker's NEXT RESTART --
_load_latest() runs once, at process start, the same "staged, requires an
operator restart" contract docs/ml-worker-plan.md §11.5 already establishes
for the dashboard's honeypotConfig fields. This script only repoints a
symlink; it does not restart anything itself.

Usage: rollback.py <isoforest|hbos|lstm_ae> <timestamp>
       rollback.py <isoforest|hbos|lstm_ae>              # lists retained versions

Note (#2230): an accepted retrain between staging and restart overrides
this pointer -- the worker logs that explicitly and prune protects the
staged version's file from deletion, so re-running the same command after
an override always works.
"""
import glob
import os
import re
import sys

MODEL_DIR = os.getenv("MODEL_DIR", "/models")
EXTENSIONS = {"isoforest": "joblib", "hbos": "joblib", "lstm_ae": "pt"}

_VERSION_RE = re.compile(r"_([0-9]+)\.")

# The very same _symlink() the worker promotes through, imported not copied
# (#2230): rollback used remove-then-symlink here, quietly re-introducing
# the crash window #169 had already fixed for every other promotion path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from models.lifecycle import _symlink, mark_staged  # noqa: E402


def retained_versions(name: str) -> list:
    ext = EXTENSIONS[name]
    paths = sorted(glob.glob(os.path.join(MODEL_DIR, f"{name}_*.{ext}")))
    return paths


def main(argv):
    if len(argv) < 2 or argv[1] not in EXTENSIONS:
        print(f"usage: {argv[0]} <{'|'.join(EXTENSIONS)}> [timestamp]", file=sys.stderr)
        return 2
    name = argv[1]

    if len(argv) == 2:
        versions = retained_versions(name)
        if not versions:
            print(f"no retained versions of {name} found in {MODEL_DIR}")
            return 0
        current = os.path.realpath(os.path.join(MODEL_DIR, f"current_{name}.{EXTENSIONS[name]}"))
        for path in versions:
            marker = " (current)" if os.path.realpath(path) == current else ""
            print(f"{path}{marker}")
        return 0

    ts = argv[2]
    ext = EXTENSIONS[name]
    target = os.path.join(MODEL_DIR, f"{name}_{ts}.{ext}")
    if not os.path.isfile(target):
        print(f"error: {target} does not exist. Retained versions:", file=sys.stderr)
        for path in retained_versions(name):
            print(f"  {path}", file=sys.stderr)
        return 1

    link = os.path.join(MODEL_DIR, f"current_{name}.{ext}")
    _symlink(target, link)  # atomic swap, #169 idiom via shared models/lifecycle (#2230)
    # Record the staging durably (#2230): prune must protect this version
    # even after the next accepted retrain legitimately re-promotes the
    # pointer -- see mark_staged()'s own docstring for why the pointer
    # alone can't be that record.
    mark_staged(MODEL_DIR, name, int(ts))
    print(f"{link} -> {target}")
    newer = [p for p in retained_versions(name)
             if (m := _VERSION_RE.search(os.path.basename(p)))
             and int(m.group(1)) > int(ts)]
    if newer:
        print(f"note: {len(newer)} newer accepted version(s) exist; an accepted retrain "
              f"before you restart will override this staging (the worker logs it loudly "
              f"and keeps this file -- re-running this command re-stages it)")
    print("Restart ml-worker for this to take effect (models load once, at process start).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
