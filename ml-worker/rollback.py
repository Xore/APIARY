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
"""
import glob
import os
import sys

MODEL_DIR = os.getenv("MODEL_DIR", "/models")
EXTENSIONS = {"isoforest": "joblib", "hbos": "joblib", "lstm_ae": "pt"}


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
    if os.path.lexists(link):
        os.remove(link)
    os.symlink(target, link)
    print(f"{link} -> {target}")
    print("Restart ml-worker for this to take effect (models load once, at process start).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
