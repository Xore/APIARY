#!/usr/bin/env python3
"""Deduplicate captured payloads without breaking their existing paths."""

import argparse
import hashlib
import json
import os
import re
import shutil
import time
from datetime import date, datetime, timezone
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


DATE_DIR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def prune_old_directories(root: Path, retention_days: int, today: date | None = None) -> dict:
    """Delete date-named subdirectories of root older than retention_days.

    Built for Dionaea's bistreams/ (#112): every accepted connection, payload
    or not, gets its own raw-capture file under a YYYY-MM-DD directory,
    98%+ duplicated by repeat scanner traffic and otherwise unbounded.
    dedupe() below reclaims the duplication; this bounds the total window,
    which also keeps what dedupe() has to hash every pass from growing
    forever.

    Directory names are parsed as dates -- Dionaea's own convention for this
    tree -- rather than read from filesystem mtime, which the directory's
    last write sets unpredictably relative to the dates of files inside it.
    Anything that isn't a YYYY-MM-DD name is left alone: this prunes only
    what it can identify with certainty, never a guess.
    """
    if retention_days <= 0 or not root.exists():
        return {"directories_removed": 0, "bytes_removed": 0}
    today = today or datetime.now(timezone.utc).date()
    removed_dirs = 0
    removed_bytes = 0
    for entry in sorted(root.iterdir()):
        if not entry.is_dir() or not DATE_DIR_RE.match(entry.name):
            continue
        try:
            entry_date = date.fromisoformat(entry.name)
        except ValueError:
            continue
        if (today - entry_date).days <= retention_days:
            continue
        try:
            removed_bytes += sum(f.stat().st_size for f in entry.rglob("*") if f.is_file())
            shutil.rmtree(entry)
            removed_dirs += 1
        except OSError:
            continue
    return {"directories_removed": removed_dirs, "bytes_removed": removed_bytes}


def candidates(roots):
    ignored = {"payload-dedupe.json", "applied.json"}
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            try:
                if path.is_file() and not path.is_symlink() and path.name not in ignored:
                    yield path
            except OSError:
                continue


def dedupe(roots, state: Path) -> dict:
    canonical = {}
    hashed = 0
    linked = 0
    reclaimed = 0
    errors = []
    cross_device = 0
    paths_examined = 0
    bytes_hashed = 0

    # #1380: stat every candidate first and group by physical inode before
    # hashing anything. A pathname that already shares an inode with another
    # -- because a previous pass hardlinked them, or they arrived pre-linked
    # -- is the same on-disk bytes as every other name in its group, so each
    # group is hashed once and every member reuses that digest, instead of
    # rereading and rehashing every pathname on every pass regardless of
    # whether it was already linked.
    inode_paths: dict[tuple[int, int], list[Path]] = {}
    stats: dict[Path, os.stat_result] = {}
    for path in sorted(candidates(roots), key=lambda item: str(item)):
        try:
            stat = path.stat()
        except OSError as error:
            errors.append(f"{path}: {error}")
            continue
        if stat.st_size == 0:
            continue
        paths_examined += 1
        stats[path] = stat
        inode_paths.setdefault((stat.st_dev, stat.st_ino), []).append(path)

    # Groups are visited in the same order the very first path in the group
    # would have been reached under the old flat, sorted-by-path loop, so
    # which physical file ends up canonical for a given piece of content is
    # unchanged.
    for _, paths in sorted(inode_paths.items(), key=lambda item: str(item[1][0])):
        representative = paths[0]
        stat = stats[representative]
        try:
            sha256 = digest(representative)
        except (OSError, PermissionError) as error:
            errors.append(f"{representative}: {error}")
            continue
        hashed += 1
        bytes_hashed += stat.st_size
        content_key = (stat.st_size, sha256)
        device_key = (stat.st_dev, stat.st_size, sha256)
        if content_key in canonical and canonical[content_key].stat().st_dev != stat.st_dev:
            cross_device += 1
        first = canonical.get(device_key)
        if first is None:
            canonical[device_key] = representative
            canonical.setdefault(content_key, representative)
            continue
        # Every name in this group already shares one inode, distinct from
        # `first`'s -- relink each of them so every pathname ends up
        # pointing at the canonical inode, same as the old per-path loop did
        # one path at a time.
        for path in paths:
            try:
                temporary = path.with_name(f".{path.name}.dedupe-{os.getpid()}")
                temporary.unlink(missing_ok=True)
                os.link(first, temporary)
                os.replace(temporary, path)
                linked += 1
                reclaimed += stat.st_size
            except (OSError, PermissionError) as error:
                errors.append(f"{path}: {error}")

    result = {
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "paths_examined": paths_examined,
        "files_hashed": hashed,
        "bytes_hashed": bytes_hashed,
        "duplicates_linked": linked,
        "bytes_reclaimed": reclaimed,
        "cross_device_duplicates_retained": cross_device,
        "errors": errors[:50],
    }
    state.parent.mkdir(parents=True, exist_ok=True)
    temporary = state.with_suffix(".tmp")
    temporary.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    temporary.replace(state)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    roots = [Path(item) for item in os.environ.get(
        "PAYLOAD_ROOTS", "/payloads/cowrie:/payloads/dionaea/binaries:/payloads/scripts/script-payloads"
    ).split(":") if item]
    state = Path(os.environ.get("DEDUPE_STATE", "/state/payload-dedupe.json"))
    interval = max(300, int(os.environ.get("PAYLOAD_DEDUPE_INTERVAL", "3600")))
    # Off unless configured, same as the Ghidra/Windows spools elsewhere in
    # this repo: BISTREAMS_ROOT empty means the mount may not even be present
    # on every deployment shape. See #112.
    bistreams_root_env = os.environ.get("BISTREAMS_ROOT", "")
    bistreams_root = Path(bistreams_root_env) if bistreams_root_env else None
    # #261: default derives from the shared HONEYPOT_RETENTION_DAYS knob at
    # a 1:1 ratio, matching this repo's previous independent 30-day default.
    # BISTREAMS_RETENTION_DAYS still overrides directly.
    bistreams_retention_days = int(os.environ.get(
        "BISTREAMS_RETENTION_DAYS", os.environ.get("HONEYPOT_RETENTION_DAYS", "30")
    ))
    while True:
        if bistreams_root is not None:
            # Prune before dedupe, not after: this bounds what dedupe has to
            # hash this pass rather than only bounding it for the next one.
            prune_result = prune_old_directories(bistreams_root, bistreams_retention_days)
            if prune_result["directories_removed"]:
                print(json.dumps({"bistreams_prune": prune_result}), flush=True)
        result = dedupe(roots, state)
        print(json.dumps(result), flush=True)
        if args.once:
            return
        time.sleep(interval)


if __name__ == "__main__":
    main()
