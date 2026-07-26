#!/usr/bin/env python3
"""Deduplicate captured payloads without breaking their existing paths."""

import argparse
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


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

    for path in sorted(candidates(roots), key=lambda item: str(item)):
        try:
            stat = path.stat()
            if stat.st_size == 0:
                continue
            sha256 = digest(path)
            hashed += 1
            content_key = (stat.st_size, sha256)
            device_key = (stat.st_dev, stat.st_size, sha256)
            if content_key in canonical and canonical[content_key].stat().st_dev != stat.st_dev:
                cross_device += 1
            first = canonical.get(device_key)
            if first is None:
                canonical[device_key] = path
                canonical.setdefault(content_key, path)
                continue
            first_stat = first.stat()
            if first_stat.st_ino == stat.st_ino:
                continue
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
        "files_hashed": hashed,
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
    while True:
        result = dedupe(roots, state)
        print(json.dumps(result), flush=True)
        if args.once:
            return
        time.sleep(interval)


if __name__ == "__main__":
    main()
