#!/usr/bin/env python3
"""Export bounded queue metadata; never export staged payloads or raw traces."""

import argparse
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/var/lib/honeypot-sandbox")
INBOX = ROOT / "inbox"
EXPORT = ROOT / "export" / "status.json"


def request_rows(state):
    rows = []
    directory = INBOX / state
    if not directory.exists():
        return rows
    for path in sorted(directory.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)[:50]:
        try:
            if path.stat().st_size > 16384:
                continue
            item = json.loads(path.read_text(encoding="utf-8"))
            sha256 = str(item.get("sha256", ""))
            if len(sha256) != 64 or any(char not in "0123456789abcdef" for char in sha256):
                continue
            rows.append({
                "sha256": sha256,
                "source": str(item.get("source", ""))[:64],
                "capture_name": str(item.get("capture_name", ""))[:128],
                "requested_at": str(item.get("requested_at", ""))[:64],
                "state": state,
            })
        except (OSError, ValueError, TypeError):
            continue
    return rows


def request_count(state):
    directory = INBOX / state
    try:
        return sum(1 for path in directory.glob("*.json") if path.is_file())
    except OSError:
        return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker-state", choices=("idle", "running", "error"), default="idle")
    args = parser.parse_args()
    states = {name: request_rows(name) for name in ("queued", "running", "completed", "failed")}
    payload = {
        "version": 1,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "worker_state": args.worker_state,
        "counts": {name: request_count(name) for name in states},
        "jobs": states["running"] + states["queued"] + states["failed"][:20],
    }
    EXPORT.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="status.", suffix=".json", dir=EXPORT.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(payload, output, indent=2)
            output.write("\n")
        os.chmod(temporary, 0o640)
        os.replace(temporary, EXPORT)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
