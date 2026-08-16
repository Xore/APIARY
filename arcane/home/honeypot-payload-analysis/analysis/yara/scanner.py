#!/usr/bin/env python3
"""Networkless, non-executing YARA scanner for hash-addressed captures."""

import hashlib
import json
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

HASH_NAME = re.compile(r"^[0-9a-fA-F]{32,64}$")
ROOTS = [Path(value) for value in os.getenv("YARA_PAYLOAD_ROOTS", "/payloads/dionaea:/payloads/cowrie:/payloads/scripts").split(":") if value]
RESULTS = Path(os.getenv("YARA_RESULTS", "/results/results.json"))


def default_rules() -> Path:
    """index.yar when a corpus has been vendored, the local rules otherwise.

    analysis/yara/sync-yara.sh generates index.yar to include the local rules
    plus everything under upstream/. It does not exist in a checkout that has
    never synced, and falling back keeps that checkout scanning with the local
    rules instead of failing to start.
    """
    index = Path("/rules/index.yar")
    return index if index.is_file() else Path("/rules/honeypot.yar")


RULES = Path(os.getenv("YARA_RULES", "")) if os.getenv("YARA_RULES") else default_rules()
INTERVAL = max(60, int(os.getenv("YARA_SCAN_INTERVAL", "900")))
MAX_BYTES = max(1024, int(os.getenv("YARA_MAX_BYTES", str(64 * 1024 * 1024))))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def corpus_sha256() -> str:
    """One hash over every rule file the scanner could load.

    rules_sha256 covers only the top file, which since index.yar is an include
    list is a hash of filenames rather than of rules: an upstream sync that
    changed every rule but no filename would not move it. This one does, so a
    result set can be tied to the corpus that produced it.
    """
    digest = hashlib.sha256()
    root = RULES.parent
    try:
        paths = sorted(p for p in root.rglob("*.yar") if p.is_file())
    except OSError:
        return ""
    for path in paths:
        try:
            digest.update(str(path.relative_to(root)).replace(os.sep, "/").encode())
            digest.update(sha256(path).encode())
        except OSError:
            continue
    return digest.hexdigest()


def auto_rules() -> list:
    """Rule names that came from upstream/auto/, written by sync-yara.sh.

    Auto-generated rules are broad by construction — "3 of 20 common .NET
    strings" matches most .NET binaries. A consumer that cannot tell an auto hit
    from a curated one will read the two as equally meaningful, so the names
    travel with the results rather than staying in the corpus.
    """
    listing = RULES.parent / "upstream" / "AUTO_RULES"
    try:
        return sorted({line.strip() for line in listing.read_text(encoding="utf-8").splitlines() if line.strip()})
    except OSError:
        return []


def candidates():
    for root in ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            try:
                if path.is_file() and not path.is_symlink() and HASH_NAME.fullmatch(path.name):
                    yield path
            except OSError:
                continue


def load_previous() -> dict:
    try:
        return json.loads(RESULTS.read_text(encoding="utf-8")).get("samples", {})
    except (OSError, ValueError, TypeError):
        return {}


def scan(path: Path, previous: dict) -> dict:
    stat = path.stat()
    if stat.st_size > MAX_BYTES:
        return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "matches": [], "error": f"sample exceeds {MAX_BYTES} byte scan limit"}
    # Never cache failures: permissions, a transient read error, or a corrected
    # rule set must be retried on the next scanner start/interval.
    if not previous.get("error") and previous.get("size") == stat.st_size and previous.get("mtime_ns") == stat.st_mtime_ns:
        return previous
    result = {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns, "scanned_at": datetime.now(timezone.utc).isoformat(), "matches": []}
    try:
        completed = subprocess.run(["yara", "-w", str(RULES), str(path)], capture_output=True, text=True, timeout=30, check=False)
        result["matches"] = sorted({line.split(maxsplit=1)[0] for line in completed.stdout.splitlines() if line.strip()})
        if completed.returncode not in (0, 1):
            result["error"] = (completed.stderr or f"yara exit {completed.returncode}").strip()[:500]
        result["sha256"] = sha256(path)
    except (OSError, subprocess.TimeoutExpired) as error:
        result["error"] = str(error)[:500]
    return result


def scan_all() -> dict:
    previous = load_previous()
    samples = {}
    errors = []
    for path in candidates():
        try:
            current = scan(path, previous.get(path.name, {}))
            current["source"] = path.parts[2] if len(path.parts) > 2 else "payloads"
            samples[path.name.lower()] = current
        except (OSError, PermissionError) as error:
            errors.append(f"{path}: {error}")
    return {"version": 1, "scanner": "YARA", "updated_at": datetime.now(timezone.utc).isoformat(), "rules_sha256": sha256(RULES), "corpus_sha256": corpus_sha256(), "auto_rules": auto_rules(), "samples": samples, "errors": errors[:50]}


def main():
    subprocess.run(["yara", "-w", str(RULES), "/dev/null"], capture_output=True, timeout=10, check=False)
    while True:
        report = scan_all()
        RESULTS.parent.mkdir(parents=True, exist_ok=True)
        temporary = RESULTS.with_suffix(".tmp")
        temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        temporary.replace(RESULTS)
        print(json.dumps({"updated_at": report["updated_at"], "samples": len(report["samples"]), "errors": len(report["errors"])}), flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
