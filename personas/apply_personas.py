#!/usr/bin/env python3
"""Validate persona wiring and idempotently seed mutable runtime personas."""

import hashlib
import json
import os
import runpy
import shutil
from datetime import datetime, timezone
from pathlib import Path


def apply(stack: Path, dionaea: Path, state: Path) -> dict:
    runpy.run_path(str(stack / "personas" / "validate_personas.py"), run_name="__main__")

    copied = []
    for service in ("ftp", "tftp", "upnp", "printer"):
        source = stack / "dionaea" / "persona" / service
        target = dionaea / service / "root"
        target.mkdir(parents=True, exist_ok=True)
        if not source.exists():
            continue
        for item in sorted(source.rglob("*")):
            if not item.is_file():
                continue
            relative = item.relative_to(source)
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, destination)
            copied.append(f"dionaea/{service}/{relative.as_posix()}")

    manifest = stack / "personas" / "personas.json"
    result = {
        "applied_at": datetime.now(timezone.utc).isoformat(),
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "runtime_files": copied,
    }
    state.mkdir(parents=True, exist_ok=True)
    temporary = state / "applied.json.tmp"
    temporary.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    temporary.replace(state / "applied.json")
    return result


if __name__ == "__main__":
    result = apply(
        Path(os.environ.get("STACK_ROOT", "/stack")),
        Path(os.environ.get("DIONAEA_ROOT", "/dionaea")),
        Path(os.environ.get("PERSONA_STATE", "/state")),
    )
    print(
        "persona apply OK: "
        f"manifest={result['manifest_sha256'][:12]} files={len(result['runtime_files'])}"
    )
