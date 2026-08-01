#!/usr/bin/env python3
"""Expose the owner-only model drift artifact over a read-only Unix socket.

The dashboard receives no host-file mount and no network endpoint. This small
root-owned adapter validates and re-serializes the fixed sanitized schema; it
has no mutation route and never exposes prompts, replies, paths, containers,
credentials, model tags, or captured data.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socketserver
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

MAX_STATUS_BYTES = 64 * 1024
STATE_VALUES = {"approved", "drift", "unavailable"}
SLOT_NAMES = {"ghidra", "sessions", "revdeck"}
CODE = re.compile(r"^[a-z0-9_:-]{1,96}$")


def _codes(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError("invalid reason codes")
    if not all(isinstance(item, str) and CODE.fullmatch(item) for item in value):
        raise ValueError("invalid reason code")
    return value


def _component(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("status") not in STATE_VALUES:
        raise ValueError("invalid component status")
    return {"status": value["status"], "codes": _codes(value.get("codes", []))}


def sanitize_status(path: Path) -> dict[str, Any]:
    stat = path.stat()
    process_uid = os.geteuid() if hasattr(os, "geteuid") else stat.st_uid
    insecure_mode = os.name == "posix" and bool(stat.st_mode & 0o077)
    if not path.is_file() or stat.st_size > MAX_STATUS_BYTES or stat.st_uid != process_uid or insecure_mode:
        raise ValueError("status artifact ownership or mode is unsafe")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema_version") != 1 or raw.get("advisory_only") is not True or raw.get("overall") not in STATE_VALUES:
        raise ValueError("invalid model-status schema")
    result: dict[str, Any] = {
        "schema_version": 1,
        "checked_at": str(raw.get("checked_at", ""))[:64],
        "overall": raw["overall"],
        "advisory_only": True,
    }
    if "codes" in raw:
        result["codes"] = _codes(raw["codes"])
    slots = raw.get("slots", {})
    if not isinstance(slots, dict) or len(slots) > 3 or not set(slots).issubset(SLOT_NAMES):
        raise ValueError("invalid model slots")
    result["slots"] = {name: _component(value) for name, value in slots.items()}
    if "runtime" in raw:
        result["runtime"] = _component(raw["runtime"])
    if "host" in raw:
        result["host"] = _component(raw["host"])
    return result


class StatusHandler(BaseHTTPRequestHandler):
    server_version = "honeypot-model-status/1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        if self.path != "/v1/status":
            self.send_error(404)
            return
        try:
            payload = sanitize_status(self.server.status_file)  # type: ignore[attr-defined]
            status = 200
        except Exception:
            payload = {"schema_version": 1, "checked_at": "", "overall": "unavailable", "codes": ["adapter_source_unavailable"], "slots": {}, "advisory_only": True}
            status = 503
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        self.send_error(405)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


if hasattr(socketserver, "UnixStreamServer"):
    class StatusServer(socketserver.UnixStreamServer):
        allow_reuse_address = True
else:  # Importable on Windows for schema tests; the service itself is Linux-only.
    class StatusServer:  # type: ignore[no-redef]
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("AF_UNIX stream servers are unavailable on this platform")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--status-file", type=Path, default=Path("/var/lib/honeypot-ghidra/model-status.json"))
    parser.add_argument("--socket", type=Path, default=Path("/run/honeypot-model-status/status.sock"))
    args = parser.parse_args()
    args.socket.parent.mkdir(parents=True, exist_ok=True)
    args.socket.unlink(missing_ok=True)
    old_umask = os.umask(0o117)
    try:
        server = StatusServer(str(args.socket), StatusHandler)
    finally:
        os.umask(old_umask)
    server.status_file = args.status_file
    os.chmod(args.socket, 0o660)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        args.socket.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
