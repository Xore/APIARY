#!/usr/bin/env python3
"""Narrow, allowlisted control surface for sensor/probe/analysis-worker
containers (#197).

The dashboard receives no host file mount, no libvirt/systemd/Docker access,
and no network endpoint into this host's Docker daemon -- per
docker-compose.yml's own stated boundary ("The dashboard never receives
access to libvirt, systemd, Docker, or sandbox samples"). This adapter is the
one thing that holds real /var/run/docker.sock access, and it exposes only
three narrow operations, only for an explicit, hardcoded container-name
allowlist -- never "any container", matching hp-autoheal's own scoping
(docker.sock access exists there too, but only acts on containers labeled
autoheal=true). There is no shell-out to the `docker` CLI anywhere in this
file: every Docker Engine API call goes over the unix socket via stdlib
http.client, with the container name passed as a URL path segment after an
exact allowlist match, never interpolated into a shell command.

Zero third-party dependencies, matching
analysis/ghidra/models/model-status-adapter.py's philosophy -- one more
thing that can't be a supply-chain surface.
"""

from __future__ import annotations

import json
import os
import re
import socket
import socketserver
from http import client as http_client
from http.server import BaseHTTPRequestHandler
from typing import Any
from urllib.parse import parse_qs, urlsplit

DOCKER_SOCK = "/var/run/docker.sock"

# Explicit, hardcoded allowlist -- the sensor/probe/analysis-worker
# containers this pane is for. Deliberately excludes hp-dashboard,
# hp-elasticsearch, hp-kibana, hp-filebeat, hp-evebox, hp-autoheal, and
# anything Dockge/infrastructure-related: a request for any other name is
# rejected before any Docker API call is made, not filtered after the fact.
ALLOWED_CONTAINERS = frozenset({
    "hp-cowrie",
    "hp-multipot",
    "hp-http",
    "hp-api-honeypot",
    "hp-dionaea",
    "hp-tftp-relay",
    "hp-dnp3",
    "hp-dicompot",
    "hp-dns-honeypot",
    "hp-citrix-honeypot",
    "hp-cisco-asa-honeypot",
    "hp-rdp-honeypot",
    "hp-snare",
    "hp-tanner",
    "hp-tanner-api",
    "hp-tanner-web",
    "hp-tanner-redis",
    "hp-tanner-phpox",
    "hp-tanner-docker",
    "hp-conpot",
    "hp-conpot-s7-1200",
    "hp-conpot-s7-1500",
    "hp-conpot-iec104",
    "hp-conpot-guardian",
    "hp-conpot-kamstrup",
    "hp-yara-scanner",
    "hp-payload-dedupe",
    "hp-pcap-sync",
    "hp-arkime-capture",
    "hp-arkime-viewer",
    "hp-ml-worker",
    "hp-llm-worker",
    "ghidra-ghidra-1",
    "ghidra-ollama-1",
    "ghidra-statictools-1",
    "ghidra-revdeck-1",
    # Post-#1418 sensor stacks (#2089): these shipped after the allowlist was
    # first written and none of them ever joined it, so /v1/services reported
    # nothing at all for them -- which reads as healthy rather than as
    # "not observable".
    "hp-beelzebub",
    "hp-hellpot",
    "hp-wordpot",
    "hp-mailoney",
    "hp-galah",
    "hp-galah-llm-broker",
    "hp-sentrypeer",
    "hp-elasticpot",
    "hp-endlessh",
    "hp-honeyfs-implant",
    "hp-zeek-proxy",
    # The canarytokens switchboard is five containers acting as one sensor.
    "hp-canarytokens-redis",
    "hp-canarytokens-frontend",
    "hp-canarytokens-switchboard",
    "hp-canarytokens-http-router",
    "hp-canarytokens-adapter",
})

ALLOWED_ACTIONS = frozenset({"start", "stop", "restart"})
MAX_LOG_LINES = 1000
DEFAULT_LOG_LINES = 200
NAME_ROUTE = re.compile(r"^/v1/services/([a-zA-Z0-9_.-]+)/(start|stop|restart|logs)$")


class DockerUnixConnection(http_client.HTTPConnection):
    """Talks to the Docker Engine API over its own unix socket instead of a
    TCP host:port -- the only thing in this file that touches DOCKER_SOCK."""

    def __init__(self, timeout: float = 10.0) -> None:
        super().__init__("localhost", timeout=timeout)

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(DOCKER_SOCK)


def docker_request(method: str, path: str, timeout: float = 10.0) -> tuple[int, Any]:
    conn = DockerUnixConnection(timeout=timeout)
    try:
        conn.request(method, path, headers={"Host": "docker"})
        resp = conn.getresponse()
        raw = resp.read()
        body = None
        if raw:
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
        return resp.status, body
    finally:
        conn.close()


def docker_request_raw(method: str, path: str, timeout: float = 15.0) -> tuple[int, bytes]:
    conn = DockerUnixConnection(timeout=timeout)
    try:
        conn.request(method, path, headers={"Host": "docker"})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _demux_docker_log_stream(raw: bytes) -> str:
    """Docker multiplexes stdout/stderr with an 8-byte frame header per
    chunk when the container has no tty (true for all of these services)
    -- strip the framing rather than show the raw binary noise."""
    out = []
    i = 0
    while i + 8 <= len(raw):
        size = int.from_bytes(raw[i + 4:i + 8], "big")
        start = i + 8
        end = start + size
        out.append(raw[start:end].decode("utf-8", errors="replace"))
        i = end
    return "".join(out) if out else raw.decode("utf-8", errors="replace")


def container_status(name: str) -> dict[str, Any]:
    status, body = docker_request("GET", f"/containers/{name}/json")
    if status == 404:
        return {"name": name, "state": "not_found"}
    if status != 200 or not isinstance(body, dict):
        return {"name": name, "state": "unknown"}
    state = body.get("State") or {}
    result: dict[str, Any] = {
        "name": name,
        "state": state.get("Status", "unknown"),
        "exit_code": state.get("ExitCode"),
        "started_at": state.get("StartedAt"),
        "restart_count": body.get("RestartCount"),
    }
    health = state.get("Health")
    if isinstance(health, dict) and health.get("Status"):
        result["health"] = health["Status"]
    return result


def list_services() -> list[dict[str, Any]]:
    return [container_status(name) for name in sorted(ALLOWED_CONTAINERS)]


def perform_action(name: str, action: str) -> tuple[int, dict[str, Any]]:
    if name not in ALLOWED_CONTAINERS:
        return 403, {"error": "container not in allowlist"}
    if action not in ALLOWED_ACTIONS:
        return 400, {"error": "unsupported action"}
    status, _ = docker_request("POST", f"/containers/{name}/{action}")
    if status == 404:
        return 404, {"error": "container not found"}
    if status == 304:
        # #2185: the Engine answers 304 Not Modified when the requested state
        # already holds -- start on an already-running container, stop on an
        # already-stopped one. That is idempotent success, not a failure;
        # reporting it as 502 made an operator who clicked Start on a running
        # service see "failed" with nothing having gone wrong. The noop flag
        # lets the UI say "already running/stopped" instead of pretending the
        # action just happened.
        return 200, {"ok": True, "action": action, "name": name, "noop": True}
    if status not in (200, 204):
        # Deliberately no upstream numerals here (#2185): the raw engine
        # status must not leak into a user-facing body.
        return 502, {"error": "docker engine returned an error"}
    return 200, {"ok": True, "action": action, "name": name}


def fetch_logs(name: str, lines: int) -> tuple[int, str]:
    if name not in ALLOWED_CONTAINERS:
        return 403, ""
    lines = max(1, min(lines, MAX_LOG_LINES))
    status, raw = docker_request_raw(
        "GET", f"/containers/{name}/logs?stdout=true&stderr=true&tail={lines}&timestamps=true"
    )
    if status == 404:
        return 404, ""
    if status != 200:
        return 502, ""
    return 200, _demux_docker_log_stream(raw)


class ServicesHandler(BaseHTTPRequestHandler):
    server_version = "honeypot-services-adapter/1"

    def _write_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        parsed = urlsplit(self.path)
        if parsed.path == "/v1/services":
            self._write_json(200, {"services": list_services()})
            return
        match = NAME_ROUTE.match(parsed.path)
        if match and match.group(2) == "logs":
            name = match.group(1)
            query = parse_qs(parsed.query)
            try:
                lines = int(query.get("lines", [str(DEFAULT_LOG_LINES)])[0])
            except ValueError:
                lines = DEFAULT_LOG_LINES
            status, text = fetch_logs(name, lines)
            if status == 403:
                self._write_json(403, {"error": "container not in allowlist"})
                return
            if status == 404:
                self._write_json(404, {"error": "container not found"})
                return
            if status != 200:
                self._write_json(502, {"error": "docker engine returned an error"})
                return
            self._write_json(200, {"name": name, "lines": lines, "log": text})
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        match = NAME_ROUTE.match(parsed.path)
        if not match or match.group(2) == "logs":
            self.send_error(404)
            return
        name, action = match.group(1), match.group(2)
        status, payload = perform_action(name, action)
        self._write_json(status, payload)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


if hasattr(socketserver, "UnixStreamServer"):
    class ServicesServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        allow_reuse_address = True
        daemon_threads = True
else:  # Importable on Windows for schema tests; the service itself is Linux-only.
    class ServicesServer:  # type: ignore[no-redef]
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("AF_UNIX stream servers are unavailable on this platform")


def main() -> int:
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, default=Path("/run/services-adapter/control.sock"))
    args = parser.parse_args()
    args.socket.parent.mkdir(parents=True, exist_ok=True)
    args.socket.unlink(missing_ok=True)
    old_umask = os.umask(0o117)
    try:
        server = ServicesServer(str(args.socket), ServicesHandler)
    finally:
        os.umask(old_umask)
    # Deliberately no post-bind chmod (#2100). A tight one (0600) zeroes an
    # inherited default ACL's mask -- deployments grant the non-root backend
    # access through exactly that channel, and every restart mints a fresh
    # socket, so the grant died each time. A wider one would be flagged as
    # overly permissive outright. The umask above already binds the socket
    # srw-rw----: owner rw, other nothing, and the group class left intact
    # as the ACL-mask channel that makes the volume's default-ACL grant
    # ("user:nobody:rw-") actually effective.
    try:
        server.serve_forever()
    finally:
        server.server_close()
        args.socket.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
