#!/usr/bin/env python3
"""Replacement Ghidra headless analysis service (#245).

Drop-in for biniamfd/ghidra-headless-rest's 5 routes that
analysis/ghidra/worker/ghidra-worker.py's GhidraClient actually calls
(confirmed directly against its own docstring, not assumed):

    GET  /v1/health
    POST /analyze                  multipart field "file"
    GET  /status/{job_id}
    GET  /results/{job_id}/functions?offset=&limit=
    GET  /results/{job_id}/strings
    GET  /results/{job_id}/imports

Deliberately stdlib-only, matching worker/ghidra-worker.py's own rule for
the same reason: this replaces a single-maintainer third-party dependency,
so it should not trade that risk for a pip dependency tree of its own.
Runs `support/analyzeHeadless` as a subprocess with -postScript
export_json.py (this directory) -- the actual decompilation/extraction
logic lives entirely in that Jython script via Ghidra's own public
scripting API, not here.
"""
import http.server
import json
import os
import queue
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

GHIDRA_BIN = os.environ.get("GHIDRA_ANALYZE_HEADLESS", "/opt/ghidra/support/analyzeHeadless")
SCRIPT_DIR = os.environ.get("GHIDRA_SCRIPT_DIR", "/opt/service")
DATA_DIR = Path(os.environ.get("GHIDRA_DATA_DIR", "/data/ghidra_projects"))
ANALYSIS_TIMEOUT = int(os.environ.get("ANALYSIS_TIMEOUT", "3600"))
PORT = int(os.environ.get("PORT", "9090"))

REQUIRED_ARTIFACTS = ("functions.json", "strings.json", "imports.json")

_lock = threading.RLock()
_jobs: dict[str, dict] = {}
_queue: "queue.Queue[str]" = queue.Queue()


def job_dir(job_id: str) -> Path:
    return DATA_DIR / job_id


def update_job(job_id: str, **changes) -> None:
    with _lock:
        _jobs[job_id].update(changes)


def worker_loop() -> None:
    while True:
        job_id = _queue.get()
        try:
            _run_job(job_id)
        finally:
            _queue.task_done()


def _run_job(job_id: str) -> None:
    jdir = job_dir(job_id)
    artifacts_dir = jdir / "artifacts"
    sample_path = jdir / "sample.bin"
    project_dir = jdir / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    update_job(job_id, status="running", started_at=time.time())

    command = [
        GHIDRA_BIN,
        str(project_dir),
        f"proj_{job_id}",
        "-import", str(sample_path),
        "-scriptPath", SCRIPT_DIR,
        "-postScript", "export_json.py", str(artifacts_dir),
        "-deleteProject",
    ]
    try:
        proc = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=ANALYSIS_TIMEOUT,
        )
        (jdir / "analysis.log").write_bytes(proc.stdout + b"\n--- stderr ---\n" + proc.stderr)
        if proc.returncode != 0:
            update_job(job_id, status="failed", completed_at=time.time(),
                       error_code="process_error", message="Ghidra analysis failed")
            return
        if not all((artifacts_dir / name).is_file() for name in REQUIRED_ARTIFACTS):
            update_job(job_id, status="failed", completed_at=time.time(),
                       error_code="export_error",
                       message="export did not produce required artifacts")
            return
        update_job(job_id, status="done", completed_at=time.time())
    except subprocess.TimeoutExpired:
        update_job(job_id, status="failed", completed_at=time.time(),
                   error_code="timeout", message="Ghidra analysis timed out")
    except Exception as exc:  # noqa: BLE001 - report, don't crash the worker thread
        update_job(job_id, status="failed", completed_at=time.time(),
                   error_code="internal_error", message=str(exc)[:512])


# --- minimal multipart/form-data parser (single "file" field only) --------
# ghidra-worker.py's own analyze() constructs exactly this shape (one file
# part, no other fields) -- see its own multipart-building code. A general
# multipart parser is not needed for a client this project also controls.
def parse_multipart_file(body: bytes, content_type: str) -> tuple[str, bytes] | None:
    match = re.search(r'boundary="?([^";]+)"?', content_type)
    if not match:
        return None
    boundary = ("--" + match.group(1)).encode()
    parts = body.split(boundary)
    for part in parts:
        part = part.strip(b"\r\n")
        if not part or part == b"--":
            continue
        header_end = part.find(b"\r\n\r\n")
        if header_end == -1:
            continue
        headers = part[:header_end].decode("latin-1")
        content = part[header_end + 4:]
        if content.endswith(b"\r\n"):
            content = content[:-2]
        fname_match = re.search(r'name="file"[^\r\n]*filename="([^"]*)"', headers)
        if fname_match:
            return fname_match.group(1) or "sample.bin", content
    return None


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def do_GET(self) -> None:  # noqa: N802 - stdlib method name
        path = self.path.split("?", 1)[0]
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)

        if path == "/v1/health":
            self._json(200, {"status": "ok"})
            return

        match = re.match(r"^/status/([a-f0-9]{32})$", path)
        if match:
            job_id = match.group(1)
            with _lock:
                job = _jobs.get(job_id)
            if job is None:
                self._json(404, {"error": "job not found"})
                return
            self._json(200, job)
            return

        match = re.match(r"^/results/([a-f0-9]{32})/(functions|strings|imports)$", path)
        if match:
            job_id, kind = match.groups()
            with _lock:
                job = _jobs.get(job_id)
            if job is None or job.get("status") != "done":
                self._json(404, {"error": "result not available"})
                return
            artifact = job_dir(job_id) / "artifacts" / f"{kind}.json"
            try:
                data = json.loads(artifact.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                self._json(404, {"error": "artifact missing"})
                return
            if kind == "functions":
                offset = int(params.get("offset", 0))
                limit = int(params.get("limit", 100))
                all_functions = data.get("functions", [])
                self._json(200, {
                    "total": len(all_functions),
                    "offset": offset,
                    "limit": limit,
                    "functions": all_functions[offset:offset + limit],
                })
                return
            self._json(200, data)
            return

        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/analyze":
            self._json(404, {"error": "not found"})
            return
        body = self._read_body()
        parsed = parse_multipart_file(body, self.headers.get("Content-Type", ""))
        if parsed is None:
            self._json(400, {"error": "no file field in multipart body"})
            return
        _filename, content = parsed

        job_id = uuid.uuid4().hex
        jdir = job_dir(job_id)
        (jdir / "artifacts").mkdir(parents=True)
        (jdir / "sample.bin").write_bytes(content)
        with _lock:
            _jobs[job_id] = {"job_id": job_id, "status": "queued", "created_at": time.time()}
        _queue.put(job_id)
        self._json(200, {"job_id": job_id, "status": "queued"})

    def log_message(self, fmt, *args) -> None:  # noqa: A003 - stdlib signature
        pass  # container logs already capture stdout; avoid double-logging every request


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=worker_loop, daemon=True).start()
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
