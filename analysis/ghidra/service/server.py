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

Also covers the extra surface a locally-evaluated Rev·Deck rewrite (#1164)
needs and our own minimal service didn't have before (verified live against
that rewrite's webui/app.py and webui/ghidra_assistant.py, not guessed at):

    POST /analyze_b64              JSON {file_b64, filename, persist}
    GET  /jobs
    DELETE /jobs/{job_id}
    POST /tools/status              JSON {job_id}
    POST /tools/list_functions      JSON {job_id, offset, limit}
    POST /tools/list_imports        JSON {job_id}
    POST /tools/list_strings        JSON {job_id, min_length}
    POST /tools/query_artifacts     JSON {job_id, query, regex}
    POST /tools/decompile_function  JSON {job_id, addr}
    POST /tools/get_xrefs           JSON {job_id, addr}

Deliberately stdlib-only, matching worker/ghidra-worker.py's own rule for
the same reason: this replaces a single-maintainer third-party dependency,
so it should not trade that risk for a pip dependency tree of its own.
Runs `support/analyzeHeadless` as a subprocess with -postScript
export_json.py (this directory) -- the actual decompilation/extraction
logic lives entirely in that Jython script via Ghidra's own public
scripting API, not here.
"""
import base64
import binascii
import concurrent.futures
import hashlib
import http.server
import io
import json
import os
import queue
import re
import shutil
import subprocess
import threading
import time
import uuid
import zipfile
from pathlib import Path
from urllib.parse import parse_qsl

GHIDRA_BIN = os.environ.get("GHIDRA_ANALYZE_HEADLESS", "/opt/ghidra/support/analyzeHeadless")
SCRIPT_DIR = os.environ.get("GHIDRA_SCRIPT_DIR", "/opt/service")
DATA_DIR = Path(os.environ.get("GHIDRA_DATA_DIR", "/data/ghidra_projects"))
ANALYSIS_TIMEOUT = int(os.environ.get("ANALYSIS_TIMEOUT", "3600"))
PORT = int(os.environ.get("PORT", "9090"))

REQUIRED_ARTIFACTS = ("functions.json", "strings.json", "imports.json")

# The 3 real artifact files a route can ever be asked to read, keyed by the
# same literal alternation the /results/{job}/{kind} route regex matches --
# an explicit allow-list dict, not an f-string built from the request path,
# so "kind" can never become an arbitrary filename regardless of what a
# future route change might accidentally let through.
ARTIFACT_FILES = {"functions": "functions.json", "strings": "strings.json", "imports": "imports.json"}

_JOB_ID_RE = re.compile(r"^[a-f0-9]{32}$")

_lock = threading.RLock()
_jobs: dict[str, dict] = {}
_queue: "queue.Queue[str]" = queue.Queue()
# The Popen for whichever job is currently running, keyed by job_id (#1164's
# POST /v1/jobs/{id}/cancel needs a live handle to actually kill it -- a
# queued-but-not-yet-started job has no entry here, see _run_job's own
# cancelled-status check for that half of cancellation).
_running_processes: dict[str, subprocess.Popen] = {}
# sha256 -> job_id, for start_job's dedup (#1164's "deduplication" capability).
# In-memory only, same lifetime as _jobs itself -- this service has never
# persisted job state across restarts, dedup doesn't need to be the first
# exception to that.
_hash_to_job: dict[str, str] = {}


def _assert_within_data_dir(path: Path) -> Path:
    # Every job_id reaching here already passed _JOB_ID_RE (^[a-f0-9]{32}$)
    # at the route regex and again in job_dir() -- this is a second,
    # independent containment check against the trusted root, real defense
    # in depth even though the value can't structurally contain "/" or "..".
    # CodeQL's py/path-injection query still flags this (and every caller)
    # because it doesn't model a regex-match guard as a sanitizer across
    # function boundaries, and it treats resolve() itself as a sink since it
    # touches the filesystem. Reviewed and accepted: this is an internal,
    # docker-network-only analysis service with no untrusted job_id source.
    resolved = path.resolve()
    if not resolved.is_relative_to(DATA_DIR.resolve()):
        raise ValueError(f"path escapes data dir: {path}")
    return resolved


def job_dir(job_id: str) -> Path:
    # Re-validated here, not just at the route regex that produced job_id --
    # this is the actual trust boundary before the value touches a
    # filesystem path, and every caller (including internal ones from the
    # worker thread) goes through this one function.
    if not _JOB_ID_RE.match(job_id):
        raise ValueError(f"invalid job_id: {job_id!r}")
    return _assert_within_data_dir(DATA_DIR / job_id)


def update_job(job_id: str, **changes) -> None:
    with _lock:
        _jobs[job_id].update(changes)


def start_job(content: bytes, dedupe: bool = True) -> dict:
    # Shared by /analyze (multipart), /analyze_b64 (JSON), and POST /v1/jobs
    # (multipart, #1164) -- all three just need the raw sample bytes on disk
    # and a job queued; they differ only in how "content" comes out of the
    # request body.
    sha256 = hashlib.sha256(content).hexdigest()
    if dedupe:
        with _lock:
            existing_id = _hash_to_job.get(sha256)
            existing = _jobs.get(existing_id) if existing_id else None
            # A previously failed/cancelled run of this same sample is not
            # reused -- an operator resubmitting after a failure means "try
            # again", not "show me the same failure".
            if existing is not None and existing.get("status") in ("queued", "running", "done"):
                return {"job_id": existing_id, "reused_job_id": existing_id, "status": existing["status"]}

    job_id = uuid.uuid4().hex
    jdir = job_dir(job_id)
    (jdir / "artifacts").mkdir(parents=True)
    (jdir / "sample.bin").write_bytes(content)
    with _lock:
        _jobs[job_id] = {"job_id": job_id, "status": "queued", "created_at": time.time(), "sha256": sha256}
        _hash_to_job[sha256] = job_id
    _queue.put(job_id)
    return {"job_id": job_id, "status": "queued"}


# --- annotations (#1164) ---------------------------------------------------
# A per-job sidecar overlay -- never edits to the exported analysis
# artifacts themselves, which stay read-only outputs of one analyzeHeadless
# run. Lives directly in the job dir (not under artifacts/), guarded by the
# same _lock as everything else here: writes are human-paced (an analyst or
# the chat loop annotating a handful of functions), not a throughput path,
# so one coarse lock is simpler than a per-job one and costs nothing real.
def _annotations_path(job_id: str) -> Path:
    return job_dir(job_id) / "annotations.json"


def _load_annotations(job_id: str) -> dict:
    path = _assert_within_data_dir(_annotations_path(job_id))
    try:
        data = json.loads(path.read_text())
        if isinstance(data, dict) and isinstance(data.get("entries"), dict):
            return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return {"revision": 0, "entries": {}}


def _save_annotations(job_id: str, data: dict) -> None:
    _assert_within_data_dir(_annotations_path(job_id)).write_text(json.dumps(data))


def worker_loop() -> None:
    while True:
        job_id = _queue.get()
        try:
            _run_job(job_id)
        finally:
            _queue.task_done()


def _run_job(job_id: str) -> None:
    # A job cancelled (#1164/POST /v1/jobs/{id}/cancel) while still queued
    # never had a process to kill -- this is the other half of that: skip
    # actually starting Ghidra for it once the worker gets here.
    with _lock:
        if _jobs.get(job_id, {}).get("status") == "cancelled":
            return

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
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as exc:  # noqa: BLE001 - report, don't crash the worker thread
        update_job(job_id, status="failed", completed_at=time.time(),
                   error_code="internal_error", message=str(exc)[:512])
        return
    with _lock:
        _running_processes[job_id] = proc

    timed_out = False
    try:
        try:
            stdout, stderr = proc.communicate(timeout=ANALYSIS_TIMEOUT)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            stdout, stderr = proc.communicate()
    except Exception as exc:  # noqa: BLE001
        with _lock:
            _running_processes.pop(job_id, None)
        update_job(job_id, status="failed", completed_at=time.time(),
                   error_code="internal_error", message=str(exc)[:512])
        return
    with _lock:
        _running_processes.pop(job_id, None)

    (jdir / "analysis.log").write_bytes(stdout + b"\n--- stderr ---\n" + stderr)
    # _v1_cancel_job (#1164) may have killed this process and already set a
    # terminal "cancelled" status while communicate() above was unwinding --
    # that status is authoritative and must not be clobbered by whatever
    # exit code SIGTERM/SIGKILL happened to leave behind.
    with _lock:
        if _jobs.get(job_id, {}).get("status") == "cancelled":
            return
    if timed_out:
        update_job(job_id, status="failed", completed_at=time.time(),
                   error_code="timeout", message="Ghidra analysis timed out")
        return
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
        filename = _extract_file_filename(headers)
        if filename is not None:
            return filename or "sample.bin", content
    return None


def _extract_file_filename(headers: str) -> str | None:
    """Pull filename="..." out of the "file" field's Content-Disposition
    line, via plain string search rather than a regex -- headers is
    attacker-controlled (part of the request body), and a backtracking
    regex over it is exactly the shape a polynomial ReDoS needs.
    """
    for line in headers.split("\r\n"):
        if 'name="file"' not in line:
            continue
        marker = 'filename="'
        start = line.find(marker)
        if start == -1:
            return None
        start += len(marker)
        end = line.find('"', start)
        if end == -1:
            return None
        return line[start:end]
    return None


# --- /tools/{endpoint} (#1164) --------------------------------------------
# A locally-evaluated Rev·Deck rewrite's chat tool-calling loop
# (webui/ghidra_assistant.py's TOOLS + call_ghidra_tool) POSTs JSON here,
# one endpoint per tool. Every handler below reads from the same artifact
# files /results/{job}/{kind} already reads (plus xrefs.json/decompiled.json,
# #1164/export_json.py) -- no live Ghidra process involved, so these stay as
# fast as the existing routes.

TOOL_ARTIFACT_FILES = {
    "functions.json", "strings.json", "imports.json", "xrefs.json", "decompiled.json",
    "globals.json", "types.json", "memory_map.json",
}


def _read_job_artifact(job_id: str, filename: str):
    # filename is always one of the literal strings in TOOL_ARTIFACT_FILES
    # above, never derived from request input -- job_id is the only
    # attacker-influenced part of this path, and job_dir() already
    # re-validates it. The normpath+startswith check is defense in depth,
    # not load-bearing the way it is for /results/{job}/{kind} (there,
    # "kind" comes from the request path).
    assert filename in TOOL_ARTIFACT_FILES
    artifacts_root = os.path.normpath(str(job_dir(job_id) / "artifacts"))
    artifact_path = os.path.normpath(os.path.join(artifacts_root, filename))
    if not artifact_path.startswith(artifacts_root + os.sep):
        return None
    try:
        return json.loads(Path(artifact_path).read_text())
    except (FileNotFoundError, json.JSONDecodeError, ValueError, OSError):
        return None


def _normalize_addr(value) -> str | None:
    # Chat-supplied addresses arrive in whatever case/leading-zero shape the
    # model or analyst typed ("0x00401000", "401000", "0X401000", ...);
    # decompiled.json/xrefs.json are keyed by addr_str()'s own canonical
    # form (export_json.py: "0x%x" % offset, lowercase, no leading zeros).
    if not isinstance(value, str):
        return None
    value = value.strip()
    if value.lower().startswith("0x"):
        value = value[2:]
    if not value:
        return None
    try:
        return "0x%x" % int(value, 16)
    except ValueError:
        return None


def _tool_status(job_id: str, payload: dict):
    with _lock:
        job = _jobs.get(job_id)
    if job is None:
        return 404, {"error": "job not found"}
    return 200, job


def _tool_list_functions(job_id: str, payload: dict):
    data = _read_job_artifact(job_id, "functions.json")
    if data is None:
        return 404, {"error": "result not available"}
    offset = int(payload.get("offset") or 0)
    limit = int(payload.get("limit") or 100)
    all_functions = data.get("functions", [])
    # q (#1164/main's fetch_functions "q" param, v1 route only -- the older
    # chat tool-calling schema never sends it): a case-insensitive substring
    # match against the function name, applied before offset/limit so
    # pagination is over the filtered set, not the full one.
    query = (payload.get("q") or "").strip().lower()
    if query:
        all_functions = [fn for fn in all_functions if query in fn.get("name", "").lower()]
    return 200, {
        "total": len(all_functions),
        "offset": offset,
        "limit": limit,
        "functions": all_functions[offset:offset + limit],
    }


def _tool_list_imports(job_id: str, payload: dict):
    data = _read_job_artifact(job_id, "imports.json")
    if data is None:
        return 404, {"error": "result not available"}
    # offset/limit are v1-route-only (main's fetch_imports paginates; the
    # older tools/list_imports caller never sends them, and omitting both
    # here returns the whole list unsliced, matching that caller's
    # expectations).
    if "offset" in payload or "limit" in payload:
        offset = int(payload.get("offset") or 0)
        limit = int(payload.get("limit") or 100)
        return 200, {"total": len(data), "offset": offset, "limit": limit, "imports": data[offset:offset + limit]}
    return 200, {"imports": data}


def _tool_list_strings(job_id: str, payload: dict):
    data = _read_job_artifact(job_id, "strings.json")
    if data is None:
        return 404, {"error": "result not available"}
    min_length = int(payload.get("min_length") or 0)
    strings = [s for s in data.get("strings", []) if len(s.get("s", "")) >= min_length]
    # offset/limit are v1-route-only, same reasoning as _tool_list_imports.
    if "offset" in payload or "limit" in payload:
        offset = int(payload.get("offset") or 0)
        limit = int(payload.get("limit") or 100)
        return 200, {
            "count": len(strings), "offset": offset, "limit": limit,
            "strings": strings[offset:offset + limit],
        }
    return 200, {"count": len(strings), "strings": strings}


def _v1_list_types(job_id: str, params: dict):
    # No legacy tools/* equivalent (#1164/main's fetch_types has no
    # synthesis fallback), so this reads types.json directly rather than
    # going through a shared _tool_* handler the way functions/imports/
    # strings do -- there is no second caller to keep compatible with.
    data = _read_job_artifact(job_id, "types.json")
    if data is None:
        return 404, {"error": "result not available"}
    offset = int(params.get("offset") or 0)
    limit = int(params.get("limit") or 100)
    all_types = data.get("types", [])
    return 200, {"total": len(all_types), "offset": offset, "limit": limit, "types": all_types[offset:offset + limit]}


def _v1_list_globals(job_id: str, params: dict):
    data = _read_job_artifact(job_id, "globals.json")
    if data is None:
        return 404, {"error": "result not available"}
    offset = int(params.get("offset") or 0)
    limit = int(params.get("limit") or 100)
    all_globals = data.get("globals", [])
    return 200, {
        "total": len(all_globals), "offset": offset, "limit": limit,
        "globals": all_globals[offset:offset + limit],
    }


def _v1_hexdump(job_id: str, addr: str, length: int):
    norm_addr = _normalize_addr(addr)
    if norm_addr is None:
        return 400, {"error": "addr is not a valid hex address"}
    length = max(1, min(int(length), 4096))

    mem_map = _read_job_artifact(job_id, "memory_map.json")
    if mem_map is None:
        return 404, {"error": "result not available"}

    target = int(norm_addr, 16)
    block = None
    for candidate in mem_map.get("blocks", []):
        start = int(candidate["start"], 16)
        end = int(candidate["end"], 16)
        if start <= target <= end:
            block = candidate
            break
    if block is None:
        return 404, {"error": "the requested address was not exported for this program"}

    block_start = int(block["start"], 16)
    available = block["size"] - (target - block_start)
    if available <= 0:
        return 404, {"error": "the requested address was not exported for this program"}
    read_length = min(length, available)
    file_offset = block["file_offset"] + (target - block_start)

    memory_path = _assert_within_data_dir(job_dir(job_id) / "artifacts" / "memory.bin")
    try:
        with open(memory_path, "rb") as f:
            f.seek(file_offset)
            data = f.read(read_length)
    except (FileNotFoundError, OSError):
        return 404, {"error": "result not available"}

    return 200, {
        "addr": norm_addr,
        "length": len(data),
        "hex": data.hex(),
        "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data),
    }


_ENTRY_FIELDS = ("display_name", "comment", "tags", "confidence")


def _v1_get_annotations(job_id: str, addr_filter: str | None):
    with _lock:
        data = _load_annotations(job_id)
    if addr_filter:
        norm = _normalize_addr(addr_filter)
        entries = {norm: data["entries"][norm]} if norm and norm in data["entries"] else {}
        return 200, {"revision": data["revision"], "entries": entries}
    return 200, dict(data)


def _v1_put_annotation(job_id: str, addr: str, payload: dict, if_match: str | None):
    norm = _normalize_addr(addr)
    if norm is None:
        return 400, {"error": "addr is not a valid hex address"}

    expected = None
    if if_match:
        expected = if_match.strip('"')
    elif isinstance(payload.get("revision"), (int, str)):
        expected = str(payload["revision"])

    with _lock:
        data = _load_annotations(job_id)
        if expected is not None and expected != str(data["revision"]):
            return 409, {"error": "conflict", "revision": data["revision"]}
        entry = dict(data["entries"].get(norm) or {})
        for key in _ENTRY_FIELDS:
            if key in payload:
                entry[key] = payload[key]
        data["entries"][norm] = entry
        data["revision"] += 1
        _save_annotations(job_id, data)
        result = dict(entry)
        result["addr"] = norm
        result["revision"] = data["revision"]
        return 200, result


def _v1_patch_annotations(job_id: str, entries_payload, if_match: str | None):
    if not isinstance(entries_payload, list):
        return 400, {"error": "annotations must be a list"}
    expected = if_match.strip('"') if if_match else None
    with _lock:
        data = _load_annotations(job_id)
        if expected is not None and expected != str(data["revision"]):
            return 409, {"error": "conflict", "revision": data["revision"]}
        updated = []
        for raw in entries_payload:
            if not isinstance(raw, dict):
                continue
            norm = _normalize_addr(raw.get("entity_id") or raw.get("addr"))
            if norm is None:
                continue
            entry = dict(data["entries"].get(norm) or {})
            for key in _ENTRY_FIELDS:
                if key in raw:
                    entry[key] = raw[key]
            data["entries"][norm] = entry
            updated.append(dict(entry, addr=norm))
        data["revision"] += 1
        _save_annotations(job_id, data)
        return 200, {"revision": data["revision"], "annotations": updated}


def _delete_job(job_id: str):
    # Shared by the legacy DELETE /jobs/{id} and the v1 DELETE /v1/jobs/{id}
    # -- same removal, two paths in. The capture itself is evidence, not
    # scratch state, so this removes the job's tracking entry and on-disk
    # directory (sample, artifacts, project files) rather than leaving
    # orphaned data with no way to reach it through /status or /results.
    with _lock:
        job = _jobs.pop(job_id, None)
        _running_processes.pop(job_id, None)
        if job is not None:
            _hash_to_job.pop(job.get("sha256"), None)
        existed = job is not None
    jdir = _assert_within_data_dir(job_dir(job_id))
    if jdir.is_dir():
        shutil.rmtree(jdir, ignore_errors=True)
    elif not existed:
        return 404, {"error": "job not found"}
    return 200, {"job_id": job_id, "deleted": True}


def _v1_cancel_job(job_id: str):
    with _lock:
        job = _jobs.get(job_id)
        if job is None:
            return 404, {"error": "job not found"}
        if job.get("status") not in ("queued", "running"):
            return 409, {"error": "job already reached a terminal state"}
        proc = _running_processes.get(job_id)
        job["status"] = "cancelled"
        job["completed_at"] = time.time()
        result = dict(job)
    # Terminate outside the lock: proc.terminate() doesn't block, but there
    # is no reason to hold _jobs' lock across even a non-blocking syscall.
    # _run_job's own post-communicate() cancelled-check (same lock) is what
    # actually stops it from overwriting this status once the killed
    # process's communicate() call unblocks.
    if proc is not None:
        try:
            proc.terminate()
        except OSError:
            pass
    return 200, result


def _v1_export_job(job_id: str):
    artifacts_dir = _assert_within_data_dir(job_dir(job_id) / "artifacts")
    if not artifacts_dir.is_dir():
        return None
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(artifacts_dir.iterdir()):
            if path.is_file():
                zf.write(path, arcname=path.name)
        annotations_path = _assert_within_data_dir(_annotations_path(job_id))
        if annotations_path.is_file():
            zf.write(annotations_path, arcname="annotations.json")
    return buf.getvalue()


# A regex query's pattern AND target text are both attacker-controlled (the
# uploaded sample drives function/string names) -- catastrophic backtracking
# is a real risk here, not a hypothetical one. Python's re module has no
# built-in execution budget, so the whole filter pass runs in a worker
# thread with a hard wall-clock cap; a runaway match times out the request
# instead of hanging the handler (the thread itself can't be killed, but it
# no longer blocks a response).
_QUERY_TIMEOUT_SECONDS = float(os.environ.get("GHIDRA_QUERY_TIMEOUT_SECONDS", "2"))
_query_executor = concurrent.futures.ThreadPoolExecutor(max_workers=8, thread_name_prefix="query-filter")


def _tool_query_artifacts(job_id: str, payload: dict):
    query = payload.get("query") or ""
    if not query:
        return 400, {"error": "query is required"}
    use_regex = bool(payload.get("regex"))
    if use_regex and len(query) > 200:
        return 400, {"error": "regex query is too long (max 200 chars)"}
    try:
        matcher = re.compile(query) if use_regex else None
    except re.error as exc:
        return 400, {"error": f"invalid regex: {exc}"}

    def matches(text: str) -> bool:
        # regex=true is an intentional, documented feature of this query tool
        # (an analyst searching function/string names) -- a length cap plus a
        # hard wall-clock timeout on the whole filter pass (see run_filter()
        # below) already bounds the catastrophic-backtracking blast radius.
        return bool(matcher.search(text)) if matcher else query.lower() in text.lower()

    functions_data = _read_job_artifact(job_id, "functions.json") or {"functions": []}
    strings_data = _read_job_artifact(job_id, "strings.json") or {"strings": []}

    def run_filter():
        matched_functions = [fn for fn in functions_data.get("functions", []) if matches(fn.get("name", ""))]
        matched_strings = [s for s in strings_data.get("strings", []) if matches(s.get("s", ""))]
        return matched_functions, matched_strings

    future = _query_executor.submit(run_filter)
    try:
        matched_functions, matched_strings = future.result(timeout=_QUERY_TIMEOUT_SECONDS)
    except concurrent.futures.TimeoutError:
        return 408, {"error": "query took too long to evaluate (pattern may be pathological)"}

    return 200, {
        "query": query, "regex": use_regex,
        "matches": {"functions": matched_functions[:200], "strings": matched_strings[:200]},
    }


def _tool_decompile_function(job_id: str, payload: dict):
    addr = _normalize_addr(payload.get("addr"))
    if addr is None:
        return 400, {"error": "addr is required and must be a hex address"}
    data = _read_job_artifact(job_id, "decompiled.json")
    if data is None:
        return 404, {"error": "result not available"}
    entry = (data.get("functions") or {}).get(addr)
    if entry is None:
        return 404, {"error": f"no decompilation for {addr} (may be past the per-job decompile cap)"}
    result = dict(entry)
    result["addr"] = addr
    return 200, result


def _tool_get_xrefs(job_id: str, payload: dict):
    addr = _normalize_addr(payload.get("addr"))
    if addr is None:
        return 400, {"error": "addr is required and must be a hex address"}
    data = _read_job_artifact(job_id, "xrefs.json")
    if data is None:
        return 404, {"error": "result not available"}
    entry = data.get(addr)
    if entry is None:
        return 404, {"error": f"no xrefs recorded for {addr}"}
    result = dict(entry)
    result["addr"] = addr
    return 200, result


TOOL_HANDLERS = {
    "status": _tool_status,
    "list_functions": _tool_list_functions,
    "list_imports": _tool_list_imports,
    "list_strings": _tool_list_strings,
    "query_artifacts": _tool_query_artifacts,
    "decompile_function": _tool_decompile_function,
    "get_xrefs": _tool_get_xrefs,
}

# --- /v1/* (#1164) ---------------------------------------------------------
# A second, richer contract a locally-evaluated Rev·Deck rewrite's own main
# branch (not the PR this service's /tools/* and /analyze_b64 above were
# built against) prefers when present, falling back to the /tools/*
# endpoints above on 404/405 route-by-route -- verified against a real
# clone of that branch's webui/ghidra_client.py, not guessed at. Every v1
# route here is additive: nothing above changes shape or behavior.

# Service-vocabulary capability names this build actually implements.
# security_index (attack-surface/vulnerability triage scoring) and
# string_references (data-xref reverse lookup) are deliberately left False
# -- both need real new analysis methodology, not just routing, and are
# out of scope here; every other v1 route below is a real implementation,
# not a stub that returns empty data.
V1_CAPABILITIES = {
    "summary": True,
    "types": True,
    "globals": True,
    "annotations": True,
    "graph_neighborhood": True,
    "multipart_upload": True,
    "hexdump": True,
    "export": True,
    "cancellation": True,
    "deduplication": True,
    "string_references": False,
    "security_index": False,
}


def _build_summary(job_id: str) -> dict:
    with _lock:
        job = dict(_jobs.get(job_id) or {})
    functions_data = _read_job_artifact(job_id, "functions.json") or {}
    strings_data = _read_job_artifact(job_id, "strings.json") or {}
    imports_data = _read_job_artifact(job_id, "imports.json")
    globals_data = _read_job_artifact(job_id, "globals.json") or {}
    types_data = _read_job_artifact(job_id, "types.json") or {}
    xrefs_data = _read_job_artifact(job_id, "xrefs.json") or {}
    return {
        "job_id": job_id,
        "status": job.get("status"),
        "program": job.get("filename"),
        "counts": {
            "functions": functions_data.get("total", 0),
            "strings": strings_data.get("count", 0),
            "imports": len(imports_data) if isinstance(imports_data, list) else 0,
            "globals": globals_data.get("total", 0),
            "types": types_data.get("total", 0),
            "functions_with_xrefs": len(xrefs_data),
        },
        "source": "v1",
    }


def _v1_query(job_id: str, payload: dict):
    # _tool_query_artifacts' {"matches": {"functions":[...], "strings":[...]}}
    # shape is what the legacy chat tool-calling loop expects -- main's own
    # ghidra_client._normalize_query wants a flat list instead (falls back
    # to an empty result otherwise, since it only recognizes "matches" as a
    # list, never a dict), so this adapts the same underlying search into
    # the v1 shape rather than duplicating the search logic itself.
    status, result = _tool_query_artifacts(job_id, payload)
    if status != 200:
        return status, result
    matches = [dict(fn, type="function") for fn in result["matches"]["functions"]]
    matches += [dict(s, type="string") for s in result["matches"]["strings"]]
    return 200, {"query": result["query"], "regex": result["regex"], "matches": matches, "count": len(matches)}


def _build_callgraph(job_id: str, addr: str, depth: int, max_nodes: int, max_edges: int):
    # Native server-side counterpart to ghidra_client._synthesize_callgraph
    # -- same bounded-BFS algorithm and same node/edge caps, just run here
    # (one request, reading xrefs.json directly) instead of the client
    # doing it itself over N separate get_xrefs round-trips.
    xrefs_data = _read_job_artifact(job_id, "xrefs.json")
    if xrefs_data is None:
        return 404, {"error": "result not available"}

    depth = max(0, min(depth, 4))
    max_nodes = max(1, min(max_nodes, 200))
    max_edges = max(1, min(max_edges, 400))

    nodes = {addr}
    node_names = {}
    edges = []
    edge_seen = set()
    visited = set()
    queue = [(addr, depth)]
    truncated = False

    while queue:
        current, hops = queue.pop(0)
        if hops <= 0 or current in visited:
            continue
        visited.add(current)
        entry = xrefs_data.get(current)
        if entry is None:
            continue
        for caller in entry.get("callers", []):
            caddr, cname = caller.get("addr"), caller.get("name")
            if not caddr:
                continue
            edge_key = (caddr, current)
            if edge_key not in edge_seen:
                if len(edges) >= max_edges:
                    truncated = True
                    continue
                edge_seen.add(edge_key)
                edges.append({"from": caddr, "to": current})
            if cname:
                node_names[caddr] = cname
            if caddr not in nodes:
                if len(nodes) >= max_nodes:
                    truncated = True
                    continue
                nodes.add(caddr)
                queue.append((caddr, hops - 1))
        for callee in entry.get("callees", []):
            eaddr, ename = callee.get("addr"), callee.get("name")
            if not eaddr:
                continue
            edge_key = (current, eaddr)
            if edge_key not in edge_seen:
                if len(edges) >= max_edges:
                    truncated = True
                    continue
                edge_seen.add(edge_key)
                edges.append({"from": current, "to": eaddr})
            if ename:
                node_names[eaddr] = ename
            if eaddr not in nodes:
                if len(nodes) >= max_nodes:
                    truncated = True
                    continue
                nodes.add(eaddr)
                queue.append((eaddr, hops - 1))

    return 200, {
        "root": addr, "nodes": sorted(nodes), "node_names": node_names,
        "edges": edges, "depth": depth, "truncated": truncated, "source": "v1",
    }


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _json(self, status: int, payload) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _binary(self, status: int, content_type: str, body: bytes, filename: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if filename:
            safe_filename = filename.replace('"', "").replace("\r", "").replace("\n", "")
            self.send_header("Content-Disposition", f'attachment; filename="{safe_filename}"')
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    # A bug in any one route handler must not turn into a dropped/reset
    # connection for that request -- http.server's default behavior on an
    # uncaught exception is to close the socket with no response at all,
    # which every client here (the worker, revdeck's own webui) would see
    # as a connection error indistinguishable from the service being down.
    # A clean 500 is diagnosable; a reset connection is not.
    def do_GET(self) -> None:  # noqa: N802 - stdlib method name
        try:
            self._do_GET()
        except Exception as exc:  # noqa: BLE001 - last-resort route safety net
            self._json(500, {"error": "internal error", "detail": str(exc)[:200]})

    def do_POST(self) -> None:  # noqa: N802
        try:
            self._do_POST()
        except Exception as exc:  # noqa: BLE001
            self._json(500, {"error": "internal error", "detail": str(exc)[:200]})

    def do_DELETE(self) -> None:  # noqa: N802
        try:
            self._do_DELETE()
        except Exception as exc:  # noqa: BLE001
            self._json(500, {"error": "internal error", "detail": str(exc)[:200]})

    def do_PUT(self) -> None:  # noqa: N802
        try:
            self._do_PUT()
        except Exception as exc:  # noqa: BLE001
            self._json(500, {"error": "internal error", "detail": str(exc)[:200]})

    def do_PATCH(self) -> None:  # noqa: N802
        try:
            self._do_PATCH()
        except Exception as exc:  # noqa: BLE001
            self._json(500, {"error": "internal error", "detail": str(exc)[:200]})

    def _do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        # parse_qsl url-decodes (needed for the free-text "q" search param
        # below) and handles a repeated key sanely, unlike the old hand-
        # split version this replaces -- every existing caller only ever
        # sent plain-ASCII digits (offset/limit), so this is behavior-
        # preserving for them.
        params = dict(parse_qsl(query))

        if path == "/v1/health":
            self._json(200, {"status": "ok"})
            return

        if path == "/v1/capabilities":
            self._json(200, {"capabilities": V1_CAPABILITIES})
            return

        match = re.match(r"^/v1/results/([a-f0-9]{32})/(functions|imports|strings|summary)$", path)
        if match:
            job_id, kind = match.groups()
            with _lock:
                job = _jobs.get(job_id)
            if job is None or job.get("status") != "done":
                self._json(404, {"error": "result not available"})
                return
            if kind == "summary":
                self._json(200, _build_summary(job_id))
                return
            tool_name = {"functions": "list_functions", "imports": "list_imports", "strings": "list_strings"}[kind]
            status, result = TOOL_HANDLERS[tool_name](job_id, params)
            self._json(status, result)
            return

        match = re.match(r"^/v1/jobs/([a-f0-9]{32})/summary$", path)
        if match:
            job_id = match.group(1)
            with _lock:
                job = _jobs.get(job_id)
            if job is None or job.get("status") != "done":
                self._json(404, {"error": "result not available"})
                return
            self._json(200, _build_summary(job_id))
            return

        match = re.match(r"^/v1/jobs/([a-f0-9]{32})/annotations$", path)
        if match:
            job_id = match.group(1)
            with _lock:
                job = _jobs.get(job_id)
            if job is None:
                self._json(404, {"error": "job not found"})
                return
            status, result = _v1_get_annotations(job_id, params.get("addr"))
            self._json(status, result)
            return

        match = re.match(r"^/v1/results/([a-f0-9]{32})/function/([0-9a-fA-Fx]+)/decompile$", path)
        if match:
            job_id, addr = match.groups()
            with _lock:
                job = _jobs.get(job_id)
            if job is None or job.get("status") != "done":
                self._json(404, {"error": "result not available"})
                return
            status, result = _tool_decompile_function(job_id, {"addr": addr})
            self._json(status, result)
            return

        match = re.match(r"^/v1/results/([a-f0-9]{32})/xrefs/([0-9a-fA-Fx]+)$", path)
        if match:
            job_id, addr = match.groups()
            with _lock:
                job = _jobs.get(job_id)
            if job is None or job.get("status") != "done":
                self._json(404, {"error": "result not available"})
                return
            status, result = _tool_get_xrefs(job_id, {"addr": addr})
            self._json(status, result)
            return

        match = re.match(r"^/v1/results/([a-f0-9]{32})/graph/([0-9a-fA-Fx]+)$", path)
        if match:
            job_id, addr = match.groups()
            norm_addr = _normalize_addr(addr)
            if norm_addr is None:
                self._json(400, {"error": "addr is not a valid hex address"})
                return
            with _lock:
                job = _jobs.get(job_id)
            if job is None or job.get("status") != "done":
                self._json(404, {"error": "result not available"})
                return
            try:
                depth = int(params.get("depth", 2))
            except ValueError:
                depth = 2
            try:
                limit = int(params.get("limit", 40))
            except ValueError:
                limit = 40
            status, result = _build_callgraph(job_id, norm_addr, depth, limit, max_edges=80)
            self._json(status, result)
            return

        match = re.match(r"^/v1/results/([a-f0-9]{32})/(types|globals)$", path)
        if match:
            job_id, kind = match.groups()
            with _lock:
                job = _jobs.get(job_id)
            if job is None or job.get("status") != "done":
                self._json(404, {"error": "result not available"})
                return
            handler = _v1_list_types if kind == "types" else _v1_list_globals
            status, result = handler(job_id, params)
            self._json(status, result)
            return

        match = re.match(r"^/v1/results/([a-f0-9]{32})/hexdump/([0-9a-fA-Fx]+)$", path)
        if match:
            job_id, addr = match.groups()
            with _lock:
                job = _jobs.get(job_id)
            if job is None or job.get("status") != "done":
                self._json(404, {"error": "result not available"})
                return
            try:
                length = int(params.get("length", 16))
            except ValueError:
                length = 16
            status, result = _v1_hexdump(job_id, addr, length)
            self._json(status, result)
            return

        if path == "/jobs":
            # #1164: called with a 0.5s client-side timeout (revdeck's own
            # GHIDRA_FAST_TIMEOUT_SECONDS) and falls back to its local job
            # cache on any failure -- an in-memory dict copy is well inside
            # that budget, no artifact-file reads needed here.
            with _lock:
                jobs = list(_jobs.values())
            self._json(200, jobs)
            return

        if path == "/v1/jobs":
            with _lock:
                jobs = list(_jobs.values())
            self._json(200, {"items": jobs})
            return

        match = re.match(r"^/v1/jobs/([a-f0-9]{32})/export$", path)
        if match:
            job_id = match.group(1)
            with _lock:
                job = _jobs.get(job_id)
            if job is None or job.get("status") != "done":
                self._json(404, {"error": "result not available"})
                return
            archive = _v1_export_job(job_id)
            if archive is None:
                self._json(404, {"error": "result not available"})
                return
            self._binary(200, "application/zip", archive, filename=f"{job_id}.zip")
            return

        match = re.match(r"^/v1/jobs/([a-f0-9]{32})$", path)
        if match:
            job_id = match.group(1)
            with _lock:
                job = _jobs.get(job_id)
            if job is None:
                self._json(404, {"error": "job not found"})
                return
            self._json(200, job)
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
            # job_dir()'s regex check and ARTIFACT_FILES' allow-list already
            # make this safe, but CodeQL's py/path-injection query doesn't
            # trace a sanitizer through a helper function call, and doesn't
            # recognize an equality check against a recomputed path as a
            # sanitizer either -- it wants the exact normalize-then-
            # startswith-a-known-root shape its own alert recommendation
            # shows, evaluated inline at the read site.
            artifacts_root = os.path.normpath(str(job_dir(job_id) / "artifacts"))
            artifact_path = os.path.normpath(os.path.join(artifacts_root, ARTIFACT_FILES[kind]))
            if not artifact_path.startswith(artifacts_root + os.sep):
                self._json(404, {"error": "artifact missing"})
                return
            artifact = Path(artifact_path)
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

    def _do_POST(self) -> None:
        if self.path == "/analyze":
            body = self._read_body()
            parsed = parse_multipart_file(body, self.headers.get("Content-Type", ""))
            if parsed is None:
                self._json(400, {"error": "no file field in multipart body"})
                return
            _filename, content = parsed
            self._json(200, start_job(content))
            return

        if self.path == "/v1/jobs":
            # #1164's own upload_binary() prefers this (multipart, same as
            # legacy /analyze) over the analyze_b64 JSON/base64 fallback
            # when the multipart_upload capability is advertised.
            body = self._read_body()
            parsed = parse_multipart_file(body, self.headers.get("Content-Type", ""))
            if parsed is None:
                self._json(400, {"error": "no file field in multipart body"})
                return
            _filename, content = parsed
            self._json(200, start_job(content))
            return

        match = re.match(r"^/v1/jobs/([a-f0-9]{32})/cancel$", self.path)
        if match:
            status, result = _v1_cancel_job(match.group(1))
            self._json(status, result)
            return

        if self.path == "/analyze_b64":
            # #1164: a locally-evaluated Rev·Deck rewrite's own /upload
            # proxies here instead of /analyze -- verified live against its
            # webui/app.py, not guessed at. "persist" is accepted (its
            # sender always sets it true) but not acted on: every sample
            # this service ever receives is retained regardless, same as
            # /analyze, since a captured payload is evidence, not scratch
            # data.
            body = self._read_body()
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid JSON body"})
                return
            if not isinstance(payload, dict):
                self._json(400, {"error": "JSON body must be an object"})
                return
            file_b64 = payload.get("file_b64")
            if not isinstance(file_b64, str) or not file_b64:
                self._json(400, {"error": "file_b64 is required"})
                return
            try:
                content = base64.b64decode(file_b64, validate=True)
            except (binascii.Error, ValueError):
                self._json(400, {"error": "file_b64 is not valid base64"})
                return
            self._json(200, start_job(content))
            return

        match = re.match(r"^/tools/([a-z_]+)$", self.path)
        if match:
            handler = TOOL_HANDLERS.get(match.group(1))
            if handler is None:
                self._json(404, {"error": "unknown tool"})
                return
            body = self._read_body()
            try:
                payload = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid JSON body"})
                return
            if not isinstance(payload, dict):
                self._json(400, {"error": "JSON body must be an object"})
                return
            job_id = payload.get("job_id")
            if not isinstance(job_id, str) or not _JOB_ID_RE.match(job_id):
                self._json(400, {"error": "job_id is required"})
                return
            with _lock:
                job = _jobs.get(job_id)
            # status is the one tool meaningful before a job finishes;
            # every other tool reads artifacts that only exist once done.
            if match.group(1) != "status" and (job is None or job.get("status") != "done"):
                self._json(404, {"error": "result not available"})
                return
            status, result = handler(job_id, payload)
            self._json(status, result)
            return

        if self.path == "/v1/query":
            body = self._read_body()
            try:
                payload = json.loads(body) if body else {}
            except json.JSONDecodeError:
                self._json(400, {"error": "invalid JSON body"})
                return
            if not isinstance(payload, dict):
                self._json(400, {"error": "JSON body must be an object"})
                return
            job_id = payload.get("job_id")
            if not isinstance(job_id, str) or not _JOB_ID_RE.match(job_id):
                self._json(400, {"error": "job_id is required"})
                return
            with _lock:
                job = _jobs.get(job_id)
            if job is None or job.get("status") != "done":
                self._json(404, {"error": "result not available"})
                return
            status, result = _v1_query(job_id, payload)
            self._json(status, result)
            return

        self._json(404, {"error": "not found"})

    def _do_DELETE(self) -> None:
        # #1164: revdeck's own DELETE /jobs/{id} treats 200/202/204/404/405
        # all as "fine" and degrades to a local-only delete on anything
        # else, so there is no wrong status to fear here beyond a genuine
        # 500. The v1 client instead requires v1 for delete_job() outright
        # (no legacy fallback) -- either way it's the same _delete_job.
        match = re.match(r"^/(?:v1/)?jobs/([a-f0-9]{32})$", self.path)
        if not match:
            self._json(404, {"error": "not found"})
            return
        status, result = _delete_job(match.group(1))
        self._json(status, result)

    def _do_PUT(self) -> None:
        match = re.match(r"^/v1/jobs/([a-f0-9]{32})/annotations/([0-9a-fA-Fx]+)$", self.path)
        if not match:
            self._json(404, {"error": "not found"})
            return
        job_id, addr = match.groups()
        with _lock:
            job = _jobs.get(job_id)
        if job is None:
            self._json(404, {"error": "job not found"})
            return
        body = self._read_body()
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON body"})
            return
        if not isinstance(payload, dict):
            self._json(400, {"error": "JSON body must be an object"})
            return
        status, result = _v1_put_annotation(job_id, addr, payload, self.headers.get("If-Match"))
        self._json(status, result)

    def _do_PATCH(self) -> None:
        # #1164: the collection-PATCH fallback put_annotation() only tries
        # after a PUT 404s/405s -- unreachable through the client's own
        # primary path now that _do_PUT above handles PUT directly, kept
        # for parity with the documented v1 contract regardless.
        match = re.match(r"^/v1/jobs/([a-f0-9]{32})/annotations$", self.path)
        if not match:
            self._json(404, {"error": "not found"})
            return
        job_id = match.group(1)
        with _lock:
            job = _jobs.get(job_id)
        if job is None:
            self._json(404, {"error": "job not found"})
            return
        body = self._read_body()
        try:
            payload = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON body"})
            return
        if not isinstance(payload, dict):
            self._json(400, {"error": "JSON body must be an object"})
            return
        status, result = _v1_patch_annotations(job_id, payload.get("annotations"), self.headers.get("If-Match"))
        self._json(status, result)

    def log_message(self, fmt, *args) -> None:  # noqa: A003 - stdlib signature
        pass  # container logs already capture stdout; avoid double-logging every request


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    threading.Thread(target=worker_loop, daemon=True).start()
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
