#!/usr/bin/env python3
"""Drain the Ghidra analysis request spool.

The dashboard writes {sha256}.request into GHIDRA_REQUEST_DIR and never talks
to the Ghidra REST service itself — same trust boundary as the sandbox
workers, and for the same reason: a dashboard RCE must not reach the analysis
infrastructure. A systemd path unit notices the new file and runs this script,
which analyses each pending sample and writes {sha256}_ghidra.json into
GHIDRA_RESULTS_DIR for the dashboard to read back.

Mirrors sandbox/windows/run_pending.sh in the ways that matter:

  * a non-blocking lock, so overlapping path-unit triggers collapse into one
    drain instead of running several analyses at once;
  * a request moved out of the spool *before* it runs, so a crash cannot
    replay the same sample forever;
  * the hash re-validated here rather than trusted from the spool, because
    this worker holds the credentials and the dashboard does not.

Stdlib only, deliberately: this runs on the host outside any container, and a
worker that needs pip install before it can drain a queue is a worker that
will be broken after the next OS upgrade.

API CONTRACT — UNVERIFIED. The endpoints below come from
DASHBOARD_INTEGRATION_PLAN.md Phase 1, not from a running container. They have
never been exercised against biniamfd/ghidra-headless-rest:1.2.1. Everything
touching the REST service is confined to GhidraClient so that correcting the
shapes is a change in one class. Run --selftest against a live container
before trusting any result this produces.
"""

from __future__ import annotations

import fcntl
import json
import mimetypes
import os
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RESULT_VERSION = 1

REQUEST_DIR = Path(os.environ.get("GHIDRA_REQUEST_DIR", "/ghidra-requests"))
RESULTS_DIR = Path(os.environ.get("GHIDRA_RESULTS_DIR", "/ghidra-results"))
SAMPLES_DIR = Path(os.environ.get(
    "GHIDRA_SAMPLES_DIR", "/var/lib/honeypot-sandbox/inbox/samples"))
API_BASE = os.environ.get("GHIDRA_API_BASE", "http://127.0.0.1:9090").rstrip("/")
LOCK_FILE = Path(os.environ.get(
    "GHIDRA_LOCK", "/run/lock/honeypot-ghidra-worker.lock"))

# Ghidra's own analysis budget is ANALYSIS_TIMEOUT in docker-compose.ghidra.yml
# (3600s). Wait longer than that here so a slow-but-working analysis is not
# killed by the client while the server is still doing useful work.
ANALYSIS_TIMEOUT = int(os.environ.get("GHIDRA_ANALYSIS_TIMEOUT", "4200"))
POLL_INTERVAL = int(os.environ.get("GHIDRA_POLL_INTERVAL", "10"))
HTTP_TIMEOUT = int(os.environ.get("GHIDRA_HTTP_TIMEOUT", "60"))


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


class GhidraError(RuntimeError):
    """Anything that means this sample did not get analysed."""


class GhidraClient:
    """Every call to the Ghidra REST service lives here.

    Isolated on purpose: the endpoint names and payload shapes are taken from
    the integration plan and have not been checked against a running
    container, so this is the one class expected to need correcting.
    """

    def __init__(self, base: str) -> None:
        self.base = base

    def _request(self, method: str, path: str, *, body: bytes | None = None,
                 content_type: str | None = None, timeout: int | None = None):
        req = urllib.request.Request(f"{self.base}{path}", data=body, method=method)
        if content_type:
            req.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(req, timeout=timeout or HTTP_TIMEOUT) as r:
                raw = r.read()
                if not raw:
                    return None
                ctype = r.headers.get("Content-Type", "")
                if "json" in ctype:
                    return json.loads(raw)
                return raw
        except urllib.error.HTTPError as e:
            raise GhidraError(f"{method} {path} -> HTTP {e.code}: "
                              f"{e.read()[:200]!r}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise GhidraError(f"{method} {path} -> {e}") from e

    def ready(self) -> bool:
        """The container's own healthcheck endpoint."""
        try:
            self._request("GET", "/readyz", timeout=10)
            return True
        except GhidraError:
            return False

    def analyze(self, sample: Path) -> str:
        """Upload a binary. Returns the job/program id used by later calls."""
        boundary = uuid.uuid4().hex
        filename = sample.name
        ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        parts = [
            f"--{boundary}\r\n".encode(),
            (f'Content-Disposition: form-data; name="file"; '
             f'filename="{filename}"\r\n').encode(),
            f"Content-Type: {ctype}\r\n\r\n".encode(),
            sample.read_bytes(),
            f"\r\n--{boundary}--\r\n".encode(),
        ]
        resp = self._request(
            "POST", "/analyze", body=b"".join(parts),
            content_type=f"multipart/form-data; boundary={boundary}",
            timeout=ANALYSIS_TIMEOUT)
        if isinstance(resp, dict):
            for key in ("id", "job_id", "program_id", "program"):
                if resp.get(key):
                    return str(resp[key])
        raise GhidraError(f"/analyze gave no usable job id: {resp!r}")

    def wait(self, job: str) -> None:
        """Block until analysis finishes, or raise on timeout."""
        deadline = time.monotonic() + ANALYSIS_TIMEOUT
        while time.monotonic() < deadline:
            resp = self._request("GET", f"/status/{job}")
            state = (resp or {}).get("status") if isinstance(resp, dict) else None
            if state in ("done", "complete", "completed", "finished"):
                return
            if state in ("error", "failed"):
                raise GhidraError(f"analysis of {job} failed server-side: {resp!r}")
            time.sleep(POLL_INTERVAL)
        raise GhidraError(f"analysis of {job} exceeded {ANALYSIS_TIMEOUT}s")

    def collect(self, job: str) -> dict:
        """Fetch the artifacts the result JSON is built from.

        A missing section is recorded as empty rather than fatal: a report
        with strings but no imports is still worth having, and losing the
        whole analysis because one endpoint moved would be the wrong trade.
        """
        out: dict = {}
        for key, path in (("functions", f"/functions/{job}"),
                          ("strings",   f"/strings/{job}"),
                          ("imports",   f"/imports/{job}")):
            try:
                out[key] = self._request("GET", path) or []
            except GhidraError as e:
                log(f"  [!] {key}: {e}")
                out[key] = []
        return out


def write_result(sha: str, payload: dict) -> None:
    """Write the result JSON atomically.

    The dashboard polls this directory, so a half-written file would be read
    as a corrupt result. Write beside it and rename, which is atomic within a
    filesystem.
    """
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    final = RESULTS_DIR / f"{sha}_ghidra.json"
    tmp = RESULTS_DIR / f".{sha}_ghidra.json.tmp"
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True))
    os.replace(tmp, final)
    final.chmod(0o600)


def write_status() -> None:
    """Queue counts, shaped for loadGhidraStatus() to read."""
    def count(pattern: str) -> int:
        return len(list(REQUEST_DIR.glob(pattern)))

    status = {
        "version": RESULT_VERSION,
        "updated_at": now(),
        "queued": count("*.request"),
        "running": count("*.request.running"),
        "failed": count("*.request.failed"),
        "done": len(list(RESULTS_DIR.glob("*_ghidra.json"))),
    }
    tmp = RESULTS_DIR / ".status.json.tmp"
    tmp.write_text(json.dumps(status, indent=2, sort_keys=True))
    os.replace(tmp, RESULTS_DIR / "status.json")


def analyse_one(client: GhidraClient, sha: str, sample: Path,
                requested_at: str) -> dict:
    started = now()
    job = client.analyze(sample)
    log(f"  analysing {sha} as job {job}")
    client.wait(job)
    parts = client.collect(job)
    return {
        "version": RESULT_VERSION,
        "sha256": sha,
        "requested_at": requested_at,
        "started_at": started,
        "completed_at": now(),
        "exit_status": "ok",
        "functions": parts["functions"],
        "strings": parts["strings"],
        "imports": parts["imports"],
        # Populated by IMPLEMENTATION_PLAN.md phases 3-5, which are not built
        # yet. Emitted as empty rather than omitted so the dashboard can read
        # one stable shape and does not need to special-case older results.
        "findcrypt": [],
        "call_graph_svg": None,
        "ai_triage": None,
        "report_pdf": None,
    }


def drain() -> int:
    REQUEST_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(REQUEST_DIR, 0o700)
    os.chmod(RESULTS_DIR, 0o700)

    client = GhidraClient(API_BASE)
    if not client.ready():
        # Leave the spool untouched. The path unit fires again on the next
        # change, and an operator starting the container is the fix — losing
        # the queue because a container was down would be gratuitous.
        log(f"Ghidra REST service at {API_BASE} is not ready; leaving queue intact")
        write_status()
        return 1

    processed = 0
    for request in sorted(REQUEST_DIR.glob("*.request")):
        sha = request.name[: -len(".request")]

        if not SHA256_RE.match(sha):
            log(f"skipping malformed request: {request.name}")
            request.rename(request.with_suffix(".request.invalid"))
            continue

        sample = SAMPLES_DIR / sha
        if not sample.is_file():
            log(f"sample {sha} is not in {SAMPLES_DIR} - dropping request")
            request.rename(request.with_suffix(".request.missing-sample"))
            continue

        try:
            requested_at = datetime.fromtimestamp(
                request.stat().st_mtime, timezone.utc).isoformat(timespec="seconds")
        except OSError:
            requested_at = now()

        # Claim before working. If the host dies mid-analysis the file is
        # already out of the spool, so the path unit will not hand the same
        # sample back on the next boot.
        claimed = request.with_suffix(".request.running")
        request.rename(claimed)
        write_status()

        try:
            result = analyse_one(client, sha, sample, requested_at)
            write_result(sha, result)
            claimed.unlink()
            processed += 1
            log(f"  [+] {sha} done")
        except GhidraError as e:
            log(f"  [!] {sha} failed: {e}")
            # Record the failure as a result too. A dashboard that shows
            # "failed, because X" is far more useful than one where the job
            # silently never appears.
            write_result(sha, {
                "version": RESULT_VERSION,
                "sha256": sha,
                "requested_at": requested_at,
                "started_at": now(),
                "completed_at": now(),
                "exit_status": "error",
                "error": str(e),
                "functions": [], "strings": [], "imports": [], "findcrypt": [],
                "call_graph_svg": None, "ai_triage": None, "report_pdf": None,
            })
            claimed.rename(claimed.with_suffix(".failed"))
        finally:
            write_status()

    write_status()
    log(f"drained {processed} request(s)")
    return 0


def selftest() -> int:
    """Check reachability and endpoint shapes against a live container.

    Exists because the API contract in this file is unverified. Run it once
    against a running biniamfd/ghidra-headless-rest before trusting output.
    """
    client = GhidraClient(API_BASE)
    print(f"API_BASE      : {API_BASE}")
    print(f"/readyz       : {'OK' if client.ready() else 'UNREACHABLE'}")
    print(f"REQUEST_DIR   : {REQUEST_DIR} (exists={REQUEST_DIR.is_dir()})")
    print(f"RESULTS_DIR   : {RESULTS_DIR} (exists={RESULTS_DIR.is_dir()})")
    print(f"SAMPLES_DIR   : {SAMPLES_DIR} (exists={SAMPLES_DIR.is_dir()})")
    print("\nNOTE: /analyze, /status, /functions, /strings and /imports are")
    print("taken from DASHBOARD_INTEGRATION_PLAN.md and are NOT verified.")
    print("Confirm them against the container's own API docs before relying")
    print("on any result this worker writes.")
    return 0 if client.ready() else 1


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    # The path unit fires on every spool change, so several invocations can
    # race during a burst. Only one may drain: concurrent analyses would
    # compete for the same Ghidra project directory.
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    lock = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return 0
    return drain()


if __name__ == "__main__":
    sys.exit(main())
