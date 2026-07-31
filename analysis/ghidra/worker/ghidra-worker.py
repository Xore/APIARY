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

API CONTRACT — verified 2026-07-31 against
biniamfd/ghidra-headless-rest:1.2.1 (Ghidra 11.3.2, artifact schema 2.1) by
running a real binary through it. The endpoints originally taken from the plan
documents were wrong; see GhidraClient for what the service actually exposes.
Re-check with --selftest after any image change.
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

# /results/{job}/functions is paged and defaults to limit=100. Ask for larger
# pages to cut round trips, and stop at MAX_FUNCTIONS so one enormous binary
# cannot produce a result document too large for the dashboard to render. When
# the cap truncates, the result says so rather than silently showing a round
# number that looks like the real total.
FUNCTION_PAGE = int(os.environ.get("GHIDRA_FUNCTION_PAGE", "500"))
MAX_FUNCTIONS = int(os.environ.get("GHIDRA_MAX_FUNCTIONS", "20000"))


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


class GhidraError(RuntimeError):
    """Anything that means this sample did not get analysed."""


class GhidraClient:
    """Every call to the Ghidra REST service lives here.

    Verified against biniamfd/ghidra-headless-rest:1.2.1 on 2026-07-31 by
    submitting a real binary and reading the responses. The service is FastAPI
    and publishes /openapi.json, which is the authority if this drifts.

    The endpoints in DASHBOARD_INTEGRATION_PLAN.md and IMPLEMENTATION_PLAN.md
    were both wrong, and they disagreed with each other. What is actually
    exposed:

        GET  /v1/health                     {"status": "ok"}   (NOT /readyz)
        POST /analyze          multipart field "file"
                               -> {"job_id": "...", "status": "queued"}
        GET  /status/{job_id}  -> {"status": "queued|running|done", ...}
        GET  /results/{job_id}/functions?offset=&limit=
                               -> {"total","offset","limit","functions":[...]}
        GET  /results/{job_id}/strings
                               -> {"count", "strings": [{"addr","s",...}]}
        GET  /results/{job_id}/imports
                               -> [ {"name","library","address",...} ]   (bare list)

    Note the three different envelope shapes across those last three: a paged
    object, a counted object, and a bare array. They are normalised here so the
    result JSON the dashboard reads has one stable shape.
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
        """/v1/health. The compose healthcheck used /readyz, which 404s."""
        try:
            resp = self._request("GET", "/v1/health", timeout=10)
            return isinstance(resp, dict) and resp.get("status") == "ok"
        except GhidraError:
            return False

    def analyze(self, sample: Path) -> str:
        """Upload a binary. Returns the job id used by every later call."""
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
        if isinstance(resp, dict) and resp.get("job_id"):
            return str(resp["job_id"])
        raise GhidraError(f"/analyze gave no job_id: {resp!r}")

    def wait(self, job: str) -> dict:
        """Block until analysis finishes. Returns the final status document.

        Observed states: queued -> running -> done. The status document also
        carries analyzer_version and the service's own sha256 of the sample,
        both worth recording in the result for provenance.
        """
        deadline = time.monotonic() + ANALYSIS_TIMEOUT
        while time.monotonic() < deadline:
            resp = self._request("GET", f"/status/{job}")
            state = (resp or {}).get("status") if isinstance(resp, dict) else None
            if state == "done":
                return resp
            if state in ("error", "failed", "cancelled"):
                raise GhidraError(f"analysis of {job} failed server-side: {resp!r}")
            time.sleep(POLL_INTERVAL)
        raise GhidraError(f"analysis of {job} exceeded {ANALYSIS_TIMEOUT}s")

    def _functions(self, job: str) -> list:
        """Page through /results/{job}/functions.

        The endpoint is paged and defaults to limit=100. A stripped binary can
        have thousands of functions, so taking the first page only would
        silently truncate every large sample — the kind of loss that looks like
        a small binary rather than a bug.
        """
        out, offset = [], 0
        while True:
            page = self._request(
                "GET", f"/results/{job}/functions?offset={offset}&limit={FUNCTION_PAGE}")
            if not isinstance(page, dict):
                break
            items = page.get("functions") or []
            out.extend({
                "address": f.get("addr", ""),
                "name": f.get("name") or f.get("canonical_name", ""),
                "signature": f.get("signature", ""),
            } for f in items)
            total = page.get("total", len(out))
            offset += len(items)
            if not items or offset >= total or len(out) >= MAX_FUNCTIONS:
                break
        return out

    def collect(self, job: str) -> dict:
        """Fetch the artifacts the result JSON is built from, normalised.

        A single failing section is recorded as empty rather than fatal: a
        report with strings but no imports is still worth having. Every section
        failing is a different matter and is caught by the caller — that means
        the contract is broken, not that the binary is empty.
        """
        out: dict = {"functions": [], "strings": [], "imports": []}
        try:
            out["functions"] = self._functions(job)
        except GhidraError as e:
            log(f"  [!] functions: {e}")
        try:
            resp = self._request("GET", f"/results/{job}/strings")
            items = resp.get("strings", []) if isinstance(resp, dict) else (resp or [])
            # Each entry is an object; "s" holds the text.
            out["strings"] = [i.get("s", "") for i in items if isinstance(i, dict) and i.get("s")]
        except GhidraError as e:
            log(f"  [!] strings: {e}")
        try:
            resp = self._request("GET", f"/results/{job}/imports")
            # Bare list here, unlike the two above.
            items = resp if isinstance(resp, list) else (resp or {}).get("imports", [])
            # "library!name" is the format the plan specified and the format
            # the dashboard search matches on.
            out["imports"] = [
                f"{i.get('library', '?')}!{i.get('name', '')}"
                for i in items if isinstance(i, dict) and i.get("name")
            ]
        except GhidraError as e:
            log(f"  [!] imports: {e}")
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
    status = client.wait(job)
    parts = client.collect(job)

    # Every section empty means the API contract is broken, not that the binary
    # is empty. Reporting that as a clean "ok" result is the failure mode this
    # worker most needs to avoid: the dashboard would render a tidy analysis
    # showing no imports and no strings, and an analyst would read it as a fact
    # about the sample. A real binary always yields at least one of the three.
    if not any(parts[k] for k in ("functions", "strings", "imports")):
        raise GhidraError(
            f"job {job} completed but returned no functions, strings or "
            f"imports - the API contract is probably broken (run --selftest)")

    truncated = len(parts["functions"]) >= MAX_FUNCTIONS
    if truncated:
        log(f"  [!] function list truncated at {MAX_FUNCTIONS}")

    return {
        "version": RESULT_VERSION,
        "sha256": sha,
        "requested_at": requested_at,
        "started_at": started,
        "completed_at": now(),
        "exit_status": "ok",
        # Straight from the service, so a result can be tied to the analyser
        # that produced it after an image upgrade. service_sha256 is the
        # service's own hash of what it received: if it disagrees with the
        # filename hash, something substituted the sample in transit.
        "analyzer_version": status.get("analyzer_version", ""),
        "artifact_schema_version": status.get("artifact_schema_version", ""),
        "service_sha256": status.get("sha256", ""),
        "functions": parts["functions"],
        "functions_truncated": truncated,
        "strings": parts["strings"],
        "imports": parts["imports"],
        # Populated by IMPLEMENTATION_PLAN.md phases 3-5 (see #102, #103), which
        # are not built. Emitted as empty rather than omitted so the dashboard
        # reads one stable shape and needs no special case for older results.
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
    """Check reachability and the endpoint contract against a live container.

    The contract was verified once, on 2026-07-31, against
    biniamfd/ghidra-headless-rest:1.2.1. This exists so an image upgrade that
    moves an endpoint is caught deliberately rather than by an analyst noticing
    that every report has become empty.
    """
    client = GhidraClient(API_BASE)
    ok = client.ready()
    print(f"API_BASE      : {API_BASE}")
    print(f"/v1/health    : {'OK' if ok else 'UNREACHABLE'}")
    print(f"REQUEST_DIR   : {REQUEST_DIR} (exists={REQUEST_DIR.is_dir()})")
    print(f"RESULTS_DIR   : {RESULTS_DIR} (exists={RESULTS_DIR.is_dir()})")
    print(f"SAMPLES_DIR   : {SAMPLES_DIR} (exists={SAMPLES_DIR.is_dir()})")
    if not ok:
        print("\nStart it with:")
        print("  docker compose -f analysis/ghidra/docker-compose.ghidra.yml up -d ghidra")
        return 1

    # Exercise the whole chain on a known-good local binary. Anything with code
    # in it will do; the point is the API, not the sample.
    probe = Path("/bin/true")
    if not probe.is_file():
        print("\n/bin/true not present - skipping the round trip")
        return 0
    print(f"\nround trip on {probe} ...")
    try:
        job = client.analyze(probe)
        status = client.wait(job)
        parts = client.collect(job)
    except GhidraError as e:
        print(f"  FAILED: {e}")
        print("  The endpoint contract has probably changed. Compare against")
        print(f"  {API_BASE}/openapi.json, which is the authority.")
        return 1
    print(f"  job            : {job}")
    print(f"  analyzer       : {status.get('analyzer_version')} "
          f"(artifacts {status.get('artifact_schema_version')})")
    for key in ("functions", "strings", "imports"):
        print(f"  {key:<15}: {len(parts[key])}")
    if not any(parts[k] for k in ("functions", "strings", "imports")):
        print("  FAILED: every section empty - the contract is broken")
        return 1
    print("\ncontract OK")
    return 0


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
