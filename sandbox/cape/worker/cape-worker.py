#!/usr/bin/env python3
"""Drain the CAPE sandbox request spool.

The dashboard writes {sha256}.request into CAPE_REQUEST_DIR and never talks
to CAPE's own web/API service directly -- same trust boundary as every other
sandbox worker in this repo (a dashboard RCE must not reach the detonation
infrastructure). A systemd path unit notices the new file and runs this
script, which submits each pending sample to CAPE's REST API, polls until
CAPE finishes analysing it, and writes {sha256}_cape.json into
CAPE_RESULTS_DIR for the dashboard to read back.

Mirrors analysis/ghidra/worker/ghidra-worker.py's own drain loop (non-blocking
lock so overlapping path-unit triggers collapse into one drain, a request
moved out of the spool before it runs so a crash cannot replay the same
sample forever, the hash re-validated here rather than trusted from the
spool) and sandbox/windows/run_pending.sh's claim-before-work discipline.
Stdlib only, deliberately: this runs on the host outside any container, and
a worker that needs pip install before it can drain a queue is a worker that
will be broken after the next OS upgrade -- same reasoning ghidra-worker.py
gives for its own stdlib-only rule.

API CONTRACT -- NOT yet verified against a live CAPE instance. Endpoints
below are CAPEv2's documented apiv2 shape (web/apiv2/views.py upstream), the
same starting point ghidra-worker.py's own header warns went stale once
before ("the endpoints originally taken from the plan documents were
wrong"). This cannot be verified end-to-end until #315's golden image and a
configured CAPE machine exist -- there is currently no guest for CAPE to
detonate anything in, so no real submission has ever been made. Re-run
--selftest against a live `cuckoo`/`cape` service once #314's Python
environment and #315's guest both exist, and correct this docstring (and the
CAPEClient methods below) against what the running service actually does,
the way ghidra-worker.py's header records having to do once already.

RESOURCE COEXISTENCE (#320): CAPE's guest and win11-sandbox both run as
KVM/QEMU domains on this host. 16 logical CPUs total; win11-sandbox alone is
already configured for 8 vCPU. Two full-sized concurrent detonations would
fully claim the host's CPU (and the host's swap is already under real
pressure at idle -- see docs/sandbox/cape/IMPLEMENTATION_PLAN.md's Host
Constraints section for the numbers this was decided from). Decision:
simplest option, a single host-wide lock shared with the Windows sandbox
worker -- only one KVM-backed detonation runs at a time, across BOTH
pipelines, not just within this one. See CAPE_KVM_SHARED_LOCK below and the
matching acquisition in sandbox/windows/run_pending.sh.
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

REQUEST_DIR = Path(os.environ.get("CAPE_REQUEST_DIR", "/cape-requests"))
RESULTS_DIR = Path(os.environ.get("CAPE_RESULTS_DIR", "/cape-results"))
SAMPLES_DIR = Path(os.environ.get(
    "CAPE_SAMPLES_DIR", "/var/lib/honeypot-sandbox/inbox/samples"))

# CAPE web's default apiv2 port (utils/api.py, Django devserver / gunicorn in
# front of it -- see docs/sandbox/cape/IMPLEMENTATION_PLAN.md Phase 4).
API_BASE = os.environ.get("CAPE_API_BASE", "http://127.0.0.1:8000").rstrip("/")
API_TOKEN = os.environ.get("CAPE_API_TOKEN", "")

# This worker's own lock: collapses overlapping path-unit triggers into one
# drain, same as every other worker in this repo.
LOCK_FILE = Path(os.environ.get(
    "CAPE_LOCK", "/run/lock/honeypot-cape-worker.lock"))

# #320's cross-pipeline lock, shared with sandbox/windows/run_pending.sh.
# Held only while a detonation is actually in flight (submit -> report
# fetched), not for the whole drain loop, so an idle worker never blocks the
# other pipeline. Empty disables it -- only meaningful on a single-host
# deployment where both guests really do compete for the same CPUs; a
# distributed deployment (CAPE workers on their own hardware) has no reason
# to serialize against win11-sandbox at all.
KVM_SHARED_LOCK = Path(os.environ.get(
    "CAPE_KVM_SHARED_LOCK", "/run/lock/honeypot-kvm-detonation.lock"))

# Per-sample budget, in seconds. CAPE's own analysis timeout (analysis.conf
# [analysis] timeout, typically 200s) plus its own processing/reporting time
# on top -- generous so a slow-but-progressing job isn't killed by the
# client while CAPE is still working, same reasoning
# GHIDRA_ANALYSIS_TIMEOUT uses.
ANALYSIS_TIMEOUT = int(os.environ.get("CAPE_ANALYSIS_TIMEOUT", "1200"))
POLL_INTERVAL = int(os.environ.get("CAPE_POLL_INTERVAL", "10"))
HTTP_TIMEOUT = int(os.environ.get("CAPE_HTTP_TIMEOUT", "60"))
SUBMIT_TIMEOUT = int(os.environ.get("CAPE_SUBMIT_TIMEOUT", "120"))

# Routing-mode decision (#316): internet/VPN are ruled out by this repo's
# blanket no-outbound-network posture. drop is the default, matching every
# other detonation route's default (win11-sandbox, the Linux runner).
# inetsim is CAPE's own alternative, deliberately not pointed at the
# existing docker-compose.sandbox.yml INetSim instance the other two
# guests share -- see sandbox/cape/network.xml's header for why.
ROUTE = os.environ.get("CAPE_ROUTE", "drop")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


class CapeError(RuntimeError):
    """Anything that means this sample did not get analysed."""


class CapeClient:
    """Every call to CAPE's own REST API lives here.

    NOT yet verified against a live instance -- see this file's module
    docstring. Endpoints match CAPEv2's documented apiv2 blueprint
    (`/apiv2/tasks/create/file/`, `/apiv2/tasks/view/<id>/`,
    `/apiv2/tasks/report/<id>/json/`), token auth via `Authorization: Token
    <key>` (CAPE_API_TOKEN, empty for a loopback-only deployment where the
    web service has no auth configured).
    """

    def __init__(self, base: str, token: str) -> None:
        self.base = base
        self.token = token

    def _request(self, method: str, path: str, *, body: bytes | None = None,
                 content_type: str | None = None, timeout: int | None = None):
        req = urllib.request.Request(f"{self.base}{path}", data=body, method=method)
        if content_type:
            req.add_header("Content-Type", content_type)
        if self.token:
            req.add_header("Authorization", f"Token {self.token}")
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
            raise CapeError(f"{method} {path} -> HTTP {e.code}: "
                             f"{e.read()[:200]!r}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise CapeError(f"{method} {path} -> {e}") from e

    def ready(self) -> bool:
        """/apiv2/cuckoo/status/. False on any failure, not just a clean 200."""
        try:
            resp = self._request("GET", "/apiv2/cuckoo/status/", timeout=10)
            return isinstance(resp, dict) and bool(resp.get("data"))
        except CapeError:
            return False

    def submit(self, sample: Path) -> int:
        """Upload a sample. Returns the numeric task id.

        Multipart POST, field "file" plus the routing-mode option -- the
        same shape ghidra-worker.py's GhidraClient.analyze() and
        _revdeck_upload() already use for their own multipart bodies in this
        repo, kept consistent rather than reaching for a third convention.
        """
        boundary = uuid.uuid4().hex
        filename = sample.name
        ctype = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        parts = [
            f"--{boundary}\r\n".encode(),
            (f'Content-Disposition: form-data; name="file"; '
             f'filename="{filename}"\r\n').encode(),
            f"Content-Type: {ctype}\r\n\r\n".encode(),
            sample.read_bytes(),
            f"\r\n--{boundary}\r\n".encode(),
            b'Content-Disposition: form-data; name="route"\r\n\r\n',
            ROUTE.encode(),
            f"\r\n--{boundary}--\r\n".encode(),
        ]
        resp = self._request(
            "POST", "/apiv2/tasks/create/file/", body=b"".join(parts),
            content_type=f"multipart/form-data; boundary={boundary}",
            timeout=SUBMIT_TIMEOUT)
        data = (resp or {}).get("data") if isinstance(resp, dict) else None
        task_ids = (data or {}).get("task_ids") if isinstance(data, dict) else None
        if task_ids:
            return int(task_ids[0])
        raise CapeError(f"/apiv2/tasks/create/file/ gave no task_ids: {resp!r}")

    def wait(self, task_id: int) -> str:
        """Block until the task reaches a terminal state. Returns that state.

        Observed CAPE states: pending -> running -> completed -> reported
        (or "failed_analysis"/"failed_processing"/"failed_reporting"/
        "banned"). "reported" is the only state a report can actually be
        fetched for; "completed" alone means processing hasn't run yet.
        """
        deadline = time.monotonic() + ANALYSIS_TIMEOUT
        last_status = "unknown"
        while time.monotonic() < deadline:
            resp = self._request("GET", f"/apiv2/tasks/status/{task_id}/")
            data = (resp or {}).get("data") if isinstance(resp, dict) else None
            last_status = data if isinstance(data, str) else "unknown"
            if last_status == "reported":
                return last_status
            if last_status.startswith("failed") or last_status == "banned":
                raise CapeError(f"task {task_id} ended in state {last_status!r}")
            time.sleep(POLL_INTERVAL)
        raise CapeError(
            f"task {task_id} did not reach 'reported' within "
            f"{ANALYSIS_TIMEOUT}s (last seen: {last_status!r})")

    def report(self, task_id: int) -> dict:
        """Fetch the full JSON report for a reported task."""
        resp = self._request("GET", f"/apiv2/tasks/report/{task_id}/json/",
                              timeout=ANALYSIS_TIMEOUT)
        if isinstance(resp, dict):
            return resp
        raise CapeError(f"task {task_id} report was not a JSON object: {resp!r}")


def acquire_kvm_lock():
    """Best-effort acquisition of the cross-pipeline detonation lock (#320).

    Blocking, not non-blocking -- unlike this worker's own LOCK_FILE (where
    a second overlapping trigger should just no-op), here waiting is the
    entire point: a queued CAPE sample should detonate once win11-sandbox's
    current job finishes, not bail out and leave the request stuck. Returns
    the open file handle (keep it referenced for the lock's lifetime) or
    None if CAPE_KVM_SHARED_LOCK is empty.
    """
    if not str(KVM_SHARED_LOCK):
        return None
    KVM_SHARED_LOCK.parent.mkdir(parents=True, exist_ok=True)
    handle = open(KVM_SHARED_LOCK, "w")
    fcntl.flock(handle, fcntl.LOCK_EX)  # blocking
    return handle


def analyse_one(client: CapeClient, sha: str, sample: Path,
                 requested_at: str) -> dict:
    started_at = now()
    kvm_lock = acquire_kvm_lock()
    try:
        task_id = client.submit(sample)
        log(f"  [+] {sha}: submitted as CAPE task {task_id} (route={ROUTE})")
        state = client.wait(task_id)
        report = client.report(task_id)
    finally:
        if kvm_lock is not None:
            kvm_lock.close()  # releases the flock

    info = report.get("info") if isinstance(report, dict) else None
    signatures = report.get("signatures") if isinstance(report, dict) else None
    target = report.get("target") if isinstance(report, dict) else None
    return {
        "version": RESULT_VERSION,
        "sha256": sha,
        "requested_at": requested_at,
        "started_at": started_at,
        "completed_at": now(),
        "exit_status": "ok",
        "task_id": task_id,
        "cape_status": state,
        "route": ROUTE,
        "score": (info or {}).get("score") if isinstance(info, dict) else None,
        "category": (target or {}).get("category") if isinstance(target, dict) else None,
        "signatures": [
            {
                "name": s.get("name", ""),
                "description": s.get("description", ""),
                "severity": s.get("severity"),
            }
            for s in (signatures or []) if isinstance(s, dict)
        ] if isinstance(signatures, list) else [],
        # The rest of CAPE's report (behavior, network, dropped files, ...)
        # is large and CAPE-version-dependent; kept as-is under "report"
        # rather than re-shaped here, the way ghidra-worker.py's own result
        # normalises three different upstream envelope shapes into one only
        # where the dashboard actually reads specific fields out of it.
        # dashboard/cape.go picks out what it needs from this.
        "report": report if isinstance(report, dict) else {},
    }


def write_result(sha: str, result: dict) -> None:
    """Atomic write: a reader must never see a half-written result.

    Same convention as ghidra-worker.py's write_result() -- write beside the
    final name and rename, which is atomic within one filesystem.
    """
    final = RESULTS_DIR / f"{sha}_cape.json"
    tmp = final.with_suffix(f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(result, indent=2))
    tmp.chmod(0o600)
    tmp.rename(final)


def drain() -> int:
    REQUEST_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(REQUEST_DIR, 0o700)
    os.chmod(RESULTS_DIR, 0o700)

    pending = sorted(REQUEST_DIR.glob("*.request"))
    if not pending:
        return 0

    client = CapeClient(API_BASE, API_TOKEN)
    if not client.ready():
        # Leave the spool untouched -- the path unit fires again on the next
        # change, same contract ghidra-worker.py's drain() holds itself to.
        log(f"CAPE API at {API_BASE} is not ready; leaving queue intact")
        return 1

    processed = 0
    for request in pending:
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

        try:
            result = analyse_one(client, sha, sample, requested_at)
            write_result(sha, result)
            claimed.unlink()
            processed += 1
            log(f"  [+] {sha} done")
        except CapeError as e:
            log(f"  [!] {sha} failed: {e}")
            write_result(sha, {
                "version": RESULT_VERSION,
                "sha256": sha,
                "requested_at": requested_at,
                "started_at": now(),
                "completed_at": now(),
                "exit_status": "error",
                "error": str(e),
                "task_id": None,
                "cape_status": None,
                "route": ROUTE,
                "score": None,
                "category": None,
                "signatures": [],
                "report": {},
            })
            claimed.rename(claimed.with_suffix(".failed"))

    log(f"drained {processed} request(s)")
    return 0


def selftest() -> int:
    """Check reachability. NOT a contract round-trip (see module docstring):

    there is no configured CAPE machine yet (#315), so there is nothing this
    could submit a real sample to. Extend this once one exists, the way
    ghidra-worker.py's own --selftest exercises a real analysis end to end.
    """
    client = CapeClient(API_BASE, API_TOKEN)
    ok = client.ready()
    print(f"API_BASE      : {API_BASE}")
    print(f"/apiv2/cuckoo/status/ : {'OK' if ok else 'UNREACHABLE'}")
    print(f"REQUEST_DIR   : {REQUEST_DIR} (exists={REQUEST_DIR.is_dir()})")
    print(f"RESULTS_DIR   : {RESULTS_DIR} (exists={RESULTS_DIR.is_dir()})")
    print(f"SAMPLES_DIR   : {SAMPLES_DIR} (exists={SAMPLES_DIR.is_dir()})")
    print(f"ROUTE         : {ROUTE}")
    print(f"KVM_SHARED_LOCK: {KVM_SHARED_LOCK or '(disabled)'}")
    if not ok:
        print("\nCAPE is not reachable. Bring up the host stack first -- see "
              "docs/sandbox/cape/IMPLEMENTATION_PLAN.md.")
        return 1
    print("\nreachability OK. No end-to-end round trip yet -- #315's guest "
          "does not exist, so CAPE has no machine to detonate anything in.")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return selftest()

    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    lock = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return 0
    return drain()


if __name__ == "__main__":
    sys.exit(main())
