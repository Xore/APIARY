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

API CONTRACT -- #318: verified live, 2026-08-08, against a real win11-cape
detonation (`--selftest --round-trip`, tasks 8 and 9, both reached
"reported" and a fetchable report). Same lesson ghidra-worker.py's own
header already recorded once ("the endpoints originally taken from the
plan documents were wrong") -- two of the endpoints assumed from CAPEv2's
documented apiv2 shape (web/apiv2/views.py upstream) needed a real
correction before this actually worked:

- `CapeClient.ready()` treated `/apiv2/cuckoo/status/` reporting itself
  disabled (`{"error": true, "error_value": "Cuckoo Status API is
  disabled"}` -- this host's api.conf has [cuckoostatus] off, an
  unrelated per-endpoint opt-in flag) as CAPE being unreachable. It is not:
  a disabled-endpoint response is still proof of a live, correctly routing
  service. See ready()'s own docstring for what actually gates the three
  endpoints this worker's real path depends on.
- `CapeClient.report()`'s URL was wrong: the real route is
  `/apiv2/tasks/get/report/<id>/json/` (an extra `get/` segment), not
  `/apiv2/tasks/report/<id>/json/`. Caught by a live 404 against a task
  that had already reached "reported" -- submit() and wait() needed no
  correction, only this one.

The round-trip probe file took two more live corrections to land on (see
ROUND_TRIP_PROBE's own comment below): a real /bin/true submission was
rejected as unsupported (this host has no Linux CAPE guest, only
win11-cape), and a plain .txt was rejected by CAPE's own filename-based
junk-file filter before it ever reached platform detection.

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
API_AUTH = os.environ.get("CAPE_API_TOKEN", "")

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

    Verified live against a real win11-cape detonation, 2026-08-08 -- see
    this file's module docstring for the result. `/apiv2/tasks/create/file/`
    and `/apiv2/tasks/status/<id>/` matched the originally-assumed
    documented shape exactly; `/apiv2/tasks/report/<id>/json/` did not --
    the real route has an extra `get/` segment
    (`/apiv2/tasks/get/report/<id>/json/`, per apiv2/urls.py), corrected
    below after a live 404 caught it. Token auth via `Authorization: Token
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
        """/apiv2/cuckoo/status/. False on any failure, not just a clean 200.

        #318, confirmed live: this endpoint is one of several apiv2 routes
        CAPE gates behind its own per-endpoint enable flag
        (api.conf's [cuckoostatus] section, off by default) -- unrelated to
        whether the service itself is up. A disabled response is still a
        well-formed JSON reply from a live, correctly routing Django app
        ({"error": true, "error_value": "Cuckoo Status API is disabled"}),
        the same proof of reachability a populated "data" key would be. Only
        a connection failure, timeout, or non-JSON/5xx response (all raised
        as CapeError by _request) means the service is actually unreachable.
        The three endpoints this worker's real submit/wait/report path
        depends on ([filecreate]/[taskstatus]/[taskreport]) are enabled by
        default on this deployment -- confirmed against the live
        /opt/CAPEv2/conf/api.conf, not assumed -- so this check only needs
        to prove the API is answering at all, not that this specific
        optional status endpoint is turned on.
        """
        try:
            resp = self._request("GET", "/apiv2/cuckoo/status/", timeout=10)
            return isinstance(resp, dict) and "error" in resp
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
        resp = self._request("GET", f"/apiv2/tasks/get/report/{task_id}/json/",
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


def write_status() -> None:
    """Queue counts, shaped for a future loadCapeStatus() to read (#319
    follow-up) -- identical field names and glob conventions to
    ghidra-worker.py's own write_status(), so the dashboard side can reuse
    loadGhidraStatus()'s staleness/live-recheck logic almost verbatim rather
    than inventing a second shape for one more worker.
    """
    def count(pattern: str) -> int:
        return len(list(REQUEST_DIR.glob(pattern)))

    status = {
        "version": RESULT_VERSION,
        "updated_at": now(),
        "queued": count("*.request"),
        "running": count("*.request.running"),
        "failed": count("*.request.failed"),
        "done": len(list(RESULTS_DIR.glob("*_cape.json"))),
    }
    tmp = RESULTS_DIR / ".status.json.tmp"
    tmp.write_text(json.dumps(status, indent=2, sort_keys=True))
    os.replace(tmp, RESULTS_DIR / "status.json")


def drain() -> int:
    REQUEST_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(REQUEST_DIR, 0o700)
    os.chmod(RESULTS_DIR, 0o700)

    pending = sorted(REQUEST_DIR.glob("*.request"))
    if not pending:
        # Matches ghidra-worker.py's own reasoning: an empty queue doesn't
        # need CAPE reachable at all, and status.json still needs writing so
        # a quiet honeypot doesn't read as a dead worker (#319 follow-up).
        write_status()
        return 0

    client = CapeClient(API_BASE, API_AUTH)
    if not client.ready():
        # Leave the spool untouched -- the path unit fires again on the next
        # change, same contract ghidra-worker.py's drain() holds itself to.
        log(f"CAPE API at {API_BASE} is not ready; leaving queue intact")
        write_status()
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
        write_status()

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
        finally:
            write_status()

    write_status()
    log(f"drained {processed} request(s)")
    return 0


# #318: NOT /bin/true, unlike ghidra-worker.py's own --selftest probe.
# Confirmed live, in order: (1) CAPE's platform autodetection
# (File.get_platform() in lib/cuckoo/common/objects.py) classifies an ELF
# as "linux", and this host has Linux binaries analysis disabled (no Linux
# CAPE guest exists, only win11-cape) -- a real /bin/true submission was
# rejected outright with "Linux binaries analysis isn't enabled". (2) a
# plain .txt fixture was rejected too, by demux.py's filename-based
# JUNK_EXTENSIONS anti-noise filter (.txt/.md/.yml/.yaml/.yar/.yara), before
# submission ever reached platform detection. .dat with the same plain
# content clears both -- see the fixture file's own header for the full
# reasoning.
ROUND_TRIP_PROBE = Path(__file__).resolve().parent / "fixtures" / "selftest-probe.dat"


def selftest_round_trip(client: CapeClient) -> int:
    """#318: exercise submit -> wait -> report against a live CAPE machine.

    Not run by default even when reachability checks pass (see selftest()
    below) -- this is a real VM detonation on shared infrastructure
    (ANALYSIS_TIMEOUT-bounded, up to 20 minutes; contends with win11-sandbox
    for the #320 shared KVM lock), not a cheap contract probe like
    ghidra-worker.py's own /bin/true check against a stateless container.
    Confirmed live (2026-08-08) against this host's actual api.conf: the
    three endpoints this depends on -- [filecreate]/[taskstatus]/
    [taskreport] -- are enabled by default, unlike [cuckoostatus] (see
    CapeClient.ready()'s own docstring).
    """
    if not ROUND_TRIP_PROBE.is_file():
        print(f"\n{ROUND_TRIP_PROBE} not present - skipping the round trip")
        return 0
    print(f"\nround trip on {ROUND_TRIP_PROBE} (route={ROUTE}) ...")
    print(f"  budget: up to {ANALYSIS_TIMEOUT}s, polling every {POLL_INTERVAL}s")
    try:
        task_id = client.submit(ROUND_TRIP_PROBE)
        print(f"  task_id        : {task_id}")
        state = client.wait(task_id)
        print(f"  final state    : {state}")
        report = client.report(task_id)
    except CapeError as e:
        print(f"  FAILED: {e}")
        print("  The endpoint contract has probably changed, or the "
              "win11-cape machine is not correctly registered. Compare "
              "against /opt/CAPEv2/web/apiv2/views.py, which is the "
              "authority on this host.")
        return 1
    info = report.get("info") if isinstance(report, dict) else None
    target = report.get("target") if isinstance(report, dict) else None
    signatures = report.get("signatures") if isinstance(report, dict) else None
    print(f"  score          : {(info or {}).get('score') if isinstance(info, dict) else None}")
    print(f"  category       : {(target or {}).get('category') if isinstance(target, dict) else None}")
    print(f"  signatures     : {len(signatures) if isinstance(signatures, list) else 0}")
    if not isinstance(report, dict) or not report:
        print("  FAILED: report was empty - the contract is broken")
        return 1
    print("\nround trip OK")
    return 0


def selftest() -> int:
    """Check reachability, then offer the #318 round trip.

    The round trip itself is gated behind --round-trip (see
    selftest_round_trip()'s own docstring for why) -- plain --selftest stays
    a cheap, always-safe check, same contract every other worker's
    --selftest in this repo holds itself to.
    """
    client = CapeClient(API_BASE, API_AUTH)
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
    if "--round-trip" not in sys.argv:
        print("\nreachability OK. Pass --selftest --round-trip for a real "
              "submit/wait/report cycle against a live win11-cape "
              "detonation (takes real minutes, see selftest_round_trip()'s "
              "own docstring).")
        return 0
    return selftest_round_trip(client)


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
