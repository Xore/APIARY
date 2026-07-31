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
import struct
import subprocess
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

# Call-graph seeds. The service exposes neighbourhoods, not a bulk edge dump
# (/v1/query is a text search), so the graph is walked from the largest
# functions outward and merged. limit is capped at 500 server-side.
GRAPH_SEEDS = int(os.environ.get("GHIDRA_GRAPH_SEEDS", "60"))
GRAPH_DEPTH = int(os.environ.get("GHIDRA_GRAPH_DEPTH", "2"))

# Cryptographic constants, scanned against the sample file directly.
#
# Not done through Ghidra: these are byte patterns, Ghidra adds nothing, and
# the service's hexdump endpoint is bounded per region so a whole-binary scan
# would mean hundreds of requests plus range discovery. The worker already
# holds the bytes.
#
# Corrected from analysis/ghidra/scripts/findcrypt.py, which had two faults
# that matter because an alert path is built on this:
#
#   * "expand 32-byte k" was labelled RC4_INIT_CHECK. It is the ChaCha20 and
#     Salsa20 constant; RC4 has no such table. A wrong algorithm name on an
#     analyst's screen is worse than no name.
#   * b"expa" (4 bytes) and DE AD BE EF (4 bytes) were separate signatures.
#     Four bytes is far too short: 0xDEADBEEF is a ubiquitous sentinel in
#     ordinary software, and "expa" is both a prefix of the ChaCha constant
#     and common text. Both would have fired on benign binaries constantly.
#
#   * SHA-256's K table was packed big-endian. On x86 these are stored
#     little-endian: the big-endian form scores 0 hits against libcrypto.so.3
#     while the little-endian form scores 5. SHA-256 detection could never
#     have fired on any x86 sample. Same correction applied to SHA-1.
#
# Minimum length is now 8 bytes. A signature that cannot meet that is not
# evidence of anything.
CRYPTO_SIGNATURES = [
    # (label, algorithm, bytes, verified)
    # "verified" means the pattern was confirmed to hit on a binary known to
    # contain that algorithm — libcrypto.so.3 or libz.so.1 on x86-64,
    # 2026-07-31. Unverified entries are kept because they are correct in
    # principle, but they have never been observed firing, so a report that
    # relies on one deserves a second look.
    ("AES S-box",             "AES",       bytes([0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5]), True),
    ("AES inverse S-box",     "AES",       bytes([0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38]), True),
    ("ChaCha20/Salsa20 sigma", "ChaCha20", b"expand 32-byte k", True),
    ("MD5 init state",        "MD5",       struct.pack("<IIII", 0x67452301, 0xEFCDAB89,
                                                       0x98BADCFE, 0x10325476), True),
    ("SHA-256 K constants",   "SHA-256",   struct.pack("<IIII", 0x428a2f98, 0x71374491,
                                                       0xb5c0fbcf, 0xe9b5dba5), True),
    ("CRC-32 table",          "CRC-32",    struct.pack("<IIII", 0x00000000, 0x77073096,
                                                       0xEE0E612C, 0x990951BA), True),
    ("DES initial permutation", "DES",     bytes([0x3a,0x32,0x2a,0x22,0x1a,0x12,0x0a,0x02]), False),
    ("SHA-1 init state",      "SHA-1",     struct.pack("<IIIII", 0x67452301, 0xEFCDAB89,
                                                       0x98BADCFE, 0x10325476, 0xC3D2E1F0), False),
]


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
                # Kept for the call-graph seeding below, which must pick the
                # largest functions rather than the first ones.
                "size": f.get("size") or 0,
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


def scan_crypto(sample: Path) -> list:
    """Scan the sample for cryptographic constant tables.

    Addresses are reported as "file+0x<offset>", not virtual addresses. The
    mapping from file offset to VA needs section headers this worker does not
    parse, and an offset labelled as an address would be quietly wrong in a
    field an analyst may act on. Saying which one it is costs nothing.
    """
    try:
        data = sample.read_bytes()
    except OSError as e:
        log(f"  [!] crypto scan: {e}")
        return []
    hits = []
    for label, algorithm, sig, _verified in CRYPTO_SIGNATURES:
        start = 0
        while True:
            at = data.find(sig, start)
            if at < 0:
                break
            hits.append({
                "address": f"file+0x{at:x}",
                "constant": label,
                "algorithm": algorithm,
            })
            start = at + 1
            # One table can repeat; report a few and stop rather than filling
            # the report with the same finding.
            if sum(1 for h in hits if h["constant"] == label) >= 4:
                break
    return hits


def build_call_graph(client: "GhidraClient", job: str, functions: list,
                     sha: str) -> str | None:
    """Walk the call graph and render it, returning the SVG filename or None.

    The service has no bulk edge dump — /v1/query is a text search — so the
    graph is assembled from neighbourhood queries seeded at the largest
    functions, which is where the original scripts/call_graph.py also started.
    Server-side limit is capped at 500.
    """
    # Seed from the LARGEST functions, not the first ones.
    #
    # The endpoint returns functions in address order, so functions[:N] is the
    # bottom of the address space — PLT thunks and init stubs, which are tiny
    # and call nothing. Seeding there produced a graph of 63 nodes and 6 edges
    # on a binary with 11228 functions: technically a call graph, and useless.
    # Body size is the same heuristic scripts/call_graph.py used.
    ranked = sorted(functions, key=lambda f: -(f.get("size") or 0))
    seeds = [f["address"] for f in ranked[:GRAPH_SEEDS] if f.get("address")]
    if not seeds:
        return None
    nodes: dict[str, str] = {}
    edges: set[tuple[str, str]] = set()
    for addr in seeds:
        try:
            g = client._request(
                "GET",
                f"/v1/results/{job}/graph/{addr}?depth={GRAPH_DEPTH}&limit=500")
        except GhidraError as e:
            log(f"  [!] graph {addr}: {e}")
            continue
        if not isinstance(g, dict):
            continue
        for n in g.get("nodes", []):
            if n.get("addr"):
                nodes[n["addr"]] = n.get("name") or n["addr"]
        for e in g.get("edges", []):
            # The service names these "source"/"target" — not from/to or
            # src/dst, both of which were guessed wrong the first time and
            # produced a silent zero-edge graph.
            src, dst = e.get("source"), e.get("target")
            if src and dst:
                edges.add((src, dst))
    if not edges:
        log("  [.] call graph: no edges recovered")
        return None

    def q(text: str) -> str:
        # Function names come from the sample and are attacker-controlled.
        # Escape for DOT, and drop anything non-printable rather than trusting
        # graphviz with it.
        clean = "".join(c for c in text if c.isprintable() and c not in '"\\')
        return clean[:64]

    dot_lines = ["digraph callgraph {", '  node [shape=box, fontsize=9];']
    for addr, name in sorted(nodes.items()):
        dot_lines.append(f'  "{q(addr)}" [label="{q(name)}"];')
    for src, dst in sorted(edges):
        dot_lines.append(f'  "{q(src)}" -> "{q(dst)}";')
    dot_lines.append("}")
    dot_path = RESULTS_DIR / f"{sha}_callgraph.dot"
    dot_path.write_text("\n".join(dot_lines))
    dot_path.chmod(0o600)

    svg_path = RESULTS_DIR / f"{sha}_callgraph.svg"
    try:
        subprocess.run(["dot", "-Tsvg", str(dot_path), "-o", str(svg_path)],
                       check=True, capture_output=True, timeout=120)
    except FileNotFoundError:
        # graphviz is an optional host dependency. Without it the DOT is still
        # written and usable; only the inline picture is lost.
        log("  [.] graphviz 'dot' not installed - DOT written, no SVG")
        return None
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log(f"  [!] graphviz failed: {e}")
        return None
    svg_path.chmod(0o600)
    log(f"  [+] call graph: {len(nodes)} nodes, {len(edges)} edges")
    return svg_path.name


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
        "findcrypt": scan_crypto(sample),
        "call_graph_svg": build_call_graph(client, job, parts["functions"], sha),
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
