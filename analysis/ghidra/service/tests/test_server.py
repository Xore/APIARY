#!/usr/bin/env python3
"""Exercise the replacement Ghidra service (#245) end-to-end against a fake
`analyzeHeadless` -- a shell script standing in for the real one, so this
runs in CI seconds without needing a real Ghidra install or a real sample.

The fake script writes the same three artifact files the real
export_json.py post-script produces, in the exact shapes
analysis/ghidra/worker/ghidra-worker.py's GhidraClient expects (confirmed
directly against the real service on the homeserver before writing this,
not invented) -- verifying server.py's HTTP/queue layer, not Ghidra itself.

Usage: analysis/ghidra/service/tests/test_server.py
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parent.parent
SERVER = str(SERVICE_DIR / "server.py")

fails = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        fails.append(label)


FAKE_HEADLESS = """#!/bin/sh
# $1=project_dir $2=proj_<id> $3=-import $4=<sample> $5=-scriptPath
# $6=<script_dir> $7=-postScript $8=export_json.py $9=<artifacts_dir>
# $10=-deleteProject -- matches server.py's _command() argv order exactly.
artifacts_dir="$9"
mkdir -p "$artifacts_dir"
cat > "$artifacts_dir/functions.json" <<'EOF'
{"total": 2, "offset": 0, "limit": 100, "functions": [
  {"addr": "0x401000", "name": "main", "canonical_name": "main", "signature": "undefined main(void)", "size": 64},
  {"addr": "0x401100", "name": "FUN_00401100", "canonical_name": "FUN_00401100", "signature": "undefined FUN_00401100(void)", "size": 32}
]}
EOF
cat > "$artifacts_dir/strings.json" <<'EOF'
{"count": 2, "strings": [{"addr": "0x402000", "s": "hello"}, {"addr": "0x402010", "s": "evil.example"}]}
EOF
cat > "$artifacts_dir/imports.json" <<'EOF'
[{"name": "printf", "library": "libc.so.6"}, {"name": "CreateProcessA", "library": "kernel32.dll"}]
EOF
exit 0
"""

FAKE_HEADLESS_FAIL = """#!/bin/sh
exit 1
"""


def get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())


def post_file(url, data):
    boundary = "----test"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="sample.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                  headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def wait_status(base, job_id, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = get(f"{base}/status/{job_id}")
        if status["status"] in ("done", "failed"):
            return status
        time.sleep(0.2)
    raise TimeoutError(f"job {job_id} did not finish in {timeout}s")


def run_server(fake_headless_script, port, data_dir):
    script_path = Path(data_dir) / "fake_headless.sh"
    script_path.write_text(fake_headless_script)
    script_path.chmod(script_path.stat().st_mode | stat.S_IEXEC)
    env = dict(os.environ)
    env.update({
        "GHIDRA_ANALYZE_HEADLESS": str(script_path),
        "GHIDRA_SCRIPT_DIR": str(SERVICE_DIR),
        "GHIDRA_DATA_DIR": str(Path(data_dir) / "jobs"),
        "PORT": str(port),
    })
    return subprocess.Popen([sys.executable, SERVER], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def wait_health(base, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = get(f"{base}/v1/health")
            if resp.get("status") == "ok":
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise TimeoutError("server did not become healthy")


def test_success_path():
    with tempfile.TemporaryDirectory() as tmp:
        port = 19191
        proc = run_server(FAKE_HEADLESS, port, tmp)
        try:
            base = f"http://127.0.0.1:{port}"
            wait_health(base)

            submit = post_file(f"{base}/analyze", b"\x7fELF fake sample bytes")
            check("job_id" in submit and submit["status"] == "queued", "analyze returns job_id + queued")
            job_id = submit["job_id"]

            status = wait_status(base, job_id)
            check(status["status"] == "done", "job reaches done")

            functions = get(f"{base}/results/{job_id}/functions?offset=0&limit=1")
            check(functions["total"] == 2, "functions total reflects full set")
            check(len(functions["functions"]) == 1, "functions respects limit")
            check(functions["functions"][0]["name"] == "main", "functions field shapes match GhidraClient's expectations")

            strings = get(f"{base}/results/{job_id}/strings")
            check(strings["count"] == 2 and strings["strings"][0]["s"] == "hello", "strings shape matches")

            imports = get(f"{base}/results/{job_id}/imports")
            check(isinstance(imports, list) and imports[0]["name"] == "printf", "imports is a bare list, matching GhidraClient")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def test_failure_path():
    with tempfile.TemporaryDirectory() as tmp:
        port = 19192
        proc = run_server(FAKE_HEADLESS_FAIL, port, tmp)
        try:
            base = f"http://127.0.0.1:{port}"
            wait_health(base)
            submit = post_file(f"{base}/analyze", b"whatever")
            status = wait_status(base, submit["job_id"])
            check(status["status"] == "failed", "a nonzero analyzeHeadless exit is reported as failed, not silently done")
            check(status.get("error_code") == "process_error", "failure carries a specific error_code")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def test_unknown_job_404s():
    with tempfile.TemporaryDirectory() as tmp:
        port = 19193
        proc = run_server(FAKE_HEADLESS, port, tmp)
        try:
            base = f"http://127.0.0.1:{port}"
            wait_health(base)
            try:
                get(f"{base}/status/{'0' * 32}")
                check(False, "unknown job_id returns 404")
            except urllib.error.HTTPError as e:
                check(e.code == 404, "unknown job_id returns 404")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def test_extract_file_filename():
    sys.path.insert(0, str(SERVICE_DIR))
    from server import _extract_file_filename  # noqa: E402 - test-local import

    headers = (
        'Content-Disposition: form-data; name="file"; filename="sample.bin"\r\n'
        "Content-Type: application/octet-stream"
    )
    check(_extract_file_filename(headers) == "sample.bin", "extracts filename from a normal part")
    check(_extract_file_filename('Content-Disposition: form-data; name="other"') is None,
          "returns None for a non-file field")
    # CodeQL flagged the old backtracking-regex version as a polynomial
    # ReDoS on pathological input (many repeated 'name="file"' substrings) --
    # this is exactly that input, run through the string-based replacement,
    # confirming it's both correct and not a regex at all.
    pathological = 'name="file"' * 5000 + ' filename="evil.bin"\r\nX-Other: y'
    start = time.monotonic()
    result = _extract_file_filename(pathological)
    elapsed = time.monotonic() - start
    check(result == "evil.bin", "still correct on pathological repeated input")
    check(elapsed < 1.0, f"pathological input stays fast ({elapsed:.3f}s), no backtracking blowup")


if __name__ == "__main__":
    test_extract_file_filename()
    test_success_path()
    test_failure_path()
    test_unknown_job_404s()
    if fails:
        print(f"\n{len(fails)} check(s) failed: {fails}")
        sys.exit(1)
    print("\nall checks passed")
