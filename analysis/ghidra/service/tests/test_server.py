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
import base64
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parent.parent
SERVER = str(SERVICE_DIR / "server.py")

fails = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        fails.append(label)


FAKE_HEADLESS = r"""#!/bin/sh
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
cat > "$artifacts_dir/xrefs.json" <<'EOF'
{"0x401000": {"callers": [], "callees": [{"addr": "0x401100", "name": "FUN_00401100"}, {"addr": "0x401200", "name": "CreateProcessA"}]},
 "0x401100": {"callers": [{"addr": "0x401000", "name": "main"}], "callees": []}}
EOF
cat > "$artifacts_dir/decompiled.json" <<'EOF'
{"decompiled_count": 2, "total_functions": 2, "truncated": false, "functions": {
  "0x401000": {"pseudocode": "void main(void) { FUN_00401100(); return; }", "signature": "void main(void)"},
  "0x401100": {"pseudocode": "void FUN_00401100(void) { return; }", "signature": "void FUN_00401100(void)"}
}}
EOF
cat > "$artifacts_dir/globals.json" <<'EOF'
{"total": 1, "truncated": false, "globals": [{"addr": "0x403000", "name": "g_counter", "type": "int", "size": 4}]}
EOF
cat > "$artifacts_dir/types.json" <<'EOF'
{"total": 1, "truncated": false, "types": [{"name": "POINT", "kind": "struct", "size": 8,
  "fields": [{"name": "x", "type": "int", "offset": 0, "size": 4}, {"name": "y", "type": "int", "offset": 4, "size": 4}]}]}
EOF
printf '\220\220\220\220HELLOBIN\000\000\000\000' > "$artifacts_dir/memory.bin"
cat > "$artifacts_dir/memory_map.json" <<'EOF'
{"blocks": [{"name": ".text", "start": "0x401000", "end": "0x40100f", "file_offset": 0, "size": 16}], "total_bytes": 16}
EOF
exit 0
"""

FAKE_HEADLESS_FAIL = """#!/bin/sh
exit 1
"""

# Sleeps long enough to reliably observe "running" (and to actually be
# killable) before it would otherwise finish -- for POST /v1/jobs/{id}/cancel,
# which needs a real live process to terminate, not one that already exited.
FAKE_HEADLESS_SLOW = """#!/bin/sh
sleep 30
exit 0
"""


def get(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read())


def get_binary(url):
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.status, r.headers.get("Content-Type"), r.read()


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


def post_json(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                  headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def delete(url):
    req = urllib.request.Request(url, method="DELETE")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, json.loads(r.read())


def put_json(url, payload, headers=None):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="PUT",
                                  headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def put_json_expect_error(url, payload, headers=None):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="PUT",
                                  headers={"Content-Type": "application/json", **(headers or {})})
    try:
        urllib.request.urlopen(req, timeout=10)
        return None
    except urllib.error.HTTPError as e:
        return e.code


def post_json_expect_error(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                  headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
        return None
    except urllib.error.HTTPError as e:
        return e.code


def wait_status(base, job_id, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = get(f"{base}/status/{job_id}")
        if status["status"] in ("done", "failed", "cancelled"):
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


def test_analyze_b64_success_path():
    # #1164: a locally-evaluated Rev·Deck rewrite's own /upload proxies to
    # this route (JSON, not multipart) instead of /analyze -- same job
    # pipeline underneath, verified against the real failure this was
    # written to fix (POST /upload -> 500, "404 ... /analyze_b64").
    with tempfile.TemporaryDirectory() as tmp:
        port = 19194
        proc = run_server(FAKE_HEADLESS, port, tmp)
        try:
            base = f"http://127.0.0.1:{port}"
            wait_health(base)

            sample = b"\x7fELF fake sample bytes, via analyze_b64"
            submit = post_json(f"{base}/analyze_b64", {
                "file_b64": base64.b64encode(sample).decode(),
                "filename": "sample.bin",
                "persist": True,
            })
            check("job_id" in submit and submit["status"] == "queued", "analyze_b64 returns job_id + queued")
            job_id = submit["job_id"]

            status = wait_status(base, job_id)
            check(status["status"] == "done", "analyze_b64 job reaches done")

            functions = get(f"{base}/results/{job_id}/functions")
            check(functions["total"] == 2, "analyze_b64 job produces the same artifacts as /analyze")

            code = post_json_expect_error(f"{base}/analyze_b64", {"filename": "x"})
            check(code == 400, "missing file_b64 is a 400, not a 500 or a crash")

            code = post_json_expect_error(f"{base}/analyze_b64", {"file_b64": "not valid base64!!", "filename": "x"})
            check(code == 400, "malformed base64 is a 400, not a 500 or a crash")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def test_tools_endpoints():
    # #1164: a locally-evaluated Rev·Deck rewrite's chat tool-calling loop
    # POSTs JSON to /tools/{endpoint} -- this exercises every tool its
    # webui/ghidra_assistant.py TOOLS schema declares, against the fixture
    # xrefs.json/decompiled.json FAKE_HEADLESS now also writes.
    with tempfile.TemporaryDirectory() as tmp:
        port = 19196
        proc = run_server(FAKE_HEADLESS, port, tmp)
        try:
            base = f"http://127.0.0.1:{port}"
            wait_health(base)

            submit = post_file(f"{base}/analyze", b"sample for tools test")
            job_id = submit["job_id"]
            wait_status(base, job_id)

            status = post_json(f"{base}/tools/status", {"job_id": job_id})
            check(status.get("status") == "done", "tools/status matches GET /status")

            functions = post_json(f"{base}/tools/list_functions", {"job_id": job_id, "offset": 0, "limit": 1})
            check(functions.get("total") == 2 and len(functions["functions"]) == 1,
                  "tools/list_functions paginates like /results")

            imports = post_json(f"{base}/tools/list_imports", {"job_id": job_id})
            check(imports.get("imports", [{}])[0].get("name") == "printf", "tools/list_imports shape")

            strings = post_json(f"{base}/tools/list_strings", {"job_id": job_id, "min_length": 6})
            check(strings["count"] == 1 and strings["strings"][0]["s"] == "evil.example",
                  "tools/list_strings applies min_length")

            hits = post_json(f"{base}/tools/query_artifacts", {"job_id": job_id, "query": "evil"})
            check(len(hits["matches"]["strings"]) == 1, "tools/query_artifacts substring search")

            hits_re = post_json(f"{base}/tools/query_artifacts", {"job_id": job_id, "query": "^FUN_", "regex": True})
            check(len(hits_re["matches"]["functions"]) == 1, "tools/query_artifacts regex search")

            decompiled = post_json(f"{base}/tools/decompile_function", {"job_id": job_id, "addr": "0x00401000"})
            check("FUN_00401100" in decompiled.get("pseudocode", ""), "tools/decompile_function normalizes addr + returns pseudocode")

            xrefs = post_json(f"{base}/tools/get_xrefs", {"job_id": job_id, "addr": "401100"})
            check(xrefs.get("callers", [{}])[0].get("name") == "main",
                  "tools/get_xrefs normalizes a bare-hex addr and returns callers")

            code = post_json_expect_error(f"{base}/tools/decompile_function", {"job_id": job_id, "addr": "not-hex"})
            check(code == 400, "tools/decompile_function rejects a non-hex addr")

            code = post_json_expect_error(f"{base}/tools/nonexistent_tool", {"job_id": job_id})
            check(code == 404, "unknown tool name 404s")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def test_v1_capabilities_and_results():
    # #1164: a locally-evaluated Rev·Deck rewrite's own main branch prefers
    # this v1 surface over /tools/*, probing /v1/capabilities first.
    with tempfile.TemporaryDirectory() as tmp:
        port = 19197
        proc = run_server(FAKE_HEADLESS, port, tmp)
        try:
            base = f"http://127.0.0.1:{port}"
            wait_health(base)

            caps = get(f"{base}/v1/capabilities")
            check(caps["capabilities"]["types"] is True, "v1/capabilities advertises real features")
            check(caps["capabilities"]["security_index"] is True,
                  "v1/capabilities advertises the real security-index scorer (#1180)")
            check(caps["capabilities"]["string_references"] is False,
                  "v1/capabilities does not falsely advertise the still-unimplemented string_references")

            submit = post_file(f"{base}/analyze", b"sample for v1 results test")
            job_id = submit["job_id"]
            wait_status(base, job_id)

            functions = get(f"{base}/v1/results/{job_id}/functions?offset=0&limit=1")
            check(functions["total"] == 2 and len(functions["functions"]) == 1,
                  "v1 functions route paginates")

            searched = get(f"{base}/v1/results/{job_id}/functions?q=FUN_")
            check(len(searched["functions"]) == 1 and searched["functions"][0]["name"] == "FUN_00401100",
                  "v1 functions route honors q as a name substring filter")

            imports = get(f"{base}/v1/results/{job_id}/imports?offset=0&limit=1")
            check(imports.get("total") == 2 and len(imports["imports"]) == 1,
                  "v1 imports route paginates (unlike the legacy tools/list_imports)")

            strings = get(f"{base}/v1/results/{job_id}/strings?offset=0&limit=100&min_length=6")
            check(strings["count"] == 1, "v1 strings route applies min_length")

            summary = get(f"{base}/v1/results/{job_id}/summary")
            check(summary["counts"]["functions"] == 2 and summary["status"] == "done",
                  "v1 summary route reports real counts")

            summary_alt = get(f"{base}/v1/jobs/{job_id}/summary")
            check(summary_alt["counts"]["functions"] == 2,
                  "v1 summary is also reachable at the /v1/jobs/{id}/summary path the client tries second")

            try:
                get(f"{base}/v1/results/{'0' * 32}/functions")
                check(False, "v1 results for an unknown job 404s")
            except urllib.error.HTTPError as e:
                check(e.code == 404, "v1 results for an unknown job 404s")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def test_v1_decompile_xrefs_query_graph():
    with tempfile.TemporaryDirectory() as tmp:
        port = 19198
        proc = run_server(FAKE_HEADLESS, port, tmp)
        try:
            base = f"http://127.0.0.1:{port}"
            wait_health(base)

            submit = post_file(f"{base}/analyze", b"sample for v1 decompile/xrefs/query/graph test")
            job_id = submit["job_id"]
            wait_status(base, job_id)

            decompiled = get(f"{base}/v1/results/{job_id}/function/0x401000/decompile")
            check("FUN_00401100" in decompiled.get("pseudocode", ""), "v1 decompile route returns pseudocode")

            xrefs = get(f"{base}/v1/results/{job_id}/xrefs/0x401100")
            check(xrefs.get("callers", [{}])[0].get("name") == "main", "v1 xrefs route returns callers")

            hits = post_json(f"{base}/v1/query", {"job_id": job_id, "query": "evil"})
            check(hits["count"] == 1 and hits["matches"][0]["type"] == "string",
                  "v1 query returns a flat typed list, not the legacy nested dict")

            graph = get(f"{base}/v1/results/{job_id}/graph/0x401000?depth=2&limit=10")
            check("0x401000" in graph["nodes"] and "0x401100" in graph["nodes"],
                  "v1 graph route walks callees from the root")
            check(any(e["from"] == "0x401000" and e["to"] == "0x401100" for e in graph["edges"]),
                  "v1 graph route records the call edge")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def test_v1_types_globals_hexdump():
    with tempfile.TemporaryDirectory() as tmp:
        port = 19199
        proc = run_server(FAKE_HEADLESS, port, tmp)
        try:
            base = f"http://127.0.0.1:{port}"
            wait_health(base)

            submit = post_file(f"{base}/analyze", b"sample for v1 types/globals/hexdump test")
            job_id = submit["job_id"]
            wait_status(base, job_id)

            types = get(f"{base}/v1/results/{job_id}/types")
            check(types["total"] == 1 and types["types"][0]["name"] == "POINT", "v1 types route serves types.json")

            globs = get(f"{base}/v1/results/{job_id}/globals")
            check(globs["total"] == 1 and globs["globals"][0]["name"] == "g_counter",
                  "v1 globals route serves globals.json")

            mem = get(f"{base}/v1/results/{job_id}/memory")
            check(len(mem["blocks"]) == 1 and mem["blocks"][0]["name"] == ".text"
                  and mem["blocks"][0]["start"] == "0x401000" and mem["blocks"][0]["size"] == 16,
                  "v1 memory route serves memory_map.json block metadata")
            check("file_offset" not in mem["blocks"][0],
                  "v1 memory route strips file_offset -- meaningless outside this service")
            check(mem["total_bytes"] == 16, "v1 memory route reports total_bytes")

            dump = get(f"{base}/v1/results/{job_id}/hexdump/0x401000?length=4")
            check(dump["hex"] == "90909090", "v1 hexdump route reads the right file offset for a block-start addr")

            dump2 = get(f"{base}/v1/results/{job_id}/hexdump/0x401004?length=8")
            check(dump2["hex"] == "48454c4c4f42494e", "v1 hexdump route translates a mid-block addr correctly")
            check(dump2["ascii"] == "HELLOBIN", "v1 hexdump route's ascii rendering matches the hex")

            try:
                get(f"{base}/v1/results/{job_id}/hexdump/0x999000?length=4")
                check(False, "hexdump for a never-exported address 404s")
            except urllib.error.HTTPError as e:
                check(e.code == 404, "hexdump for a never-exported address 404s")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def test_v1_security_index():
    # #1180: FAKE_HEADLESS's own xrefs.json has main (0x401000) call both
    # FUN_00401100 (internal, no signal) and CreateProcessA (imported,
    # command_execution, high weight) -- so main is the one function that
    # should score, and FUN_00401100 should have zero signals.
    with tempfile.TemporaryDirectory() as tmp:
        port = 19200
        proc = run_server(FAKE_HEADLESS, port, tmp)
        try:
            base = f"http://127.0.0.1:{port}"
            wait_health(base)

            submit = post_file(f"{base}/analyze", b"sample for v1 security index test")
            job_id = submit["job_id"]
            wait_status(base, job_id)

            summary = get(f"{base}/v1/results/{job_id}/security/summary")
            check(summary["available"] is True, "security summary reports available for a completed job")
            check(summary["summary"]["total_functions"] == 1,
                  "security summary counts only the one function with real signals")
            check(summary["summary"]["bands"]["high"] == 1,
                  "security summary bands the CreateProcessA caller as high")
            check(summary["summary"]["categories"]["command_execution"] == 1,
                  "security summary counts the command_execution category")
            check(summary["summary"]["root_count"] == 1,
                  "security summary counts main (no callers) as an attack-surface root")
            check(summary["coverage"]["components"]["call_edges"] == 1.0,
                  "security coverage reports call_edges as fully computed")

            functions = get(f"{base}/v1/results/{job_id}/security/functions")
            check(len(functions["items"]) == 1 and functions["items"][0]["name"] == "main",
                  "security functions route ranks the scored function")
            check(functions["items"][0]["band"] == "high" and functions["items"][0]["score"] == 40.0,
                  "security functions route reports the right score/band")
            check(functions["pagination"]["total"] == 1, "security functions pagination reports the real total")

            filtered = get(f"{base}/v1/results/{job_id}/security/functions?category=memory_safety")
            check(filtered["items"] == [], "security functions route filters by category")

            bad_sort = None
            try:
                get(f"{base}/v1/results/{job_id}/security/functions?sort=bogus")
            except urllib.error.HTTPError as e:
                bad_sort = e.code
            check(bad_sort == 422, "security functions route rejects an invalid sort field")

            detail = get(f"{base}/v1/results/{job_id}/security/functions/0x401000")
            check(detail["name"] == "main" and len(detail["signals"]) == 1,
                  "security function detail returns main's own signal")
            check(detail["signals"][0]["signal_id"] == "calls_createprocessa",
                  "security function detail identifies the CreateProcessA signal")
            check(len(detail["signals"][0]["evidence"]) == 1,
                  "security function detail carries evidence for its signal")

            try:
                get(f"{base}/v1/results/{job_id}/security/functions/0x401100")
                check(False, "security function detail 404s for a zero-signal function")
            except urllib.error.HTTPError as e:
                check(e.code == 404, "security function detail 404s for a zero-signal function")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def test_v1_annotations():
    with tempfile.TemporaryDirectory() as tmp:
        port = 19200
        proc = run_server(FAKE_HEADLESS, port, tmp)
        try:
            base = f"http://127.0.0.1:{port}"
            wait_health(base)

            submit = post_file(f"{base}/analyze", b"sample for v1 annotations test")
            job_id = submit["job_id"]
            wait_status(base, job_id)

            empty = get(f"{base}/v1/jobs/{job_id}/annotations")
            check(empty["revision"] == 0 and empty["entries"] == {}, "annotations start empty at revision 0")

            created = put_json(f"{base}/v1/jobs/{job_id}/annotations/0x401000",
                                {"display_name": "main_renamed", "comment": "entry point"})
            check(created["revision"] == 1 and created["display_name"] == "main_renamed",
                  "PUT creates an annotation and bumps the revision")

            fetched = get(f"{base}/v1/jobs/{job_id}/annotations")
            check(fetched["revision"] == 1 and fetched["entries"]["0x401000"]["comment"] == "entry point",
                  "GET reflects the created annotation")

            filtered = get(f"{base}/v1/jobs/{job_id}/annotations?addr=0x00401000")
            check(list(filtered["entries"].keys()) == ["0x401000"],
                  "GET ?addr= filters to one entry and normalizes the address")

            updated = put_json(f"{base}/v1/jobs/{job_id}/annotations/0x401000",
                                {"comment": "updated comment"}, headers={"If-Match": '"1"'})
            check(updated["revision"] == 2 and updated["comment"] == "updated comment"
                  and updated["display_name"] == "main_renamed",
                  "PUT with a matching If-Match succeeds, merges fields, and bumps revision again")

            conflict_code = put_json_expect_error(
                f"{base}/v1/jobs/{job_id}/annotations/0x401000",
                {"comment": "stale write"}, headers={"If-Match": '"1"'})
            check(conflict_code == 409, "PUT with a stale If-Match 409s instead of silently overwriting")

            patched = urllib.request.urlopen(urllib.request.Request(
                f"{base}/v1/jobs/{job_id}/annotations",
                data=json.dumps({"annotations": [{"entity_id": "0x401100", "comment": "callee"}]}).encode(),
                method="PATCH", headers={"Content-Type": "application/json"}), timeout=10)
            patched_body = json.loads(patched.read())
            check(patched_body["revision"] == 3 and patched_body["annotations"][0]["addr"] == "0x401100",
                  "PATCH collection fallback creates an entry too")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def test_v1_job_lifecycle_and_dedup():
    with tempfile.TemporaryDirectory() as tmp:
        port = 19201
        proc = run_server(FAKE_HEADLESS, port, tmp)
        try:
            base = f"http://127.0.0.1:{port}"
            wait_health(base)

            sample = b"identical sample bytes for dedup test"
            first = post_file(f"{base}/analyze", sample)
            job_id = first["job_id"]
            wait_status(base, job_id)

            second = post_file(f"{base}/analyze", sample)
            check(second.get("reused_job_id") == job_id and second["job_id"] == job_id,
                  "an identical sample reuses the existing completed job instead of re-analyzing")

            different = post_file(f"{base}/analyze", b"a totally different sample")
            check(different["job_id"] != job_id, "a different sample gets its own job, not deduped")

            listing = get(f"{base}/v1/jobs")
            check(any(j["job_id"] == job_id for j in listing["items"]), "v1 jobs list uses the {items:[...]} shape")

            single = get(f"{base}/v1/jobs/{job_id}")
            check(single["status"] == "done", "v1 GET /jobs/{id} matches legacy /status/{id}")

            status_code, content_type, archive_bytes = get_binary(f"{base}/v1/jobs/{job_id}/export")
            check(status_code == 200 and "zip" in content_type, "v1 export route returns a zip")
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
                names = zf.namelist()
                check("functions.json" in names and "decompiled.json" in names,
                      "exported archive contains the job's artifact files")

            del_status, del_body = delete(f"{base}/v1/jobs/{job_id}")
            check(del_status == 200 and del_body["deleted"] is True, "v1 DELETE /jobs/{id} works at the v1 path too")
            try:
                get(f"{base}/v1/jobs/{job_id}")
                check(False, "deleted job is gone from v1 GET /jobs/{id}")
            except urllib.error.HTTPError as e:
                check(e.code == 404, "deleted job is gone from v1 GET /jobs/{id}")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def test_v1_job_cancel():
    with tempfile.TemporaryDirectory() as tmp:
        port = 19202
        proc = run_server(FAKE_HEADLESS_SLOW, port, tmp)
        try:
            base = f"http://127.0.0.1:{port}"
            wait_health(base)

            submit = post_file(f"{base}/analyze", b"sample for cancel test")
            job_id = submit["job_id"]

            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if get(f"{base}/status/{job_id}")["status"] == "running":
                    break
                time.sleep(0.1)
            else:
                check(False, "job reached running before the cancel attempt")

            cancel_started = time.monotonic()
            cancelled = post_json(f"{base}/v1/jobs/{job_id}/cancel", {})
            check(cancelled["status"] == "cancelled", "cancel marks the job cancelled immediately")

            final = wait_status(base, job_id, timeout=10)
            elapsed = time.monotonic() - cancel_started
            check(final["status"] == "cancelled", "job stays cancelled once the killed process's wait unblocks")
            check(elapsed < 25, f"cancel actually killed the process rather than waiting out the 30s sleep ({elapsed:.1f}s)")

            code = post_json_expect_error(f"{base}/v1/jobs/{job_id}/cancel", {})
            check(code == 409, "cancelling an already-terminal job 409s")

            code = post_json_expect_error(f"{base}/v1/jobs/{'0' * 32}/cancel", {})
            check(code == 404, "cancelling an unknown job 404s")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


def test_jobs_list_and_delete():
    with tempfile.TemporaryDirectory() as tmp:
        port = 19195
        proc = run_server(FAKE_HEADLESS, port, tmp)
        try:
            base = f"http://127.0.0.1:{port}"
            wait_health(base)

            submit = post_file(f"{base}/analyze", b"sample for jobs list test")
            job_id = submit["job_id"]
            wait_status(base, job_id)

            jobs = get(f"{base}/jobs")
            check(isinstance(jobs, list) and any(j.get("job_id") == job_id for j in jobs),
                  "GET /jobs lists a submitted job")

            status, body = delete(f"{base}/jobs/{job_id}")
            check(status == 200 and body.get("deleted") is True, "DELETE /jobs/{id} confirms deletion")

            jobs_after = get(f"{base}/jobs")
            check(all(j.get("job_id") != job_id for j in jobs_after), "deleted job no longer listed")

            try:
                get(f"{base}/status/{job_id}")
                check(False, "deleted job's /status 404s")
            except urllib.error.HTTPError as e:
                check(e.code == 404, "deleted job's /status 404s")

            try:
                urllib.request.urlopen(urllib.request.Request(f"{base}/jobs/{'0' * 32}", method="DELETE"), timeout=10)
                check(False, "deleting an unknown job_id 404s")
            except urllib.error.HTTPError as e:
                check(e.code == 404, "deleting an unknown job_id 404s")
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
    test_analyze_b64_success_path()
    test_tools_endpoints()
    test_v1_capabilities_and_results()
    test_v1_decompile_xrefs_query_graph()
    test_v1_types_globals_hexdump()
    test_v1_security_index()
    test_v1_annotations()
    test_v1_job_lifecycle_and_dedup()
    test_v1_job_cancel()
    test_jobs_list_and_delete()
    test_failure_path()
    test_unknown_job_404s()
    if fails:
        print(f"\n{len(fails)} check(s) failed: {fails}")
        sys.exit(1)
    print("\nall checks passed")
