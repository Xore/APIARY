#!/usr/bin/env python3
"""Exercise the Ghidra worker's spool discipline against a stub REST server."""
import json, os, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

WORKER = str(Path(__file__).resolve().parent / "ghidra-worker.py")


class Stub(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = self.path
        if p == "/readyz":                 return self._json({"ok": True})
        if p.startswith("/status/"):       return self._json({"status": "done"})
        if p.startswith("/functions/"):    return self._json(
            [{"address": "0x401000", "name": "sub_401000", "signature": "int f()"}])
        if p.startswith("/strings/"):      return self._json(["hello", "evil.com"])
        if p.startswith("/imports/"):      return self._json(["kernel32.dll!CreateProcessA"])
        self._json({"err": "nope"}, 404)

    def do_POST(self):
        if self.path == "/analyze":
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            return self._json({"id": "job-123"})
        self._json({"err": "nope"}, 404)


def run(env, tmp):
    e = dict(os.environ, **env)
    return subprocess.run([sys.executable, WORKER], env=e,
                          capture_output=True, text=True)


def main():
    srv = HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_port}"

    tmp = Path(tempfile.mkdtemp())
    req, res, smp = tmp / "req", tmp / "res", tmp / "smp"
    for d in (req, res, smp): d.mkdir()

    good = "a" * 64
    bad = "NOTAHASH"
    missing = "b" * 64
    (smp / good).write_bytes(b"MZ\x90\x00fake pe")
    for h in (good, bad, missing):
        (req / f"{h}.request").write_text("")

    env = {"GHIDRA_REQUEST_DIR": str(req), "GHIDRA_RESULTS_DIR": str(res),
           "GHIDRA_SAMPLES_DIR": str(smp), "GHIDRA_API_BASE": base,
           "GHIDRA_LOCK": str(tmp / "lock")}
    r = run(env, tmp)

    fails = []
    def check(cond, label):
        print(("  PASS  " if cond else "  FAIL  ") + label)
        if not cond: fails.append(label)

    print("--- worker stderr ---"); print(r.stderr.strip())
    print("--- assertions ---")
    check(r.returncode == 0, "exit 0")

    rf = res / f"{good}_ghidra.json"
    check(rf.is_file(), "result written for valid request")
    if rf.is_file():
        d = json.loads(rf.read_text())
        check(d["exit_status"] == "ok", "exit_status ok")
        check(d["sha256"] == good, "sha256 recorded")
        check(len(d["strings"]) == 2, "strings collected")
        check(len(d["imports"]) == 1, "imports collected")
        check(d["version"] == 1, "version stamped")
        check(all(k in d for k in ("findcrypt", "call_graph_svg", "ai_triage",
                                   "report_pdf")), "future keys present")
        check(oct(rf.stat().st_mode)[-3:] == "600", "result is 0600")

    check(not (req / f"{good}.request").exists(), "consumed request removed")
    check((req / f"{bad}.request.invalid").exists(), "malformed hash quarantined")
    check((req / f"{missing}.request.missing-sample").exists(),
          "missing sample quarantined")

    st = res / "status.json"
    check(st.is_file(), "status.json written")
    if st.is_file():
        s = json.loads(st.read_text())
        check(s["done"] == 1, f"status done=1 (got {s['done']})")

    # Re-run must be a no-op, not a replay.
    before = sorted(p.name for p in res.iterdir())
    r2 = run(env, tmp)
    after = sorted(p.name for p in res.iterdir())
    check(r2.returncode == 0 and before == after, "second run is idempotent")

    print(f"\n{len(fails)} failure(s)")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
