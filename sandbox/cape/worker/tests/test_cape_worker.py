#!/usr/bin/env python3
"""Exercise cape-worker.py's status.json discipline (#319 follow-up).

No CAPE service involved -- write_status() only ever globs REQUEST_DIR and
RESULTS_DIR, and drain()'s empty-queue path returns before it ever
constructs a CapeClient, so both are testable without stubbing CAPE's API at
all. That is deliberately as far as this file goes: the submit/poll/report
round trip already has its own live acceptance test (--selftest
--round-trip, #318, documented in the worker's own module docstring) rather
than a mocked one here, the same division ghidra-worker.py's own test suite
draws between its stubbed spool-discipline tests and full_capabilities.py's
against-the-real-tree checks.

Usage: sandbox/cape/worker/tests/test_cape_worker.py
"""
import importlib.util
import json
import tempfile
from pathlib import Path

WORKER = str(Path(__file__).resolve().parent.parent / "cape-worker.py")

fails = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        fails.append(label)


def load_worker(request_dir: Path, results_dir: Path):
    spec = importlib.util.spec_from_file_location("cape_worker", WORKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.REQUEST_DIR = request_dir
    mod.RESULTS_DIR = results_dir
    return mod


def test_write_status_counts_match_ghidra_worker_shape():
    """Same field names/glob patterns as ghidra-worker.py's write_status(),
    so a future loadCapeStatus() can reuse loadGhidraStatus()'s staleness and
    live-recheck logic almost verbatim (see write_status()'s own docstring).
    """
    with tempfile.TemporaryDirectory() as td:
        req, res = Path(td) / "req", Path(td) / "res"
        req.mkdir()
        res.mkdir()
        worker = load_worker(req, res)

        for name in [
            "1" * 64 + ".request",
            "2" * 64 + ".request.running",
            "3" * 64 + ".request.failed",
        ]:
            (req / name).write_text("")
        (res / ("4" * 64 + "_cape.json")).write_text("{}")
        (res / ("5" * 64 + "_cape.json")).write_text("{}")

        worker.write_status()
        status = json.loads((res / "status.json").read_text())

        check(status["queued"] == 1, f"queued counts *.request only: {status}")
        check(status["running"] == 1, f"running counts *.request.running: {status}")
        check(status["failed"] == 1, f"failed counts *.request.failed: {status}")
        check(status["done"] == 2, f"done counts *_cape.json in RESULTS_DIR: {status}")
        check(status["version"] == worker.RESULT_VERSION, f"version matches RESULT_VERSION: {status}")
        check("updated_at" in status and status["updated_at"], f"updated_at is set: {status}")


def test_write_status_is_atomic():
    """Written via a temp file + os.replace, same discipline write_result()
    itself already holds to -- a reader must never see a half-written file.
    """
    with tempfile.TemporaryDirectory() as td:
        req, res = Path(td) / "req", Path(td) / "res"
        req.mkdir()
        res.mkdir()
        worker = load_worker(req, res)
        worker.write_status()
        check(not (res / ".status.json.tmp").exists(), "temp file is not left behind")
        check((res / "status.json").exists(), "status.json was written")


def test_drain_empty_queue_still_writes_status():
    """An empty spool must not skip status.json -- otherwise a quiet
    honeypot (zero submissions) is indistinguishable from a dead worker,
    exactly the case ghidra-worker.py's own drain() comment calls out.
    """
    with tempfile.TemporaryDirectory() as td:
        req, res = Path(td) / "req", Path(td) / "res"
        worker = load_worker(req, res)
        rc = worker.drain()
        check(rc == 0, f"drain() on an empty queue returns 0, got {rc}")
        check((res / "status.json").exists(), "drain() wrote status.json for an empty queue")
        status = json.loads((res / "status.json").read_text())
        counts = {k: status[k] for k in ("queued", "running", "failed", "done")}
        check(counts == {"queued": 0, "running": 0, "failed": 0, "done": 0},
              f"empty queue reports all-zero counts: {status}")


def main():
    test_write_status_counts_match_ghidra_worker_shape()
    test_write_status_is_atomic()
    test_drain_empty_queue_still_writes_status()
    if fails:
        print(f"\n{len(fails)} FAILURE(S):")
        for f in fails:
            print(f"  - {f}")
        return 1
    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
