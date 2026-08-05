#!/usr/bin/env python3
"""Drain the shared GPU job queue -- pick up jobs deferred by insufficient
headroom (ghidra-worker.py's AI triage today) and run them once the card
frees.

Triggered by honeypot-gpu-queue-drain.timer, a plain systemd oneshot on a
short interval, not a long-running daemon -- matches the rest of this
worker's systemd-native design (see ghidra-worker.py's own module
docstring for why: a `docker run` background service every other honeypot
component already avoids). Processes at most one job per invocation:
simple, and the next timer tick picks up wherever this one left off, the
same reasoning honeypot-ghidra-worker.path's own single-flock drain uses.

Imports ghidra-worker.py as a module (same technique its own test suite
already uses, see tests/test_ghidra_worker.py) to reuse run_triage_workflows()
and patch_result_triage() rather than duplicating the exact assembly logic
a live triage run uses -- a deferred job's result must look identical to
what it would have been if the GPU had been free the first time.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gpu_queue  # noqa: E402

ES_HOST = os.environ.get("GPU_QUEUE_ES_HOST", "http://elasticsearch:9200")


def _load_ghidra_worker():
    spec = importlib.util.spec_from_file_location("ghidra_worker", HERE / "ghidra-worker.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ghidra_worker"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main() -> int:
    queued = gpu_queue.list_queue(ES_HOST, status="queued", job_type="ghidra-triage", size=1)
    if not queued:
        return 0
    job = queued[0]
    job_id = job["_id"]
    ref = job["ref"]

    if job.get("abort_requested"):
        gpu_queue.update_status(ES_HOST, job_id, "aborted")
        print(f"[gpu-queue-drain] {job_id} ({ref}): aborted per operator request")
        return 0

    if not gpu_queue.has_headroom(job["estimated_vram_mib"]):
        print(f"[gpu-queue-drain] {job_id} ({ref}): still not enough free VRAM, leaving queued")
        return 0

    worker = _load_ghidra_worker()

    # Config may have changed since this job was enqueued (an operator
    # disabling triage entirely, say) -- re-check rather than trusting the
    # decision that was valid at enqueue time.
    if not worker.TRIAGE_API_BASE or not worker.endpoint_is_local(worker.TRIAGE_API_BASE):
        gpu_queue.update_status(ES_HOST, job_id, "failed",
                                 error="triage endpoint no longer configured/local")
        print(f"[gpu-queue-drain] {job_id} ({ref}): triage endpoint no longer "
              f"configured or local, marking failed rather than retrying forever")
        return 1

    gpu_queue.update_status(ES_HOST, job_id, "running")
    gpu_queue.increment_attempts(ES_HOST, job_id)
    try:
        payload = job.get("payload") or {}
        ai_triage = worker.run_triage_workflows(payload.get("evidence", ""), payload.get("note", ""))
        if ai_triage is None:
            gpu_queue.update_status(ES_HOST, job_id, "failed", error="model produced no usable answer")
            print(f"[gpu-queue-drain] {job_id} ({ref}): model produced no usable answer")
            return 1
        if not worker.patch_result_triage(ref, ai_triage):
            gpu_queue.update_status(ES_HOST, job_id, "failed", error="result no longer exists to patch")
            print(f"[gpu-queue-drain] {job_id} ({ref}): result file is gone, nothing to patch")
            return 1
    except Exception as e:  # noqa: BLE001
        gpu_queue.update_status(ES_HOST, job_id, "failed", error=repr(e))
        print(f"[gpu-queue-drain] {job_id} ({ref}): failed unexpectedly: {e!r}")
        return 1

    gpu_queue.update_status(ES_HOST, job_id, "completed")
    print(f"[gpu-queue-drain] {job_id} ({ref}): completed "
          f"(risk={ai_triage['risk_level']}, family={ai_triage['family_guess'] or 'none offered'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
