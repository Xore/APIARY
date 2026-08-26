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
Every tick also opens with a stale-running sweep (#2075): a drainer death
mid-generation used to strand its job as an eternally-running zombie --
requeued once, then failed, per the semantics recorded next to
gpu_queue.py's status list.

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
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gpu_queue  # noqa: E402

ES_HOST = os.environ.get("GPU_QUEUE_ES_HOST", "http://elasticsearch:9200")

# Staleness bound for the crash-recovery sweep below (#2075): well past the
# longest legitimate run. run_triage_workflows() makes one TRIAGE_TIMEOUT-
# bounded request per workflow (two today), so 2x TRIAGE_TIMEOUT plus fixed
# slack can only be exceeded by a drainer that is never coming back. Same
# default and env var as ghidra-worker.py's own TRIAGE_TIMEOUT -- read here
# directly rather than by loading the worker module, so the sweep stays
# cheap enough to sit ahead of the early return in main().
TRIAGE_TIMEOUT = int(os.environ.get("GHIDRA_TRIAGE_TIMEOUT", "300"))
STALE_RUNNING_SECONDS = 2 * TRIAGE_TIMEOUT + 600


def _parse_ts(value) -> float | None:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def sweep_stale_running() -> int:
    """Crash recovery for the running state (#2075): a drainer that died
    between update_status('running') and any terminal write left its job
    'running' forever -- only queued jobs are picked up again, and nothing
    ever consulted started_at. Runs at the head of every tick; returns how
    many zombies were cleaned up."""
    try:
        running = gpu_queue.list_queue(ES_HOST, status="running", job_type="ghidra-triage")
    except Exception as e:  # noqa: BLE001 - ES down must not fail the whole tick
        print(f"[gpu-queue-drain] stale-running sweep skipped ({e!r})")
        return 0

    now = time.time()
    cleaned = 0
    for job in running:
        job_id = job["_id"]
        started = _parse_ts(job.get("started_at"))
        if started is None:
            # update_status("running") always stamps started_at, so a
            # running job without one is already corrupt bookkeeping --
            # age it out now rather than leaving it unowned.
            age_text = "no usable started_at"
        else:
            age = now - started
            if age <= STALE_RUNNING_SECONDS:
                continue  # legitimately generating; not the sweep's business
            age_text = f"running for {int(age)}s"

        if int(job.get("attempts") or 0) < 2:
            gpu_queue.requeue(ES_HOST, job_id)
            print(f"[gpu-queue-drain] {job_id} ({job['ref']}): {age_text} -- "
                  f"drainer died mid-run; requeued (attempt {int(job.get('attempts') or 0) + 1})")
        else:
            gpu_queue.update_status(ES_HOST, job_id, "failed",
                                    error="drainer died mid-generation (recovered by stale-running sweep)")
            print(f"[gpu-queue-drain] {job_id} ({job['ref']}): {age_text} -- "
                  f"drainer died mid-run again; marked failed instead of retrying forever")
        cleaned += 1
    return cleaned


def _load_ghidra_worker():
    spec = importlib.util.spec_from_file_location("ghidra_worker", HERE / "ghidra-worker.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["ghidra_worker"] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main() -> int:
    sweep_stale_running()

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
        # #1698: the pre-flight check above only catches a job aborted while
        # it was still queued. Hand the worker a predicate so an operator can
        # also stop one that is already generating -- it is consulted between
        # streamed chunks, and abandoning the stream is what actually frees
        # the GPU (ollama cancels the inference task on client disconnect).
        ai_triage = worker.run_triage_workflows(
            payload.get("evidence", ""), payload.get("note", ""),
            should_abort=lambda: gpu_queue.is_abort_requested(ES_HOST, job_id))
        if ai_triage is None:
            gpu_queue.update_status(ES_HOST, job_id, "failed", error="model produced no usable answer")
            print(f"[gpu-queue-drain] {job_id} ({ref}): model produced no usable answer")
            return 1
        if not worker.patch_result_triage(ref, ai_triage):
            gpu_queue.update_status(ES_HOST, job_id, "failed", error="result no longer exists to patch")
            print(f"[gpu-queue-drain] {job_id} ({ref}): result file is gone, nothing to patch")
            return 1
    except worker.TriageAborted:
        # Not a failure: somebody asked for this. Terminal state is `aborted`,
        # the same one the pre-flight path uses, so the queue reads the same
        # whether the abort landed before or during the run.
        gpu_queue.update_status(ES_HOST, job_id, "aborted")
        print(f"[gpu-queue-drain] {job_id} ({ref}): aborted mid-generation on operator request")
        return 0
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
