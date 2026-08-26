#!/usr/bin/env python3
"""Tests for gpu-queue-drain.py's stale-running sweep (#2075).

A drainer that died between update_status("running") and any terminal
write -- reboot, OOM kill, power loss mid-generation -- used to strand its
job as an eternally-running zombie: only queued jobs are ever picked up
again, and nothing consulted started_at. The sweep at the head of every
tick owns that transition now: requeue once (attempts < 2), then fail with
an honest error.

Hermetic by construction: every ES touchpoint is stubbed on the module
object, so this runs in seconds on hosts without docker, nvidia-smi, or
Elasticsearch -- which is exactly the point, since the production failure
this guards against only shows up on the real host.
"""
import importlib.util
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

spec = importlib.util.spec_from_file_location("gpu_queue_drain", HERE.parent / "gpu-queue-drain.py")
drain = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drain)

fails = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        fails.append(label)


class FakeQueue:
    """Records what the sweep does instead of talking to Elasticsearch."""

    def __init__(self, jobs):
        self.jobs = jobs
        self.requeued = []
        self.failed = {}
        self.list_calls = []

    def list_queue(self, es_host, status=None, job_type=None, size=100):
        self.list_calls.append(status)
        return [j for j in self.jobs if j.get("status") == status]

    def requeue(self, es_host, job_id):
        self.requeued.append(job_id)

    def update_status(self, es_host, job_id, status, error=None):
        self.failed[job_id] = (status, error)


def zombie(job_id, started_epoch, attempts=1):
    fmt = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_epoch))
    return {"_id": job_id, "ref": f"ref-{job_id}", "status": "running",
            "started_at": fmt, "attempts": attempts}


def run_sweep(jobs):
    fake = FakeQueue(jobs)
    drain.gpu_queue = fake
    cleaned = drain.sweep_stale_running()
    return fake, cleaned


def test_zombie_past_bound_is_requeued_once():
    old = time.time() - (drain.STALE_RUNNING_SECONDS + 120)
    fake, cleaned = run_sweep([zombie("z1", old, attempts=1)])
    check(cleaned == 1, "one zombie past the bound is cleaned up")
    check(fake.requeued == ["z1"], "a first-strike zombie is requeued, giving its retry a chance")
    check(fake.failed == {}, "a first-strike zombie is not marked failed")


def test_repeat_zombie_is_failed_not_looped_forever():
    old = time.time() - (drain.STALE_RUNNING_SECONDS + 120)
    fake, _ = run_sweep([zombie("z2", old, attempts=2)])
    check(fake.requeued == [], "an already-retried zombie is not requeued again")
    status, error = fake.failed.get("z2", (None, None))
    check(status == "failed", "an already-retried zombie reaches a terminal state")
    check("died" in (error or ""), "the terminal error says the drainer died, not a model failure")


def test_legitimately_running_job_is_never_touched():
    fresh = time.time() - 60
    fake, cleaned = run_sweep([zombie("live", fresh, attempts=1)])
    check(cleaned == 0, "a generation inside the bound is left alone")
    check(fake.requeued == [] and fake.failed == {}, "no writes for a legitimately-running job")


def test_running_job_without_usable_started_at_does_not_hide():
    # update_status("running") always stamps started_at, so a running job
    # without one is already corrupt bookkeeping -- it must not become an
    # unownable zombie just because its timestamp is garbage.
    bad = {"_id": "z3", "ref": "ref-z3", "status": "running",
           "started_at": "not-a-timestamp", "attempts": 0}
    fake, cleaned = run_sweep([bad])
    check(cleaned == 1, "a running job with a corrupt started_at is aged out")
    check(fake.requeued == ["z3"], "corrupt-started_at job takes the requeue path on its first strike")


def test_sweep_targets_only_running_ghidra_jobs():
    fake, _ = run_sweep([])
    check(fake.list_calls == ["running"],
          "the sweep queries exactly the status nothing else owns")


def test_sweep_runs_before_the_queued_early_return():
    # The whole reason the sweep exists: a spool whose only job is a zombie
    # has zero queued entries, and main() used to return before anything
    # could notice. The zombie must be cleaned even when there is no work.
    old = time.time() - (drain.STALE_RUNNING_SECONDS * 3)
    fake = FakeQueue([zombie("z4", old, attempts=2)])

    def list_queue(es_host, status=None, job_type=None, size=100):
        fake.list_calls.append(status)
        return [j for j in fake.jobs if j.get("status") == status]

    fake.list_queue = list_queue
    drain.gpu_queue = fake
    rc = drain.main()
    check(rc == 0, "an empty-but-for-a-zombie queue drains cleanly")
    check("running" in fake.list_calls and "queued" in fake.list_calls,
          "the tick looked at running jobs before deciding there was no work")
    status, error = fake.failed.get("z4", (None, None))
    check(status == "failed",
          "the zombie reached a terminal state even though nothing was queued")


def test_es_outage_does_not_fail_the_tick():
    def broken_list_queue(es_host, status=None, job_type=None, size=100):
        raise ConnectionError("elasticsearch unreachable")

    drain.gpu_queue = type("Q", (), {"list_queue": staticmethod(broken_list_queue)})()
    check(drain.sweep_stale_running() == 0,
          "ES being down during the sweep skips it without raising")


if __name__ == "__main__":
    test_zombie_past_bound_is_requeued_once()
    test_repeat_zombie_is_failed_not_looped_forever()
    test_legitimately_running_job_is_never_touched()
    test_running_job_without_usable_started_at_does_not_hide()
    test_sweep_targets_only_running_ghidra_jobs()
    test_sweep_runs_before_the_queued_early_return()
    test_es_outage_does_not_fail_the_tick()
    if fails:
        print(f"\n{len(fails)} failure(s)")
        sys.exit(1)
    print("\nall gpu-queue-drain tests passed")
