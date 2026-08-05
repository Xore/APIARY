# Shared GPU job queue

One RTX 4000 Ada Generation (20475 MiB) is shared across every GPU-bound
consumer in this stack (`docs/gpu-ml-worker-acceleration.md` §5,
`docs/local-llm-model-evaluation.md`'s #568 section). Until now, a consumer
that needed the card while it was busy either blocked, competed with
whatever else was running, or (Ghidra's automated triage, the first
consumer wired up) simply skipped that request. This directory holds the
shared mechanism: check free VRAM before calling Ollama, and if there isn't
enough, defer the job instead of losing or blocking it.

## Why Elasticsearch, not a file or a database

Queue state lives in Elasticsearch (`gpu-job-queue` index), the same rule
the dashboard's read path already follows for everything else it shows an
operator — no direct file access. That also means any consumer, in any
container or on the bare host, can enqueue and any other process (the
dashboard, a drainer, an operator running `curl`) can see and act on the
same state without needing a shared filesystem.

## `gpu_queue.py`

Deliberately stdlib-only (`urllib` + `subprocess`, no `elasticsearch`
client, no third-party dependency) so this exact file can be vendored
as-is into any worker's environment, containerized or not. It is
*vendored*, not imported across process/container boundaries:

- `analysis/ghidra/worker/gpu_queue.py` — installed alongside
  `ghidra-worker.py` by `install-analysis-host.sh`.
- `llm-worker/gpu_queue.py` — copied into the container image at build
  time (llm-worker doesn't call into this yet; ghidra-worker.py's AI
  triage is the only consumer today, see "What's wired up" below).

Every consumer's test suite has a contract test asserting its vendored
copy matches this canonical one byte-for-byte (same pattern as
`ghidra-worker.py`'s `TRIAGE_SYSTEM`/`evaluate-models.py` contract test) —
a copy that's drifted is exactly the kind of thing easy to miss in review.
Keep them in sync by hand; there's no build step that does it for you.

### Host-side callers and Elasticsearch

Elasticsearch has no port published to the host on purpose — every other
consumer reaches it by Docker network alias (`http://elasticsearch:9200`),
never from outside Docker. `ghidra-worker.py` is a bare host-level systemd
service, not a container, and can't resolve that name directly.
`gpu_queue.py` detects this (`/.dockerenv`'s absence, the standard way to
tell) and bridges host-side calls through a throwaway
`docker run --network honeynet curlimages/curl` container instead — the
same pattern this repo's other host-side scripts already use for
Elasticsearch access. Containerized callers use `urllib` directly.

## What's wired up

**Ghidra automated triage** (`analysis/ghidra/worker/ghidra-worker.py`):
before calling Ollama for AI triage, checks `gpu_queue.has_headroom()`
against `GHIDRA_TRIAGE_ESTIMATED_VRAM_MIB` (default 14500, measured live
for the approved `qwen3:14b` at the ghidra slot's context — see
`docs/local-llm-model-evaluation.md`'s #568 section). If there isn't
enough, the job is enqueued (`job_type: "ghidra-triage"`, `payload.evidence`
holding exactly what would have been sent to the model) and the
deterministic analysis (decompilation, imports, strings, fuzzy hashes,
capa) still completes and is written normally — only the AI triage field
is deferred, not the whole result.

**The queue is a best-effort optimization layered on triage's pre-existing
fail-soft contract, never a new way for it to fail worse than before this
existed.** If the queue itself is unreachable when a job would be
deferred (Elasticsearch down, a network hiccup), `ghidra-worker.py` falls
through to calling Ollama directly instead of losing the analysis over an
infra problem unrelated to whether the model itself works.

**`gpu-queue-drain.py`**, triggered every 2 minutes by
`honeypot-gpu-queue-drain.timer`, picks up the oldest queued
`ghidra-triage` job, re-checks headroom and `abort_requested`, and if
there's room, imports `ghidra-worker.py` as a module to reuse its exact
`run_triage_workflows()` (so a deferred job's result looks identical to
what a live run would have produced) and `patch_result_triage()` (fills in
just the `ai_triage` field on the already-written result, atomically).
Processes at most one job per invocation — simple, and the next tick picks
up wherever this one left off.

**Dashboard** (`dashboard/gpu_queue.go`): the `/ghidra` page's "GPU queue"
section lists every job (ES-only read, `docSearchAll` against
`gpu-job-queue`) and offers an Abort button on anything still `queued`.
Abort only has an effect before a drainer has committed to running a job
— once `running`, the Ollama call is already in flight, matching
`is_abort_requested()`'s own contract. Setting the flag on a
running/finished job is harmless (the drainer only checks it before
starting a queued one), just a no-op.

## What isn't wired up yet

- **llm-worker** (session/payload/report analysis) doesn't check headroom
  or enqueue yet — `llm-worker/gpu_queue.py` is vendored and contract-tested,
  ready to wire in, but the actual integration (llm-worker's own equivalent
  of `_triage`'s headroom check) hasn't been done.
- **Rev·Deck** (interactive chat) has no queueing at all — an interactive
  session waiting on a queue doesn't have an obvious UX yet, unlike a
  background triage job.
- **GitHub-analysis publishing** — not GPU-bound itself (it publishes
  already-computed Ghidra results), out of scope.
- **Concurrent-model-loading awareness**: the queue only checks free VRAM
  right now, not whether `OLLAMA_MAX_LOADED_MODELS` would actually let two
  jobs' models coexist. `analysis/ghidra/benchmarks/probe-gpu-capabilities.py
  --concurrent-load-models` exists to measure that manually; the queue
  doesn't consult it yet.

## ES document shape

```json
{
  "job_id": "uuid",
  "job_type": "ghidra-triage",
  "ref": "sha256 of the capture (or another job-type-specific reference)",
  "model": "qwen3:14b",
  "estimated_vram_mib": 14500,
  "status": "queued | running | completed | failed | aborted",
  "requested_at": "2026-08-05T15:35:08Z",
  "started_at": null,
  "finished_at": null,
  "abort_requested": false,
  "error": null,
  "attempts": 0,
  "payload": {}
}
```

`payload` is job-type-specific and not indexed as structured fields
(`"enabled": false` in the mapping) — nothing queries into it, a drainer
just fetches the whole document and reads what it needs to actually run
the job later.
