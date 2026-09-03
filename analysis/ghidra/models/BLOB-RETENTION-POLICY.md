# `ghidra_ollama_models` blob retention policy

Filed as #2852 (492 G on `/var`, the single largest reducible item — reducible
in principle, because Ollama model blobs are re-pullable from the upstream
registry, unlike captured honeypot data). This document records the audit
that issue asked for and the resulting policy.

## What's in the volume, measured 2026-09-03

`docker exec ghidra-ollama-1 ollama list` returns 47 models, 492 G total
(`docker system df`), backed by 158 blob files and 47 manifests
(`sudo du -sh .../models/{blobs,manifests}` → 492G / 200K — the manifests
themselves are negligible; it is all weights).

`analysis/ghidra/models/audit-blob-retention.sh` (added by this change)
classifies every pulled model against two sources:

1. **Live-service tags** — read straight from config: `approved-models.json`'s
   three slot artifacts (all `qwen3:14b`), `llm-worker/.env.example`'s
   `LLM_MODEL` default, `honeypot-galah/compose.yml`'s `LLM_MODEL`
   (`qwen2.5:7b-instruct-q4_K_M`), and `vault-worker/.env.example`'s
   `VAULT_EMBEDDING_MODEL` (`nomic-embed-text:latest`).
2. **Roster files** passed as arguments — the paused #1947 benchmark's own
   model lists on the homeserver, `/mnt-1/benchmarks/models_all.txt` (38
   models, phase 1's corpus, already run) and `/mnt-1/benchmarks/models_extra_all.txt`
   (95 models, the phase 2-4 roster #1947 has not yet pulled or run).

Result, run against both roster files: **every one of the 47 currently
pulled models is accounted for** — either a live-service dependency or a
member of #1947's roster. Zero fall into class (b) superseded-tag or (c)
referenced-by-nothing. The blob-level cross-reference (manifest digests vs.
files under `blobs/`) is likewise clean: no orphaned blobs from an
interrupted pull, no manifest pointing at a missing blob.

**Nothing was removed.** The issue's own premise — that this volume holds
obvious stale/duplicate cruft — does not hold once checked against the
paused benchmark's roster; it holds *more* models than are pulled yet (87 of
the 95-entry extra roster, including the two largest planned pulls,
`GLM-4.6-REAP-218B` and `LOREA-cyber-66B`, have not been fetched — resuming
#1947 will grow this volume further before it shrinks). A prior session's
memory note on #1947 says exactly why removal now would be a mistake: "a
missing blob surfaces weeks later as a benchmark that cannot reproduce its
own baseline."

## Policy

1. **Do not prune `ghidra_ollama_models` while #1947 is open.** Every model
   in `models_all.txt` is load-bearing for reproducing phase 1's already-published
   results; every model in `models_extra_all.txt` is load-bearing for phases
   2-4, which have not run yet.
2. **Once #1947 closes (or is explicitly abandoned)**, re-run
   `audit-blob-retention.sh` without the roster-file arguments — that drops
   the benchmark roster from "known" and leaves only the three live-service
   tags. Anything the benchmark pulled and nothing else references at that
   point is a legitimate (b)/(c) candidate for `ollama rm`.
3. **Removal always goes through `ollama rm <tag>` (or the HTTP delete API),
   never `rm` under `/var/lib/docker/volumes`** — the manifest index must stay
   consistent with the blob store, and only Ollama's own removal path
   updates both.
4. **The three live-service tags are permanent exceptions** regardless of
   benchmark state: `qwen3:14b` (ghidra/revdeck/sessions slots, and
   `llm-worker`'s default), `qwen2.5:7b-instruct-q4_K_M` (galah), and
   `nomic-embed-text:latest` (vault-worker's embedding model, currently
   disabled by `VAULT_EMBEDDING_ENABLED=false` but pinned for when it is
   turned on).
5. **A model bump changes what's "live"** — if `approved-models.json`,
   `llm-worker/.env.example`, `honeypot-galah/compose.yml` or
   `vault-worker/.env.example` change which tag they reference, the old tag
   drops out of the live set on the next audit run; it isn't removed
   automatically, and shouldn't be until the new tag has actually been
   verified serving traffic.

## What this means for the `/var` capacity incident

This audit closes #2852 without reclaiming space: the 492 G is fully
spoken-for, not neglected.

It should not be read as a pointer to the other levers, because they were
worked in the same batch and **all four ended at zero bytes reclaimed**:

| lever | outcome |
|---|---|
| #2852 (this) | 0 — every one of the 47 pulled models is live-service or #1947 roster |
| #2862 (dionaea bistreams) | 0 by design — the 30-day window was kept on a forensic argument, and nothing in the store is 30 days old yet |
| #2859 (writable layers / build cache) | 0 — 99.9% of the 245.8 GB is one excluded benchmark container, and the build cache sits under its own 20 GB `reservedSpace` floor by design |
| #2882 (reporter `audit.json`) | 0 so far — rotation is implemented but cannot deploy until `honeypot-utilities`' Arcane project sync is unblocked (#2858), and on first start the 6 GB file becomes `audit.json.1` and is not released for roughly four more rotations |

`/var` was measured **worse** at the end of that batch than at the start
(94% → 96%, 116 G → 86 G free), and the Elasticsearch cluster is still `red`
on the disk watermark. See #2820 for the re-measurement and #2823 for the
alarm.

The two reclaims still on the table are both decisions rather than code:

- **#2904** — 52.39 GB of dangling anonymous CI volumes, the largest
  provably disposable item on the host, blocked on a human's removal
  decision.
- **#1947** — this volume. Rule 2 above would release the **44 benchmark-only
  models, roughly 475 G of the 492 G**, and unlike captured honeypot data
  every byte of it is re-pullable from the upstream registry. That number
  belongs next to any decision about #1947's fate: the benchmark is *paused*
  pending a RAM install, not progressing, so this policy is in practice an
  indefinite hold on 475 G. It is still the right hold — a missing blob
  surfaces weeks later as a benchmark that cannot reproduce its own baseline
  — but it should be held knowingly.
