You are reconciling a slice of APIARY's documentation with the repository's actual
current state. Work only in the worktree given below. Do not touch anything else.

## Your assignment

GitHub issue #3399, tasks #23–#55 (Group D, first half). The core
architecture/operations docs — this is the highest-traffic, highest-drift slice,
because these are the pages people actually read to operate the thing.

docs/STACK-REBUILD.md, docs/GEOIP-THREAT-INTEL.md, docs/RECOVERY.md,
docs/NETWORK.md, docs/TESTING.md, docs/persona-design.md,
docs/settings-operations.md, docs/KEYCLOAK-OPERATIONS.md, docs/ARCHITECTURE.md,
docs/ROCKY-10-MIGRATION.md, docs/PIPELINES.md, docs/gpu-docker-passthrough.md,
docs/gpu-ml-worker-acceleration.md, docs/knowledge-store-design.md, docs/STORAGE.md,
docs/DASHBOARD-CUTOVER.md, docs/ES-CONSUME-PATTERNS.md, docs/KEYCLOAK-CUTOVER.md,
docs/OPERATIONS.md, docs/canarytoken-live-fire-checklist.md,
docs/community-threat-intel-sharing.md,
docs/container-writable-layer-audit-2026-09-03.md, docs/dionaea-bistreams-retention.md,
docs/honeypot-network-isolation.md, docs/ip-reporting-plan.md,
docs/kvm-network-traffic-analysis.md, docs/kvm-snapshot-vs-golden-image.md,
docs/llm-inference-backend-comparison.md, docs/ml-gpu-coordinated-roadmap.md,
docs/security-fixes.md, README.md, docs/ROADMAP.md, docs/agent-intrusion-threat-model.md,
docs/benchmarks/claim-pools/README.md, docs/dashboard-manual-ip-block-design.md,
docs/ml-worker-plan.md

## The job, per file

Compare what the doc claims against what the repository actually does, and
correct the doc. Not the reverse.

Sources of truth, cheapest first:
1. `arcane/manifests/home-production.json` — the authoritative stack inventory
2. `arcane/home/*/compose.yml` — services, ports, env vars, profiles
3. `git ls-files arcane/home | cut -d/ -f3 | sort -u` — the real stack count
4. `arcane/home/honeypot-dashboard/backend-service/src/main.rs` — the route table
5. `arcane/home/honeypot-init/` — Elasticsearch templates, ingest pipelines, ILM
6. `grep -rn 'profiles:' --include='*.yml'`
7. `graphify query "<question>"` and `graphify explain "<concept>"` when a claim
   spans several files — there is a graphify index in graphify-out/
8. `.github/workflows/*.yml` for anything a CI doc claims

Note the known-hot numbers in this slice, and verify each yourself rather than
trusting this list:
- ARCHITECTURE.md says "31 Arcane-managed sensor/worker/utility stacks", "37 sync
  entries", "Sensor stacks ×22", "Sensor stacks ×21 (isolated networks)" in two
  different diagrams. README.md says "38 deployment pieces — 32 under
  arcane/home/ plus 6 at their own repository-root paths". These cannot all be
  right. Establish the truth from the manifest and the filesystem, then make
  every doc agree, including inside the mermaid node labels.
- NETWORK.md says "zero exceptions across all 32 stacks" for the HP_BIND rule.
- ARCHITECTURE.md enumerates eight compose profile groups; verify with grep.

Specifically hunt for:
- **Counts** that drifted: stacks, sensors, sync entries, deployment pieces.
- **Ports** that moved. Check `arcane/home/*/compose.yml` and `vps/`.
- **Index names** renamed or removed. The init stack is authoritative; the
  PIPELINES.md index catalog is the thing to check against it.
- **Route paths** that no longer exist. Check main.rs.
- **Env var names and defaults** that changed.
- **Claims about retired things.** The Go dashboard (deleted at #1628),
  `Xore/auth-backend` (retired), `honeypot-wordpot` (retired at #2381), the
  Python agent-intrusion worker (retired at #1649, ported to Rust),
  `autoSync` behaviour in ARCANE-GIT-SYNC.md, and anything about the dashboard
  cutover being planned rather than complete (#1628 completed 2026-08-22).
- **References to files or directories that moved** (#1502 moved everything under
  `arcane/home/`; #2352 moved the YARA scanner).
- **Mermaid node labels carrying numbers** — a stale count inside a diagram is
  invisible to the link checker and invisible to the mermaid parser, so a
  diagram can be perfectly valid and perfectly wrong. Fix the labels.

Rules:
- A file is done when it is either corrected, or you have verified every claim in
  it and found no drift. Record which, per file, in your final report.
- **Do not restyle prose that is not wrong.** Minimal diffs. Rewriting a
  paragraph's wording is out of scope.
- Counts, identifiers and paths must be checked by command, never by eye.
- If a doc is genuinely obsolete — superseded by another, or describing a
  retired thing wrongly — say so explicitly in your report and propose deletion.
  Do not silently delete it.
- A plan or record doc may legitimately describe intent that is not shipped. If
  a doc is that kind, mark it as design-record rather than rewriting it to look
  like current behaviour.
- Never invent a number. If you cannot determine the truth, say "undetermined"
  in your report and leave the doc's claim alone.

## Hard rules

- Work ONLY in your worktree. Never `cd` to the main checkout, never run `git
  stash`, never touch `.grit/worktrees/*` belonging to another agent, never push.
- Do not modify any file outside your assigned list, except that you MAY fix a
  broken mermaid diagram in an assigned file if you find one.
- Do not run the full test suite or any docker command. Read-only inspection plus
  your doc edits.
- Commit your work on the worktree's branch with a conventional commit message
  (`docs(<area>): ...`), no AI attribution in the message, and do NOT push.

## Gates your work must keep green

These run in CI. Do not break them:
- `python3 scripts/check-doc-links.py` — every non-fenced relative link resolves
- `node scripts/check-mermaid.mjs` — every mermaid block parses (it needs a
  headless browser and takes ~30s; run it from your worktree)
- `python3 scripts/check-doc-paths-exist.py` — every repo-path citation resolves
- `python3 scripts/check-docs-reachable.py` — docs stay linked from docs/README.md
- `python3 scripts/check-doc-stale-paths.py` — no bare pre-#1502 paths
  (`arcane/**` is exempt; use a `stale-path-ok:` waiver for genuine history)

Run all five before you finish. A green run is part of the deliverable.

## Report back

For each of your files, one line: `path — corrected (what) | verified, no drift
| obsolete (proposal) | undetermined (which claim, why)`. Then a short list of
cross-cutting findings that other slices should know about — in particular, the
authoritative stack/sensor/sync counts with the command you used to establish
them, and every doc that quotes a different number. Be specific about numbers.
