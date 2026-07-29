# Shared Work Ledger

This is the coordination source of truth for Kimi, Codex, and Sonnet.
Use it to claim work, record evidence, request review, and hand off unfinished
tasks without duplicating changes.

Last reconciled: 2026-07-29

## Working agreement

1. Read [`ROADMAP.md`](ROADMAP.md) and this ledger before starting.
2. Claim exactly one primary work item by setting `Owner`, `Status`, `Branch`,
   and `Updated`. Do not start an item already owned by another agent.
3. Keep changes inside the claimed scope. Create a new ledger row when new work
   is materially different.
4. Record commands, tests, deployment results, and blockers in the item's
   evidence file or pull request. Never mark an item done from code inspection
   alone when its acceptance criteria require a live system.
5. Move work to `REVIEW` before another agent validates it. The reviewer must
   not be the implementing owner.
6. A handoff must leave a concrete next action. `BLOCKED` without a stated
   unblock condition is not a valid status.
7. Production-changing actions require explicit user authorization. External
   reporting features remain in dry-run mode until separately approved.

## Status vocabulary

| Status | Meaning |
|---|---|
| `READY` | Scoped, dependency-clear, and unclaimed |
| `CLAIMED` | Assigned but implementation has not started |
| `IN_PROGRESS` | Active changes are underway |
| `BLOCKED` | No safe progress until the recorded condition changes |
| `REVIEW` | Implementation complete; independent verification required |
| `DONE` | Acceptance criteria and review both complete |
| `ARCHIVE_CANDIDATE` | Historical value only; verify links before moving |

## Agent lanes

These are default coordination lanes, not exclusive capabilities.

| Agent | Primary lane | Review lane |
|---|---|---|
| Kimi | Repository-wide audits, documentation reconciliation, data/ML research | Scope completeness and doc-to-code consistency |
| Codex | Implementation, integration tests, CI/CD, runtime diagnosis | Buildability, operational safety, deployment evidence |
| Sonnet | Architecture, UX/API contracts, threat modeling, focused code review | Design coherence, security boundaries, acceptance criteria |

## Active ledger

| ID | Priority | Status | Owner | Reviewer | Work item | Depends on | Branch / PR | Updated | Next action |
|---|---:|---|---|---|---|---|---|---|---|
| OPS-001 | P0 | `BLOCKED` | Codex | Sonnet | Restore observability and deployment access for the home stack | User restores home SSH/Dockge access or runner | — | 2026-07-29 | Register the `production-home` runner and restore `production-vps` secrets; then inspect/recover the stopped home Compose stack |
| DASH-001 | P0 | `IN_PROGRESS` | Codex | Sonnet | Finish file-based dashboard render-engine migration and CSP cutover | OPS-001 for live acceptance | `codex/align-dashboard-theme-rendering`, [PR #26](https://github.com/Xore/honeypot-stack/pull/26) | 2026-07-29 | Move ops pages first from `page_*.go` into embedded `ui/*.html`; preserve route output and add nonce tests |
| DASH-002 | P1 | `READY` | — | Sonnet | Complete modal inventory: event detail, payload preview, exports, remaining destructive actions | DASH-001 partials; modal controller exists | — | 2026-07-29 | Specify data attributes/API boundaries for event detail and payload preview, then implement one modal per reviewable change |
| DASH-003 | P1 | `READY` | — | Kimi | Add missing dashboard regression tests and visual acceptance matrix | DASH-001, DASH-002 | — | 2026-07-29 | Turn the matrix in `DASHBOARD-UI-REDESIGN-GUIDE.md` §4 into repeatable browser checks |
| ML-001 | P1 | `READY` | — | Codex | Reconcile and validate the existing ML worker v0.1 scaffold | OPS-001 for live ES checks | — | 2026-07-29 | Compare `ml-worker/` to `ml-worker-plan.md`, add unit fixtures, and decide whether v0.1 is actually runnable before changing its status |
| ML-002 | P1 | `READY` | — | Kimi | Implement v0.2 feature engineering and HBOS fast filtering | ML-001 | — | 2026-07-29 | Write a feature-schema contract and synthetic five-source fixture set before model changes |
| ML-003 | P2 | `READY` | — | Sonnet | Implement v0.3–v0.4 temporal and composite scoring | ML-002 | — | 2026-07-29 | Review sequence-window and explanation contracts; define bounded fallback behavior |
| ML-004 | P2 | `READY` | — | Codex | Implement ML-to-dashboard delivery (v0.5–v0.7) | ML-002, DASH-001 | — | 2026-07-29 | Choose the smallest reliable transport; do not add Redis until file/ES polling limits are measured |
| ML-005 | P3 | `READY` | — | Kimi | Retraining, versioning, drift detection, and threshold controls | ML-003, ML-004 | — | 2026-07-29 | Define offline evaluation and rollback evidence required for v0.8/v1.0 |
| LLM-001 | P2 | `READY` | — | Sonnet | Build the guarded GPU LLM analysis worker in dry-run mode | OPS-001, stable ES, GPU verification | — | 2026-07-29 | Re-verify hardware/model pins and threat-model prompt injection before creating `llm-worker/` |
| GPU-001 | P3 | `READY` | — | Kimi | Add CUDA/fallback and embedding clustering to ML worker | ML-003, LLM-001 GPU-sharing contract | — | 2026-07-29 | Verify current CUDA/PyTorch compatibility; record exact pins before edits |
| REP-001 | P1 | `READY` | — | Sonnet | Build IP reporter Phase 1 with file tailing, SQLite dedup, whitelist, and dry-run | OPS-001 for integration; no external sends | — | 2026-07-29 | Resolve the three documented questions in the plan and define a no-network acceptance suite |
| REP-002 | P2 | `READY` | — | Codex | Add Suricata/Blocklist.de validation and metrics | REP-001 | — | 2026-07-29 | Implement synthetic fixtures and rate-limit tests; keep production reporting disabled |
| KVM-001 | P2 | `READY` | — | Kimi | Reconcile KVM/network-analysis guides with implemented sandbox tooling | OPS-001 for host verification | — | 2026-07-29 | Produce a gap list: implemented scripts, host-only steps, stale paths, and missing automation |
| NOISE-001 | P3 | `READY` | — | Sonnet | Design a safe background-noise prototype that cannot contaminate evidence | KVM-001 and isolation review | — | 2026-07-29 | Threat-model attribution, filtering, and capture labeling before adding any packet generator |
| DOC-001 | P2 | `READY` | — | Kimi | Verify completed/stale docs and prepare archive move | Current roadmap stabilized | — | 2026-07-29 | Validate archive candidates listed in `ROADMAP.md`; update inbound links before moving files |

## Handoff template

Add this block to the pull request, ledger note, or task report:

```text
Work item:
From / to:
Status:
Branch / commit / PR:
Files changed:
What is complete:
What remains:
Commands and tests run:
Observed failures:
Production state changed: yes/no (details)
Exact next action:
Unblock condition:
```

## Review checklist

- Scope matches one ledger item.
- Public routes, APIs, data retention, and security boundaries are preserved.
- Tests cover failure paths and synthetic fixtures contain no real indicators.
- Documentation status matches verified implementation, not intention.
- No credentials, real infrastructure addresses, payloads, or captured data are
  committed.
- Deployment claims include a run URL and post-deploy health evidence.

