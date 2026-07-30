# Shared Work Ledger

This is the coordination source of truth for Kimi, Codex, and Sonnet.
Use it to claim work, record evidence, request review, and hand off unfinished
tasks without duplicating changes.

Last reconciled: 2026-07-30

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
| OPS-001 | P0 | `IN_PROGRESS` | Codex | Sonnet | Restore observability and deployment access for the home stack | Recovery still needs user SSH/Dockge access; observability no longer does | `main` @ `13b6a7c` | 2026-07-30 | Runner and VPS secrets are done. `Diagnostics` workflow (`workflow_dispatch`, read-only) now answers all three checks over the `production-home` runner: run it with target `both` and paste the step summary here. Recovering a stopped stack still needs a human shell |
| DASH-001 | P0 | `IN_PROGRESS` | Codex | Sonnet | Finish file-based dashboard render-engine migration and CSP cutover | OPS-001 for live acceptance | [PR #26](https://github.com/Xore/honeypot-stack/pull/26) merged 2026-07-29; `main` @ `9c15991`, `63608e4` | 2026-07-30 | Page migration is **done** — all 14 route templates live in `dashboard/ui/`, every `page_*.go` is a one-line binding, and `TestRouteTemplatesRenderFromEmbeddedUI` fails the build if markup returns to Go. Remaining: the §6 step 4 CSP cutover, which needs a per-request `Nonce` threaded into every page data struct, plus the optional one-file-per-route split of the multi-template bundles |
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
| GHA-001 | P2 | `READY` | — | Sonnet | Pull the upstream auto-generated YARA corpus from `Xore/honeypot` into the local scanner | — | — | 2026-07-30 | Implement `sync-yara.sh` per roadmap Phase 4: fetch, `yara --compile` validate, pin the upstream SHA in a lock file, keep local rules in a separate subtree |
| GHA-002 | P2 | `READY` | — | Codex | Build the manual GitHub-analysis publisher and dashboard button | GHA-001, OPS-001 for host access | — | 2026-07-30 | Resolve the three open questions in the roadmap (retention denylist, archive convention, quota cap) before writing `analysis/github/`; dry-run default must be a test, not a convention |
| WSBX-001 | P2 | `IN_PROGRESS` | Codex | Sonnet | Windows sandbox backend (`sandbox/windows/IMPLEMENTATION_PLAN.md`) | KVM host access for the guest half | `main` | 2026-07-30 | Phase 7's dashboard half is done: content-based Windows/Linux routing, separate spools, merged results and exports, backend off by default. Next is the host half — Phases 1–6 plus the systemd path unit — which needs the KVM host and therefore OPS-001 |
| ATTR-001 | P1 | `REVIEW` | Sonnet | Codex | Stop attributing tunnelled traffic to the WireGuard peer ([#54](https://github.com/Xore/honeypot-stack/issues/54)) | — | `main` | 2026-07-30 | Dashboard half is implemented: a failed `via_port` join now clears the source instead of recording `10.8.0.1`, and the gap is counted as `Unattributed` on `/source-health`. Verify on the live stack that `/ips` no longer lists the peer and note the reported figure |
| ATTR-002 | P2 | `READY` | — | Sonnet | Close the source-recovery gap on the VPS so fewer events are unattributed | ATTR-001 for the measurement, OPS-001 for host access | — | 2026-07-30 | Two independent causes: portbridge logs UDP with no `via_port` (`cl.log(r, client, nil)`), and no dionaea rule carries `:pp`. Decide per sensor whether to add a UDP correlation key or PROXY-wrap the TCP rules; both need a VPS redeploy |
| WSBX-002 | P3 | `BLOCKED` | — | Sonnet | Ghidra static-analysis entry points on the payloads page | `analysis/ghidra/DASHBOARD_INTEGRATION_PLAN.md` Phase 2 | — | 2026-07-30 | Deferred out of Phase 7 on purpose: `serveGhidraSubmit`, `/ghidra/submit`, and `GHIDRA_REQUEST_DIR` do not exist, so the checkbox and button would be a dead route. Build the Ghidra spool first, then the two entry points are a small addition to `serveSandboxSubmit` |

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

