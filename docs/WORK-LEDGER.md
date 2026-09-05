# Working Agreement

> Deleted by the 2026-08-30 bulk purge and restored verbatim by #2896/#2947
> on 2026-09-04. Nothing below was updated during that window.

**Work is tracked in [GitHub issues](https://github.com/Xore/APIARY/issues), not in this file.**

This file used to carry a table of open work items. That table is gone: every
row was migrated to an issue on 2026-07-30, and the issues are now the single
place where work is claimed, coordinated, and reviewed. What remains here is
the part that is not a work item — how we agree to work.

## Why issues and not a ledger table

A markdown table cannot notify anyone, cannot be assigned, cannot carry a
review thread, and cannot be linked from the commit that closes it. It also
drifts: a status column is only as true as the last person who remembered to
edit it, and by the time two agents are editing the same file they are
conflicting over coordination metadata instead of doing the work.

Issues fix all of that, and they put the discussion next to the diff.

## What belongs in an issue

Everything that is work: new features, security defects, bugs, operational
gaps, documentation reconciliation, and anything a plan document describes but
nobody has built yet. If it is not in an issue, it is not tracked.

That includes things noticed in passing. An observation recorded only in a
commit message or a document paragraph is an observation that will be
rediscovered from scratch in three months.

## What belongs in `docs/`

Design, rationale, and reference: how a subsystem is meant to work, why a
particular approach was chosen, what the constraints are. A plan document
should be readable as an explanation, not as a checklist.

The distinction is simple. **The document says what the thing is; the issue
says that it does not exist yet.** When a document describes something
unbuilt, the open item moves to an issue and the document keeps the design
with a link to it.

## How to work an issue

1. Read [`ROADMAP.md`](ROADMAP.md) for sequencing, then the issue.
2. Assign yourself before starting. An unassigned issue is unclaimed; do not
   start one someone else holds.
3. Keep changes inside the issue's scope. Materially different work gets a new
   issue — and opening one mid-task is cheap and correct.
4. Record commands, tests, deployment results, and blockers **in the issue**.
   Never close an item from code inspection alone when its acceptance criteria
   require a live system.
5. Review happens on the pull request or in the issue thread. The reviewer is
   not the implementer.
6. A handoff must leave a concrete next action. "Blocked" without a stated
   unblock condition is not a status.
7. **Production-changing actions require explicit user authorization.**
   External reporting features stay in dry-run until separately approved. This
   one is not a convention to be relaxed later; where the codebase can enforce
   it with a test, it should.

## Labels

| Label | Scope |
|---|---|
| `dashboard` | The Go dashboard, its routes, templates and CSS |
| `vps` | The VPS edge — portbridge, socat, Suricata |
| `windows-sandbox` | `sandbox/windows` and the detonation guest |
| `ghidra` | Static-analysis integration |
| `analysis` | The payload analysis pipeline |
| `ml` / `llm` | The enrichment workers |
| `reporting` | External abuse reporting and publication |
| `ops` | Deployment, runners, observability, host access |
| `security` | Hardening work or a security defect |
| `blocked` | Cannot proceed without an external input or decision |

`blocked` is worth using honestly. Several issues need host access nobody
currently has, and labelling them so is more useful than leaving them looking
merely unstarted.

## Agent lanes

Default coordination lanes, not exclusive capabilities.

| Agent | Primary lane | Review lane |
|---|---|---|
| Kimi | Repository-wide audits, documentation reconciliation, data/ML research | Scope completeness and doc-to-code consistency |
| Codex | Implementation, integration tests, CI/CD, runtime diagnosis | Buildability, operational safety, deployment evidence |
| Sonnet | Architecture, UX/API contracts, threat modeling, focused code review | Design coherence, security boundaries, acceptance criteria |

## Review checklist

- Scope matches one issue.
- Public routes, APIs, data retention, and security boundaries are preserved.
- Tests cover failure paths, and synthetic fixtures contain no real indicators.
- Documentation status matches verified implementation, not intention.
- No credentials, real infrastructure addresses, payloads, or captured data are
  committed.
- Deployment claims include a run URL and post-deploy health evidence.
