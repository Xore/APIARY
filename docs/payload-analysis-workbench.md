# Payload analysis workbench

The dashboard's `/payload-workbench/{sha256}` route is the unified, local-first orchestration surface for issue #155. It is a separate page rather than an extension of `/ghidra`: recipes and parent runs span deterministic analysis, Ghidra, and two sandbox backends, while `/ghidra/{sha256}`, `/sandbox/{job}` and `/payload-analysis/{sha256}` remain the canonical native result renderers.

## Trust boundary

The browser supplies a captured SHA-256, analyzer IDs from a fixed registry, and three bounded orchestration values: timeout, maximum queue age, and retry allowance. It cannot supply a filesystem path, URL, command, container, VM, network policy, prompt, model tag, credential, environment variable, or free-form JSON. The server resolves the capture from its existing read-only payload mounts and writes only the same empty `{sha256}.request` markers used by the legacy Ghidra and sandbox submit routes.

The dashboard has no Docker, libvirt, systemd, Ghidra, statictools, Ollama, or host-worker socket. Dynamic children retain the existing KVM isolation and fixed network policy. Cancellation removes one exact, still-pending marker; after the host handoff claims it, cancellation is refused and never becomes a process, container, VM, or GPU kill.

GitHub publication is deliberately absent from `Run all`. The workbench links to the existing administrator-only publisher, which retains its confirmation, dry-run, audit, and external-egress gates.

## Analyzer registry

| ID | Applicability | Adapter | Concurrency |
|---|---|---|---|
| `deterministic` | every captured payload | immediate bounded local analysis | CPU |
| `ghidra` | executable, library, or unknown binary | existing Ghidra request spool | shared GPU |
| `linux-sandbox` | dynamically supported non-Windows payload | existing Linux web-request spool | Linux KVM |
| `windows-sandbox` | dynamically supported Windows payload | existing Windows web-request spool | Windows KVM |
| `revdeck` | code artifacts | unavailable until #78 defines the verified contract | shared GPU |

Availability and applicability are computed on the server. An unavailable or incompatible child is retained as `skipped` with a reason, so a parent run explains what did not execute. Model drift is advisory and never changes this decision: deterministic analysis and ingestion continue when the model-status adapter is unavailable or reports drift.

## Recipes and runs

Recipes are stored under `/state/analysis-workbench/recipes.json`. Each edit appends a new immutable revision; an optimistic `base_revision` check rejects lost updates. A recipe is either private to its authenticated subject or shared. Submitted runs copy the selected revision into `recipe_snapshot`, so a later recipe edit cannot change the meaning of an existing result.

Parent runs live as bounded JSON documents under `/state/analysis-workbench/runs/`. The idempotency digest covers owner, captured hash, recipe ID/revision, and the normalized typed selection. Repeating the same request returns the existing run instead of queueing duplicate children; a deliberate rerun uses the bounded child retry action.

Child lifecycle states are `queued`, `claimed`, `running`, `completed`, `skipped`, `failed`, `timed_out`, and `cancelled`. Polling reconciles request markers, existing worker status files, and native result timestamps. One failed child produces a `partial` parent when another child completed, and every completed child links to its native escaped result.

## HTTP contracts

All APIs require a live administrator identity. Every mutation additionally requires a same-origin request, `application/json`, one document no larger than 64 KiB, and the closed Go schema (unknown fields are rejected).

| Method and route | Purpose |
|---|---|
| `GET /api/payload-workbench/registry/{sha256}` | server-derived registry, applicability, external-publication notice, and advisory model health |
| `GET /api/payload-workbench/recipes` | visible private/shared recipe revisions |
| `POST /api/payload-workbench/recipes` | append an immutable recipe revision |
| `GET /api/payload-workbench/runs?sha256=...` | recent parent runs for the caller and payload |
| `POST /api/payload-workbench/runs` | submit a saved revision or typed one-off selection |
| `GET /api/payload-workbench/runs/{run_id}` | reconcile and return one parent run |
| `POST /api/payload-workbench/runs/{run_id}/children/{analyzer_id}/retry` | bounded deliberate retry |
| `POST /api/payload-workbench/runs/{run_id}/children/{analyzer_id}/cancel` | cancel an exact pending marker when supported |

Create, recipe-save, retry, and cancel outcomes use the existing dashboard audit sink. Audit fields name the contract fields but do not copy payload content, prompts, model replies, filenames, credentials, or tool output.

## Model-status adapter

`/var/lib/honeypot-ghidra/model-status.json` remains root-owned mode `0600`. `honeypot-model-status-adapter.service` reads and re-validates it, strips every field outside schema v1, and serves only `GET /v1/status` over `/run/honeypot-model-status/status.sock`. The dashboard mounts that runtime directory read-only and uses `MODEL_STATUS_SOCKET=/model-status/status.sock`. There is no TCP listener and no write, pull, replace, promote, prompt, or model-selection route.

Re-run `sudo analysis/ghidra/install-analysis-host.sh` to install or update the adapter. Its failure only displays `unavailable`; it never disables a worker.

## Deployment, backup, and rollback

The default `ANALYSIS_WORKBENCH_DIR=/state/analysis-workbench` is inside the existing `dashboard-state` volume. `scripts/backup-state.sh` already archives the complete volume, including recipes and runs.

Deploy the dashboard normally after merging. Rollback is additive and safe:

1. deploy the previous dashboard image;
2. optionally disable `honeypot-model-status-adapter.service`;
3. leave `analysis-workbench/` in the state volume (older dashboards ignore it), or restore the named dashboard-state backup while the dashboard is stopped.

The old `/ghidra/submit` and `/sandbox/submit` routes remain compatible. No worker or native result schema is changed by the workbench.

## Limitations

- Backend-specific settings appear only after the backend implements a typed request contract. The current empty-marker workers cannot truthfully accept duration/profile, report-stage, evidence-budget, or artifact-policy choices, so the UI does not pretend they can.
- Rev·Deck/GhidrAssist remains visibly unavailable pending #78.
- A sandbox request already claimed by the host cannot be cancelled from the dashboard.
- Shared-GPU fairness and collision/soak validation remain tracked by #84; the registry exposes the concurrency class and does not bypass serialization.
