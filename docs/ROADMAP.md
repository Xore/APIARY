# Honeypot Stack Roadmap

This roadmap converts the plans under `docs/` into an executable sequence.
Day-to-day ownership and handoffs live in [`WORK-LEDGER.md`](WORK-LEDGER.md).

Last audited: 2026-07-29

## Current baseline

- The VPS edge, WireGuard peer, Suricata, and portbridge are producing fresh
  data.
- The home service surface is currently unavailable: Dashboard, EveBox,
  Kibana, Arkime, and tested honeypot ports refuse connections.
- The dashboard theme alignment and render-engine foundation are on
  `codex/align-dashboard-theme-rendering` / PR #26.
- `ml-worker/` exists as a scaffold but is not present as a root Compose
  service and has no verified live acceptance evidence.
- `llm-worker/` and `reporter/` do not exist.
- The sandbox and analysis trees contain substantial implemented KVM,
  Windows, YARA, PCAP, and export tooling; their long-form guides need a
  doc-to-code reconciliation before more parallel implementation.

## Gate 0 — Restore a trustworthy runtime

Nothing ingestion-dependent can be accepted until this gate is green.

1. Restore authorized management access to the homeserver.
2. Recover the home Docker/Dockge Compose stack.
3. Verify the VPS Suricata mount on the home host is current and visible inside
   Dashboard, Filebeat, and EveBox.
4. Register the `production-home` Actions runner.
5. Restore `production-vps` environment secrets: `VPS_HOST`, `VPS_SSH_KEY`,
   and optional `VPS_USER`/`VPS_PORT`.
6. Record a green end-to-end check: sensor log → Filebeat/Elasticsearch →
   Dashboard and EveBox.

Exit criteria:

- Dashboard, EveBox, Kibana, and Arkime respond through the VPS.
- Elasticsearch health and Filebeat output are green.
- Dashboard source-health timestamps advance.
- A synthetic TEST-NET event appears once in the intended views.
- A deployment run completes for both targets.

## Release 1 — Finish the dashboard platform

Source documents:

- [`DASHBOARD-RENDER-ENGINE-GUIDE.md`](DASHBOARD-RENDER-ENGINE-GUIDE.md)
- [`DASHBOARD-UI-REDESIGN-GUIDE.md`](DASHBOARD-UI-REDESIGN-GUIDE.md)
- [`settings-user-configuration-roadmap.md`](settings-user-configuration-roadmap.md)
- [`dashboard-profile-actions-roadmap.md`](dashboard-profile-actions-roadmap.md)

Deliverables:

1. Move shared partials and route templates from Go constants into embedded
   `dashboard/ui/` files in the documented order.
2. Add typed render methods, per-request nonces, and CSP headers only after all
   inline-handler dependencies are removed.
3. Complete event detail, payload preview, export, and destructive-action
   modals using the shared modal contract.
4. Add role-aware action, command routing, lazy-list, live-map preservation,
   and modal state tests.
5. Automate the dark/light desktop/tablet/mobile visual acceptance matrix.
6. Add the authenticated profile action menu and route settings, administrator
   settings, and logout to auth-backend.

Exit criteria are the completion criteria in the render-engine guide §9 plus a
successful live deployment after Gate 0.

## Release 2 — Safe enrichment foundations

### 2A. ML worker v0.1–v0.2

Source: [`ml-worker-plan.md`](ml-worker-plan.md)

Coordinated execution order for ML, LLM, dashboard delivery, and shared GPU
operation: [`ml-gpu-coordinated-roadmap.md`](ml-gpu-coordinated-roadmap.md).

1. Audit the existing scaffold against its claimed v0.1 behavior.
2. Add deterministic synthetic fixtures and unit tests.
3. Add feature engineering for all documented sources.
4. Add HBOS as a bounded fast filter.
5. Integrate with Compose only after resource, checkpoint, and failure behavior
   are explicit.

Do not begin GPU acceleration here; first prove a CPU baseline and output
quality.

### 2B. IP reporter Phase 1

Source: [`ip-reporting-plan.md`](ip-reporting-plan.md)

1. Start with file tailing, as the document already recommends.
2. Implement whitelist/CIDR filtering, SQLite deduplication, cooldowns, rate
   limits, and structured audit logs.
3. Default to dry-run; acceptance tests must perform no external reports.
4. Treat Suricata reporting as a later phase and auto-banning as out of scope.

Production reporting requires a separate explicit authorization after sampled
false-positive review.

## Release 3 — Analysis intelligence

### 3A. ML temporal/composite detection

- Implement `ml-worker-plan.md` v0.3–v0.4.
- Establish evaluation fixtures and bounded CPU fallback.
- Require explainable output fields before dashboard exposure.

### 3B. ML dashboard delivery

- Implement v0.5–v0.7 after the dashboard rendering platform is stable.
- Measure ES/file polling before introducing Redis.
- Preserve SSE and current dashboard resource limits.

### 3C. Guarded LLM worker

Source: [`gpu-llm-analysis-worker.md`](gpu-llm-analysis-worker.md)

- Re-verify GPU/model pins on the live host.
- Implement input sanitization and schema validation before model integration.
- Start in offline/dry-run mode with synthetic injection-resistance tests.
- Publish no ports and send no captured data to external services.

## Release 4 — Acceleration and lifecycle

Sources:

- [`gpu-ml-worker-acceleration.md`](gpu-ml-worker-acceleration.md)
- [`ml-worker-plan.md`](ml-worker-plan.md) v0.8–v1.0

Deliverables:

- CUDA selection with reliable CPU fallback.
- A tested GPU-sharing budget between ML and LLM workers.
- Embedding-based clustering with a versioned index mapping.
- Retraining schedules, model versioning, drift detection, rollback, and
  threshold controls.

This release requires measured CPU baselines from Release 2 and stable output
contracts from Release 3.

## Release 5 — Capture fidelity and deception

Sources:

- [`kvm-network-traffic-analysis.md`](kvm-network-traffic-analysis.md)
- [`honeypot-network-isolation.md`](honeypot-network-isolation.md)
- [`background-noise.md`](background-noise.md)
- [`windows11-malware-lab-hardening.md`](windows11-malware-lab-hardening.md)
- [`kvm-snapshot-vs-golden-image.md`](kvm-snapshot-vs-golden-image.md)

Sequence:

1. Reconcile the guides against the existing `sandbox/` and `analysis/` trees.
2. Convert missing high-value host procedures into versioned, testable scripts.
3. Validate retention, capture rotation, isolation, and evidence labeling.
4. Prototype background noise only after proving it is tagged/excluded from
   attacker evidence, ML training data, alerts, and public reporting.

## Documentation disposition

### Active implementation plans

- `DASHBOARD-RENDER-ENGINE-GUIDE.md`
- `DASHBOARD-UI-REDESIGN-GUIDE.md`
- `settings-user-configuration-roadmap.md`
- `ml-gpu-coordinated-roadmap.md`
- `ml-worker-plan.md`
- `gpu-ml-worker-acceleration.md`
- `gpu-llm-analysis-worker.md`
- `ip-reporting-plan.md`

### Operational runbooks

- `CGNAT-DEPLOYMENT.md`
- `CI-CD.md`
- `honeypot-network-isolation.md`
- `kvm-network-traffic-analysis.md`
- `windows11-malware-lab-hardening.md`
- `kvm-snapshot-vs-golden-image.md`

### Research/reference designs

- `background-noise.md`

### Archive candidates requiring verification

- `MONOLITH-BREAKDOWN-ROADMAP.md` — all phases are recorded complete.
- `security-fixes.md` — references removed files and a point-in-time CodeQL
  alert set; compare with current alerts before archiving.
- `DASHBOARD-UI-REDESIGN-GUIDE.md` — archive only after the render-engine guide
  absorbs its remaining test and visual acceptance requirements.

Archiving is intentionally a separate work item (`DOC-001`) so link repair and
status verification happen before files move.

## Priority rule

When multiple items are ready, select work in this order:

1. production recovery or data-integrity blockers;
2. security and isolation defects;
3. shared platform work that unblocks multiple features;
4. deterministic CPU/dry-run foundations;
5. user-facing integrations;
6. GPU optimization and deception enhancements.
