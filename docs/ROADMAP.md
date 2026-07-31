# Honeypot Stack Roadmap

This roadmap is the **sequencing** document: what order the work should happen
in, and why. The work itself lives in
[GitHub issues](https://github.com/Xore/honeypot-stack/issues) — see
[`WORK-LEDGER.md`](WORK-LEDGER.md) for how issues are used.

Every deliverable below links to its issue. If something is described here with
no issue behind it, that is a gap: open one.

Last audited: 2026-07-30

## Current baseline

- The VPS edge, WireGuard peer, Suricata, and portbridge are producing fresh
  data.
- CI credentials are in place: the `production-home` runner is online and the
  VPS deployment secrets are set. Deployment is no longer credential-blocked,
  and a read-only Diagnostics workflow can inspect both stacks on demand.
- The dashboard render-engine migration is finished — all fourteen route
  templates live in `dashboard/ui/`, and a test fails the build if markup moves
  back into Go. The CSP cutover has not happened and the modal inventory is
  still partial.
- `ml-worker/` exists as a scaffold, is not a Compose service, and has no
  verified live acceptance evidence. `llm-worker/` and `reporter/` do not
  exist.
- The sandbox and analysis trees contain substantial implemented KVM, Windows,
  YARA, PCAP, and export tooling. Their long-form guides have drifted from it
  and need reconciliation before more parallel implementation.

## Gate 0 — Restore a trustworthy runtime

**[#57](https://github.com/Xore/honeypot-stack/issues/57)**

Nothing ingestion-dependent can be accepted until this gate is green. The
runner, the VPS secrets, and the Diagnostics workflow are done; what remains is
authorized management access to the homeserver, which is not automatable and is
not something the Diagnostics workflow should ever be widened to cover.

## Release 1 — Finish the dashboard platform

Source documents:
[`DASHBOARD-RENDER-ENGINE-GUIDE.md`](DASHBOARD-RENDER-ENGINE-GUIDE.md),
[`DASHBOARD-UI-REDESIGN-GUIDE.md`](DASHBOARD-UI-REDESIGN-GUIDE.md),
[`settings-user-configuration-roadmap.md`](settings-user-configuration-roadmap.md),
[`settings-operations.md`](settings-operations.md),
[`dashboard-profile-actions-roadmap.md`](dashboard-profile-actions-roadmap.md)

| Deliverable | Issue |
|---|---|
| Shared partials and all fourteen route templates in embedded `dashboard/ui/` | ✅ 2026-07-30 |
| CSP cutover with a per-request nonce | [#58](https://github.com/Xore/honeypot-stack/issues/58) |
| Event detail, payload preview, export and destructive-action modals | [#59](https://github.com/Xore/honeypot-stack/issues/59) |
| Behavioural tests and the visual acceptance matrix | [#60](https://github.com/Xore/honeypot-stack/issues/60) |
| Profile action menu, route/administrator settings, logout | [#77](https://github.com/Xore/honeypot-stack/issues/77) |
| Settings subsystem: introspection token rollout and the 72-hour soak | [#81](https://github.com/Xore/honeypot-stack/issues/81) |

The CSP header goes on **last**, after every inline handler is gone. Shipping it
early means either a broken dashboard or a policy quietly written loose enough
to be meaningless.

## Release 2 — Safe enrichment foundations

### 2A. ML worker v0.1–v0.2

Source: [`ml-worker-plan.md`](ml-worker-plan.md). Coordinated execution order
across ML, LLM, dashboard delivery and shared GPU:
[`ml-gpu-coordinated-roadmap.md`](ml-gpu-coordinated-roadmap.md).

| Deliverable | Issue |
|---|---|
| Runtime compatibility record: GPU, drivers and every ML/LLM pin verified live | [#82](https://github.com/Xore/honeypot-stack/issues/82) |
| Audit the scaffold against claimed v0.1 behaviour; fixtures and unit tests | [#61](https://github.com/Xore/honeypot-stack/issues/61) |
| Feature engineering and HBOS fast filtering | [#62](https://github.com/Xore/honeypot-stack/issues/62) |

#82 gates both the ML and LLM tracks. Everything below it assumes host facts
that nobody has verified since they were written down.

Compose integration comes only after resource, checkpoint and failure behaviour
are explicit. Do not begin GPU acceleration here — prove a CPU baseline and
output quality first.

### 2B. IP reporter Phase 1

Source: [`ip-reporting-plan.md`](ip-reporting-plan.md)

| Deliverable | Issue |
|---|---|
| File tailing, whitelist/CIDR, SQLite dedup, cooldowns, rate limits, dry-run | [#68](https://github.com/Xore/honeypot-stack/issues/68) |
| Suricata and Blocklist.de validation with metrics | [#69](https://github.com/Xore/honeypot-stack/issues/69) |

Production reporting requires separate explicit authorization after sampled
false-positive review. Auto-banning is out of scope.

## Release 3 — Analysis intelligence

| Deliverable | Issue |
|---|---|
| 3A — ML temporal/composite detection (v0.3–v0.4), explainable output | [#63](https://github.com/Xore/honeypot-stack/issues/63) |
| 3B — ML dashboard delivery (v0.5–v0.7) | [#64](https://github.com/Xore/honeypot-stack/issues/64) |
| 3C — Upstream YARA corpus sync | [#73](https://github.com/Xore/honeypot-stack/issues/73) |
| 3C — Manual, admin-only GitHub-analysis publisher and dashboard button | [#74](https://github.com/Xore/honeypot-stack/issues/74) |
| 3D — Guarded LLM analysis worker, offline and dry-run | [#66](https://github.com/Xore/honeypot-stack/issues/66) |
| 3D — Local Ollama canary with a real model, synthetic first | [#83](https://github.com/Xore/honeypot-stack/issues/83) |

Source documents:
[`github-analysis-integration-roadmap.md`](github-analysis-integration-roadmap.md),
[`gpu-llm-analysis-worker.md`](gpu-llm-analysis-worker.md).

The YARA corpus sync is the only Release 3 item that does not require Gate 0.

Publication is **manual and button-triggered**, never scheduled; the
cron-driven `collect.sh` path is retired rather than replaced. The dashboard
holds no token and runs no `git`.

## Release 4 — Acceleration and lifecycle

| Deliverable | Issue |
|---|---|
| CUDA selection, GPU-sharing budget, embedding clustering | [#67](https://github.com/Xore/honeypot-stack/issues/67) |
| Shared-GPU slot scheduling, collision drills, 72-hour soak | [#84](https://github.com/Xore/honeypot-stack/issues/84) |
| Retraining, versioning, drift detection, rollback, thresholds (v0.8–v1.0) | [#65](https://github.com/Xore/honeypot-stack/issues/65) |

Sources: [`gpu-ml-worker-acceleration.md`](gpu-ml-worker-acceleration.md),
[`ml-worker-plan.md`](ml-worker-plan.md) v0.8–v1.0. Requires measured CPU
baselines from Release 2 and stable output contracts from Release 3.

## Release 5 — Capture fidelity and deception

| Deliverable | Issue |
|---|---|
| Reconcile the KVM/network-analysis guides against the implemented tooling | [#70](https://github.com/Xore/honeypot-stack/issues/70) |
| Background-noise design that cannot contaminate evidence | [#71](https://github.com/Xore/honeypot-stack/issues/71) |

Sources: [`kvm-network-traffic-analysis.md`](kvm-network-traffic-analysis.md),
[`honeypot-network-isolation.md`](honeypot-network-isolation.md),
[`background-noise.md`](background-noise.md),
[`windows11-malware-lab-hardening.md`](windows11-malware-lab-hardening.md),
[`kvm-snapshot-vs-golden-image.md`](kvm-snapshot-vs-golden-image.md).

Reconciliation first. `e443499` is the argument for that ordering: it found
three files the documentation referenced and that had never been written, plus
paths in `kvm_manage.sh` that disagreed with what Packer actually produces.

## Windows sandbox and static analysis

Tracked as its own issue set rather than a release, because it runs on the
analysis host and does not gate anything in the main stack.

| Deliverable | Issue |
|---|---|
| Phase 1 golden image (epic) | [#47](https://github.com/Xore/honeypot-stack/issues/47) |
| Windows 11 evaluation ISO — operator action | [#49](https://github.com/Xore/honeypot-stack/issues/49) |
| Packer build | [#51](https://github.com/Xore/honeypot-stack/issues/51) |
| libvirt domain and the `GOLDEN_READY` snapshot | [#52](https://github.com/Xore/honeypot-stack/issues/52) |
| End-to-end smoke test, dashboard submit to report | [#53](https://github.com/Xore/honeypot-stack/issues/53) |
| Ghidra request spool and payload-page entry points | [#76](https://github.com/Xore/honeypot-stack/issues/76) |
| Ghidra pipeline phases 3–5 | [#78](https://github.com/Xore/honeypot-stack/issues/78) |

## Operational hygiene

| Deliverable | Issue |
|---|---|
| Bound the Suricata `eve.json` growth on the VPS without breaking Filebeat | [#79](https://github.com/Xore/honeypot-stack/issues/79) |

Not urgent and not blocked, but it is a disk-exhaustion path whose first
symptom would be missing events rather than a disk alert.

## Attribution

| Deliverable | Issue |
|---|---|
| Stop attributing tunnelled traffic to the WireGuard peer | ✅ [#54](https://github.com/Xore/honeypot-stack/issues/54) |
| Close the VPS-side source-recovery gap | [#75](https://github.com/Xore/honeypot-stack/issues/75) |

## Documentation disposition

Verification, link repair and archiving are tracked in
[#72](https://github.com/Xore/honeypot-stack/issues/72). Nothing moves before
its status is verified and inbound links are repaired.

Active implementation plans: `DASHBOARD-RENDER-ENGINE-GUIDE.md`,
`DASHBOARD-UI-REDESIGN-GUIDE.md`, `settings-user-configuration-roadmap.md`,
`ml-gpu-coordinated-roadmap.md`, `ml-worker-plan.md`,
`gpu-ml-worker-acceleration.md`, `gpu-llm-analysis-worker.md`,
`ip-reporting-plan.md`, `github-analysis-integration-roadmap.md`.

Operational runbooks: `CGNAT-DEPLOYMENT.md`, `CI-CD.md`,
`honeypot-network-isolation.md`, `kvm-network-traffic-analysis.md`,
`windows11-malware-lab-hardening.md`, `kvm-snapshot-vs-golden-image.md`.

Research/reference: `background-noise.md`.

Already archived: [`archive/SANDBOX_APIS.md`](archive/SANDBOX_APIS.md) —
superseded by `Xore/honeypot/docs/SCANNERS.md`.

## Priority rule

When multiple issues are ready, select in this order:

1. production recovery or data-integrity blockers;
2. security and isolation defects;
3. shared platform work that unblocks multiple features;
4. deterministic CPU/dry-run foundations;
5. user-facing integrations;
6. GPU optimization and deception enhancements.
