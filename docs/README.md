# Documentation map

Start here. The four pillar pages describe the system as it is deployed
today (post dashboard-cutover #1628, 2026-08-22); everything below them is
either a runbook, a design record, or a research note — labeled by what
kind of truth it holds.

## Pillars — what the system *is*

| Page | Covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | system design: two-machine topology, trust boundaries, the dashboard tier, correlation surfaces, sandbox routes |
| [PIPELINES.md](PIPELINES.md) | data flow: ingestion → enrichment → indexing → worker loops → dashboard reads; payload lifecycle; full index catalog |
| [NETWORK.md](NETWORK.md) | network design: CGNAT pattern, ingress paths, source attribution, per-sensor isolation, Docker control surface |
| [STORAGE.md](STORAGE.md) | storage: host tree contract, who-writes/who-reads, Elasticsearch layout, retention and growth bounds |

## Runbooks — how to operate it

| Page | Use when |
|---|---|
| [OPERATIONS.md](OPERATIONS.md) | day-2 operation of the fleet |
| [STACK-REBUILD.md](STACK-REBUILD.md) | rebuilding or migrating an Arcane-managed stack |
| [RECOVERY.md](RECOVERY.md) | something is down |
| [BACKUP-ESSENTIALS.md](BACKUP-ESSENTIALS.md) | backup scope and restore expectations |
| [CONTAINER-UPDATES.md](CONTAINER-UPDATES.md) | updating images without breaking pinned contracts |
| [KEYCLOAK-OPERATIONS.md](KEYCLOAK-OPERATIONS.md) | identity-tier administration |
| [CI-CD.md](CI-CD.md) | how CI validates and ships changes |
| [TESTING.md](TESTING.md) | test surfaces per tier |

## Deployment records — how it got this way

Point-in-time records kept because the decisions in them still bind:
[CGNAT-DEPLOYMENT.md](CGNAT-DEPLOYMENT.md) (the deployment pattern itself),
[ARCANE-GIT-SYNC.md](ARCANE-GIT-SYNC.md) (how commits reach the live host),
[DASHBOARD-CUTOVER.md](DASHBOARD-CUTOVER.md) (the Go→TanStack/Rust cutover,
completed 2026-08-22), [KEYCLOAK-CUTOVER.md](KEYCLOAK-CUTOVER.md),
[HOMESERVER-DISK-LAYOUT.md](HOMESERVER-DISK-LAYOUT.md) (physical disks +
autoinstall).

## Design references — component deep-dives

[Sensors](SENSORS.md) · [persona design](persona-design.md) ·
[deception extensions](DECEPTION-EXTENSIONS.md) ·
[GeoIP/threat intel](GEOIP-THREAT-INTEL.md) ·
[payload workbench](payload-analysis-workbench.md) ·
[network isolation](honeypot-network-isolation.md) ·
[agent-intrusion threat model](agent-intrusion-threat-model.md) ·
[Ghidra/GPU analysis](gpu-docker-passthrough.md) ·
[KVM traffic analysis](kvm-network-traffic-analysis.md) ·
[snapshot-vs-golden-image](kvm-snapshot-vs-golden-image.md) ·
[Windows 11 malware lab](windows11-malware-lab-hardening.md)

## Plans and evaluations — forward-looking or comparative

[ROADMAP.md](ROADMAP.md) · [WORK-LEDGER.md](WORK-LEDGER.md) ·
[ml-worker plan](ml-worker-plan.md) / [evaluation](ml-worker-evaluation.md) /
[GPU acceleration](gpu-ml-worker-acceleration.md) /
[coordination roadmap](ml-gpu-coordinated-roadmap.md) ·
[LLM backend comparison](llm-inference-backend-comparison.md) /
[model evaluation](local-llm-model-evaluation.md) /
[production canary record](llm-production-canary-record.md) /
[synthetic canary record](llm-synthetic-canary-record.md) ·
[ip reporting plan](ip-reporting-plan.md) ·
[settings roadmaps](settings-user-configuration-roadmap.md) +
[operations](settings-operations.md) ·
[dashboard roadmap](dashboard-profile-actions-roadmap.md) ·
[github-analysis roadmap](github-analysis-integration-roadmap.md) ·
[community sharing policy](community-threat-intel-sharing.md) ·
[background noise](background-noise.md)

## Records — audit trails

[runtime compatibility record](runtime-compatibility-record.md) ·
[security fixes](security-fixes.md) ·
[manual ip-block design](dashboard-manual-ip-block-design.md) ·
[canarytoken creation design](dashboard-canarytoken-creation-design.md)

Subdirectories (`analysis/`, `research/`, `sandbox/`, `vps/`, `autoinstall/`,
`deploy-profiles/`, `archive/`) hold the same kinds of documents scoped to
their component.
