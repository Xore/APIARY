# honeypot-stack — big multi-service honeypot (Dockge, home → VPS)

A full honeypot deployment that follows this repo's CGNAT pattern: the sensors
run at **home under Dockge**, publish only on the WireGuard interface, and are
exposed to the internet **through the VPS** — HTTP via Traefik, everything else
raw-tunnelled with a port bridge.

This is a public repository: copy the example environment files locally and
never commit real addresses, credentials, captures, payloads, or sandbox images.

```mermaid
flowchart LR
  attacker["attacker"] -->|"HTTP/HTTPS"| traefik["Traefik<br/>TLS, auth"]
  attacker -->|"raw TCP/UDP"| portbridge["portbridge"]
  traefik --> wg["WireGuard tunnel"]
  portbridge --> wg
  wg --> home["home honeypot stacks<br/>@ 10.8.0.2"]
```

**All core sensors run without compose profiles.** The only profile is the
optional on-demand `geoip-update` maintenance job. 13 deployment pieces —
12 independent Dockge stacks at home plus the VPS (see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for why the home side split into
12 separate Compose stacks):

| Piece | Runs on | What |
|---|---|---|
| `honeypot-init` ([docker-compose.init.yml](docker-compose.init.yml)) | **home** | one-shot bootstrap jobs: log paths, Elasticsearch templates, Arkime schema, persona validation |
| `honeypot-cowrie`, `honeypot-dionaea`, `honeypot-conpot`, `honeypot-dnp3`, `honeypot-http`, `honeypot-multipot` (this repository, one compose file each) | **home** | the sensors: Cowrie, Dionaea (+ TFTP relay), Conpot personas, DNP3, HTTP/API honeypots, multipot |
| `honeypot-tanner` ([docker-compose.tanner.yml](docker-compose.tanner.yml)) | **home** | SNARE + TANNER application-emulation boundary |
| `honeypot-elk` ([docker-compose.elk.yml](docker-compose.elk.yml)) | **home** | Filebeat, Elasticsearch, Kibana, EveBox, Arkime |
| `honeypot-dashboard` ([docker-compose.dashboard.yml](docker-compose.dashboard.yml)) | **home** | the live investigation dashboard |
| `honeypot-payload-analysis` ([docker-compose.payload-analysis.yml](docker-compose.payload-analysis.yml)) | **home** | payload dedup + YARA scanning |
| `honeypot-utilities` ([docker-compose.utilities.yml](docker-compose.utilities.yml)) | **home** | autoheal, log rotation, disk-space monitoring, reporting |
| [`vps/`](vps/) | **VPS** | Traefik, portbridge raw tunnels, Suricata, and HTTP bridges (SSO via [Xore/auth-backend](https://github.com/Xore/auth-backend)) |

## Read next

| Guide | Covers |
|---|---|
| [docs/CGNAT-DEPLOYMENT.md](docs/CGNAT-DEPLOYMENT.md) | **Start here to deploy.** Home + VPS setup, Dockge, firewall, DNS, boot-safe networking |
| [docs/HOMESERVER-DISK-LAYOUT.md](docs/HOMESERVER-DISK-LAYOUT.md) | Physical disk layout of the homeserver and an Ubuntu autoinstall template to reproduce it |
| [scripts/install-homeserver.sh](scripts/install-homeserver.sh) | Unattended provisioning script (Docker, GPU/NVIDIA, WireGuard, Dockge, the stacks themselves) for a manually-installed base Ubuntu system — fill in [scripts/install-homeserver.conf.example](scripts/install-homeserver.conf.example) first, same idea as a Windows `autounattend.xml` answer file. First cut, see [#518](https://github.com/Xore/honeypot-stack/issues/518) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System architecture and data flow — trust boundaries, container map, event ingestion, correlation/enrichment (p0f, HASSH/JA3/JA4, GeoIP), payload lifecycle, sandbox detonation, evidence types (6 diagrams) |
| [docs/SENSORS.md](docs/SENSORS.md) | The sensor table, resource budgets, investigation UIs, SNARE+TANNER, Suricata, Arkime, and how real attacker IPs survive the tunnel |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Persona inventory, the seeded cowrie filesystem, GeoIP, and how to actually read the data (dashboard, Kibana, Arkime, backups) |
| [docs/ip-reporting-plan.md](docs/ip-reporting-plan.md) | Defensive IP-blocklist reporting (AbuseIPDB/Blocklist.de), dry-run by default |
| [docs/community-threat-intel-sharing.md](docs/community-threat-intel-sharing.md) | Decision: community threat-intel sharing (T-Pot's `ewsposter`/`hpfeeds`) declined, and why |
| [docs/persona-design.md](docs/persona-design.md) | Outbound network policy per honeypot, and host-naming/banner/placement guidance |
| [docs/analysis/ghidra/README.md](docs/analysis/ghidra/README.md) | Static analysis pipeline: headless Ghidra, local AI triage, fuzzy hashing/structural parsing |
| [docs/payload-analysis-workbench.md](docs/payload-analysis-workbench.md) | Unified payload workbench: typed analyzer registry, immutable recipes, fan-out, status, security, deployment and rollback |
| [sandbox/README.md](sandbox/README.md) | The Linux KVM/libvirt detonation sandbox |
| [docs/CI-CD.md](docs/CI-CD.md) | Repository automation, deployment environments, runner setup |
| [docs/STACK-REBUILD.md](docs/STACK-REBUILD.md) | Runbook for a full deliberate reset — stop order, what's preserved vs wiped, and the ordering/permission pitfalls to avoid |
| [deploy-profiles/](deploy-profiles/) | Named deployment shapes (full / ICS-only / web-only) — which of the 17 split home stacks run for a given deployment, plus a validator catching cross-stack drift before deploy |
| [docs/RECOVERY.md](docs/RECOVERY.md) | `factory-reset.sh` — one entry point for "back up, optionally wipe/reset, restart" on the same host |
| [docs/ROADMAP.md](docs/ROADMAP.md) / [docs/WORK-LEDGER.md](docs/WORK-LEDGER.md) | What order work happens in, and how issues are claimed/reviewed |
| [docs/ml-worker-plan.md](docs/ml-worker-plan.md), [docs/gpu-llm-analysis-worker.md](docs/gpu-llm-analysis-worker.md), [docs/gpu-ml-worker-acceleration.md](docs/gpu-ml-worker-acceleration.md) | The homeserver's NVIDIA GPU running local LLM log/payload analysis and CUDA-accelerated anomaly detection — no data leaves the machine |

Work is tracked in [GitHub issues](https://github.com/Xore/honeypot-stack/issues).

## Containment & safety — read this

The honeypot now runs **on your home network**. Higher-interaction sensors
(Dionaea captures live malware; SNARE/TANNER evaluate payloads) are genuinely
hostile-adjacent. Protect your LAN:

- Keep `HP_BIND=10.8.0.2` — sensors bind the WireGuard interface only, never the
  home LAN.
- The `honeynet` / `tanner_local` bridges have no route to your other stacks;
  **do not** attach them to anything real. Never mount the Docker socket.
- Ideally run this on a **dedicated host or VLAN** that can only reach the VPS
  over WireGuard, not the rest of your LAN. Firewall the honeypot host off from
  internal subnets.
- All third-party images (Dionaea, Conpot, SNARE/TANNER, ELK) need a live
  `docker compose pull`/`build` to confirm tags — verify against upstream before
  trusting them.
- Attacker IPs are personal data (GDPR) — keep logs access-controlled and
  short-lived.

> Prefer to keep attackers off your LAN entirely? Run this whole stack **on the
> VPS** instead: set `HP_BIND=0.0.0.0`, skip the `vps/` tunnel stack, and expose
> the ports directly. You lose nothing but the tunnel.
