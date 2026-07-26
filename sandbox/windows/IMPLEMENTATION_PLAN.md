# Windows 11 Malware Sandbox — Golden Image Implementation Plan

> **Status**: In Progress  
> **Last updated**: 2026-07-27  
> **Host platform**: KVM + QEMU + libvirt + docker-compose (NO VMware)

---

## Host Constraints

The analysis host runs **KVM/QEMU/libvirt** and **docker-compose** only.
- No VMware Workstation, no VirtualBox, no Hyper-V
- No GitHub Actions — the sandbox is triggered **from the dashboard**, not CI
- All VM lifecycle (create, snapshot, revert, destroy) via `virsh` / `qemu-img`
- Gateway services run as **Docker Compose services** (INetSim, Zeek, Suricata, mitmproxy)
- Golden image built automatically with **Packer + QEMU builder**
- Orchestrator uses `libvirt` Python API (`libvirt-python`)
- Results written to a spool directory the dashboard reads — **no outbound network, no git push**

---

## Architecture Overview

```
KVM Host (Linux)
│
├── libvirt isolated network: virbr-sandbox (10.10.10.0/24)
│   NO internet routing — host firewall drops all forward to WAN
│
├── Windows 11 KVM Guest (10.10.10.2)
│   ├── FLARE-VM tools
│   ├── Sysmon (SwiftOnSecurity config)
│   ├── FakeNet-NG (intercepts all outbound traffic on the guest)
│   ├── PowerShell ScriptBlock logging (Event 4104)
│   ├── ETW / ProcMon / Regshot
│   └── WinRM (port 5985) — remote orchestration from host
│
├── Docker network: sandbox-net (10.10.10.0/24, same bridge)
│   ├── inetsim      (10.10.10.1)  — fake DNS/HTTP/SMTP/FTP/IRC
│   ├── mitmproxy    (10.10.10.1:8080) — SSL intercept, HTTP/S MITM
│   ├── zeek         — reads tap/mirror of virbr-sandbox
│   └── suricata     — IDS on virbr-sandbox
│
└── Host-side sandbox worker (systemd path unit)
    ├── Watches SANDBOX_REQUEST_DIR for {hash}.request files
    │   written by the dashboard (sandbox_submit.go)
    ├── virsh snapshot-revert → golden image
    ├── WinRM → copy sample, start tools, detonate
    ├── Wait observation window
    ├── Collect artifacts via SMB / virsh guest-agent
    └── Write {hash}_sandbox.json → SANDBOX_RESULTS_DIR
        (dashboard reads this; no git push, no outbound connection)
```

---

## Wiring Pattern — mirrors Ghidra dashboard integration

The sandbox follows the **exact same spool-file pattern** as the Ghidra
integration (`analysis/ghidra/DASHBOARD_INTEGRATION_PLAN.md`):

| Concern | Sandbox (this plan) | Ghidra (reference) |
|---|---|---|
| Trigger | `POST /sandbox/submit` → writes `{hash}.request` to `SANDBOX_REQUEST_DIR` | `POST /ghidra/submit` → writes `{sha256}.request` to `GHIDRA_REQUEST_DIR` |
| Worker | Host-side systemd path unit (`honeypot-sandbox-worker.path`), never run by the dashboard | Host-side systemd path unit (`honeypot-ghidra-worker.path`) |
| Results | Worker writes `{hash}_sandbox.json` to `SANDBOX_RESULTS_DIR`; dashboard only reads | Worker writes `{sha256}_ghidra.json` to `GHIDRA_RESULTS_DIR`; dashboard only reads |
| Trust boundary | Dashboard never touches Docker, libvirt, or the VM directly | Same |
| List page | `GET /sandbox` → `sandboxData()` → `{{define "sandbox"}}` | `GET /ghidra` → `ghidraData()` |
| Detail page | `GET /sandbox/{job}` | `GET /ghidra/{sha256}` |
| JSON API | `GET /api/sandbox`, `/api/sandbox/{job}` | `GET /api/ghidra`, `/api/ghidra/{sha256}` |
| Export | `GET /export/sandbox/{job}` (bundle download) | `GET /export/ghidra/{sha256}` |

No new trust boundary is introduced. The dashboard container stays
unprivileged and **never** calls `virsh`, `docker`, or WinRM directly.

---

## Research: Golden Image vs Snapshots

See full comparison: [`docs/golden_image_vs_snapshots.md`](docs/golden_image_vs_snapshots.md)

### TL;DR for this project

| | Golden Image (qcow2 base) | KVM Snapshot (internal) |
|---|---|---|
| **Reset time** | ~30-60s (clone from base qcow2) | ~5-10s (virsh snapshot-revert) |
| **Reproducibility** | 100% — always byte-identical | 99% — depends on snapshot age |
| **Storage** | 1× full image + thin clones | 1 image + delta chains |
| **Rebuild** | Packer re-runs from scratch | Manual or scripted |
| **Our approach** | Packer builds base qcow2 | virsh snapshot on top for fast revert |

**Decision**: Use Packer to build a reproducible base `qcow2` (golden image),
then take a `virsh` internal snapshot on first boot as the revert target.
This gives both reproducibility (rebuild anytime) and fast revert (5-10s).

---

## Phase 0 — Host Prerequisites

```bash
# KVM / QEMU / libvirt
apt install -y qemu-kvm libvirt-daemon-system libvirt-clients virtinst \
    qemu-utils virt-manager bridge-utils genisoimage

# Packer (HashiCorp)
curl -fsSL https://apt.releases.hashicorp.com/gpg | gpg --dearmor \
    -o /usr/share/keyrings/hashicorp.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] \
https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
    > /etc/apt/sources.list.d/hashicorp.list
apt update && apt install -y packer
packer plugins install github.com/hashicorp/qemu

# Python deps for orchestrator
pip install libvirt-python pywinrm python-evtx lxml requests smbprotocol

# Docker Compose (for gateway services)
apt install -y docker-compose-plugin

# User permissions
usermod -aG kvm,libvirt,docker $USER
```

### Isolated libvirt Network

```xml
<!-- /etc/libvirt/qemu/networks/sandbox.xml -->
<network>
  <name>sandbox</name>
  <bridge name='virbr-sandbox'/>
  <ip address='10.10.10.254' netmask='255.255.255.0'/>
  <!-- NO <forward> = fully isolated, no NAT, no routing to WAN -->
</network>
```

```bash
virsh net-define /etc/libvirt/qemu/networks/sandbox.xml
virsh net-autostart sandbox
virsh net-start sandbox

# Block all forwarding from sandbox bridge to WAN (belt + suspenders)
iptables -I FORWARD -i virbr-sandbox -o eth0 -j DROP
iptables -I FORWARD -i eth0 -o virbr-sandbox -j DROP
```

---

## Phase 1 — Automated Golden Image with Packer + QEMU

See: [`packer/win11-analysis.pkr.hcl`](packer/win11-analysis.pkr.hcl)

Packer automates the full Windows 11 install + FLARE-VM + logging config
into a single reproducible `qcow2` image.

### Build
```bash
cd sandbox/windows/packer

# Download Windows 11 evaluation ISO first
# https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise
# Place at: /isos/Win11_Eval.iso

packer init win11-analysis.pkr.hcl
packer build win11-analysis.pkr.hcl
# Output: /golden-images/win11-analysis.qcow2  (~25-35 GB)
# Build time: ~3-5 hours (FLARE-VM install takes most of it)
```

### What Packer Does
1. Boot Windows 11 ISO with `autounattend.xml` (fully unattended install)
2. WinRM auto-enabled via `SetupComplete.cmd` in autounattend
3. PowerShell provisioner runs `setup_analysis.ps1`:
   - Installs FLARE-VM (Chocolatey)
   - Installs Sysmon + SwiftOnSecurity config
   - Enables PS ScriptBlock/Module/Transcription logging
   - Installs FakeNet-NG
   - Creates analysis directories
   - Hardens VM (disable Defender, UAC, WU, telemetry)
   - Populates decoy user environment (anti-evasion)
4. Sysprep + shutdown → Packer exports `win11-analysis.qcow2`

### Rebuilding
```bash
# Rebuild from scratch (e.g. after FLARE-VM update)
packer build -force win11-analysis.pkr.hcl

# Update just the logging config without full rebuild:
virt-customize -a /golden-images/win11-analysis.qcow2 \
    --upload sysmon_config.xml:/Windows/sysmon_config.xml \
    --run-command 'C:\Windows\sysmon64.exe -c C:\Windows\sysmon_config.xml'
```

---

## Phase 2 — VM Lifecycle with virsh

See: [`setup/kvm_manage.sh`](setup/kvm_manage.sh)

```bash
# Import golden image as a new VM (thin clone — fast, uses CoW)
qemu-img create -f qcow2 -F qcow2 \
    -b /golden-images/win11-analysis.qcow2 \
    /vms/win11-sandbox.qcow2

# Define VM from template XML
virsh define sandbox/windows/packer/win11-kvm.xml

# First boot → take internal snapshot as revert point
virsh start win11-sandbox
# ... wait for boot, WinRM ready ...
virsh snapshot-create-as win11-sandbox GOLDEN_READY \
    --description "FLARE-VM + logging + FakeNet ready" \
    --atomic

# Revert before each detonation run
virsh snapshot-revert win11-sandbox GOLDEN_READY --running
# Takes ~5-10 seconds
```

---

## Phase 3 — Windows 11 Hardening for Malware Analysis

See: [`setup/harden_analysis_vm.ps1`](setup/harden_analysis_vm.ps1)

### 3.1 Disable Noise Sources
```
✓ Windows Defender real-time + cloud + MAPS disabled
✓ Windows Update disabled (service + registry + GPO)
✓ Windows Error Reporting disabled
✓ Cortana / Search indexing disabled
✓ All telemetry disabled (DiagTrack service + registry)
✓ Windows Firewall disabled (FakeNet-NG handles traffic)
✓ UAC disabled
✓ SmartScreen disabled
✓ Action Center / notifications disabled
✓ OneDrive removed
✓ Memory integrity (HVCI) disabled
```

### 3.2 Enable Maximum Telemetry (Analyst Side)
```
✓ Sysmon 64 with SwiftOnSecurity config
✓ PowerShell ScriptBlock logging (Event 4104)
✓ PowerShell Module logging (Event 4103)
✓ PowerShell Transcription to C:\PSTranscripts\
✓ Process creation auditing (Event 4688 + full cmdline)
✓ Object access auditing (Event 4663)
✓ Registry auditing (Event 4657)
✓ All event log sizes expanded to 500 MB
✓ FakeNet-NG intercepting all outbound traffic
✓ QEMU guest agent (for host-side artifact collection)
```

### 3.3 Anti-Evasion (Make VM Look Real)
```
✓ Hostname: DESKTOP-$(random 7 chars) — matches real Win11 pattern
✓ Username: john.doe / jane.smith / mike.wilson (rotation)
✓ Populate: Documents, Desktop, Downloads with decoy files
✓ Install: Chrome, 7-Zip, Notepad++ (common software footprint)
✓ Browser history: inject fake history entries
✓ Recent files: inject 20+ fake recent document entries
✓ Disk: 80 GB+ (malware checks disk size < 60 GB = sandbox)
✓ RAM: 8 GB+ (malware checks < 4 GB = sandbox)
✓ CPU: 4 vCPU (malware checks < 2 = sandbox)
✓ Screen: 1920x1080
✓ QEMU CPU model: host-passthrough (exposes real CPU, not QEMU)
✓ QEMU vendor string: mask with -cpu ...,vendor=GenuineIntel
✓ No QEMU-specific devices visible
✓ Disk serial: random realistic value
✓ MAC address: real OUI prefix (Intel/Realtek, not QEMU 52:54:00)
✓ BIOS: SeaBIOS/OVMF with patched vendor strings
✓ Uptime: > 3 days before analysis
✓ > 50 processes running at analysis time
```

### 3.4 KVM-Specific Anti-Detection
```xml
<!-- In VM XML — mask QEMU/KVM from guest -->
<cpu mode='host-passthrough'>
  <feature policy='disable' name='hypervisor'/>
</cpu>
<features>
  <acpi/><apic/>
  <kvm><hidden state='on'/></kvm>   <!-- hides KVM CPUID leaf -->
  <vmport state='off'/>              <!-- disables VMware port -->
</features>

<!-- Disk: virtio-blk with custom serial -->
<disk type='file' device='disk'>
  <driver name='qemu' type='qcow2' cache='none'/>
  <serial>WD-WX31A74K3593</serial>
</disk>

<!-- NIC: e1000e with Intel OUI MAC -->
<interface type='network'>
  <mac address='00:1A:2B:3C:4D:5E'/>
  <model type='e1000e'/>
</interface>
```

---

## Phase 4 — Docker Compose Gateway Services

See: [`docker-compose.sandbox.yml`](../../docker-compose.sandbox.yml)

All gateway services run as Docker containers on the same host, connected
to the `virbr-sandbox` bridge. No container has outbound internet access.

```yaml
# Key services (all on sandbox-net, no WAN routing):
inetsim:    # fake DNS/HTTP/HTTPS/SMTP/FTP/IRC — responds to everything
mitmproxy:  # SSL intercept of HTTP/S, logs full request/response + bodies
zeek:       # protocol analysis (conn.log, dns.log, http.log, files.log)
suricata:   # IDS alerts, ET rules
```

---

## Phase 5 — Orchestration (KVM / libvirt)

See: [`orchestrate/run_sample.py`](orchestrate/run_sample.py)

The orchestrator is invoked by the **host-side systemd worker** (Phase 7),
never directly by the dashboard. It uses `libvirt-python`:

```python
import libvirt
conn = libvirt.open('qemu:///system')
dom  = conn.lookupByName('win11-sandbox')

# Revert to golden snapshot
snap = dom.snapshotLookupByName('GOLDEN_READY')
dom.revertToSnapshot(snap, libvirt.VIR_DOMAIN_SNAPSHOT_REVERT_RUNNING)
```

### Full Run Cycle
```
1.  virsh snapshot-revert win11-sandbox GOLDEN_READY   (~5-10s)
2.  Wait for WinRM on 10.10.10.2:5985                  (~45s boot)
3.  docker compose -f docker-compose.sandbox.yml up -d  (start capture)
4.  WinRM: Start-FakeNet, Start-ProcMon, Regshot snap1
5.  WinRM: Copy sample → C:\Samples\<sha>.exe
6.  WinRM: Start-Process C:\Samples\<sha>.exe
7.  Sleep observation window (default: 300s)
8.  WinRM: Stop-ProcMon, export CSV; Regshot snap2+diff
9.  WinRM: wevtutil export Sysmon + PowerShell EVTX
10. virsh qemu-agent-command → copy artifacts from guest
    OR mount via SMB share on guest
11. docker compose stop → collect Zeek/Suricata/mitmproxy logs
12. extract_iocs.py → ioc_extracted.json
13. generate_report.py → report.pdf
14. Write {hash}_sandbox.json → SANDBOX_RESULTS_DIR       ← dashboard reads this
15. virsh snapshot-revert GOLDEN_READY  (cleanup, always runs)
    NO git push. NO outbound connection.
```

---

## Phase 6 — Artifact Collection

```
SANDBOX_RESULTS_DIR/{sha256}/
├── metadata.json
├── sysmon.evtx + sysmon.json
├── powershell_4104.evtx
├── powershell_transcripts/
├── procmon.csv
├── regshot_diff.txt
├── fakenet_logs/
│   ├── dns_queries.txt
│   ├── http_requests.log
│   └── downloads/          ← second-stage payloads caught by FakeNet
├── network.pcap             ← from Zeek/tcpdump on host bridge
├── zeek_logs/
├── suricata_alerts.json
├── mitmproxy_flows.bin
├── file_drops/
├── ioc_extracted.json
└── report.pdf

# Plus the top-level result summary the dashboard reads:
SANDBOX_RESULTS_DIR/{sha256}_sandbox.json
```

---

## Phase 7 — Dashboard Integration (spool-file pattern)

The sandbox is triggered **from the dashboard payloads page** — the same
one-click pattern used by Ghidra
(`analysis/ghidra/DASHBOARD_INTEGRATION_PLAN.md`). There is no CI/CD
involvement and no outbound network connection.

### 7.1 Trigger flow

```
Analyst clicks "Submit to sandbox" on /payloads
  → POST /sandbox/submit  (dashboard: sandbox_submit.go)
      validates hash, confirms payload exists via s.payloadPath(hash)
      writes {hash}.request to SANDBOX_REQUEST_DIR  (O_CREATE|O_EXCL)
      redirects to /payloads?analysis=queued&hash=…

systemd path unit (honeypot-sandbox-worker.path) detects new .request
  → honeypot-sandbox-worker.service fires
      runs orchestrate/run_sample.py
      writes {hash}_sandbox.json → SANDBOX_RESULTS_DIR
      deletes {hash}.request
      updates status.json (queued/running/done counts)

Dashboard reads results
  → GET /sandbox          → loadSandboxResults() → {{define "sandbox"}}
  → GET /sandbox/{job}    → loadSandboxResult(hash)
  → GET /api/sandbox      → serveGandboxAPI()
  → GET /export/sandbox/{job} → stream report.pdf or artifact zip
```

### 7.2 Systemd worker units

```ini
# /etc/systemd/system/honeypot-sandbox-worker.path
[Unit]
Description=Watch for honeypot sandbox detonation requests
After=libvirtd.service docker.service

[Path]
PathChanged=/sandbox-requests
Unit=honeypot-sandbox-worker.service

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/honeypot-sandbox-worker.service
[Unit]
Description=Honeypot sandbox detonation worker (one-shot)
After=libvirtd.service docker.service

[Service]
Type=oneshot
ExecStart=/opt/honeypot-sandbox/run_pending.sh
Environment=SANDBOX_REQUEST_DIR=/sandbox-requests
Environment=SANDBOX_RESULTS_DIR=/sandbox-results
Environment=LIBVIRT_URI=qemu:///system
Environment=VM_DOMAIN=win11-sandbox
Environment=GOLDEN_SNAPSHOT=GOLDEN_READY
Environment=VM_HOST=10.10.10.2
Environment=VM_USER=analyst
Environment=OBSERVATION_SECS=300
```

### 7.3 Docker Compose wiring

```yaml
# docker-compose.yml (main stack)
services:
  dashboard:
    environment:
      - SANDBOX_REQUEST_DIR=/sandbox-requests
      - SANDBOX_RESULTS_DIR=/sandbox-results
    volumes:
      - sandbox-requests:/sandbox-requests        # read-write (dashboard writes markers)
      - sandbox-results:/sandbox-results:ro        # read-only (dashboard reads results)

volumes:
  sandbox-requests:
  sandbox-results:
```

The host-side systemd worker owns read-write access to both volumes.
The dashboard container **never** calls `virsh`, `docker`, or WinRM.

### 7.4 Environment variables (add to `.env.example`)

```dotenv
# ── Windows sandbox dashboard integration ─────────────────────────────
SANDBOX_REQUEST_DIR=/sandbox-requests
SANDBOX_RESULTS_DIR=/sandbox-results
SANDBOX_ALERT_RISK_SCORE=50
VM_DOMAIN=win11-sandbox
GOLDEN_SNAPSHOT=GOLDEN_READY
VM_HOST=10.10.10.2
VM_USER=analyst
OBSERVATION_SECS=300
```

### 7.5 Queue health + alerting

Extend the existing alert-check block in `main.go` (~line 1690) with
sandbox-worker health checks — same pattern as Ghidra:

```go
sandboxStatus := loadSandboxStatus()
if sandboxStatus.HandoffOld {
    s.checkAlerts(fmt.Sprintf(
        "sandbox handoff stalled: %d request(s) waiting for host worker",
        sandboxStatus.Handoff))
}
if sandboxStatus.WorkerState == "stale" || sandboxStatus.WorkerState == "error" {
    s.checkAlerts(fmt.Sprintf(
        "sandbox worker unhealthy: state=%s queued=%d running=%d",
        sandboxStatus.WorkerState, sandboxStatus.Queued, sandboxStatus.Running))
}
for _, result := range loadSandboxResults() {
    if result.RiskScore < sandboxAlertThreshold() {
        continue
    }
    s.checkAlerts(fmt.Sprintf(
        "sandbox high-risk result: sha256=%s score=%d verdict=%s",
        result.SHA256, result.RiskScore, result.Verdict))
}
```

---

## Tool Summary

| Tool | Purpose | Host/Guest |
|------|---------|------------|
| Packer + QEMU builder | Automated golden image build | Host |
| virsh / libvirt-python | VM lifecycle + snapshots | Host |
| FLARE-VM (mandiant) | 100+ analysis tools | Guest |
| Sysmon + SwiftOnSecurity config | Process/network/registry telemetry | Guest |
| PowerShell 4104/4103/Transcription | PS downloader capture | Guest |
| FakeNet-NG (mandiant) | Intercept ALL outbound traffic | Guest |
| ProcMon / Regshot | Process + registry diff | Guest |
| INetSim (Docker) | Fake internet (DNS/HTTP/SMTP/IRC) | Host |
| mitmproxy (Docker) | SSL intercept, payload capture | Host |
| Zeek (Docker) | Protocol-level PCAP analysis | Host |
| Suricata (Docker) | IDS alerts | Host |
| WinRM | Remote orchestration | Host→Guest |
| QEMU guest agent | File copy without network | Host→Guest |
| python-evtx | Parse EVTX to JSON | Host |
| systemd path unit | Spool-file trigger (no CI/CD) | Host |

---

## File Structure

```
sandbox/windows/
├── IMPLEMENTATION_PLAN.md         ← this file
├── packer/
│   ├── win11-analysis.pkr.hcl    ← Packer build definition
│   ├── win11-kvm.xml             ← libvirt domain XML template
│   ├── autounattend.xml          ← Windows unattended install answer file
│   └── scripts/
│       └── setup_analysis.ps1    ← runs inside VM during Packer build
├── setup/
│   ├── prepare_vm.ps1            ← manual prep (if not using Packer)
│   ├── enable_logging.ps1        ← Sysmon + PS logging
│   ├── harden_analysis_vm.ps1    ← full hardening + anti-evasion
│   └── kvm_manage.sh             ← virsh helper: create/snapshot/revert
├── config/
│   ├── sysmon_config.xml         ← SwiftOnSecurity config
│   ├── fakenet.ini               ← FakeNet-NG config
│   └── inetsim.conf              ← INetSim config (used by Docker service)
├── orchestrate/
│   ├── run_sample.py             ← KVM detonation orchestrator
│   ├── extract_iocs.py           ← IOC extraction from EVTX + logs
│   └── generate_report.py        ← PDF report generator
├── worker/
│   ├── run_pending.sh            ← called by systemd, processes spool queue
│   ├── honeypot-sandbox-worker.path    ← systemd path unit
│   └── honeypot-sandbox-worker.service ← systemd oneshot service
└── docs/
    └── golden_image_vs_snapshots.md
```
