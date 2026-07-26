# Windows 11 Malware Sandbox — Golden Image Implementation Plan

> **Status**: In Progress  
> **Last updated**: 2026-07-26  
> **Host platform**: KVM + QEMU + libvirt + docker-compose (NO VMware)

---

## Host Constraints

The analysis host runs **KVM/QEMU/libvirt** and **docker-compose** only.
- No VMware Workstation, no VirtualBox, no Hyper-V
- All VM lifecycle (create, snapshot, revert, destroy) via `virsh` / `qemu-img`
- REMnux gateway replaced by **Docker Compose services** (INetSim, Zeek, Suricata, mitmproxy)
- Golden image built automatically with **Packer + QEMU builder**
- Orchestrator uses `libvirt` Python API (`libvirt-python`) instead of pyVmomi
- Self-hosted GitHub Actions runner runs directly on the KVM host

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
└── Orchestrator (Python, runs on host)
    ├── virsh snapshot-revert → golden image
    ├── WinRM → copy sample, start tools, detonate
    ├── Wait observation window
    ├── Collect artifacts via SMB / virsh guest-agent
    └── Push reports → Xore/Honeypot repo
```

---

## Research: Golden Image vs Snapshots

See full comparison: [`docs/golden_image_vs_snapshots.md`](../docs/golden_image_vs_snapshots.md)

### TL;DR for this project

| | Golden Image (qcow2 base) | KVM Snapshot (internal) |
|---|---|---|
| **Reset time** | ~30-60s (clone from base qcow2) | ~5-10s (virsh snapshot-revert) |
| **Reproducibility** | 100% — always byte-identical | 99% — depends on snapshot age |
| **Storage** | 1× full image + thin clones | 1 image + delta chains |
| **Rebuild** | Packer re-runs from scratch | Manual or scripted |
| **Best for** | CI/CD pipeline, many parallel runs | Single analyst workstation |
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
into a single reproducible `qcow2` image. Based on
[proactivelabs/packer-windows](https://github.com/proactivelabs/packer-windows)
and [Mikroways/windows-packer-terraform-libvirt](https://github.com/Mikroways/windows-packer-terraform-libvirt).

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
# Use virt-customize (libguestfs) to patch the qcow2 in-place
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

### Snapshot vs Clone decision per use case

| Use case | Method |
|----------|--------|
| Analyst runs one sample at a time | `virsh snapshot-revert` (5-10s) |
| CI parallel runs (multiple samples) | Clone from golden qcow2 per run |
| Monthly golden image refresh | `packer build -force` |
| Quick config patch | `virt-customize` on qcow2 |

---

## Phase 3 — Windows 11 Hardening for Malware Analysis

See: [`setup/harden_analysis_vm.ps1`](setup/harden_analysis_vm.ps1)

Hardening for a malware analysis lab has **opposite goals** to production hardening:
we want maximum visibility, minimum interference, and anti-sandbox-detection.

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
✓ Windows Defender Application Guard disabled
✓ Memory integrity (HVCI) disabled (interferes with some malware)
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
✓ No QEMU-specific devices visible (virtio drivers have no QEMU strings)
✓ Disk serial: random realistic value (not QEMU HARDDISK default)
✓ MAC address: real OUI prefix (Intel/Realtek, not QEMU 52:54:00)
✓ BIOS: SeaBIOS/OVMF with patched vendor strings
✓ Uptime: > 3 days before analysis (some malware checks uptime)
✓ > 50 processes running at analysis time
```

### 3.4 KVM-Specific Anti-Detection
```
# In VM XML — mask QEMU/KVM from guest
<cpu mode='host-passthrough'>
  <feature policy='disable' name='hypervisor'/>
</cpu>
<features>
  <acpi/><apic/>
  <kvm><hidden state='on'/></kvm>   ← hides KVM CPUID leaf
  <vmport state='off'/>              ← disables VMware port (some malware checks both)
</features>

# Disk: use virtio-blk with custom serial
<disk type='file' device='disk'>
  <driver name='qemu' type='qcow2' cache='none'/>
  <serial>WD-WX31A74K3593</serial>   ← looks like a real WD drive
</disk>

# NIC: use e1000e model with Intel OUI MAC
<interface type='network'>
  <mac address='00:1A:2B:3C:4D:5E'/> ← Intel OUI
  <model type='e1000e'/>
</interface>
```

---

## Phase 4 — Docker Compose Gateway Services

See: [`docker-compose.sandbox.yml`](../../docker-compose.sandbox.yml)

Instead of a separate REMnux VM, all gateway services run as Docker containers
on the same host, connected to the `virbr-sandbox` bridge.

```yaml
# Key services:
inetsim:    # fake DNS/HTTP/HTTPS/SMTP/FTP/IRC — responds to everything
mitmproxy:  # SSL intercept of HTTP/S, logs full request/response + bodies
zeek:       # protocol analysis (conn.log, dns.log, http.log, files.log)
suricata:   # IDS alerts, ET rules
```

All containers attach to the host bridge `virbr-sandbox` via `macvlan` driver
or via a dedicated `sandbox-net` Docker network routed through the bridge.

---

## Phase 5 — Orchestration (KVM / libvirt)

See: [`orchestrate/run_sample.py`](orchestrate/run_sample.py) (updated)

Orchestrator uses `libvirt-python` API instead of vmrun:

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
10. virsh qemu-agent-command (copy files from guest via guest agent)
    OR mount via SMB share on guest
11. docker compose stop → collect Zeek/Suricata/mitmproxy logs
12. extract_iocs.py → ioc_extracted.json
13. generate_report.py → report.pdf
14. virsh snapshot-revert GOLDEN_READY  (cleanup, always runs)
15. git add reports/ iocs/ && git push
```

---

## Phase 6 — Artifact Collection

```
reports/windows-sandbox/<sha256>/
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
├── zeek_logs/               ← conn.log, dns.log, http.log, files.log
├── suricata_alerts.json
├── mitmproxy_flows.bin      ← full HTTP/S flows
├── file_drops/
├── ioc_extracted.json
└── report.pdf
```

---

## Phase 7 — GitHub Actions Integration

Requires a **self-hosted runner** on the KVM host (cannot use ubuntu-latest).
See [`runner/README.md`](runner/README.md) for setup.

```yaml
windows_sandbox:
  name: Windows 11 KVM Detonation
  runs-on: [self-hosted, kvm, windows-sandbox]
  needs: [analyze]
  if: |
    contains(toJson(github.event.commits.*.modified), 'samples/PE') ||
    contains(toJson(github.event.commits.*.added), 'samples/PE')
  steps:
    - uses: actions/checkout@v4
    - name: Detonate PE samples
      env:
        LIBVIRT_URI: qemu:///system
        VM_NAME: win11-sandbox
        VM_HOST: 10.10.10.2
        VM_USER: analyst
        VM_PASS: ${{ secrets.WIN_SANDBOX_PASS }}
        GOLDEN_SNAPSHOT: GOLDEN_READY
      run: python3 sandbox/windows/orchestrate/run_sample.py --file-list /tmp/changed_files.txt
    - name: Commit artifacts
      run: |
        git config user.name honeypot-bot
        git config user.email honeypot-bot@noreply
        git add reports/windows-sandbox/ iocs/
        git diff --cached --quiet || git commit -m "bot: kvm sandbox results [skip ci]"
        git push
```

Add `WIN_SANDBOX_PASS` as a **repository secret**.

---

## Tool Summary

| Tool | Purpose | Host/Guest |
|------|---------|------------|
| Packer + QEMU builder | Automated golden image build | Host |
| virsh / libvirt-python | VM lifecycle + snapshots | Host |
| FLARE-VM (mandiant) | 100+ analysis tools | Guest |
| Sysmon + SwiftOnSecurity config | Process/network/registry telemetry | Guest |
| Enable-All-The-Logs (bobby-tablez) | One-shot logging enablement | Guest |
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
├── runner/
│   └── README.md                 ← self-hosted runner setup (KVM host)
└── docs/
    └── golden_image_vs_snapshots.md
```
