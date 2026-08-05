# Windows 11 Malware Sandbox — Golden Image Implementation Plan

> **Status**: In Progress — Phase 7's dashboard half is implemented, and the
> host half now has its orchestrator, spool worker, and systemd units. What
> remains is the golden image itself (Phases 1–3) and the gateway compose
> (Phase 4); until a `win11-sandbox` domain exists, the worker will
> revert-fail on every request and preserve it as `.request.failed`. There
> is no `GOLDEN_READY` snapshot — see the revised Golden Image vs Snapshots
> decision below and #358 for why.  
> **Last updated**: 2026-07-30  
> **Host platform**: KVM + QEMU + libvirt + docker-compose (NO VMware)  
> **Phase 1 tracking**: [#47](https://github.com/Xore/honeypot-stack/issues/47)
> — one issue per remaining step, each with its own verification and failure
> modes. Start there rather than from this document if you are picking the
> work up cold.
>
> **Decide [#94](https://github.com/Xore/honeypot-stack/issues/94) before
> building the image.** Every WinRM and SMB step below assumes a credentialed
> management channel into a running infected guest, and the credentials and the
> share are baked into the golden image — which makes this cheap to settle now
> and expensive to settle later. [#91](https://github.com/Xore/honeypot-stack/issues/91)
> covers the image-side defects the same channel depends on.

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
│   └── WinRM (port 5985) — remote orchestration from host (see #94)
│
├── Docker network: `sandbox` (macvlan, internal: true, 10.10.10.0/24)
│   ├── inetsim      (10.10.10.1)  — fake DNS/HTTP/SMTP/FTP/IRC
│   ├── mitmproxy    (10.10.10.1:8080) — SSL intercept, HTTP/S MITM
│   ├── zeek         — reads tap/mirror of virbr-sandbox
│   └── suricata     — IDS on virbr-sandbox
│
└── Host-side sandbox worker (systemd path unit)
    ├── Watches WINDOWS_SANDBOX_REQUEST_DIR for {hash}.request files
    │   written by the dashboard (sandbox_submit.go) — routed here only
    │   after the dashboard's determination path (see below) classifies
    │   the payload as Windows; everything else goes to the pre-existing
    │   Linux runner (sandbox/linux-runner.service, sandbox/worker.sh)
    │   watching the original SANDBOX_REQUEST_DIR
    ├── destroy + fresh CoW clone from golden image + start (kvm_manage.sh
    │   revert / run_sample.py revert_to_golden() — not a virsh snapshot,
    │   see #358)
    ├── WinRM → copy sample, start tools, detonate
    ├── Wait observation window
    ├── Collect artifacts via SMB / virsh guest-agent
    └── Write {hash}_sandbox.json → WINDOWS_SANDBOX_RESULTS_DIR
        (dashboard reads this; no git push, no outbound connection)
```

---

## Wiring Pattern — mirrors Ghidra dashboard integration

The sandbox follows the **exact same spool-file pattern** as the Ghidra
integration (`analysis/ghidra/DASHBOARD_INTEGRATION_PLAN.md`):

| Concern | Sandbox (this plan) | Ghidra (reference) |
|---|---|---|
| Trigger | `POST /sandbox/submit` → determines Windows vs Linux (see below), writes `{hash}.request` to `WINDOWS_SANDBOX_REQUEST_DIR` or `SANDBOX_REQUEST_DIR` accordingly, plus optionally to `GHIDRA_REQUEST_DIR` if the submit form's Ghidra checkbox was set | `POST /ghidra/submit` → writes `{sha256}.request` to `GHIDRA_REQUEST_DIR` |
| Worker | Host-side systemd path unit (`honeypot-windows-sandbox-worker.path`), never run by the dashboard | Host-side systemd path unit (`honeypot-ghidra-worker.path`) |
| Results | Worker writes `{hash}_sandbox.json` to `SANDBOX_RESULTS_DIR`; dashboard only reads | Worker writes `{sha256}_ghidra.json` to `GHIDRA_RESULTS_DIR`; dashboard only reads |
| Trust boundary | Dashboard never touches Docker, libvirt, or the VM directly | Same |
| List page | `GET /sandbox` → `sandboxData()` → `{{define "sandbox"}}` | `GET /ghidra` → `ghidraData()` |
| Detail page | `GET /sandbox/{job}` | `GET /ghidra/{sha256}` |
| JSON API | `GET /api/sandbox`, `/api/sandbox/{job}` | `GET /api/ghidra`, `/api/ghidra/{sha256}` |
| Export | `GET /export/sandbox/{job}` (bundle download) | `GET /export/ghidra/{sha256}` |

No new trust boundary is introduced. The dashboard container stays
unprivileged and **never** calls `virsh`, `docker`, or WinRM directly.

---

## Determination Path — Windows VM vs Linux VM

Today `/sandbox/submit` writes one request to one spool directory and
assumes a single backend. With two VM backends (this Windows plan, and the
pre-existing Linux runner at `sandbox/linux-runner.service` /
`sandbox/run-linux-sample.sh`), the dashboard needs to pick the right one
**per submission**, using content the dashboard already computes for every
captured payload today.

### Signal: reuse `classifyPayload` — no new classifier

`dashboard/payload_kind.go`'s `classifyPayload(data []byte) payloadClassification`
already sniffs magic bytes (`MZ` → `debug/pe`, `\x7fELF` → `debug/elf`,
script shebangs/headers) and returns a `Platform` of `"Windows"`,
`"Linux"`, or `"Cross-platform"` for every kind of payload the dashboard
already stores — this is the exact same classification already shown on
the payload detail page ("Windows PE forensics" card, etc). Routing needs
no new detection logic, only a decision on top of the existing field.

| `classifyPayload(...).Code` | `.Platform` | Routed to |
|---|---|---|
| `pe-exe` (Windows PE executable) | `Windows` | **Windows VM** (this plan) |
| `pe-dll` (Windows DLL) | `Windows` | **Windows VM** — DLL is loaded via `rundll32`/a loader stub in the guest, not double-clicked |
| `vbscript`, `batch`, `powershell`, `jscript` | `Windows` | **Windows VM** — these need `cscript.exe`/`cmd.exe`/PowerShell/Wine-equivalents that only exist in the Windows golden image |
| `elf-exe` (Linux ELF executable) | `Linux` | **Linux VM** (pre-existing `sandbox/run-linux-sample.sh` path) |
| `elf-library` (Linux `.so`) | `Linux` | **Linux VM** — static analysis only, `Dynamic: false`, no detonation either way |
| `shell`, `python`, `javascript`, `php` | `Linux` / `Cross-platform` | **Linux VM** — the existing Linux runner already detonates these under `strace`; Windows adds nothing to `bash`/CPython/Node.js analysis |
| anything with `Dynamic: false` (documents, static-only libraries) | — | **No VM at all** — static analysis only, matches existing `classifyPayload` behavior (`pdf`, `ole`, `pe-dll`, `elf-library`) |

### Determination function (`dashboard/sandbox_submit.go`)

```go
type sandboxTarget string

const (
	targetWindows sandboxTarget = "windows"
	targetLinux   sandboxTarget = "linux"
)

// determineSandboxTarget classifies the payload the same way the payload
// detail page already does, and picks a VM backend. Only Windows-native
// executables/DLLs/scripts need the Windows golden image; everything else
// — including cross-platform scripts — already detonates correctly on the
// existing Linux runner.
func determineSandboxTarget(data []byte) (target sandboxTarget, dynamic bool) {
	c := classifyPayload(data)
	if !c.Dynamic {
		return "", false // static-only payload — no VM submission possible
	}
	if c.Platform == "Windows" {
		return targetWindows, true
	}
	return targetLinux, true // Linux and Cross-platform both run on the Linux VM
}
```

### Updated `serveSandboxSubmit` flow

1. Validate `hash`, confirm the payload exists via `s.payloadPath(hash)` —
   unchanged.
2. Read the payload (already required to classify it for the payloads
   page), call `determineSandboxTarget(data)`.
3. If `dynamic == false`: reject with `400` ("this payload has no dynamic
   detonation path — see its static analysis instead") rather than queuing
   a VM run that would never do anything.
4. If `target == targetWindows`: write `{hash}.request` to
   `WINDOWS_SANDBOX_REQUEST_DIR` (this plan's worker, Phase 7).
5. If `target == targetLinux`: write `{hash}.request` to the existing
   `SANDBOX_REQUEST_DIR` (unchanged — the pre-existing Linux runner already
   watches this directory; no changes needed on that side at all).
6. If the submit form's new **Ghidra** field (below) was checked, also
   write `{hash}.request` (well, `{sha256}.request`) to `GHIDRA_REQUEST_DIR`
   per `analysis/ghidra/DASHBOARD_INTEGRATION_PLAN.md` — independent of
   which VM was chosen, since Ghidra is static analysis and applies to any
   binary/DLL regardless of which detonation backend runs it.
7. Redirect to `/payloads?analysis=queued&hash=…&target={target}` so the
   payloads-page notice can say e.g. "Sandbox analysis (Windows VM)
   requested for …" instead of a generic message.

### New field + dedicated button: Ghidra selection on the payloads page

Each payload row gets **two** independent ways to queue Ghidra, covering
both the "detonate and reverse-engineer together" case and the "static
analysis only, no VM at all" case:

1. A **checkbox on the sandbox submit form** — queues Ghidra alongside
   whichever VM the determination path picked.
2. A **dedicated "Send to Ghidra" button** — queues Ghidra on its own,
   with no VM submission at all (e.g. for the `Dynamic: false` payloads
   the determination path rejects from VM submission — DLLs, documents,
   static libraries — Ghidra is often the *only* applicable analysis).

This is the same standalone button described in
`analysis/ghidra/DASHBOARD_INTEGRATION_PLAN.md` Phase 3 — shown here
alongside the sandbox form so the two entry points are visibly distinct
on the page rather than one being buried inside the other:

```html
<div class="payload-actions">
  <form method="post" action="/sandbox/submit" class="inline">
    <input type="hidden" name="hash" value="{{.SHA256}}">
    <label class="checkbox">
      <input type="checkbox" name="ghidra" value="1">
      Also run Ghidra static analysis
    </label>
    <button type="submit" class="btn-sm">Submit to sandbox</button>
  </form>

  <form method="post" action="/ghidra/submit" class="inline">
    <input type="hidden" name="hash" value="{{.SHA256}}">
    <button type="submit" class="btn-sm btn-secondary">Send to Ghidra</button>
  </form>
  {{if .GhidraResult}}<a href="/ghidra/{{.SHA256}}" class="badge">Ghidra: {{.GhidraResult.RiskLabel}}</a>{{end}}
</div>
```

Both paths converge on the same spool and worker — there is exactly one
way Ghidra analysis gets queued under the hood
(`GHIDRA_REQUEST_DIR`/`serveGhidraSubmit` from
`analysis/ghidra/DASHBOARD_INTEGRATION_PLAN.md` Phase 2), just two UI
entry points into it:

- `serveSandboxSubmit` reads `r.FormValue("ghidra") == "1"` and, if set,
  writes the Ghidra spool entry itself as one extra step alongside the VM
  request (step 6 above).
- The dedicated button posts directly to the existing `/ghidra/submit`
  route (`serveGhidraSubmit`) — no changes needed there at all.

No new permission check is needed for either — both are gated by the same
`requireAdmin` + `sameOriginRequest` checks already guarding their
respective handlers, and both write with the same idempotent
`O_CREATE|O_EXCL` pattern, so clicking both the checkbox and the button
(or double-clicking either) never queues a duplicate run.

The dashboard never decides *which* VM Ghidra needs — Ghidra's headless
container analyzes the binary directly and doesn't care which detonation
backend (if any) also ran it, so Ghidra submission (via either entry
point) is entirely independent of the Windows/Linux determination above.

---

## Research: Golden Image vs Snapshots

See full comparison:
[`docs/kvm-snapshot-vs-golden-image.md`](../../docs/kvm-snapshot-vs-golden-image.md)

### TL;DR for this project

| | Golden Image (qcow2 base) | KVM Snapshot (internal) |
|---|---|---|
| **Reset time** | ~1-2min (fresh CoW clone + cold boot) | ~5-10s (virsh snapshot-revert) |
| **Reproducibility** | 100% — always byte-identical | 99% — depends on snapshot age |
| **Storage** | 1× full image + thin clones | 1 image + delta chains |
| **Rebuild** | Packer re-runs from scratch | Manual or scripted |
| **Our approach** | Packer builds base qcow2, fresh clone every reset | Not usable here — see below |

**Decision, revised (#358)**: the original plan was `virsh` snapshot-revert
on top of the Packer-built base for fast (5-10s) reverts. That turned out
not to be usable on this host: this domain's `<cpu migratable='off'/>`
(deliberate, for anti-VM-detection CPU fidelity) blocks memory-state
snapshots outright, and disk-only snapshots hit a separate, reproducible
QEMU/libvirt bug on the resulting multi-layer backing chain — a freshly
spawned qemu process fails to open the golden image even though file
permissions are provably fine. Actual approach: every reset destroys the
domain, deletes the per-run CoW clone, and creates a fresh one from the
golden image (`kvm_manage.sh revert` / `run_sample.py`'s
`revert_to_golden()`). Cold boot every run (~1-2min) instead of a
memory-state resume, but with no snapshot-machinery failure mode.

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

# PXE boot staging (packer/pxe/prepare-pxe.sh, #288/#406) -- builds and
# signs the custom ipxe.efi this template's install-time boot depends on.
# Confirmed missing on a from-scratch host during the 2026-08-05 rebuild:
# packer/pxe/prepare-pxe.sh fails partway through without these.
apt install -y p7zip-full python3-virt-firmware sbsigntool

# Python deps for orchestrator
pip install libvirt-python pywinrm python-evtx lxml requests smbprotocol

# Docker Compose (for gateway services)
apt install -y docker-compose-plugin

# User permissions -- kvm specifically is required to run `packer build`
# (or any direct qemu-system-x86_64 invocation) as a non-root user; its
# absence fails late and unhelpfully ("qemu-system-x86_64: Could not access
# KVM kernel module: Permission denied"), confirmed live 2026-08-05.
usermod -aG kvm,libvirt,docker $USER
```

### Isolated libvirt Network

The network is defined by [`setup/sandbox-network.xml`](setup/sandbox-network.xml)
— read it there rather than from a copy here. The sketch this section used to
carry had neither the DHCP reservation nor the DNS option, and a network
defined from it would come up without the pinned `10.10.10.2` lease that
`VM_HOST` depends on.

The three things that file gets right, and that any replacement must too:

| | Why |
|---|---|
| No `<forward>` element | Its absence *is* the isolation — no NAT, no route to WAN. Never add it "temporarily". |
| One-address DHCP pool, pinned to the guest MAC | `VM_HOST=10.10.10.2` is always correct, so the orchestrator never discovers a lease. A second guest failing to get an address is the desired outcome: two samples on one bridge contaminate each other's network evidence. |
| `dhcp-option=6,10.10.10.1` — not `<dns><forwarder/></dns>` | The guest must query INetSim *directly*. A forwarder would route DNS through libvirt's dnsmasq, a host process, which cannot reach a macvlan container — every lookup would SERVFAIL and every sample would go quiet. |

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
3. PowerShell provisioners run `01-hardening.ps1`, `02-flarevm-start.ps1`, `03-flarevm-wait.ps1` (x12), `04-tools.ps1`:
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

# First boot → verify it boots and WinRM answers
virsh start win11-sandbox
# ... wait for boot, WinRM ready ...

# Reset before each detonation run: destroy + fresh CoW clone from the
# golden image + start. Not a virsh snapshot revert -- this domain's
# <cpu migratable='off'/> (deliberate, for anti-VM-detection fidelity)
# blocks memory-state snapshots outright, and disk-only snapshots hit a
# separate, reproducible QEMU/libvirt bug on the resulting multi-layer
# backing chain (#358). The golden image is never written to, so there's
# nothing to snapshot -- every reset just makes a fresh clone.
sandbox/windows/setup/kvm_manage.sh revert
# Cold boot, ~1-2 minutes
```

Before trusting a freshly-reset guest as an acceptance point, run the pafish/
al-khaser verification pass (#298) against the freshly-booted guest — see
[`docs/vm-detection-verification.md`](docs/vm-detection-verification.md).
Everything upstream of this (SMBIOS/CPUID spoofing, Defender/telemetry
disables) is reasoned-through hardening against *known* checks; this is the
only step that empirically confirms it holds up in a real booted guest.

---

## Phase 3 — Windows 11 Hardening for Malware Analysis

Implemented in
[`packer/scripts/`](packer/scripts/) — four provisioner scripts, the
hardening and anti-evasion phases run at image-build time, not as a separate
script. (Earlier revisions of this plan named a `setup/harden_analysis_vm.ps1`
that was never written.)

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
# Key services (all on the "sandbox" macvlan network, no WAN routing):
inetsim:    # fake DNS/HTTP/HTTPS/SMTP/FTP/IRC — responds to everything
mitmproxy:  # SSL intercept of HTTP/S, logs full request/response + bodies
zeek:       # protocol analysis (conn.log, dns.log, http.log, files.log)
suricata:   # IDS alerts, ET rules
```

---

## Phase 5 — Orchestration (KVM / libvirt)

See: [`orchestrate/run_sample.py`](orchestrate/run_sample.py)

The orchestrator is invoked by the **host-side systemd worker** (Phase 7),
never directly by the dashboard. It shells out to `virsh` (see `virsh()` in
`orchestrate/run_sample.py` — not `libvirt-python`):

```python
# Reset to golden: destroy, delete the per-run CoW clone, make a fresh one
# from the golden image, start. Not a snapshot revert -- see #358 for why.
subprocess.run([VIRSH_PATH, '--connect', LIBVIRT_URI, 'destroy', VM_DOMAIN], ...)
VM_DISK.unlink()
subprocess.run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2',
                 '-b', str(GOLDEN_IMAGE), str(VM_DISK)], check=True, ...)
virsh(['start', VM_DOMAIN])
```

### Full Run Cycle
```
1.  kvm_manage.sh revert: destroy + fresh CoW clone + start (~5-10s to spawn)
2.  Wait for WinRM on 10.10.10.2:5985                  (~1-2min cold boot)
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
14. Write {hash}_sandbox.json → WINDOWS_SANDBOX_RESULTS_DIR   ← dashboard reads this
15. kvm_manage.sh revert / revert_to_golden()  (cleanup, always runs)
    NO git push. NO outbound connection.
```

---

## Phase 6 — Artifact Collection

```
WINDOWS_SANDBOX_RESULTS_DIR/{sha256}/
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
WINDOWS_SANDBOX_RESULTS_DIR/{sha256}_sandbox.json
```

---

## Phase 7 — Dashboard Integration (spool-file pattern)

> **Implemented 2026-07-30** (dashboard side only):
> `determineSandboxTarget`, per-target spools via `sandboxRequestDir`, the
> `Dynamic: false` rejection, `&target=` on the return URL and the payloads
> notice, merged results/status/exports across both result directories, and
> the `WINDOWS_SANDBOX_REQUEST_DIR` / `WINDOWS_SANDBOX_RESULTS_DIR` wiring in
> `.env.example` and `docker-compose.yml`. Both variables are empty by
> default: until an operator sets them, Windows submissions are refused with
> a message naming the missing backend rather than misrouted into the Linux
> spool. Tests live in `dashboard/sandbox_target_test.go` and
> `dashboard/sandbox_test.go`.
>
> **Deliberately not implemented — step 6 and the Ghidra field below.**
> `serveGhidraSubmit`, the `/ghidra/submit` route, and `GHIDRA_REQUEST_DIR`
> do not exist in the dashboard; they are Phase 2 of
> `analysis/ghidra/DASHBOARD_INTEGRATION_PLAN.md`, tracked in
> [#76](https://github.com/Xore/honeypot-stack/issues/76). Adding the checkbox
> and the second form now would ship a button that 404s and a spool write with
> no reader. Do #76 first, then come back for step 6 — it is two lines in
> `serveSandboxSubmit` once the spool exists.
>
> **Host half — implemented 2026-07-30.** `/windows-sandbox-requests` now has
> a consumer: `run_pending.sh` drains the spool and
> `honeypot-windows-sandbox-worker.{path,service}` drive it, with
> `honeypot-windows-sandbox.default.example` as the host configuration
> template. The worker takes a non-blocking lock so overlapping path-unit
> triggers collapse into one drain, claims each request before detonating so a
> crash cannot replay it, and preserves a request as `.request.failed` when the
> orchestrator exits non-zero rather than retiring it as complete.
>
> `orchestrate/run_sample.py` was written against VMware — `vmrun`, a `.vmx`
> path, and snapshot `SNAPSHOT_3_GOLDEN` — which contradicted this plan's own
> "No VMware Workstation" constraint and would never have run on this host. It
> now drives libvirt via `virsh --connect $LIBVIRT_URI` (destroy + fresh CoW
> clone + start, per #358 — not `snapshot-revert`, which turned out not to
> be usable on this host's CPU config), takes `--results-dir`, and returns a
> non-zero exit on a failed detonation so the worker can tell a real report
> from a broken run.
>
> **Still ahead:** Phases 1–3 (Packer golden image, VM lifecycle, guest
> hardening) and Phase 4 (gateway Compose). The Compose default leaves the
> backend switched off until a golden domain exists.

The sandbox is triggered **from the dashboard payloads page** — the same
one-click pattern used by Ghidra
(`analysis/ghidra/DASHBOARD_INTEGRATION_PLAN.md`). There is no CI/CD
involvement and no outbound network connection.

### 7.1 Trigger flow

```
Analyst checks (optionally) "Also run Ghidra static analysis" and clicks
"Submit to sandbox" on /payloads
  → POST /sandbox/submit  (dashboard: sandbox_submit.go)
      validates hash, confirms payload exists via s.payloadPath(hash)
      reads payload, calls determineSandboxTarget(data)   ← see
        "Determination Path" above
        ├── dynamic == false → 400, no VM submission possible
        ├── target == windows → writes {hash}.request to
        │     WINDOWS_SANDBOX_REQUEST_DIR  (O_CREATE|O_EXCL)
        └── target == linux   → writes {hash}.request to
              SANDBOX_REQUEST_DIR  (unchanged, pre-existing Linux runner)
      if ghidra=1 on the form: also writes {hash}.request to
        GHIDRA_REQUEST_DIR (independent of target, see
        analysis/ghidra/DASHBOARD_INTEGRATION_PLAN.md)
      redirects to /payloads?analysis=queued&hash=…&target={target}

Windows path:
  systemd path unit (honeypot-windows-sandbox-worker.path) detects new
  .request in WINDOWS_SANDBOX_REQUEST_DIR
    → honeypot-windows-sandbox-worker.service fires
        runs orchestrate/run_sample.py (this plan)
        writes {hash}_sandbox.json (Platform: "Windows") →
          WINDOWS_SANDBOX_RESULTS_DIR
        deletes {hash}.request
        updates status.json (queued/running/done counts)

Linux path (pre-existing, unchanged):
  sandbox/linux-runner.service / sandbox/worker.sh detects new .request
  in SANDBOX_REQUEST_DIR, runs sandbox/run-linux-sample.sh, writes
  {hash}_sandbox.json (Platform: "Linux") → SANDBOX_RESULTS_DIR

Dashboard reads results from BOTH result directories, merged by
loadSandboxResults() into one list (Platform field distinguishes them)
  → GET /sandbox          → loadSandboxResults() → {{define "sandbox"}}
  → GET /sandbox/{job}    → loadSandboxResult(hash)
  → GET /api/sandbox      → serveSandboxAPI()
  → GET /export/sandbox/{job} → stream report.pdf or artifact zip
```

### 7.2 Systemd worker units

Named and pathed distinctly from the pre-existing Linux worker
(`sandbox/linux-runner.service`) so both can run on the same host without
colliding:

```ini
# /etc/systemd/system/honeypot-windows-sandbox-worker.path
[Unit]
Description=Watch for honeypot Windows sandbox detonation requests
After=libvirtd.service docker.service

[Path]
PathChanged=/windows-sandbox-requests
Unit=honeypot-windows-sandbox-worker.service

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/honeypot-windows-sandbox-worker.service
[Unit]
Description=Honeypot Windows sandbox detonation worker (one-shot)
After=libvirtd.service docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/libexec/honeypot-sandbox/windows/run_pending.sh
Environment=WINDOWS_SANDBOX_REQUEST_DIR=/windows-sandbox-requests
Environment=WINDOWS_SANDBOX_RESULTS_DIR=/windows-sandbox-results
Environment=LIBVIRT_URI=qemu:///system
Environment=VM_DOMAIN=win11-sandbox
Environment=GOLDEN_IMAGE=/var/dockge/sandbox/golden-images/win11-analysis.qcow2
Environment=VM_DISK=/var/dockge/sandbox/vms/win11-sandbox.qcow2
Environment=VM_HOST=10.10.10.2
Environment=VM_USER=analyst
Environment=OBSERVATION_SECS=1800  # #297: 30min default, 15-60min recommended
```

### 7.3 Docker Compose wiring

```yaml
# docker-compose.yml (main stack)
services:
  dashboard:
    environment:
      - SANDBOX_REQUEST_DIR=/sandbox-requests               # Linux (unchanged)
      - SANDBOX_RESULTS_DIR=/sandbox-results                # Linux (unchanged)
      - WINDOWS_SANDBOX_REQUEST_DIR=/windows-sandbox-requests
      - WINDOWS_SANDBOX_RESULTS_DIR=/windows-sandbox-results
    volumes:
      - sandbox-requests:/sandbox-requests                    # read-write
      - sandbox-results:/sandbox-results:ro                   # read-only
      - windows-sandbox-requests:/windows-sandbox-requests    # read-write
      - windows-sandbox-results:/windows-sandbox-results:ro   # read-only

volumes:
  sandbox-requests:
  sandbox-results:
  windows-sandbox-requests:
  windows-sandbox-results:
```

Each host-side systemd worker owns read-write access to its own pair of
volumes only — the Windows worker never sees the Linux spool and vice
versa. The dashboard container **never** calls `virsh`, `docker`, or WinRM.

### 7.4 Environment variables (add to `.env.example`)

```dotenv
# ── Linux sandbox (pre-existing, unchanged) ───────────────────────────
SANDBOX_REQUEST_DIR=/sandbox-requests
SANDBOX_RESULTS_DIR=/sandbox-results
SANDBOX_ALERT_RISK_SCORE=50

# ── Windows sandbox dashboard integration (this plan) ─────────────────
WINDOWS_SANDBOX_REQUEST_DIR=/windows-sandbox-requests
WINDOWS_SANDBOX_RESULTS_DIR=/windows-sandbox-results
VM_DOMAIN=win11-sandbox
GOLDEN_IMAGE=/var/dockge/sandbox/golden-images/win11-analysis.qcow2
VM_DISK=/var/dockge/sandbox/vms/win11-sandbox.qcow2
VM_HOST=10.10.10.2
VM_USER=analyst
OBSERVATION_SECS=1800
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
│       └── 01-hardening.ps1 … 08-traffic-noise.ps1  ← run inside VM during build
├── setup/
│   ├── enable_logging.ps1        ← Sysmon + PS logging
│   ├── kvm_manage.sh             ← virsh helper: create/snapshot/revert
│   └── sandbox-network.xml       ← the libvirt network; no <forward> is the point
├── config/
│   ├── fakenet.ini               ← FakeNet-NG config
│   └── inetsim.conf              ← INetSim config (used by the gateway service)
├── gateway/inetsim/              ← gateway container build context
├── orchestrate/
│   ├── run_sample.py             ← KVM detonation orchestrator
│   ├── extract_iocs.py           ← IOC extraction from EVTX + logs
│   └── generate_report.py        ← PDF report generator
├── runner/README.md              ← host-side runner notes
├── run_pending.sh                            ← called by systemd, drains the spool under flock
├── honeypot-windows-sandbox-worker.path      ← systemd path unit
├── honeypot-windows-sandbox-worker.service   ← systemd oneshot service
├── honeypot-windows-sandbox.default.example  ← /etc/default template
└── docs/
    └── packer-golden-image-guide.md
```

The worker files are at the top of `sandbox/windows/`, not under a `worker/`
subdirectory — the systemd units reference the real paths. `sysmon_config.xml`
is not vendored; it is fetched from SwiftOnSecurity during the Packer build.
