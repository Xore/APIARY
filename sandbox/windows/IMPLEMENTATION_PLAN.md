# Windows 11 Malware Sandbox — Golden Image Implementation Plan

> **Status**: Planned / In Progress  
> **Last updated**: 2026-07-26  
> **Author**: honeypot-stack automated planning

---

## Goal

Create a reproducible, fully-monitored Windows 11 VM that:
- Runs PE payloads captured by Cowrie/Dionaea in a real Windows environment
- Captures **everything**: network traffic, DNS, HTTP, PowerShell downloads,
  registry changes, process trees, file drops, C2 callbacks, IP beaconing
- Resets to a clean known-good snapshot automatically after each run
- Exports all artifacts to `Xore/Honeypot/reports/windows-sandbox/`

---

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│              Isolated Host Network               │
│          (VMware Host-Only / vSwitch)            │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │        Windows 11 Analysis VM            │   │
│  │        (FLARE-VM golden image)           │   │
│  │                                          │   │
│  │  • FLARE-VM tools                        │   │
│  │  • Sysmon (SwiftOnSecurity config)       │   │
│  │  • ProcMon / ProcExp / Regshot           │   │
│  │  • Wireshark / RawCap                    │   │
│  │  • FakeNet-NG (intercepts all traffic)   │   │
│  │  • PowerShell ScriptBlock logging (4104) │   │
│  │  • ETW consumer (process/network events) │   │
│  │  • Python orchestrator (run_sample.py)   │   │
│  └──────────────────────────────────────────┘   │
│               │ DNS / HTTP / TCP                 │
│               ▼                                  │
│  ┌──────────────────────────────────────────┐   │
│  │         REMnux Gateway VM                │   │
│  │                                          │   │
│  │  • INetSim (fake DNS/HTTP/SMTP/FTP)      │   │
│  │  • Wireshark / tcpdump (full PCAP)       │   │
│  │  • Zeek (protocol-level analysis)        │   │
│  │  • Suricata (IDS alerts)                 │   │
│  │  • MITM proxy (mitmproxy / Burp)         │   │
│  └──────────────────────────────────────────┘   │
│               │                                  │
│               ▼ BLOCKED — no real internet       │
└─────────────────────────────────────────────────┘

                       │ artifacts exported via shared folder / SMB
                       ▼
         Linux analysis host → Xore/Honeypot repo
```

---

## Phase 1 — Base Windows 11 VM Setup

### 1.1 Windows 11 ISO

- **Source**: [Microsoft Windows 11 Dev Environment](https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/)
  — free 90-day evaluation VM (VMware/Hyper-V/VirtualBox/Parallels)
  OR build from retail ISO with:
  - Windows 11 22H2/23H2 x64
  - Username: `analyst` / Password: `malware` (standard lab convention)
  - No Microsoft Account sign-in (local account only)
- **Hypervisor**: VMware Workstation Pro (preferred for snapshot speed)
  or VirtualBox (free alternative)
- **VM specs**: 4 vCPU, 8 GB RAM, 100 GB disk (thin provisioned)

### 1.2 Initial Hardening / Analyst Preparation

Run `sandbox/windows/setup/prepare_vm.ps1` after OS install:

```
- Disable Windows Defender real-time protection
- Disable Windows Defender cloud-delivered protection
- Disable automatic sample submission
- Disable Windows Update (prevents noise during analysis)
- Disable UAC prompts
- Disable Windows Firewall (FakeNet-NG handles all traffic)
- Enable Remote Desktop (for remote orchestration)
- Add C:\ to Defender exclusion list
- Set DNS to REMnux IP (fake DNS via INetSim)
- Set static IP: 10.10.10.2 / Gateway: 10.10.10.1 (REMnux)
- Enable long file paths
- Set timezone to UTC
- Disable sleep/screen lock
```

---

## Phase 2 — FLARE-VM Installation (Golden Image)

### What is FLARE-VM
[mandiant/flare-vm](https://github.com/mandiant/flare-vm) — Mandiant's Windows
distribution for malware analysis. Installs 100+ tools via Chocolatey.

### Install
```powershell
# On the Windows 11 VM (PowerShell as Administrator)
Set-ExecutionPolicy Unrestricted -Force
(New-Object Net.WebClient).DownloadFile(
    'https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',
    "$env:USERPROFILE\Desktop\install.ps1"
)
cd $env:USERPROFILE\Desktop
.\install.ps1   # takes 2-4 hours, reboots several times
```

### Key Tools Installed by FLARE-VM

| Category | Tools |
|----------|-------|
| Disassemblers | Ghidra, Binary Ninja (trial), x64dbg, OllyDbg |
| Network | Wireshark, RawCap, NetworkMiner, FakeNet-NG |
| Process | Process Monitor, Process Hacker, Process Explorer |
| Registry | Regshot, Registry Explorer (Zimmerman) |
| PE Tools | PEStudio, PEiD, CFF Explorer, PE-bear, DIE |
| Forensics | Volatility, Autopsy, FTK Imager |
| Scripting | Python 3, PowerShell 7 |
| Unpackers | UPX, de4dot, dnSpy, ILSpy |
| Office | OfficeMalScanner, oledump, oletools |

---

## Phase 3 — Telemetry / Logging Stack

This is the most critical layer — capturing **everything** the malware does.

### 3.1 Sysmon

Install Sysmon with the [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config)
(the industry standard for high-fidelity malware analysis logging).

```powershell
# Automated via Enable-All-The-Logs
# https://github.com/bobby-tablez/Enable-All-The-Logs
irm https://raw.githubusercontent.com/bobby-tablez/Enable-All-The-Logs/main/enable_logs.ps1 | iex
```

**Sysmon Event IDs captured:**

| Event ID | What it captures |
|----------|------------------|
| 1 | Process creation (full cmdline + hashes) |
| 2 | File creation time change |
| 3 | Network connection (src/dst IP, port, process) |
| 5 | Process terminated |
| 6 | Driver loaded (kernel-mode implants) |
| 7 | Image loaded (DLL injection detection) |
| 8 | CreateRemoteThread (process injection) |
| 10 | Process accessed (credential dumping) |
| 11 | File created |
| 12/13/14 | Registry create/modify/delete |
| 15 | FileCreateStreamHash (ADS) |
| 17/18 | Pipe created/connected |
| 22 | DNS query (every domain the malware resolves) |
| 23 | File deleted |
| 25 | Process tampering |
| 255 | Error |

### 3.2 PowerShell Logging (Most Important for Droppers)

Enables capturing of every PowerShell script — including obfuscated/encoded
payloads that are decoded and executed in memory.

```powershell
# Enable ScriptBlock logging (EVID 4104) — captures deobfuscated PS code
$basePath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $basePath -Force | Out-Null
Set-ItemProperty -Path $basePath -Name EnableScriptBlockLogging -Value 1

# Enable Module logging (EVID 4103) — every module call
$modPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -Path $modPath -Force | Out-Null
Set-ItemProperty -Path $modPath -Name EnableModuleLogging -Value 1
New-Item -Path "$modPath\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$modPath\ModuleNames" -Name '*' -Value '*'

# Enable transcription — full session transcript to file
$transPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
New-Item -Path $transPath -Force | Out-Null
Set-ItemProperty -Path $transPath -Name EnableTranscripting -Value 1
Set-ItemProperty -Path $transPath -Name OutputDirectory -Value 'C:\PSTranscripts'
Set-ItemProperty -Path $transPath -Name EnableInvocationHeader -Value 1
```

**What this captures:**
- Encoded `IEX (New-Object Net.WebClient).DownloadString(...)` — decoded automatically
- Obfuscated `$env:ComSpec[14,15,...]` style cradles — logged after decode
- AMSI bypass attempts
- Full download URLs of second-stage payloads
- C2 communication via PowerShell web requests

### 3.3 Windows Event Logging (GPO)

Enable via `Enable-All-The-Logs` or manual GPO:

```
- Event 4688: Process creation with full command line
- Event 4648: Explicit credential use
- Event 4624/4625: Logon success/failure
- Event 4663: File object access
- Event 4657: Registry value modification
- Event 5140/5145: Network share access
- Event 7045: New service installed (persistence)
- Event 4720/4732: User account creation/group modification
```

### 3.4 ETW (Event Tracing for Windows)

Run `SilkETW` or `ProcMon` to capture:
- .NET CLR events (dotnet malware)
- WMI activity (WMI persistence, lateral movement)
- COM object instantiation
- Windows Defender events (what it tried to flag)

### 3.5 FakeNet-NG (Network Capture on Windows)

FakeNet-NG runs **on the Windows VM itself** and intercepts ALL outbound traffic:
- Fake DNS: resolves every domain to 127.0.0.1 (or REMnux)
- Fake HTTP/HTTPS: captures full request/response including downloaded payloads
- Fake SMTP/FTP: captures credential exfiltration
- Hard-coded IP bypass: intercepts even malware using raw IPs
- Tags traffic with process name + PID

Config: `sandbox/windows/config/fakenet.ini`

---

## Phase 4 — REMnux Gateway VM

REMnux runs on Linux and acts as the network gateway for the Windows VM.

### Setup
```bash
# Download REMnux OVA from https://remnux.org/
# Import to VMware, set network adapter to Host-Only
# Static IP: 10.10.10.1

# Configure INetSim
sudo nano /etc/inetsim/inetsim.conf
#   service_bind_address  0.0.0.0
#   dns_default_ip        10.10.10.1
#   start_service_dns
#   start_service_http
#   start_service_https
#   start_service_smtp
#   start_service_ftp
#   start_service_irc    # Mirai C2 uses IRC
sudo systemctl enable inetsim && sudo systemctl start inetsim

# Start Zeek on the host-only interface
sudo zeek -i vmnet1 /opt/zeek/share/zeek/site/local.zeek &

# Start Suricata
sudo suricata -c /etc/suricata/suricata.yaml -i vmnet1 &

# Full packet capture
sudo tcpdump -i vmnet1 -w /captures/session_$(date +%s).pcap &

# mitmproxy for HTTP/HTTPS inspection (with SSL interception)
mitmproxy --listen-host 10.10.10.1 --listen-port 8080 \
  --ssl-insecure -w /captures/http_flows.bin &
```

---

## Phase 5 — Automated Run Orchestration

`sandbox/windows/orchestrate/run_sample.py` — runs on the Linux analysis host
and drives the full detonation cycle via VMware Python API (`pyVmomi`) or
VirtualBox API.

### Run Cycle

```
1. Revert Windows VM to CLEAN_SNAPSHOT
2. Wait for VM boot (WinRM/SSH ready)
3. Copy sample to C:\Samples\<sha256>.exe via SMB/WinRM
4. Start REMnux capture services (tcpdump, INetSim, Zeek)
5. Start Windows telemetry collectors:
   a. ProcMon (capture to C:\Logs\procmon.pml)
   b. Regshot first snapshot
   c. Wireshark / RawCap
6. Execute sample via WinRM:
   Invoke-Command -ScriptBlock { Start-Process C:\Samples\<sha>.exe }
7. Wait observation window (default: 5 minutes)
8. Collect artifacts:
   a. Export ProcMon log → CSV → JSON
   b. Regshot second snapshot → diff
   c. Export Sysmon EVTX
   d. Export PowerShell logs (4103/4104 EVTX + C:\PSTranscripts\)
   e. Export FakeNet-NG logs + downloaded payloads
   f. Export Wireshark PCAP
   g. Copy C:\Drops\ (file drops directory)
9. Copy all artifacts to Linux host
10. Generate PDF report
11. Revert VM to CLEAN_SNAPSHOT (isolation)
12. Push artifacts to Xore/Honeypot/reports/windows-sandbox/<sha256>/
```

---

## Phase 6 — Artifact Collection & Report Generation

### Artifacts Per Run

```
reports/windows-sandbox/<sha256>/
├── metadata.json            # sha256, md5, sha1, filename, run timestamp
├── sysmon.evtx              # raw Sysmon event log
├── sysmon.json              # parsed Sysmon events (python-evtx)
├── powershell_4104.evtx     # PS ScriptBlock log
├── powershell_transcripts/  # full PS session transcripts
├── procmon.csv              # Process Monitor log (process/file/registry/network)
├── regshot_diff.txt         # Registry diff before/after
├── fakenet_logs/            # FakeNet-NG per-protocol logs
│   ├── dns_queries.txt      # every domain resolved
│   ├── http_requests.log    # full HTTP request/response
│   └── downloads/           # files downloaded by the malware
├── network.pcap             # full packet capture (from REMnux)
├── zeek_logs/               # Zeek conn.log, dns.log, http.log, files.log
├── suricata_alerts.json     # IDS rule hits
├── file_drops/              # files created on disk by malware
├── ioc_extracted.json       # auto-extracted: IPs, domains, URLs, hashes
└── report.pdf               # combined PDF report
```

### IOC Extraction

`sandbox/windows/orchestrate/extract_iocs.py` processes all artifacts:

- Parse Sysmon Event 22 → DNS queries → C2 domains
- Parse Sysmon Event 3 → outbound IPs → C2 IPs
- Parse FakeNet HTTP logs → download URLs → second-stage payloads
- Parse PowerShell 4104 logs → `DownloadString` / `DownloadFile` URLs
- Hash all file drops → submit to VT pipeline
- Extract URLs from PowerShell scripts with regex
- Write to `Xore/Honeypot/iocs/` (IPs, domains, URLs CSV)

---

## Phase 7 — Snapshot Management

### Golden Snapshot Strategy

```
SNAPSHOT_0_CLEAN_OS      ← Post-install, no tools
SNAPSHOT_1_FLAREVM       ← FLARE-VM installed, no logging config
SNAPSHOT_2_LOGGING       ← All logging enabled (Sysmon, PS logging, GPO)
SNAPSHOT_3_GOLDEN        ← Complete golden image (revert target)
```

Always revert to `SNAPSHOT_3_GOLDEN` before each detonation run.

### VMware CLI Snapshot Commands
```bash
# Revert to golden snapshot
vmrun revertToSnapshot \
  "/vms/win11-analysis/win11-analysis.vmx" \
  "SNAPSHOT_3_GOLDEN"

# Start VM
vmrun start "/vms/win11-analysis/win11-analysis.vmx" nogui
```

---

## Phase 8 — Anti-Evasion Measures

Many malware samples detect sandboxes and refuse to run. Countermeasures:

### VM Detection Bypass
```
- Rename VMware tools process (vmtoolsd.exe → svchost.exe alias)
- Edit CPUID to not expose VMware vendor string
- Set realistic CPU count (4+), RAM (8GB+)
- Populate user documents, browser history, recent files
- Install common software: Chrome, Office, Steam (decoy presence)
- Set hostname to something generic: DESKTOP-XXXX
- Set username to something non-analyst-looking: john.doe
- Enable > 100 processes at boot (looks like real machine)
- Set screen resolution to 1920x1080
- Disk size > 80 GB (many malware check disk size)
- Hardware serial numbers look real (edit VMX: serialNumber, uuid.bios)
```

### Timing Attacks
```
- Use longer observation window for time-delayed malware
- Run in different time-of-day slots (some malware is business-hours-only)
- Simulate mouse movement / user activity during run
```

### AMSI / AV Bypass Detection
```
- Leave Windows Defender disabled (standard for analysis)
- Log AMSI bypass attempts via PowerShell 4104
- SysmonEvent 10 catches credential-dumping anti-AV bypass patterns
```

---

## Phase 9 — Integration with Existing Pipeline

Extend `Xore/Honeypot/.github/workflows/analyze.yml` with a `windows_sandbox` job:

```yaml
windows_sandbox:
  name: Windows 11 Detonation
  runs-on: self-hosted   # must run on the host with VMware
  needs: [analyze]       # after VT/Joe
  if: contains(github.event.head_commit.message, 'PE') || 
      contains(toJson(github.event.commits.*.modified), 'samples/PE')
  steps:
    - uses: actions/checkout@v4
    - name: Detonate PE samples
      run: |
        python3 sandbox/windows/orchestrate/run_sample.py \
          --file-list /tmp/changed_files.txt \
          --filter-type PE
    - name: Push artifacts
      run: |
        git add reports/windows-sandbox/ iocs/
        git commit -m "bot: windows sandbox results [skip ci]" || true
        git push
```

> **Note**: The `windows_sandbox` job requires a **self-hosted GitHub Actions
> runner** on the VMware host. The standard `ubuntu-latest` runner cannot
> control a local VMware VM. See `sandbox/windows/runner/README.md`.

---

## Tool Summary

| Tool | Source | Purpose | Phase |
|------|--------|---------|-------|
| FLARE-VM | mandiant/flare-vm | Windows analysis toolkit | 2 |
| Sysmon | Microsoft Sysinternals | Process/network/registry telemetry | 3.1 |
| SwiftOnSecurity config | SwiftOnSecurity/sysmon-config | Best-practice Sysmon ruleset | 3.1 |
| Enable-All-The-Logs | bobby-tablez | One-shot logging enablement | 3.1 |
| PowerShell ScriptBlock logging | Built-in Windows | Capture PS downloads | 3.2 |
| FakeNet-NG | mandiant/flare-fakenet-ng | Windows network interception | 3.5 |
| ProcMon | Sysinternals | Process/file/registry monitor | 5 |
| Regshot | Regshot project | Registry diff | 5 |
| REMnux | remnux.org | Linux analysis/gateway VM | 4 |
| INetSim | INetSim | Fake internet services | 4 |
| Zeek | zeek.org | Protocol-level PCAP analysis | 4 |
| Suricata | OISF | IDS alerts on live traffic | 4 |
| mitmproxy | mitmproxy.org | HTTP/S MITM for payload capture | 4 |
| WinRM | Built-in Windows | Remote sample execution | 5 |
| python-evtx | Willi Ballenthin | Parse EVTX files to JSON | 6 |

---

## File Structure in This Repo

```
sandbox/windows/
├── IMPLEMENTATION_PLAN.md     ← this file
├── setup/
│   ├── prepare_vm.ps1         ← run once on new VM: disable AV, set DNS, etc.
│   ├── install_flarevm.ps1    ← FLARE-VM installer wrapper
│   ├── enable_logging.ps1     ← enable Sysmon + PS logging + GPO
│   └── anti_evasion.ps1       ← realistic user environment setup
├── config/
│   ├── sysmon_config.xml      ← SwiftOnSecurity Sysmon config (pinned)
│   ├── fakenet.ini            ← FakeNet-NG configuration
│   └── inetsim.conf           ← REMnux INetSim configuration
├── orchestrate/
│   ├── run_sample.py          ← main detonation orchestrator
│   ├── collect_artifacts.py   ← post-run artifact collection
│   ├── extract_iocs.py        ← IOC extraction from all logs
│   └── generate_report.py     ← PDF report generator
├── runner/
│   └── README.md              ← self-hosted GitHub Actions runner setup
└── templates/
    └── windows_report.html    ← HTML template for weasyprint PDF
```
