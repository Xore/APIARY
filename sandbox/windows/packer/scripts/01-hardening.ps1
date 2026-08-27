#Requires -RunAsAdministrator
# 01-hardening.ps1 — Packer provisioner, step 1 of win11-analysis.pkr.hcl's build.
#
# Guest hardening and Chocolatey. Fast and local.
#
# This template used to also install FLARE-VM (via Boxstarter, which reboots
# repeatedly by design) between this step and the tooling step, which is why
# the build was split across more scripts than it needs now -- a Boxstarter
# reboot mid-script silently terminated Packer's elevated scheduled-task
# provisioner (0x41306/exit 267014), so no single script could span one
# safely. FLARE-VM is gone as of 2026-08-02 (see the headers of
# sandbox/windows/packer/win11-analysis.pkr.hcl and
# sandbox/windows/packer/scripts/04-tools.ps1 for why); the settle-restart
# before 04-tools.ps1 is the only remnant of that structure, kept as cheap
# insurance rather than because anything here still reboots the guest.

Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force
$ErrorActionPreference = 'Continue'

Write-Host '================================================================'
Write-Host ' Honeypot-Stack: Windows 11 Analysis VM - hardening'
Write-Host '================================================================'
# ── Network: leave it alone ───────────────────────────────────────────────
Write-Host '[Phase 1] Network configuration (DHCP - nothing to do)...'
$adapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1
#
# ┌─ DO NOT ASSIGN A STATIC IP HERE ──────────────────────────────────────┐
# │ This script runs inside Packer, over the network it is configuring.   │
# │ A previous version did:                                               │
# │                                                                       │
# │   New-NetIPAddress -IPAddress 10.10.10.2 -DefaultGateway 10.10.10.1   │
# │                                                                       │
# │ and killed the build every time. QEMU user-mode networking puts the   │
# │ guest on 10.0.2.15 via 10.0.2.2, and Packer reaches WinRM through a   │
# │ hostfwd to it. Adding a default route via 10.10.10.1 — an address     │
# │ that does not exist until the guest is on the sandbox bridge — takes  │
# │ out WinRM and the guest's internet in one statement.                  │
# │                                                                       │
# │ The failure is quiet and expensive. Packer runs this as an elevated   │
# │ scheduled task, so the script keeps going after contact is lost: the  │
# │ log freezes at this phase while the guest spends hours failing every  │
# │ Chocolatey download, until the 5h provisioner timeout. Observed       │
# │ 2026-07-31 — three hours in, WinRM answering nothing, qcow2 being     │
# │ written but never growing.                                            │
# │                                                                       │
# │ Nothing needs to be configured. setup/sandbox-network.xml reserves    │
# │ 10.10.10.2 for this guest's MAC and hands out INetSim as the resolver │
# │ via dhcp-option=6, so DHCP produces the right answer on the sandbox   │
# │ bridge and QEMU's NAT produces the right answer during the build.     │
# │ The address belongs to the network definition, not to the guest.      │
# └───────────────────────────────────────────────────────────────────────┘
Write-Host "[+] Adapter '$($adapter.Name)' left on DHCP"

# ── Disable Windows Defender ─────────────────────────────────────────────
Write-Host '[Phase 2] Disabling Windows Defender...'
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
Set-MpPreference -MAPSReporting 0 -ErrorAction SilentlyContinue
Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath 'C:\' -ErrorAction SilentlyContinue
$defPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
New-Item $defPath -Force | Out-Null
Set-ItemProperty $defPath DisableAntiSpyware 1

# ── Disable Windows Update ────────────────────────────────────────────────
Write-Host '[Phase 3] Disabling Windows Update...'
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Set-Service wuauserv -StartupType Disabled -ErrorAction SilentlyContinue
$wuPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item $wuPath -Force | Out-Null
Set-ItemProperty $wuPath NoAutoUpdate 1
Set-ItemProperty $wuPath AUOptions 1

# ── Disable Telemetry / DiagTrack ─────────────────────────────────────────
Write-Host '[Phase 4] Disabling telemetry...'
Stop-Service DiagTrack -Force -ErrorAction SilentlyContinue
Set-Service DiagTrack -StartupType Disabled -ErrorAction SilentlyContinue
Stop-Service dmwappushservice -Force -ErrorAction SilentlyContinue
Set-Service dmwappushservice -StartupType Disabled -ErrorAction SilentlyContinue
$telPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
New-Item $telPath -Force | Out-Null
Set-ItemProperty $telPath AllowTelemetry 0
Set-ItemProperty $telPath DisableEnterpriseAuthProxy 1

# ── Disable UAC ───────────────────────────────────────────────────────────
Write-Host '[Phase 5] Disabling UAC...'
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    EnableLUA 0

# ── Disable Firewall ─────────────────────────────────────────────────────
Write-Host '[Phase 6] Disabling Windows Firewall...'
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# ── Disable SmartScreen ───────────────────────────────────────────────────
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' `
    EnableSmartScreen 0 -ErrorAction SilentlyContinue

# ── Install Chocolatey ────────────────────────────────────────────────────
Write-Host '[Phase 7] Installing Chocolatey...'
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
$env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine')

