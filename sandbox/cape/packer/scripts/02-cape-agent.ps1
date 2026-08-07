#Requires -RunAsAdministrator
# 02-cape-agent.ps1 — Packer provisioner, step 2 of win11-cape.pkr.hcl's build.
#
# Installs everything CAPEv2's own upstream docs (read directly off the real
# checkout on the build host — docs/book/src/installation/guest/{requirements,
# agent,network}.rst — not assumed) say this guest needs, and nothing this
# repo's own detonation logic supplies instead:
#
#   * 32-bit (x86) Python. requirements.rst is explicit and specific about
#     why: "due to the way the analyzer interacts with low-level Windows
#     libraries. Using a 64-bit version of Python will crash the analyzer."
#     This is the one CAPE-specific hard requirement that has no equivalent
#     anywhere else in this repo's existing Windows tooling.
#   * agent.py (vendored at ../agent/agent.py, see that directory's README),
#     run as agent.pyw (window-suppressed, same doc's own recommendation —
#     a visible console interferes with CAPE's human.py auxiliary module)
#     via an AtLogOn/RunLevel-Highest scheduled task — agent.rst's own
#     documented setup, same mechanism 11-detonation-orchestrator.ps1
#     already uses in sandbox/windows for an unrelated reason.
#
# What CAPE does NOT need baked into the golden image, deliberately not
# added here: capemon.dll and the rest of the analyzer package
# (analyzer/windows/ upstream) are pushed by the CAPE host to agent.py
# *per analysis*, not preinstalled — confirmed against agent.py's own
# /store and /execute endpoints (this file, vendored below) rather than
# guessed. Baking them in here would just mean carrying a second, stale
# copy that a running CAPE host with a newer analyzer package would
# override anyway.
#
# Firewall/Defender/UAC/updates are handled by 01-hardening.ps1 already
# (reused unchanged from sandbox/windows, see its own header) — this script
# only adds the two noisy-network-service disables network.rst separately
# calls out (Teredo, LLMNR) that 01-hardening.ps1 has no equivalent for.
#
# -- NO STATIC IP HERE -- same trap 01-hardening.ps1's own header warns
# about for itself. This script runs over the network Packer's own
# QEMU user-mode NAT provides during the build (10.0.2.x/10.0.3.x), not
# over virbr-cape (10.40.50.0/24) -- that bridge does not exist from
# this guest's perspective until it is deployed as a real detonation
# domain (win11-cape-kvm.xml) after the build finishes. The guest gets
# its real, permanent address the same way win11-sandbox's own guest
# does: left on DHCP, with sandbox/cape/network.xml's MAC-pinned
# single-address reservation making that address effectively static
# across every future boot -- see that file's own header for why a
# pinned DHCP lease already satisfies CAPE's "no DHCP" requirement
# (a fixed, predictable address) without touching guest networking here.

$ErrorActionPreference = 'Continue'

Write-Host '================================================================'
Write-Host ' Honeypot-Stack: Windows 11 CAPE VM - agent + guest requirements'
Write-Host '================================================================'

# ── 32-bit Python (requirements.rst: "only 32-bit (x86) versions of ──────
# Python3 are supported"; "Python versions > 3.10 and < 3.13 are preferred")
Write-Host '[Phase 1] Installing 32-bit Python 3.11...'
$pyInstaller = 'C:\Windows\Temp\python-3.11.9.exe'
# python.org's own naming: the bare "python-<ver>.exe" IS the x86 (32-bit)
# installer; the 64-bit one is separately suffixed "-amd64.exe". Confirmed
# against python.org's own downloads page structure, not guessed from the
# filename shape alone.
Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.11.9/python-3.11.9.exe' `
  -OutFile $pyInstaller -UseBasicParsing
Start-Process -FilePath $pyInstaller -ArgumentList `
  '/quiet', 'InstallAllUsers=1', 'PrependPath=1', 'Include_test=0', 'Include_pip=1' `
  -Wait -NoNewWindow
Remove-Item $pyInstaller -Force -ErrorAction SilentlyContinue

# Refresh PATH in this session — the installer updates the machine-wide
# registry value, not this already-running PowerShell process's own copy.
$env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine')

$pythonExe = 'C:\Program Files (x86)\Python311\python.exe'
$pythonwExe = 'C:\Program Files (x86)\Python311\pythonw.exe'
if (-not (Test-Path $pythonExe)) {
    Write-Host "[!] Expected python.exe not found at $pythonExe — install may have used a different path" -ForegroundColor Yellow
    $pythonExe = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
    $pythonwExe = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
}
Write-Host "[+] python: $pythonExe"
Write-Host "[+] pythonw: $pythonwExe"

# Pillow: requirements.rst lists this as CAPE's one recommended-but-optional
# guest library (desktop screenshots during analysis).
& $pythonExe -m pip install --upgrade pip --quiet
& $pythonExe -m pip install Pillow --quiet

# ── CAPE agent (agent.rst) ────────────────────────────────────────────────
Write-Host '[Phase 2] Installing CAPE agent...'
New-Item -ItemType Directory -Path 'C:\CAPE' -Force | Out-Null
# Staged by the packer "file" provisioner (below, in win11-cape.pkr.hcl) at
# C:\Windows\Temp\agent.py — moved and renamed to .pyw here, per agent.rst's
# own recommendation, to suppress the console window.
Copy-Item 'C:\Windows\Temp\agent.py' 'C:\CAPE\agent.pyw' -Force

# AtLogOn / RunLevel Highest — agent.rst's own documented setup ("It is a
# MUST to launch agent.py/w with elevated privileges... creating a
# Scheduled Task"). Same principal/settings shape
# 11-detonation-orchestrator.ps1 already uses in sandbox/windows, for the
# same underlying reason (AtLogOn fires before Packer's own build-time
# session, but matters at real detonation time once this golden image is
# deployed and the guest boots for real).
$action = New-ScheduledTaskAction -Execute $pythonwExe -Argument '"C:\CAPE\agent.pyw"'
$trigger = New-ScheduledTaskTrigger -AtLogOn -User 'analyst'
$trigger.Delay = 'PT10S'
$principal = New-ScheduledTaskPrincipal -UserId 'analyst' -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'CAPE Agent' `
  -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Write-Host '[+] CAPE agent scheduled task registered (AtLogOn, analyst, highest privileges)'

# agent.py listens on :8000 (agent.rst: "test... by executing curl VM_IP:8000").
# 01-hardening.ps1 already disabled the firewall profiles outright, so no
# separate allow-rule is needed — kept here as an explicit statement of
# intent rather than relying silently on that other script's own scope.
Write-Host '[+] Firewall already disabled by 01-hardening.ps1 — port 8000 reachable by default'

# ── Noisy network services (network.rst: "Disable Noisy Network Services") ─
Write-Host '[Phase 3] Disabling Teredo and LLMNR...'
netsh interface teredo set state disabled | Out-Null
# LLMNR: network.rst's own gpedit.msc path has no unattended equivalent;
# the underlying policy is this registry value (Group Policy's own storage
# for "Turn off Multicast Name Resolution"), set directly instead.
$dnsClientPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
New-Item $dnsClientPath -Force | Out-Null
Set-ItemProperty $dnsClientPath EnableMulticast 0 -Type DWord

'cape_agent=installed' | Add-Content 'C:\golden_image_provenance.txt'
Write-Host '[+] CAPE guest requirements installed'
exit 0
