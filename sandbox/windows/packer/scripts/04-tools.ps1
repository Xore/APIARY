#Requires -RunAsAdministrator
# 04-tools.ps1 — Packer provisioner, step 3 of win11-analysis.pkr.hcl's build.
#
# The analysis tooling: Sysmon, PowerShell logging, FakeNet-NG, Regshot, the
# QEMU guest agent, the analysis directories and shares, the decoy environment,
# and the final resolver. Everything run_sample.py depends on in the guest is
# installed here -- Procmon, Regshot, FakeNet and Sysmon, none of which come
# from (or ever required) FLARE-VM, which is why this template no longer
# installs it at all as of 2026-08-02.
#
# Runs after the settle-restart (step 2 of the template), so any pending
# reboot from 01-hardening.ps1 is finished by the time any of it executes.

Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force
$ErrorActionPreference = 'Continue'

# Confirmed live (build errored after 6h15m despite every phase below it
# succeeding, including this script's own final "Setup complete" banner):
# `choco install X -ErrorAction SilentlyContinue` does not do what it looks
# like it does. -ErrorAction is a PowerShell cmdlet parameter; choco.exe is
# a native executable, so PowerShell never strips it -- choco's own CLI
# parser receives "-ErrorAction" and "SilentlyContinue" as literal argv and
# reads the latter as one more package name to install ("Chocolatey
# installed 3/4 packages. 1 packages failed... SilentlyContinue not
# installed"). That phantom package always fails, choco.exe exits non-zero,
# and because $LASTEXITCODE is only ever set by a native command (no
# PowerShell cmdlet touches it), that stale non-zero value survives
# untouched all the way to the end of the script -- which is exactly what
# Packer's own `exit $LastExitCode` provisioner wrapper reads as this
# script's overall result. Same failure class as the wevtutil incident
# documented in win11-analysis.pkr.hcl: a native command's exit code
# silently overriding real success, deleting a multi-hour build over
# tooling nothing downstream depends on.
#
# Invoke-OptionalChoco is the fix: run choco for real (no bogus flag to
# corrupt its argv), then explicitly consume and clear $LASTEXITCODE so a
# failed optional package is visible in the log but can never again poison
# this script's own final exit status. Every call site below already has
# its own fallback/marker-file handling for "the tool didn't show up" --
# this only fixes how that failure gets reported, not what happens after.
function Invoke-OptionalChoco {
    param([Parameter(Mandatory)][string]$Package)
    & choco install $Package -y --no-progress
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "[!] choco install $Package exited $LASTEXITCODE -- continuing, see the fallback/marker handling below"
        $global:LASTEXITCODE = 0
    }
}

Write-Host '================================================================'
Write-Host ' Honeypot-Stack: Windows 11 Analysis VM - tooling'
Write-Host '================================================================'

'flarevm=not-installed (removed 2026-08-02, see win11-analysis.pkr.hcl)' | Add-Content 'C:\golden_image_provenance.txt'

# ── Install Sysmon ────────────────────────────────────────────────────────
Write-Host '[Phase 9] Installing Sysmon...'
$sysmonPath = 'C:\Tools\SysinternalsSuite'
if (-not (Test-Path "$sysmonPath\Sysmon64.exe")) {
    choco install sysinternals -y --no-progress
}
# The config comes from a third-party branch at build time, so two things can
# go wrong and neither should cost three hours. DownloadFile throws a
# terminating error, which would abort the whole provisioner at Phase 9 over a
# momentary blip on a host we do not control.
#
# Sysmon without a config still logs process creation, network connections and
# image loads — a thinner record than SwiftOnSecurity's, but the detonation is
# still observed. Losing that is much better than losing the build.
$configUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml'
$configPath = 'C:\Windows\sysmon_config.xml'
$sysmonConfigured = $false
try {
    (New-Object Net.WebClient).DownloadFile($configUrl, $configPath)
    # A 404 or a captive-portal page downloads happily and is not XML. Sysmon
    # would reject it with a message no one reads until a report comes back
    # empty, so check here instead.
    [xml](Get-Content $configPath) | Out-Null
    & "$sysmonPath\Sysmon64.exe" -accepteula -i $configPath
    $sysmonConfigured = $true
    Write-Host '[+] Sysmon installed with sysmon-config'
} catch {
    Write-Warning "[!] Sysmon config unusable ($($_.Exception.Message)) - falling back to defaults"
    & "$sysmonPath\Sysmon64.exe" -accepteula -i
}
# Record which of the two ran. A report that looks thin should be traceable to
# this without guessing.
"sysmon_config=$(if ($sysmonConfigured) { 'sysmon-config' } else { 'defaults' })" |
    Add-Content 'C:\golden_image_provenance.txt'
Write-Host '[+] Sysmon installed'

# ── PowerShell Logging ────────────────────────────────────────────────────
Write-Host '[Phase 10] Enabling PowerShell logging...'
$logPaths = @{
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' = @{
        EnableScriptBlockLogging = 1; EnableScriptBlockInvocationLogging = 1
    }
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' = @{
        EnableModuleLogging = 1
    }
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' = @{
        EnableTranscripting = 1
        OutputDirectory = 'C:\PSTranscripts'
        EnableInvocationHeader = 1
    }
}
foreach ($p in $logPaths.Keys) {
    New-Item $p -Force | Out-Null
    foreach ($n in $logPaths[$p].Keys) { Set-ItemProperty $p $n $logPaths[$p][$n] }
}
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
    -Force | Out-Null
Set-ItemProperty `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
    -Name '*' -Value '*'
New-Item 'C:\PSTranscripts' -ItemType Directory -Force | Out-Null
Write-Host '[+] PowerShell logging enabled'

# ── Process Creation Auditing ─────────────────────────────────────────────
auditpol /set /subcategory:'Process Creation' /success:enable /failure:enable
Set-ItemProperty `
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    ProcessCreationIncludeCmdLine_Enabled 1 -Type DWORD -Force -ErrorAction SilentlyContinue

# ── Expand Event Log Sizes ────────────────────────────────────────────────
@('Microsoft-Windows-Sysmon/Operational',
  'Microsoft-Windows-PowerShell/Operational',
  'Security', 'System', 'Application') | ForEach-Object {
    wevtutil sl $_ /ms:524288000
}

# ── Install FakeNet-NG ────────────────────────────────────────────────────
Write-Host '[Phase 11] Installing FakeNet-NG...'
Invoke-OptionalChoco -Package fakenet-ng
# Fallback: manual install from GitHub releases
if (-not (Get-Command fakenet -ErrorAction SilentlyContinue)) {
    $url = 'https://github.com/mandiant/flare-fakenet-ng/releases/latest/download/fakenet.zip'
    New-Item 'C:\Tools\FakeNet' -ItemType Directory -Force | Out-Null
    (New-Object Net.WebClient).DownloadFile($url, 'C:\Tools\FakeNet\fakenet.zip')
    Expand-Archive 'C:\Tools\FakeNet\fakenet.zip' 'C:\Tools\FakeNet' -Force
}

# run_sample.py launches fakenet with
#   -c C:\Tools\FakeNet\configs\honeypot_fakenet.ini
# so the config has to be in the golden image, not applied at detonation time.
# The template's file provisioner stages it in Temp (the only directory that
# reliably exists before this script runs); it comes from config/fakenet.ini in
# the repo so there is one copy to review, not two.
$fnConfigDir = 'C:\Tools\FakeNet\configs'
New-Item $fnConfigDir -ItemType Directory -Force | Out-Null
$staged = 'C:\Windows\Temp\honeypot_fakenet.ini'
if (Test-Path $staged) {
    Move-Item $staged "$fnConfigDir\honeypot_fakenet.ini" -Force
    Write-Host '[+] FakeNet config installed'
} else {
    Write-Warning '[!] honeypot_fakenet.ini was not staged - FakeNet will use defaults'
}

# #294: fake-intranet landing page the HTTP/HTTPS listeners' Webroot points
# at (relative to $fnConfigDir, per honeypot_fakenet.ini's DefaultFiles).
$stagedWebroot = 'C:\Windows\Temp\honeypot_fakenet_defaultFiles'
if (Test-Path $stagedWebroot) {
    Move-Item $stagedWebroot "$fnConfigDir\defaultFiles" -Force
    Write-Host '[+] FakeNet intranet webroot installed'
} else {
    Write-Warning '[!] FakeNet defaultFiles were not staged - HTTP/HTTPS will use the stock 200 OK'
}
Write-Host '[+] FakeNet-NG installed'

# ── Install Regshot ───────────────────────────────────────────────────────
# orchestrate/run_sample.py shells out to a hard-coded
# C:\Tools\Regshot\Regshot-x64-Unicode.exe for the before/after registry diff.
# Chocolatey drops the binary under its own lib tree, so copy it to the path
# the orchestrator expects rather than teaching the orchestrator a second one —
# every other tool it drives lives under C:\Tools\.
Write-Host '[Phase 11b] Installing Regshot...'
$regshotDir = 'C:\Tools\Regshot'
$regshotExe = "$regshotDir\Regshot-x64-Unicode.exe"
New-Item $regshotDir -ItemType Directory -Force | Out-Null
Invoke-OptionalChoco -Package regshot
if (-not (Test-Path $regshotExe)) {
    $found = Get-ChildItem 'C:\ProgramData\chocolatey\lib' -Recurse `
        -Filter 'Regshot*x64*Unicode*.exe' -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($found) { Copy-Item $found.FullName $regshotExe -Force }
}
if (Test-Path $regshotExe) {
    Write-Host '[+] Regshot installed'
} else {
    # Not fatal: a detonation without a registry diff is still a usable report,
    # and failing the whole 3-hour build over one optional tool is worse. The
    # marker file is what the smoke test checks.
    Write-Warning '[!] Regshot NOT installed - registry diffs will be missing'
    'MISSING' | Set-Content 'C:\Tools\Regshot\MISSING.txt'
}

# ── QEMU Guest Agent ─────────────────────────────────────────────────────
Write-Host '[Phase 12] Installing QEMU guest agent...'
Invoke-OptionalChoco -Package qemu-guest-agent
Start-Service QEMU-GA -ErrorAction SilentlyContinue

# ── Analysis Directories ─────────────────────────────────────────────────
# #91: these shares were 'Everyone' -- FullAccess on Samples, ReadAccess on
# Logs -- on a machine whose entire purpose is running a detonated sample
# with a writable, network-reachable path and a lab-shaped share name to
# find. Checked orchestrate/run_sample.py before narrowing this rather than
# removing the shares outright as #91 first suggested: it authenticates to
# both over SMB explicitly as -U 'analyst%<pass>' (copy_sample_to_vm,
# collect_artifacts), never relying on anonymous/Everyone access, so
# 'Everyone' was already redundant with what the orchestrator actually
# needs -- narrowing to the analyst account changes nothing for it and
# closes the share to every other process on the box, detonated sample
# included.
@('C:\Samples','C:\Logs','C:\Drops','C:\Captures') | ForEach-Object {
    New-Item $_ -ItemType Directory -Force | Out-Null
}
New-SmbShare -Name 'Samples' -Path 'C:\Samples' -FullAccess 'analyst' -ErrorAction SilentlyContinue
New-SmbShare -Name 'Logs'    -Path 'C:\Logs'    -ReadAccess 'analyst' -ErrorAction SilentlyContinue

# Decoy user environment (fake documents, a decoy SMB share, realistic
# recent-files) lives in scripts/05-decoy-content.ps1, the next provisioner
# in win11-analysis.pkr.hcl -- separate from this script deliberately, since
# it's cosmetic and nothing run_sample.py touches, unlike everything above.

# ── Final DNS: set to INetSim (10.10.10.1) ────────────────────────────────
# Safe here and only here — this is the last phase, so it cannot cost the
# build its internet the way the old Phase 1 static IP did. Unlike an address
# and a gateway, a resolver the guest cannot reach yet breaks nothing until
# the guest is on the sandbox bridge.
#
# Deliberately belt-and-braces: setup/sandbox-network.xml already hands out
# 10.10.10.1 via dhcp-option=6, and this survives a guest that somehow misses
# the DHCP option. The cost is that 10.10.10.1 is now written down in three
# places — here, that file, and the inetsim ipv4_address in
# docker-compose.sandbox.yml. All three are pinned constants; change one and
# you must change all three, or the static entry here will silently win over
# DHCP and every lookup will go to a dead address.
Write-Host '[Phase 13] Setting DNS to INetSim gateway (10.10.10.1)...'
$adapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses '10.10.10.1'

Write-Host '================================================================'
Write-Host '[+] Setup complete. Packer will now shut down and export qcow2.'
Write-Host '================================================================'

# Explicit, not implicit: Packer's provisioner wrapper does `exit
# $LastExitCode`, which reads whatever a native command last left behind --
# see Invoke-OptionalChoco's comment above for the incident that taught
# this. Every native call in this script already resets it, but this line
# means a future edit that adds one more without remembering that can never
# again cost a real, successful build over nothing.
exit 0
