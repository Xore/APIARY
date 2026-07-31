#Requires -RunAsAdministrator
# setup_analysis.ps1 — Packer provisioner script
# Runs inside the Windows 11 VM during golden image build
# Installs: FLARE-VM, Sysmon, FakeNet-NG, hardening, anti-evasion

Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force
$ErrorActionPreference = 'Continue'

Write-Host '================================================================'
Write-Host ' Honeypot-Stack: Windows 11 Analysis VM Setup'
Write-Host ' Running inside Packer QEMU build'
Write-Host '================================================================'

# ── Network: static IP + DNS ──────────────────────────────────────────────
Write-Host '[Phase 1] Network configuration...'
$adapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1
New-NetIPAddress -InterfaceAlias $adapter.Name `
    -IPAddress '10.10.10.2' -PrefixLength 24 -DefaultGateway '10.10.10.1' `
    -ErrorAction SilentlyContinue
Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses '10.10.10.1'
# During Packer build we need real internet for Chocolatey — revert DNS after
# Use host NAT temporarily; set INetSim DNS after build
Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses '8.8.8.8','1.1.1.1'

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

# ── Install FLARE-VM ─────────────────────────────────────────────────────
Write-Host '[Phase 8] Installing FLARE-VM (this takes 2-4 hours)...'
(New-Object Net.WebClient).DownloadFile(
    'https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',
    "$env:TEMP\\flarevm_install.ps1"
)
# Run FLARE-VM installer unattended
& "$env:TEMP\\flarevm_install.ps1" -password 'malware123!' -noWait -noGui -noChecks
Write-Host '[+] FLARE-VM installation triggered (running in background via scheduled task)'

# Wait for FLARE-VM to finish (polls for completion file)
$maxWait = 14400  # 4 hours
$elapsed = 0
while ($elapsed -lt $maxWait) {
    Start-Sleep 60
    $elapsed += 60
    if (Test-Path 'C:\ProgramData\chocolatey\lib\flarevm.installer') {
        Write-Host "[+] FLARE-VM complete after ${elapsed}s"
        break
    }
    Write-Host "[.] Waiting for FLARE-VM... ${elapsed}s elapsed"
}

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
    Set-Content 'C:\golden_image_provenance.txt'
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
choco install fakenet-ng -y --no-progress -ErrorAction SilentlyContinue
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
choco install regshot -y --no-progress -ErrorAction SilentlyContinue
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
choco install qemu-guest-agent -y --no-progress -ErrorAction SilentlyContinue
Start-Service QEMU-GA -ErrorAction SilentlyContinue

# ── Analysis Directories ─────────────────────────────────────────────────
@('C:\Samples','C:\Logs','C:\Drops','C:\Captures') | ForEach-Object {
    New-Item $_ -ItemType Directory -Force | Out-Null
}
New-SmbShare -Name 'Samples' -Path 'C:\Samples' -FullAccess 'Everyone' -ErrorAction SilentlyContinue
New-SmbShare -Name 'Logs'    -Path 'C:\Logs'    -ReadAccess 'Everyone' -ErrorAction SilentlyContinue

# ── Anti-Evasion: Decoy Environment ──────────────────────────────────────
Write-Host '[Phase 13] Setting up decoy user environment...'
# Create decoy documents
$docs = "$env:USERPROFILE\Documents"
@('Q3_Budget_2026.xlsx','Project_Proposal.docx','Meeting_Notes_July.txt',
  'Client_Contacts.xlsx','HR_Policy_2026.pdf') | ForEach-Object {
    [System.IO.File]::WriteAllText("$docs\$_", "Decoy file for $_ - created by honeypot-stack")
}
# Inject fake recent files
$recent = "$env:APPDATA\Microsoft\Windows\Recent"
New-Item $recent -ItemType Directory -Force | Out-Null
@('Report_Final.docx','Budget_Q3.xlsx','Presentation.pptx') | ForEach-Object {
    New-Item "$recent\$_.lnk" -ItemType File -Force | Out-Null
}
Write-Host '[+] Decoy environment created'

# ── Final DNS: set to INetSim (10.10.10.1) ────────────────────────────────
Write-Host '[Phase 14] Setting DNS to INetSim gateway (10.10.10.1)...'
$adapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses '10.10.10.1'

Write-Host '================================================================'
Write-Host '[+] Setup complete. Packer will now shut down and export qcow2.'
Write-Host '================================================================'
