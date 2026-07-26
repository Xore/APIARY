#Requires -RunAsAdministrator
# enable_logging.ps1 — Install Sysmon + enable all Windows telemetry
# Run AFTER FLARE-VM install, before taking SNAPSHOT_3_GOLDEN

Write-Host '[*] Installing Sysmon + enabling full telemetry...' -ForegroundColor Cyan

# ── Install Sysmon via Enable-All-The-Logs (bobby-tablez) ──
Write-Host '[*] Running Enable-All-The-Logs (Sysmon + GPO + PS logging)...'
Invoke-Expression (Invoke-RestMethod `
    'https://raw.githubusercontent.com/bobby-tablez/Enable-All-The-Logs/main/enable_logs.ps1') `
    -ErrorAction Stop

# ── Verify Sysmon is running ──
$svc = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
if ($svc.Status -ne 'Running') {
    Write-Warning 'Sysmon not running! Check installation.'
} else {
    Write-Host '[+] Sysmon64 running' -ForegroundColor Green
}

# ── PowerShell Enhanced Logging ──
Write-Host '[*] Enabling PowerShell ScriptBlock + Module + Transcription logging...'
$paths = @{
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' = @{
        EnableScriptBlockLogging = 1
        EnableScriptBlockInvocationLogging = 1
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
foreach ($path in $paths.Keys) {
    New-Item -Path $path -Force | Out-Null
    foreach ($name in $paths[$path].Keys) {
        Set-ItemProperty -Path $path -Name $name -Value $paths[$path][$name] -Force
    }
}
New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
    -Force | Out-Null
Set-ItemProperty `
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
    -Name '*' -Value '*'

# ── Extend event log sizes ──
Write-Host '[*] Expanding event log sizes...'
@(
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Security',
    'System',
    'Application'
) | ForEach-Object {
    wevtutil sl $_ /ms:524288000   # 500 MB each
}

# ── Install FakeNet-NG ──
Write-Host '[*] Installing FakeNet-NG...'
$fakeNetUrl = 'https://github.com/mandiant/flare-fakenet-ng/releases/latest/download/fakenet.zip'
$fakeNetDest = 'C:\Tools\FakeNet'
New-Item -Path $fakeNetDest -ItemType Directory -Force | Out-Null
Invoke-WebRequest -Uri $fakeNetUrl -OutFile "$fakeNetDest\fakenet.zip" -UseBasicParsing
Expand-Archive -Path "$fakeNetDest\fakenet.zip" -DestinationPath $fakeNetDest -Force
Write-Host '[+] FakeNet-NG installed at C:\Tools\FakeNet' -ForegroundColor Green

# ── Copy FakeNet config ──
$configSrc = 'C:\honeypot-stack\sandbox\windows\config\fakenet.ini'
if (Test-Path $configSrc) {
    Copy-Item $configSrc "$fakeNetDest\configs\honeypot_fakenet.ini" -Force
    Write-Host '[+] Copied FakeNet honeypot config' -ForegroundColor Green
}

Write-Host '[+] Logging setup complete. Take SNAPSHOT_3_GOLDEN now.' -ForegroundColor Green
