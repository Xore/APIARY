#Requires -RunAsAdministrator
# prepare_vm.ps1 — Run once on a fresh Windows 11 VM before FLARE-VM install
# This script prepares a clean analysis environment.

param(
    [string]$REMnuxIP    = '10.10.10.1',
    [string]$AnalystIP   = '10.10.10.2',
    [string]$SubnetMask  = '255.255.255.0',
    # #91: was DESKTOP-AN4LY5T -- a substring check for ANALY/SANDBOX/MALWARE
    # in the hostname is among the cheapest evasion checks a sample can run.
    [string]$Hostname    = 'DESKTOP-JK3PLQ2'
)

Write-Host '[*] Preparing Windows 11 Malware Analysis VM...' -ForegroundColor Cyan

# ── Disable Windows Defender ──
Write-Host '[*] Disabling Windows Defender...'
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true
Set-MpPreference -SubmitSamplesConsent 2
Set-MpPreference -MAPSReporting 0
Add-MpPreference -ExclusionPath 'C:\'

# Disable Defender via registry (persists across reboots)
$defPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
New-Item -Path $defPath -Force | Out-Null
Set-ItemProperty -Path $defPath -Name DisableAntiSpyware -Value 1

# ── Disable Windows Firewall ──
Write-Host '[*] Disabling Windows Firewall (FakeNet-NG will handle traffic)...'
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# ── Disable Windows Update ──
Write-Host '[*] Disabling Windows Update...'
Stop-Service wuauserv -Force
Set-Service wuauserv -StartupType Disabled
$wuPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item -Path $wuPath -Force | Out-Null
Set-ItemProperty -Path $wuPath -Name NoAutoUpdate -Value 1
Set-ItemProperty -Path $wuPath -Name AUOptions -Value 1

# ── Disable UAC ──
Write-Host '[*] Disabling UAC...'
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name EnableLUA -Value 0

# ── Network: static IP + DNS to REMnux ──
Write-Host "[*] Setting static IP $AnalystIP, DNS $REMnuxIP..."
$adapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1
Remove-NetIPAddress -InterfaceAlias $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceAlias $adapter.Name `
    -IPAddress $AnalystIP -PrefixLength 24 -DefaultGateway $REMnuxIP
Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $REMnuxIP

# ── PowerShell Logging ──
Write-Host '[*] Enabling PowerShell ScriptBlock logging (Event 4104)...'
$sb = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
New-Item -Path $sb -Force | Out-Null
Set-ItemProperty -Path $sb -Name EnableScriptBlockLogging -Value 1
Set-ItemProperty -Path $sb -Name EnableScriptBlockInvocationLogging -Value 1

$mod = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
New-Item -Path $mod -Force | Out-Null
Set-ItemProperty -Path $mod -Name EnableModuleLogging -Value 1
New-Item -Path "$mod\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$mod\ModuleNames" -Name '*' -Value '*'

$trans = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
New-Item -Path $trans -Force | Out-Null
Set-ItemProperty -Path $trans -Name EnableTranscripting -Value 1
Set-ItemProperty -Path $trans -Name OutputDirectory -Value 'C:\PSTranscripts'
Set-ItemProperty -Path $trans -Name EnableInvocationHeader -Value 1
New-Item -Path 'C:\PSTranscripts' -ItemType Directory -Force | Out-Null

# ── Process Creation Auditing (Event 4688) ──
Write-Host '[*] Enabling process creation auditing (Event 4688)...'
auditpol /set /subcategory:'Process Creation' /success:enable /failure:enable
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
    -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWORD -Force -ErrorAction SilentlyContinue

# ── Create analysis directories ──
Write-Host '[*] Creating analysis directories...'
@('C:\Samples', 'C:\Logs', 'C:\Drops', 'C:\PSTranscripts', 'C:\Captures') | ForEach-Object {
    New-Item -Path $_ -ItemType Directory -Force | Out-Null
}

# Share C:\Samples for easy file drop from host
New-SmbShare -Name 'Samples' -Path 'C:\Samples' `
    -FullAccess 'Everyone' -ErrorAction SilentlyContinue
New-SmbShare -Name 'Logs' -Path 'C:\Logs' `
    -ReadAccess 'Everyone' -ErrorAction SilentlyContinue

# ── Anti-evasion: realistic environment ──
Write-Host '[*] Setting up realistic user environment...'
Rename-Computer -NewName $Hostname -Force -ErrorAction SilentlyContinue

# Set realistic screen resolution hint in registry
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name LogPixels -Value 96

# Disable hibernation
powercfg /hibernate off
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0

# ── Enable WinRM for remote orchestration ──
Write-Host '[*] Enabling WinRM...'
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force
Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB -Value 1024

Write-Host '[+] VM preparation complete. Take SNAPSHOT_1_PREPARED before installing FLARE-VM.' -ForegroundColor Green
