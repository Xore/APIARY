# 10-baseline.ps1 - OS hardening-relaxation for a detonation box, telemetry off,
# Windows Update controlled, power settings sane for 24/7 VM use.
$ErrorActionPreference = 'Continue'
Write-Host '== 10-baseline =='

# --- Disable Windows Update auto-reboots during builds; keep manual control ---
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
New-Item -Path $wu -Force | Out-Null
Set-ItemProperty $wu -Name NoAutoUpdate -Value 1 -Type DWord
Set-ItemProperty $wu -Name NoAutoRebootWithLoggedOnUsers -Value 1 -Type DWord

# --- Telemetry / CEIP / advertising ID off ---
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Force | Out-Null
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name AllowTelemetry -Value 0 -Type DWord
Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' -Name Enabled -Value 0 -Type DWord -ErrorAction SilentlyContinue

# --- Power: never sleep, never turn off display, high performance ---
powercfg /change standby-timeout-ac 0
powercfg /change monitor-timeout-ac 0
powercfg /change hibernate-timeout-ac 0
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  # High performance
Disable-MMAgent -PageCombining -ErrorAction SilentlyContinue

# --- Show file extensions + hidden files (finance user who "knows computers") ---
$adv = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty $adv -Name HideFileExt -Value 0
Set-ItemProperty $adv -Name Hidden -Value 1

# --- UAC: keep enabled (realistic) but don't prompt admins aggressively ---
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name ConsentPromptBehaviorAdmin -Value 5

# --- Defender: real-time protection ON but cloud/automatic sample submission OFF
#     so payloads don't get uploaded to MS cloud during analysis. ---
Set-MpPreference -MAPSReporting Disabled -ErrorAction SilentlyContinue
Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction SilentlyContinue  # Never send
# Exclusions for analysis tooling directories
Add-MpPreference -ExclusionPath 'C:\Tools' -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath 'C:\Detonation' -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path 'C:\Detonation' | Out-Null

# --- Disable Windows SmartScreen (prompts break detonation automation) ---
Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name EnableSmartScreen -Value 0 -Type DWord -Force
Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost' -Name EnableWebContentEvaluation -Value 0 -Type DWord -ErrorAction SilentlyContinue

# --- Timezone already EST via unattend; sync clock ---
w32tm /resync /force 2>$null

# --- Long WinRM timeouts for slow detonations ---
winrm set winrm/config '@{MaxTimeoutms="1800000"}'

Write-Host '== 10-baseline done =='
