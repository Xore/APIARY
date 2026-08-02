# 70-traffic-noise.ps1 - Background "user browsing" traffic generator with
# built-in filterability. All noise traffic is TAGGED three ways so it can be
# filtered out of pcaps/logs deterministically later:
#   1. Marker domain suffix: *.mcg-persona.net  (unique, grep-able)
#   2. Marker HTTP header:  X-Persona-Noise: 1   (visible in FakeNet HTTP logs)
#   3. Marker User-Agent:  Chrome/... MCGPersona/1.0
# FakeNet serves all of it; a post-filter script (tools/filter-pcap.sh on the
# host) strips the noise from captures using the same marker list.
$ErrorActionPreference = 'Continue'
Write-Host '== 70-traffic-noise =='

$personaDir = 'C:\ProgramData\persona'

# ---------------- Noise target list ----------------
# Mix: corporate-looking intranet hosts + "external" SaaS/news hosts.
# All share the marker suffix OR are listed in the marker file so the filter
# can remove them regardless.
$noiseHosts = @(
  # Marker-suffixed (always filterable by *.mcg-persona.net)
  'intranet.mcg-persona.net', 'erp.mcg-persona.net', 'treasury.mcg-persona.net',
  'hr.mcg-persona.net', 'concur.mcg-persona.net', 'mail.mcg-persona.net',
  'sharepoint.mcg-persona.net', 'files.mcg-persona.net', 'vpn.mcg-persona.net',
  'wsus.mcg-persona.net', 'adfs.mcg-persona.net',
  # "External" flavor (filterable via explicit list in marker file)
  'news-feed.mcg-persona.net', 'market-data.mcg-persona.net', 'cdn-static.mcg-persona.net'
)
$noiseHosts | Set-Content "$personaDir\noise-hosts.txt"

# ---------------- The generator ----------------
$gen = @'
# noise-gen.ps1 - runs as mwilson at logon, generates tagged background traffic.
# Cadence mimics a knowledge worker: bursts of browsing, idle gaps, heavier
# during work hours. Randomized everywhere; never periodic.
$ErrorActionPreference = 'SilentlyContinue'
$hosts = Get-Content 'C:\ProgramData\persona\noise-hosts.txt'
$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 MCGPersona/1.0'
$paths = @('/','/index.html','/intranet.html','/erp','/erp/api/session','/treasury','/api/v2/quotes','/static/app.js','/static/site.css','/favicon.ico','/auth/refresh','/news/top','/mail/sync')

function Invoke-NoiseRequest {
  param($h, $path, $method = 'GET')
  $scheme = if ((Get-Random -Maximum 100) -lt 70) { 'https' } else { 'http' }
  try {
    Invoke-WebRequest -Uri "${scheme}://${h}${path}" -Method $method `
      -UserAgent $ua -Headers @{ 'X-Persona-Noise' = '1'; 'Accept-Language' = 'en-US,en;q=0.9' } `
      -TimeoutSec 5 -UseBasicParsing | Out-Null
  } catch {}
}

function Send-NoiseDns {
  param($h)
  try { Resolve-DnsName -Name $h -Type A -ErrorAction Stop | Out-Null } catch {}
}

while ($true) {
  $hour = (Get-Date).Hour
  $work = ($hour -ge 8 -and $hour -lt 18)

  # Burst of 3-12 "browsing" requests
  $burst = Get-Random -Minimum 3 -Maximum 12
  for ($i = 0; $i -lt $burst; $i++) {
    $h = $hosts | Get-Random
    Send-NoiseDns $h
    Invoke-NoiseRequest $h ($paths | Get-Random)
    # Occasionally POST (form submit / API call)
    if ((Get-Random -Maximum 100) -lt 20) {
      try {
        Invoke-WebRequest -Uri "https://$h/api/submit" -Method POST `
          -UserAgent $ua -Headers @{ 'X-Persona-Noise' = '1' } `
          -Body (@{ ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); page = ($paths | Get-Random) } | ConvertTo-Json) `
          -ContentType 'application/json' -TimeoutSec 5 -UseBasicParsing | Out-Null
      } catch {}
    }
    Start-Sleep -Milliseconds (Get-Random -Minimum 400 -Maximum 6000)
  }

  # Inter-burst gap: 1-6 min work hours, 10-45 min off hours
  if ($work) { Start-Sleep -Seconds (Get-Random -Minimum 60 -Maximum 360) }
  else       { Start-Sleep -Seconds (Get-Random -Minimum 600 -Maximum 2700) }
}
'@
$gen | Set-Content "$personaDir\noise-gen.ps1" -Encoding UTF8

# Hidden launcher (no console window)
$vbs = @"
Set sh = CreateObject("WScript.Shell")
sh.Run "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ProgramData\persona\noise-gen.ps1", 0, False
"@
$vbs | Set-Content "$personaDir\noise-launcher.vbs"

$action  = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument '"C:\ProgramData\persona\noise-launcher.vbs"'
$trigger = New-ScheduledTaskTrigger -AtLogOn -User 'mwilson'
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'Windows Network Connectivity Monitor' `
  -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null

Write-Host '== 70-traffic-noise done =='
