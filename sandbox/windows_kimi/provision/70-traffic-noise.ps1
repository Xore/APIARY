# 70-traffic-noise.ps1 - Background "user browsing" traffic generator with
# built-in filterability. All noise traffic is TAGGED three ways so it can be
# filtered out of pcaps/logs deterministically later:
#   1. Marker domain suffix: *.mcg-persona.net  (unique, grep-able)
#   2. Marker HTTP header:  X-Persona-Noise: 1   (visible in FakeNet HTTP logs)
#   3. Marker User-Agent:  Chrome/... MCGPersona/1.0
# FakeNet serves all of it; a post-filter script (tools/filter-pcap.sh on the
# host) strips the noise from captures using the same marker list.
#
# The https half is real TLS since #2449: FakeNet's 443 listener terminates
# SSL with the static persona CA that 40-fakenet.ps1 generated and imported
# into LocalMachine\Root at build time (detnode.ini: UseSSL + static_ca).
# Marker visibility therefore differs by layer: on a HOST-side pcap, 443
# sessions are encrypted -- only the *.mcg-persona.net SNI and the DNS lookups
# match; the X-Persona-Noise header and MCGPersona UA are inside the stream
# FakeNet itself terminates, so they show in FakeNet's own HTTP(S) logs and on
# the plain-HTTP third of requests. tools/filter-pcap.sh documents the same
# split.
#
# #2449: requests are wrapped in try/catch so one failure never stops the
# loop, but failures are COUNTED and one summary line per burst lands in
# C:\ProgramData\persona\noise-stats.log (plus Write-Host) -- a lopsided
# error rate (e.g. CA trust broken so every TLS handshake dies) must be
# visible in an output stream, not look identical to steady success.
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
# Per-burst ok/failed counts append to C:\ProgramData\persona\noise-stats.log
# so a dead TLS story (or any other systematic failure) is visible in a log
# instead of indistinguishable from success (#2449). One line per burst --
# bursts fire every 1-6 work minutes, so growth is ~100 lines/working day.
$ErrorActionPreference = 'SilentlyContinue'
$hosts = Get-Content 'C:\ProgramData\persona\noise-hosts.txt'
$statsLog = 'C:\ProgramData\persona\noise-stats.log'
$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 MCGPersona/1.0'
$paths = @('/','/index.html','/intranet.html','/erp','/erp/api/session','/treasury','/api/v2/quotes','/static/app.js','/static/site.css','/favicon.ico','/auth/refresh','/news/top','/mail/sync')
$script:windowOk = 0
$script:windowFail = 0
$script:lastErr = ''

function Invoke-NoiseRequest {
  param($h, $path, $method = 'GET')
  $scheme = if ((Get-Random -Maximum 100) -lt 70) { 'https' } else { 'http' }
  try {
    Invoke-WebRequest -Uri "${scheme}://${h}${path}" -Method $method `
      -UserAgent $ua -Headers @{ 'X-Persona-Noise' = '1'; 'Accept-Language' = 'en-US,en;q=0.9' } `
      -TimeoutSec 5 -UseBasicParsing | Out-Null
    $script:windowOk++
  } catch {
    $script:windowFail++
    $script:lastErr = $_.Exception.Message
  }
}

function Send-NoiseDns {
  param($h)
  try { Resolve-DnsName -Name $h -Type A -ErrorAction Stop | Out-Null } catch {}
}

function Write-NoiseWindow {
  $line = '{0} burst: {1} ok / {2} failed{3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $script:windowOk, $script:windowFail, $(if ($script:lastErr) { ' | last: ' + $script:lastErr } else { '' })
  Write-Host $line
  Add-Content -Path $statsLog -Value $line
  $script:windowOk = 0
  $script:windowFail = 0
  $script:lastErr = ''
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
    # Occasionally POST (form submit / API call) -- always https, so this is
    # the canary branch: 100% failures here means TLS trust is broken.
    if ((Get-Random -Maximum 100) -lt 20) {
      try {
        Invoke-WebRequest -Uri "https://$h/api/submit" -Method POST `
          -UserAgent $ua -Headers @{ 'X-Persona-Noise' = '1' } `
          -Body (@{ ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); page = ($paths | Get-Random) } | ConvertTo-Json) `
          -ContentType 'application/json' -TimeoutSec 5 -UseBasicParsing | Out-Null
        $script:windowOk++
      } catch {
        $script:windowFail++
        $script:lastErr = $_.Exception.Message
      }
    }
    Start-Sleep -Milliseconds (Get-Random -Minimum 400 -Maximum 6000)
  }

  Write-NoiseWindow

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
