#Requires -RunAsAdministrator
# 08-traffic-noise.ps1 — Packer provisioner, step 6b of win11-analysis.pkr.hcl's build.
#
# #291: background "user browsing" traffic generator with built-in
# filterability. All noise traffic is tagged three independent ways so it
# can be stripped out of a capture deterministically after the fact:
#   1. Marker domain suffix: *.acp-persona.net (unique, grep-able)
#   2. Marker HTTP header:   X-Persona-Noise: 1
#   3. Marker User-Agent:    Chrome/... ACPPersona/1.0
# FakeNet answers all of it (config/fakenet.ini's DNS/HTTP/HTTPS listeners
# already answer any hostname). tools/filter-pcap.sh (host-side) builds a
# tshark display filter from the same three markers and splits a capture
# into clean.pcap / noise.pcap. Ported from
# sandbox/windows_kimi/provision/70-traffic-noise.ps1 (merged at 536b505);
# the marker suffix and UA tag were changed from that prototype's
# mcg-persona.net/MCGPersona -- fictional-company-specific -- to this
# image's own #293 persona, and the AtLogOn user changed from
# 'mwilson' to 'analyst'.
#
# If this is ever re-themed, change the suffix here AND in
# ../../tools/filter-pcap.sh together -- they must agree.
#
# #2546 (mirrors #2449 on windows_kimi): the https half is real TLS -- 04-tools.ps1
# generates a static persona CA and imports it into LocalMachine\Root at build
# time, and config/fakenet.ini's [HTTPS] section points the 443 listener at
# that same pair (static_ca + ca_cert/ca_key), so the guest actually trusts
# what the listener presents instead of every handshake failing certificate
# verification. Marker visibility differs by layer: on a HOST-side pcap, 443
# sessions are encrypted -- only the *.acp-persona.net SNI and the DNS
# lookups match; the X-Persona-Noise header and ACPPersona UA are inside the
# stream FakeNet itself terminates, so they show in FakeNet's own HTTP(S)
# logs and on the plain-HTTP third of requests. tools/filter-pcap.sh
# documents the same split.
#
# #2546: requests are wrapped in try/catch so one failure never stops the
# loop, but failures are COUNTED and one summary line per burst lands in
# C:\ProgramData\persona\noise-stats.log (plus Write-Host) -- a lopsided
# error rate (e.g. CA trust broken so every TLS handshake dies) must be
# visible in an output stream, not look identical to steady success.

$ErrorActionPreference = 'Continue'
Write-Host '================================================================'
Write-Host ' Honeypot-Stack: Windows 11 Analysis VM - traffic-noise generator'
Write-Host '================================================================'

$personaDir = 'C:\ProgramData\persona'
New-Item -ItemType Directory -Force -Path $personaDir | Out-Null

# ---------------- Noise target list ----------------
# Mix of corporate-looking intranet hosts + "external" SaaS/news hosts, all
# sharing the marker suffix so filter-pcap.sh can remove every one of them.
$noiseHosts = @(
  'intranet.acp-persona.net', 'erp.acp-persona.net', 'treasury.acp-persona.net',
  'hr.acp-persona.net', 'concur.acp-persona.net', 'mail.acp-persona.net',
  'sharepoint.acp-persona.net', 'files.acp-persona.net', 'vpn.acp-persona.net',
  'wsus.acp-persona.net', 'adfs.acp-persona.net',
  'news-feed.acp-persona.net', 'market-data.acp-persona.net', 'cdn-static.acp-persona.net'
)
$noiseHosts | Set-Content "$personaDir\noise-hosts.txt"

# ---------------- The generator ----------------
$gen = @'
# noise-gen.ps1 - runs as analyst at logon, generates tagged background traffic.
# Cadence mimics a knowledge worker: bursts of browsing, idle gaps, heavier
# during work hours. Randomized everywhere; never periodic.
# Per-burst ok/failed counts append to C:\ProgramData\persona\noise-stats.log
# so a dead TLS story (or any other systematic failure) is visible in a log
# instead of indistinguishable from success (#2546).
$ErrorActionPreference = 'SilentlyContinue'
$hosts = Get-Content 'C:\ProgramData\persona\noise-hosts.txt'
$statsLog = 'C:\ProgramData\persona\noise-stats.log'
$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 ACPPersona/1.0'
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

  # Inter-burst gap: 1-6 min work hours, 10-45 min off hours -- never periodic
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
$trigger = New-ScheduledTaskTrigger -AtLogOn -User 'analyst'
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'Windows Network Connectivity Monitor' `
  -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null

'traffic_noise=installed (marker suffix: acp-persona.net)' | Add-Content 'C:\golden_image_provenance.txt'
Write-Host '[+] Traffic-noise generator registered'
exit 0
