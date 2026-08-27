# 40-fakenet.ps1 - Install FLARE FakeNet-NG, tune config for a fake finance
# intranet, register a startup scheduled task.
$ErrorActionPreference = 'Continue'
Write-Host '== 40-fakenet =='

$py = Get-Content C:\ProgramData\persona\python-path.txt -ErrorAction SilentlyContinue
if ($py) { $py = ($py -replace '^Python: ','').Trim() }
if (-not $py -or -not (Test-Path $py)) {
  $py = (Get-Command python -ErrorAction SilentlyContinue).Source
}
if (-not $py) { $py = 'C:\Program Files\Python312\python.exe' }
Write-Host "Using Python: $py"

$fn = 'C:\Tools\fakenet'
New-Item -ItemType Directory -Force -Path C:\Tools | Out-Null

if (-not (Test-Path "$fn\fakenet")) {
  git clone --depth 1 https://github.com/mandiant/flare-fakenet-ng.git $fn
}

# FakeNet's python deps (pydivert/win Divert etc. are in requirements.txt)
& $py -m pip install --quiet -r "$fn\requirements.txt"

# ---------------- Copy our tuned config over the default ----------------
$custom = 'D:\fakenet\detnode.ini'   # PROVISION cdrom, if packer cd_files mounted
if (-not (Test-Path $custom)) { $custom = "$PSScriptRoot\..\fakenet\detnode.ini" }
if (Test-Path $custom) {
  Copy-Item $custom "$fn\fakenet\configs\detnode.ini" -Force
  Write-Host 'Custom detnode.ini installed.'

  # Smoke check (#2446): assert the parse contract fakenet.py enforces
  # before anything can listen. configparser preserves section-header
  # whitespace, fakenet.py getbooleans 'enabled' on every section other
  # than [FakeNet]/[Diverter] with no exception handling, and
  # expand_listeners silently skips sections without a Listener key. The
  # original detnode.ini violated all three (a padded "[ Diverter ]"
  # header crashed the parse before [DNS Listener]/[BlackListIDs] could)
  # and shipped zero listeners behind DivertTraffic=Yes -- a blackholed
  # wire reported as "installed". Headers are compared UNtrimmed here on
  # purpose: a padded header is itself the defect.
  $cur = $null
  $secs = @{}
  switch -Regex -File "$fn\fakenet\configs\detnode.ini" {
    '^\s*\[(.+)\]\s*$'               { $cur = $Matches[1]; $secs[$cur] = @{} }
    '^\s*[#;]'                       { }
    '^\s*$'                          { }
    '^\s*([^=;#]+?)\s*=\s*(.*?)\s*$' { if ($cur) { $secs[$cur][$Matches[1].Trim().ToLower()] = $Matches[2].Trim() } }
  }
  $violations = @()
  foreach ($name in $secs.Keys) {
    if ($name -eq 'FakeNet' -or $name -eq 'Diverter') { continue }
    if (-not $secs[$name].ContainsKey('enabled')) {
      $violations += "${name}: no Enabled key (fakenet.py dies at parse)"
      continue
    }
    if ('1','yes','true','on' -notcontains $secs[$name]['enabled'].ToLower()) { continue }
    foreach ($req in 'port','protocol','listener') {
      if (-not $secs[$name].ContainsKey($req)) {
        $violations += "${name}: Enabled listener has no $req (silently skipped as Anonymous)"
      }
    }
  }
  if ($violations.Count -gt 0) {
    $violations | ForEach-Object { Write-Warning "[!] detnode.ini parse contract: $_" }
    exit 1
  }
  $enabledCount = ($secs.Keys | Where-Object {
    $_ -notin 'FakeNet','Diverter' -and $secs[$_].ContainsKey('enabled') -and
    '1','yes','true','on' -contains $secs[$_]['enabled'].ToLower()
  }).Count
  Write-Host "[+] detnode.ini parse contract OK ($enabledCount enabled listener sections)"
} else {
  Write-Host 'Custom detnode.ini not found; using upstream default.'
  Copy-Item "$fn\fakenet\configs\default.ini" "$fn\fakenet\configs\detnode.ini" -Force
}

# ---------------- Fake intranet web root ----------------
$webroot = "$fn\fakenet\defaultFiles"
New-Item -ItemType Directory -Force -Path $webroot | Out-Null
@"
<!DOCTYPE html>
<html><head><title>Meridian Capital Group - Intranet</title></head>
<body style="font-family:Segoe UI,Arial">
<h2>Meridian Capital Group</h2>
<p><b>Finance Intranet</b> - You are connected to CORPNET.</p>
<ul>
<li><a href="/erp">Dynamics ERP</a></li>
<li><a href="/treasury">Treasury Portal</a></li>
<li><a href="/hr">HR Self-Service</a></li>
</ul>
<p style="color:#888;font-size:11px">IT Help Desk: ext. 4357 | FIN-WS0147</p>
</body></html>
"@ | Set-Content "$webroot\intranet.html"

# ---------------- Launcher script ----------------
@"
@echo off
rem FakeNet-NG launcher for detnode
"$py" "$fn\fakenet\fakenet.py" -c "$fn\fakenet\configs\detnode.ini"
"@ | Set-Content 'C:\Tools\start-fakenet.cmd'

# ---------------- Scheduled task: start FakeNet at boot as SYSTEM ----------------
$action  = New-ScheduledTaskAction -Execute $py -Argument "`"$fn\fakenet\fakenet.py`" -c `"$fn\fakenet\configs\detnode.ini`"" -WorkingDirectory "$fn\fakenet"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'FakeNetNG' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

Write-Host '== 40-fakenet done =='
