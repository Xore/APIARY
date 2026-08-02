# 30-tools.ps1 - Chocolatey, browsers, office suite, analysis tooling.
$ErrorActionPreference = 'Continue'
Write-Host '== 30-tools =='

# ---------------- Chocolatey ----------------
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
  Set-ExecutionPolicy Bypass -Scope Process -Force
  [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
  Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
  $env:Path += ";$env:ALLUSERSPROFILE\chocolatey\bin"
  refreshenv 2>$null
}

# ---------------- End-user apps (persona) ----------------
choco install -y --no-progress --ignore-checksums `
  googlechrome `
  7zip `
  notepadplusplus `
  adobereader `
  libreoffice-fresh

# Optional: real MS Office via Office Deployment Tool (needs volume/O365 license).
# ODT + a config XML placed in C:\ProgramData\persona\odt-config.xml will be
# picked up here if present:
if (Test-Path 'C:\ProgramData\persona\odt-config.xml') {
  choco install -y --no-progress officedeploymenttool
  & "C:\Program Files\OfficeDeploymentTool\setup.exe" /configure 'C:\ProgramData\persona\odt-config.xml'
}

# ---------------- Python ----------------
choco install -y --no-progress python --version=3.12.*
$py = Get-ChildItem 'C:\Program Files\Python3*\python.exe' | Select-Object -First 1 -ExpandProperty FullName
if (-not $py) { $py = (Get-Command python -ErrorAction SilentlyContinue).Source }
"Python: $py" | Out-File C:\ProgramData\persona\python-path.txt

# ---------------- Analysis tooling ----------------
choco install -y --no-progress `
  sysinternals `
  wireshark `
  git

& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet `
  pefile `
  yara-python `
  oletools `
  requests `
  python-docx `
  openpyxl `
  selenium

# ---------------- Sysinternals: accept EULAs so they run headless ----------------
$siPaths = @('C:\ProgramData\chocolatey\lib\sysinternals\tools', 'C:\Tools\sysinternals', 'C:\Program Files\Sysinternals')
foreach ($p in $siPaths) {
  if (Test-Path $p) {
    Get-ChildItem $p -Filter *.exe | ForEach-Object {
      & $_.FullName /accepteula -nobanner 2>$null | Out-Null
    }
  }
}
# Registry-based EULA acceptance as fallback
New-Item -Path 'HKCU:\Software\Sysinternals' -Force | Out-Null
foreach ($t in @('Process Explorer','Process Monitor','Autoruns','TCPView','PsExec','Strings','Sigcheck')) {
  New-Item -Path "HKCU:\Software\Sysinternals\$t" -Force | Out-Null
  Set-ItemProperty "HKCU:\Software\Sysinternals\$t" -Name EulaAccepted -Value 1 -Type DWord
}

Write-Host '== 30-tools done =='
