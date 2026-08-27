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
} else {
  Write-Host 'Custom detnode.ini not found; using upstream default.'
  Copy-Item "$fn\fakenet\configs\default.ini" "$fn\fakenet\configs\detnode.ini" -Force
}

# ---------------- HTTPS trust: static persona CA (#2449) ----------------
# The noise generator's https half only works if the guest trusts what the
# 443 listener presents. detnode.ini sets UseSSL=Yes with static_ca=Yes
# against the CA generated here, once per build: the issuer is stable across
# boots. Upstream's non-static path mints a throwaway temp_certs root and
# imports/removes it in the machine Root store on every start/stop (certutil
# addstore/delstore churn a sample could notice), so we don't use it. The CA
# stays inside the image on purpose -- a private key committed to this repo
# would fail scripts/check-public-leaks.py.
& $py -c "import OpenSSL" 2>$null
if ($LASTEXITCODE -ne 0) {
  Write-Host 'pyopenssl missing; installing (FakeNet needs it anyway)'
  & $py -m pip install --quiet pyopenssl
}
$caCert = "$fn\fakenet\configs\meridian-ca.crt"
$caKey  = "$fn\fakenet\configs\meridian-ca.key"
$caGen = Join-Path $env:TEMP 'gen-persona-ca.py'
@'
# One-shot self-signed "corporate issuing CA" for the persona's HTTPS noise
# (#2449). Idempotent: if both files exist, leave them alone so a re-run
# never rotates the issuer a guest already trusts.
#
# Built with the `cryptography` x509 builder API (a FakeNet core dep) rather
# than pyOpenSSL's deprecated PKey/X509 surface, whose methods keep
# disappearing between releases.
import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

cert_path, key_path = sys.argv[1], sys.argv[2]
if os.path.exists(cert_path) and os.path.exists(key_path):
    print('persona CA already present: %s' % cert_path)
    sys.exit(0)

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Meridian Capital Group'),
    x509.NameAttribute(NameOID.COMMON_NAME, 'Meridian Capital Group Corporate CA'),
])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(2026082701)
    .not_valid_before(now - datetime.timedelta(hours=1))
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=None,
            decipher_only=None,
        ),
        critical=True,
    )
    .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    .sign(key, hashes.SHA256())
)
with open(cert_path, 'wb') as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
with open(key_path, 'wb') as f:
    f.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
print('persona CA generated: %s' % cert_path)
'@ | Set-Content $caGen -Encoding ASCII
& $py $caGen $caCert $caKey
Remove-Item $caGen -ErrorAction SilentlyContinue
if (-not (Test-Path $caCert) -or -not (Test-Path $caKey)) {
  Write-Host 'WARNING: persona CA generation failed; HTTPS noise will fail certificate validation.'
}

# detnode.ini hard-codes absolute CA/leaf-cert paths against the
# C:\Tools\fakenet default; rewrite them if FakeNet landed elsewhere.
$installedIni = "$fn\fakenet\configs\detnode.ini"
if (Test-Path $installedIni) {
  $iniText = (Get-Content $installedIni -Raw).Replace('C:\Tools\fakenet', $fn)
  Set-Content $installedIni -Value $iniText -Encoding ASCII -NoNewline
}

# Trust the persona CA for every account in the guest -- the noise generator
# runs as mwilson, FakeNet as SYSTEM, and machine Root covers both. Same
# admin assumption as the SYSTEM scheduled task registered below.
$trusted = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue |
  Where-Object { $_.Subject -like 'CN=Meridian Capital Group Corporate CA*' }
if ($trusted) {
  Write-Host 'Persona CA already trusted in LocalMachine Root.'
} elseif (Test-Path $caCert) {
  certutil -addstore -f Root $caCert | Out-Null
  Write-Host 'Persona CA imported into LocalMachine Root.'
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
