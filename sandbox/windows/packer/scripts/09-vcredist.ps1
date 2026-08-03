#Requires -RunAsAdministrator
# 09-vcredist.ps1 — Packer provisioner, step 7 of win11-analysis.pkr.hcl's build (#368).
#
# Without this, System32 has only the CLR-bundled vcruntime/msvcp DLLs
# (.NET's own private copies), not the standalone system-wide
# redistributable most natively-compiled C++ apps link against via the
# normal DLL search path. al-khaser (a natively-compiled C++ EXE) confirmed
# this live: it failed to launch at all, exit code -1073741515 / 0xC0000135
# (STATUS_DLL_NOT_FOUND), before this script existed. That is not specific
# to al-khaser -- a meaningful fraction of real-world Windows malware is
# also natively compiled and dynamically linked against this same runtime.
# Without it, those samples fail to launch the same way, which in a
# detonation report reads as "sample did nothing interesting" rather than
# "sample couldn't even start" -- a silent false-negative source for the
# whole sandbox's actual purpose, not a cosmetic gap.
#
# Both x64 and x86: 32-bit samples are common and need the x86 runtime even
# on a 64-bit OS (it installs to SysWOW64, alongside the x64 copy in
# System32).
#
# Installer exit code 1638 (ERROR_PRODUCT_VERSION) means a satisfying
# version is already present -- confirmed live not to mean "nothing to do
# and nothing changed": the actual runtime DLLs were verified present
# (Test-Path C:\Windows\System32\vcruntime140.dll) and al-khaser ran
# cleanly afterward. Treat 1638 as success, same as 0.

$ErrorActionPreference = 'Continue'
Write-Host '================================================================'
Write-Host ' Honeypot-Stack: Windows 11 Analysis VM - VC++ Redistributable'
Write-Host '================================================================'

$installers = @(
    @{ Name = 'x64'; Url = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'; Path = "$env:TEMP\vc_redist.x64.exe" }
    @{ Name = 'x86'; Url = 'https://aka.ms/vs/17/release/vc_redist.x86.exe'; Path = "$env:TEMP\vc_redist.x86.exe" }
)

foreach ($installer in $installers) {
    Write-Host "[+] Downloading VC++ Redistributable ($($installer.Name))..."
    Invoke-WebRequest -Uri $installer.Url -OutFile $installer.Path -UseBasicParsing

    Write-Host "[+] Installing VC++ Redistributable ($($installer.Name))..."
    $p = Start-Process -FilePath $installer.Path -ArgumentList '/install', '/quiet', '/norestart' -Wait -PassThru
    if ($p.ExitCode -eq 0 -or $p.ExitCode -eq 1638) {
        Write-Host "[+] $($installer.Name) install exit code $($p.ExitCode) -- OK"
    } else {
        Write-Host "[!] $($installer.Name) install exit code $($p.ExitCode) -- unexpected, check manually"
    }
    Remove-Item -Path $installer.Path -Force -ErrorAction SilentlyContinue
}

# Verify the actual files landed, not just that the installer claimed
# success -- this is the check that would have caught the original gap.
$checkFiles = @(
    'C:\Windows\System32\vcruntime140.dll',
    'C:\Windows\System32\vcruntime140_1.dll',
    'C:\Windows\System32\msvcp140.dll',
    'C:\Windows\SysWOW64\vcruntime140.dll',
    'C:\Windows\SysWOW64\msvcp140.dll'
)
$missing = $checkFiles | Where-Object { -not (Test-Path $_) }
if ($missing) {
    Write-Host "[!] Missing after install: $($missing -join ', ')"
    exit 1
}
Write-Host '[+] VC++ Redistributable runtime files verified present (x64 + x86).'
