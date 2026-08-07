#Requires -RunAsAdministrator
# 10-loldrivers.ps1 — Packer provisioner, step 8 of win11-analysis.pkr.hcl's build.
#
# BYOVD (Bring Your Own Vulnerable Driver) bait: a curated set of the most
# commonly abused signed-but-vulnerable kernel drivers, dropped onto disk
# for a detonated sample to find and load, plus disabling the Microsoft
# Vulnerable Driver Blocklist so a sample that tries actually succeeds
# instead of being silently blocked -- which would make this whole sandbox
# report "nothing happened" for a real BYOVD privesc/EDR-kill attempt
# instead of observing it.
#
# win11-analysis / its backup ONLY -- never win11-ghosts.qcow2. win11-ghosts
# has real WAN egress (#325/#331); a sample that actually exploits one of
# these for kernel-level code execution there is a genuine host compromise
# vector, not a contained, observed technique like it is here on the fully
# air-gapped analysis guest.
#
# #467's answer: win11-ghosts CAN get this set, but only behind an explicit,
# admin-gated, opt-in tool -- never unconditionally like this provisioner.
# That tool is sandbox/ghosts/provision-loldrivers.sh, which keeps its own
# copy of the driver list below rather than sharing this file (see that
# script's own comment on why). If the driver list here ever changes,
# update that copy too.
#
# Sourced from the LOLDrivers project (https://www.loldrivers.io /
# github.com/magicsword-io/LOLDrivers), pinned by hash and fetched from
# GitHub's LFS media endpoint (the repo's own domain resolves to a null
# route from at least one vantage point used while building this --
# possibly deliberately sinkholed as a known vulnerable-driver host, which
# is itself a reasonable thing for a security tool to do).
#
# Verified live on win11-analysis.qcow2 (2026-08-03): with the blocklist
# key set, RTCore64.sys, kprocesshacker.sys, and dbutil_2_3.sys all load
# and run via `sc create ... type= kernel && sc start`. WinRing0x64.sys
# fails with error 577 (signature verification -- a separate, unrelated
# certificate issue, not the blocklist). gdrv.sys fails with error 1275
# ("driver has been blocked from loading") -- it's a 32-bit driver
# (MachineType: I386 in its LOLDrivers entry), and x64 Windows cannot load
# 32-bit kernel drivers regardless of any policy, so this is expected and
# not a blocklist problem. 3 of 5 loading is well past what's needed for
# BYOVD realism; not chasing replacements for the other 2.

$ErrorActionPreference = 'Continue'
Write-Host '================================================================'
Write-Host ' Honeypot-Stack: Windows 11 Analysis VM - LOLDrivers BYOVD bait'
Write-Host '================================================================'

$drivers = @(
    @{ Name = 'RTCore64.sys';      Hash = '2d8e4f38b36c334d0a32a7324832501d' }
    @{ Name = 'WinRing0x64.sys';   Hash = '828bb9cb1dd449cd65a29b18ec46055f' }
    @{ Name = 'kprocesshacker.sys';Hash = 'bbbc9a6cc488cfb0f6c6934b193891eb' }
    @{ Name = 'gdrv.sys';          Hash = 'b0954711c133d284a171dd560c8f492a' }
    @{ Name = 'dbutil_2_3.sys';    Hash = 'c996d7971c49252c582171d9380360f2' }
)

foreach ($d in $drivers) {
    $url  = "https://media.githubusercontent.com/media/magicsword-io/LOLDrivers/main/drivers/$($d.Hash).bin"
    $dest = "C:\Windows\Temp\$($d.Name)"
    Write-Host "[+] Downloading $($d.Name)..."
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing

    $actual = (Get-FileHash -Path $dest -Algorithm MD5).Hash.ToLower()
    if ($actual -ne $d.Hash) {
        Write-Host "[!] $($d.Name) hash mismatch: expected $($d.Hash), got $actual -- removing"
        Remove-Item -Path $dest -Force -ErrorAction SilentlyContinue
        continue
    }
    Write-Host "[+] $($d.Name) verified ($actual)."
}

# Same offline-registry-write lesson as harden-defender-offline.sh (#91):
# but this key isn't reverted by anything at boot the way Tamper Protection
# reverts live Defender settings, so a plain live Set-ItemProperty here is
# sufficient -- proven at the exact same registry path via the offline
# virt-win-reg route already (see IMPLEMENTATION_PLAN.md), this is just the
# in-build equivalent so a fresh Packer run doesn't need a separate offline
# pass afterward.
$ciPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
New-Item -Path $ciPath -Force | Out-Null
Set-ItemProperty -Path $ciPath -Name VulnerableDriverBlocklistEnable -Value 0 -Type DWord
Write-Host '[+] Microsoft Vulnerable Driver Blocklist disabled.'

$present = Get-ChildItem -Path 'C:\Windows\Temp' -Filter '*.sys' -ErrorAction SilentlyContinue
Write-Host "[+] LOLDrivers present in C:\Windows\Temp: $($present.Count)"
