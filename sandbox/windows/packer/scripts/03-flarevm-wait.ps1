#Requires -RunAsAdministrator
# 03-flarevm-wait.ps1 — Packer provisioner, step 3 of 4. Run repeatedly.
#
# Waits for FLARE-VM to finish. This script is invoked several times in a row
# by win11-analysis.pkr.hcl, and it is written to be idempotent so that being
# killed mid-run costs nothing: each invocation either observes that FLARE-VM
# is done and returns immediately, or waits out its slice and returns.
#
# Why a loop of short waits instead of one long one: Boxstarter reboots the
# guest an unpredictable number of times, and each reboot terminates whichever
# elevated scheduled task Packer is running (exit 267014). One long wait would
# therefore only ever survive until the next reboot. A sequence of bounded
# waits turns each reboot into "this slice ended early" instead of "the build
# failed", and Packer re-establishes WinRM for the following provisioner.
#
# This script never fails the build. Deciding whether FLARE-VM actually
# finished is 04-tools.ps1's job, which runs once, at the end, when the answer
# is knowable.

$ErrorActionPreference = 'Continue'

# Chocolatey records installed packages as directories under lib\. FLARE-VM's
# own metapackage landing there is the completion signal the original script
# used, and it is still the right one.
$marker  = 'C:\ProgramData\chocolatey\lib\flarevm.installer'
$sliceSec = 1200   # 20 min per invocation

if (Test-Path $marker) {
    Write-Host '[+] FLARE-VM already complete'
    exit 0
}

if (-not (Test-Path 'C:\flarevm-started.txt')) {
    # Step 2 never got far enough to write its marker. Say so loudly here
    # rather than waiting 20 minutes for something that was never started.
    Write-Warning '[!] No C:\flarevm-started.txt - FLARE-VM was never triggered'
    exit 0
}

$elapsed = 0
while ($elapsed -lt $sliceSec) {
    Start-Sleep 60
    $elapsed += 60
    if (Test-Path $marker) {
        Write-Host "[+] FLARE-VM complete (this slice waited ${elapsed}s)"
        exit 0
    }
    # Chocolatey's lib dir is the only visible progress FLARE-VM offers
    # without parsing its logs; report the count so a build that is moving
    # can be told apart from one that is wedged.
    $pkgs = (Get-ChildItem 'C:\ProgramData\chocolatey\lib' -Directory `
                -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "[.] FLARE-VM still installing - ${elapsed}s this slice, $pkgs choco packages present"
}

Write-Host '[.] Slice ended, FLARE-VM still running - continuing in next step'
exit 0
