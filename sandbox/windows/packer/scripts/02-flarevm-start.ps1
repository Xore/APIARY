#Requires -RunAsAdministrator
# 02-flarevm-start.ps1 — Packer provisioner, step 2 of 4.
#
# Triggers the FLARE-VM install and returns immediately. It does NOT wait:
# waiting is step 3's job, and doing both here is what broke the build.
#
# FLARE-VM installs through Boxstarter, which reboots the guest repeatedly and
# resumes via auto-login. Packer runs this as an elevated scheduled task, so
# the first reboot terminates the task with 0x41306 — SCHED_S_TASK_TERMINATED,
# which Packer reports as "exit status: 267014". That is expected here and is
# listed in valid_exit_codes for this provisioner. Treating it as a failure is
# what ended the 14:27 build after 30 minutes, with FLARE-VM's debloat.vm
# package already installed and the machine on its way down.

Set-ExecutionPolicy Unrestricted -Scope LocalMachine -Force
$ErrorActionPreference = 'Continue'

Write-Host '================================================================'
Write-Host ' Honeypot-Stack: starting FLARE-VM (2-4 h, reboots repeatedly)'
Write-Host '================================================================'

# ── Install FLARE-VM ─────────────────────────────────────────────────────
Write-Host '[Phase 8] Triggering FLARE-VM install...'
$installer = "$env:TEMP\flarevm_install.ps1"
(New-Object Net.WebClient).DownloadFile(
    'https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',
    $installer
)

# A marker step 3 can find. Written before the installer runs, so a guest that
# reboots seconds later still shows step 3 that the attempt was made — the
# absence of this file means the download or the trigger failed, which is a
# different problem from FLARE-VM being slow.
"started=$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" |
    Set-Content 'C:\flarevm-started.txt'

# -noWait: the installer hands off to Boxstarter and returns. -noGui/-noChecks
# keep it non-interactive. The password is the local analyst account's, which
# Boxstarter needs to re-establish auto-login across its reboots.
& $installer -password 'malware123!' -noWait -noGui -noChecks

Write-Host '[+] FLARE-VM triggered; Boxstarter now owns the reboot cycle'
