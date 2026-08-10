#Requires -RunAsAdministrator
# 11-detonation-orchestrator.ps1 — Packer provisioner, installs the in-guest
# detonation orchestrator (#490).
#
# #94 found that run_sample.py drives the entire detonation over a live,
# credentialed WinRM channel to the running guest -- every step (sample copy,
# ProcMon/FakeNet start, execute, registry snapshots, artifact collection) is
# a winrm_run() PowerShell call against the guest while the untrusted sample
# is running in it, authenticated with a fixed password baked into every
# golden image. A sample that reaches SYSTEM has a listening service, working
# credentials, and a share, for the entire observation window. #490 is the
# full rearchitect: move the whole sequence into the guest itself, so there
# is no live host-to-guest channel at all while a sample runs.
#
# This script installs C:\Analysis\orchestrator.ps1 (the in-guest port of
# run_sample.py's detonate() sequence) and a scheduled task that runs it at
# logon. The host's side of this (sandbox/windows/orchestrate/run_sample.py's
# detonate_inguest()) stages a job before ever starting the domain:
#   1. Build a fresh CoW clone from the golden image (domain NOT started yet).
#   2. virt-copy-in the sample + a job.json describing it into that clone's
#      C:\Analysis\ directory -- offline, via libguestfs, while nothing has
#      the disk open. No SMB share, no live connection of any kind.
#   3. Start the domain. AtLogOn fires this script; it finds job.json, runs
#      the full sequence locally, and Stop-Computer's itself when done.
#   4. The host has no channel to ask "are you done" -- it just polls
#      `virsh domstate` (not a guest-authenticated call, libvirt itself) and
#      treats a clean self-shutdown within a generous deadline as success. If
#      the deadline passes with the domain still running, the host force-kills
#      it (virsh destroy) and flags the result as a watchdog timeout rather
#      than silently producing nothing.
#   5. Either way, once the domain is off, virt-copy-out C:\Analysis\Logs\*
#      back to the host -- offline again, same as step 2.
#
# On any OTHER boot (no job.json -- Packer's own build, a plain
# kvm_manage.sh revert with nothing staged, a manual debug boot), this script
# finds nothing to do and exits immediately. It never touches WinRM at all;
# that stays available for build/debug tooling (verify_vm_detection.py,
# ad hoc golden-image edits) exactly as before -- #490 removes the live
# channel from the detonation path specifically, not WinRM from the image.
#
# Known trade-off, deliberately accepted: the graceful early-stop feature
# added this session (observe_with_early_stop(), a host-side sentinel file
# polled during a host-side sleep) has no equivalent here -- the observation
# wait now happens inside the guest, and there is by design no live channel
# left to signal "wrap up early" through. A host that wants to cut a run
# short now has only the blunt instrument the watchdog already provides:
# force the domain off early and salvage whatever C:\Analysis\Logs already
# has via virt-copy-out, same as a genuine timeout. Documented here rather
# than silently dropped.

$ErrorActionPreference = 'Continue'
Write-Host '================================================================'
Write-Host ' Honeypot-Stack: Windows 11 Analysis VM - detonation orchestrator'
Write-Host '================================================================'

# #956: 'Samples' -> 'Inbox' below -- pafish's gensandbox_path() (real
# source) flags any running module's path containing "\SAMPLE" as a
# sandbox tell, and this is where run_sample.py's stage_job_offline()
# virt-copy-in's the sample the job actually detonates.
$analysisDir = 'C:\Analysis'
New-Item -ItemType Directory -Force -Path $analysisDir | Out-Null
New-Item -ItemType Directory -Force -Path "$analysisDir\Logs" | Out-Null
New-Item -ItemType Directory -Force -Path "$analysisDir\Inbox" | Out-Null

# ---------------- The in-guest orchestrator itself --------------------
# Ported from run_sample.py's detonate() sequence. Kept as one flat script
# (not a module) so a single virt-copy-in of this one file plus job.json is
# everything the host ever needs to stage -- no dependency install step in
# the hot path.
$orchestrator = @'
$ErrorActionPreference = "Stop"
$analysisDir = "C:\Analysis"
$jobPath = "$analysisDir\job.json"
$logPath = "$analysisDir\Logs\orchestrator.log"

# No job staged -- an ordinary boot (Packer build, a bare revert, a manual
# debug boot). Nothing to do; exit immediately rather than idle-looping.
if (-not (Test-Path $jobPath)) { exit 0 }

function Step($msg) {
    $line = "$(Get-Date -Format o) $msg"
    Add-Content -Path $logPath -Value $line
    Write-Host $line
}

# Runs best-effort: mirrors run_sample.py's own philosophy throughout --
# a missing/failed *optional* artifact (ProcMon export, autoruns diff) must
# not cost the whole run. Only sample execution and the observation wait
# itself are load-bearing; everything else is wrapped so one failure can't
# take down steps after it.
function TryStep($name, [scriptblock]$body) {
    try {
        & $body
        Step "$name : OK"
    } catch {
        Step "$name : FAILED -- $($_.Exception.Message)"
    }
}

Step "START"
$job = Get-Content $jobPath -Raw | ConvertFrom-Json
$samplePath = "$analysisDir\Inbox\$($job.sample_filename)"
$obsSecs = [int]$job.observation_secs

# ---------------- Telemetry start (best-effort) ----------------
TryStep "fakenet_start" {
    Start-Process powershell `
        -ArgumentList "-Command C:\Tools\FakeNet\fakenet.exe -c C:\Tools\FakeNet\configs\honeypot_fakenet.ini -l $analysisDir\Logs\fakenet_log.txt" `
        -WindowStyle Hidden
    Start-Sleep -Seconds 5
}
TryStep "procmon_start" {
    Start-Process C:\Tools\SysinternalsSuite\Procmon64.exe `
        -ArgumentList "/AcceptEula /Quiet /BackingFile $analysisDir\Logs\procmon.pml" `
        -WindowStyle Hidden
    Start-Sleep -Seconds 3
}

# ---------------- Autoruns "before" snapshot ----------------
# No registry "before" export here -- #480: every run starts from an
# identical fresh clone of the same golden image, so the "before" registry
# state never actually varies run to run. The host caches ONE golden-image
# baseline (run_sample.py's regenerate_registry_baseline(), regenerated
# only when the golden image itself changes) and diffs it against this
# run's single "after" export host-side, instead of every single run
# re-capturing an ~8.5-minute, ~230MB "before" state that would just
# re-derive the same golden-image baseline over and over. Autoruns' own
# before/after CSVs stay per-run (cheap, and boot-time scheduled-task
# churn is worth capturing per-run rather than assumed identical).
$autorunsc = @('C:\Tools\SysinternalsSuite\autorunsc64.exe', 'C:\Tools\SysinternalsSuite\autorunsc.exe') |
    Where-Object { Test-Path $_ } | Select-Object -First 1
TryStep "autoruns_before" {
    & $autorunsc -a * -c -accepteula > "$analysisDir\Logs\autoruns_before.csv"
    Get-Service | ConvertTo-Csv -NoTypeInformation | Out-File "$analysisDir\Logs\services_before.csv"
}

# ---------------- Execute the sample (load-bearing) ----------------
Step "sample_launch $samplePath"
$proc = Start-Process -FilePath $samplePath -PassThru -WindowStyle Normal
Step "sample_launched pid=$($proc.Id)"

# ---------------- Observation window (load-bearing) ----------------
# No early-stop channel here by design -- see 11-detonation-orchestrator.ps1's
# header comment. A host that wants this run cut short forces the domain off
# and salvages whatever is in Logs\ already, same as a watchdog timeout.
Step "observing for ${obsSecs}s"
Start-Sleep -Seconds $obsSecs
Step "observation_done"

# ---------------- "After" registry snapshot ----------------
# reg.exe, not Regshot -- #444 found Regshot is GUI-only and never exits
# headless, in any session. The diff against the #480 golden-image
# baseline happens host-side (run_sample.py's
# diff_registry_against_baseline(), after virt-copy-out) -- no fc.exe
# call here, no in-guest "before" export to diff against.
TryStep "regshot_after" {
    cmd.exe /c "reg.exe export HKLM\SOFTWARE $analysisDir\Logs\reg_hklm_after.reg /y"
    cmd.exe /c "reg.exe export HKCU\Software $analysisDir\Logs\reg_hkcu_after.reg /y"
}
TryStep "autoruns_after" {
    & $autorunsc -a * -c -accepteula > "$analysisDir\Logs\autoruns_after.csv"
    Get-Service | ConvertTo-Csv -NoTypeInformation | Out-File "$analysisDir\Logs\services_after.csv"
    Compare-Object -ReferenceObject (Get-Content "$analysisDir\Logs\autoruns_before.csv") `
        -DifferenceObject (Get-Content "$analysisDir\Logs\autoruns_after.csv") `
        | Out-File "$analysisDir\Logs\autoruns_diff.txt"
    Compare-Object -ReferenceObject (Get-Content "$analysisDir\Logs\services_before.csv") `
        -DifferenceObject (Get-Content "$analysisDir\Logs\services_after.csv") `
        | Out-File "$analysisDir\Logs\services_diff.txt"
}

# ---------------- Stop telemetry + export (best-effort) ----------------
TryStep "procmon_stop_and_export" {
    # /Terminate, not Stop-Process -Force: confirmed live (#502) that a raw
    # process kill never gives Procmon's own shutdown code a chance to
    # signal its kernel-mode minifilter (PROCMON24) to detach -- it stays
    # attached and refuses manual unload (fltmc unload PROCMON24 ->
    # 0x801f0010 / ERROR_FLT_DO_NOT_DETACH) until the guest reboots.
    # /Terminate is Procmon's own documented clean-shutdown flag; confirmed
    # live the filter unloads cleanly afterward instead.
    Start-Process C:\Tools\SysinternalsSuite\Procmon64.exe -ArgumentList "/Terminate" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
    # #502: this export hangs unpredictably for reasons never fully
    # root-caused, in every session type tried (Responding=True, no visible
    # window/dialog the whole time). Re-confirmed live after landing the
    # /Terminate fix above: this is a genuinely separate problem from the
    # filter-unload issue that fix addresses, not a symptom of it --
    # reproduced against a freshly /Terminate'd instance (filter cleanly
    # unloaded, confirmed absent from fltmc filters) with a brand-new,
    # ~20s capture, still hadn't produced a .csv after 300+s. Not fatal --
    # a missing procmon.csv is far better than losing the whole report --
    # far better than losing the whole report -- but TryStep's try/catch
    # alone does NOT bound this: Start-Process -Wait never throws on its
    # own, it just blocks forever, unlike run_sample.py's WinRM-path
    # equivalent (stop_procmon(), which already bounds the same export at
    # 300s via run_and_wait_via_cim's poll_timeout). Without an explicit
    # bound here, every later step in this script (Sysmon/PowerShell EVTX
    # export, PS transcript copy, fakenet stop) silently never ran whenever
    # this hung, and the only thing that eventually noticed was the host's
    # 45-minute watchdog force-killing the whole domain.
    $exportProc = Start-Process C:\Tools\SysinternalsSuite\Procmon64.exe `
        -ArgumentList "/OpenLog $analysisDir\Logs\procmon.pml /SaveAs $analysisDir\Logs\procmon.csv /Quiet" `
        -WindowStyle Hidden -PassThru
    if (-not $exportProc.WaitForExit(90000)) {
        Step "procmon_stop_and_export : export still running after 90s, force-killing so later steps still run"
        Stop-Process -Id $exportProc.Id -Force -ErrorAction SilentlyContinue
    }
}
TryStep "sysmon_evtx_export" {
    wevtutil epl Microsoft-Windows-Sysmon/Operational "$analysisDir\Logs\sysmon.evtx"
}
TryStep "powershell_evtx_export" {
    wevtutil epl Microsoft-Windows-PowerShell/Operational "$analysisDir\Logs\powershell_scriptblock.evtx"
}
TryStep "pstranscripts_copy" {
    # 04-tools.ps1 configures PowerShell transcription's OutputDirectory as
    # C:\PSTranscripts, not C:\Logs\PSTranscripts -- confirmed by reading
    # that script rather than assumed.
    if (Test-Path "C:\PSTranscripts") {
        Copy-Item "C:\PSTranscripts" "$analysisDir\Logs\PSTranscripts" -Recurse -Force
    }
}
TryStep "fakenet_stop" {
    Stop-Process -Name fakenet -Force -ErrorAction SilentlyContinue
    # config/fakenet.ini's DumpDir is hardcoded to C:\Logs\fakenet_downloads
    # (not overridable by the -l flag passed at launch, which only
    # redirects fakenet's own primary log) -- confirmed by reading that
    # ini rather than assumed, same as the transcription path above.
    if (Test-Path "C:\Logs\fakenet_downloads") {
        Copy-Item "C:\Logs\fakenet_downloads" "$analysisDir\Logs\fakenet_downloads" -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Step "DONE"
# Clean self-shutdown is the host's ONLY completion signal (see this file's
# header) -- everything above must have already flushed to disk before this
# fires. A hard `virsh destroy` watchdog kill instead of this line reaching
# the disk is exactly the "hung/killed, not completed" case the host side
# distinguishes on.
Stop-Computer -Force
'@

$orchestrator | Set-Content "$analysisDir\orchestrator.ps1" -Encoding UTF8
Write-Host '[+] In-guest orchestrator installed'

# ---------------- Scheduled task: AtLogOn, same fix pattern as #368's ------
# PersonaDaemon fix (07-living-persona.ps1) -- explicit Interactive Principal
# plus a startup Delay, since AtLogOn fires before the desktop is reliably
# ready for a Start-Process'd GUI-capable sample to land on it.
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$analysisDir\orchestrator.ps1`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User 'analyst'
$trigger.Delay = 'PT20S'
$principal = New-ScheduledTaskPrincipal -UserId 'analyst' -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'Detonation Orchestrator' `
  -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

'detonation_orchestrator=installed' | Add-Content 'C:\golden_image_provenance.txt'
Write-Host '[+] Detonation orchestrator scheduled task registered'
exit 0
