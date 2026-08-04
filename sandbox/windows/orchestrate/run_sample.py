#!/usr/bin/env python3
"""
run_sample.py — Windows 11 sandbox detonation orchestrator

#490: default mode is in-guest orchestration, no live channel to the guest
while a sample is actually running:
1. Build a fresh CoW clone from the golden image (domain NOT started)
2. virt-copy-in the sample + a job.json into that clone's C:\\Analysis --
   offline, via libguestfs, while nothing has the disk open
3. Start the domain. Its own AtLogOn-triggered scheduled task (installed by
   packer/scripts/11-detonation-orchestrator.ps1) finds job.json and runs
   the entire sequence locally: telemetry start, registry/autoruns
   snapshots, execute sample, observe, snapshot again, telemetry stop,
   EVTX export -- then Stop-Computer's itself.
4. The host has no channel to ask "are you done" -- it polls `virsh
   domstate` (libvirt itself, not a guest-authenticated call) and treats a
   clean self-shutdown within a generous deadline as success. Past the
   deadline with the domain still running, it force-kills it (virsh
   destroy) and flags the result as a watchdog timeout instead of silently
   producing nothing.
5. Either way, once the domain is off: virt-copy-out C:\\Analysis\\Logs back
   to the host -- offline again.
6. Revert (throw away the used clone), same as always.

A sample that achieves SYSTEM during its run finds no listening service, no
credentials, and no share to reach the host with -- there is nothing live to
attack. See #94 (found the original live-WinRM-channel exposure) and #490
(this rearchitect).

Legacy WinRM-driven mode (copy sample over SMB, drive every step over a live
authenticated WinRM channel while the sample runs, pull results back over
SMB) is preserved behind WINDOWS_SANDBOX_LEGACY_WINRM=1 for one release as a
rollback path, not because it's still the intended way to run this. It has
the exposure #490 exists to remove -- use it only to compare a suspicious
result against, or if the in-guest path is broken and needs bypassing.

Artifacts are written to the local results directory only. This orchestrator
performs no outbound network access and never pushes anywhere: the analysis
host has no route off the sandbox bridge, and the dashboard reads results from
the spool. See IMPLEMENTATION_PLAN.md "Host Constraints".

Requires:
  pip install pywinrm paramiko python-evtx   # legacy mode + verify_vm_detection.py only
  libguestfs-tools (virt-copy-in/out, guestfish) -- the default in-guest mode
  libvirt with the golden domain defined (see IMPLEMENTATION_PLAN.md Phase 2)

Env vars:
  WINDOWS_SANDBOX_LEGACY_WINRM  Set to 1 to use the old live-WinRM path
                     instead of the default in-guest orchestration (#490)
  VM_HOST            IP of Windows VM (legacy WinRM mode / debug tooling only)
  VM_USER            Windows username (legacy mode only)
  VM_PASS            Windows password (legacy mode only)
  LIBVIRT_URI        libvirt connection URI (default: qemu:///system)
  VM_DOMAIN          libvirt domain name (default: win11-sandbox)
  VIRSH_PATH         Path to the virsh binary (default: /usr/bin/virsh)
  GUESTFISH_PATH     Path to the guestfish binary (default: /usr/bin/guestfish)
  GOLDEN_IMAGE       Path to the golden qcow2 (default:
                     /var/dockge/sandbox/golden-images/win11-analysis.qcow2)
  VM_DISK            Path to the per-run CoW clone (default:
                     /var/dockge/sandbox/vms/$VM_DOMAIN.qcow2)
  OBSERVATION_SECS   Seconds to observe (default: 1800 -- #297, 15-60min
                     recommended per RESEARCH.md; a short window is
                     defeated by a sample doing nothing more than a long
                     sleep before its real payload)
  WATCHDOG_BUFFER_SECS  Extra seconds beyond OBSERVATION_SECS the host waits
                     for the guest's own self-shutdown before concluding the
                     run is hung and force-killing it (default: 2700 -- #490
                     live-tested: the guest's own unfiltered registry export
                     alone took ~8.5min each for the before/after snapshot,
                     ~17min total, before autoruns/telemetry-stop/EVTX-export
                     overhead on top of that; 45min gives real headroom
                     rather than sitting at the measured floor)
"""

import os
import re
import time
import json
import hashlib
import argparse
import logging
import subprocess
import shutil
import tempfile
from pathlib import Path
from datetime import datetime, timezone

try:
    import winrm
except ImportError:
    winrm = None  # WinRM not available — use subprocess fallback

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

VM_HOST         = os.environ.get('VM_HOST',          '10.10.10.2')
VM_USER         = os.environ.get('VM_USER',          'analyst')
# Must match winrm_pass's actual default in packer/win11-analysis.pkr.hcl —
# this drifted out of sync with it (was 'malware') until #358's cleanup.
VM_PASS         = os.environ.get('VM_PASS',          'malware123!')
VIRSH_PATH      = os.environ.get('VIRSH_PATH',       '/usr/bin/virsh')
GUESTFISH_PATH  = os.environ.get('GUESTFISH_PATH',   '/usr/bin/guestfish')
VIRT_COPY_IN_PATH  = os.environ.get('VIRT_COPY_IN_PATH',  '/usr/bin/virt-copy-in')
VIRT_COPY_OUT_PATH = os.environ.get('VIRT_COPY_OUT_PATH', '/usr/bin/virt-copy-out')
LIBVIRT_URI     = os.environ.get('LIBVIRT_URI',      'qemu:///system')
VM_DOMAIN       = os.environ.get('VM_DOMAIN',        'win11-sandbox')
GOLDEN_IMAGE    = Path(os.environ.get('GOLDEN_IMAGE',
                        '/var/dockge/sandbox/golden-images/win11-analysis.qcow2'))
VM_DISK         = Path(os.environ.get('VM_DISK',
                        f'/var/dockge/sandbox/vms/{VM_DOMAIN}.qcow2'))
OBS_SECS        = int(os.environ.get('OBSERVATION_SECS', '1800'))  # #297
WATCHDOG_BUFFER_SECS = int(os.environ.get('WATCHDOG_BUFFER_SECS', '2700'))  # #490
LEGACY_WINRM_MODE = os.environ.get('WINDOWS_SANDBOX_LEGACY_WINRM', '') == '1'
# Touch this file during a run's observation window to cut it short without
# failing the job -- see observe_with_early_stop(). Fixed path rather than
# per-job: only one detonation runs at a time (single VM, single worker), so
# there is never more than one observation window active to target.
STOP_EARLY_SENTINEL = Path(os.environ.get('STOP_EARLY_SENTINEL',
                        '/var/lib/honeypot-windows-sandbox/stop-early'))
ARTIFACT_DIR    = Path(os.environ.get('WINDOWS_SANDBOX_RESULTS_DIR', 'reports/windows-sandbox'))
SAMPLE_SHARE    = f'\\\\{VM_HOST}\\Samples'
LOGS_SHARE      = f'\\\\{VM_HOST}\\Logs'


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def virsh(cmd: list, timeout: int = 120) -> str:
    """Execute a virsh command against the configured libvirt URI."""
    result = subprocess.run(
        [VIRSH_PATH, '--connect', LIBVIRT_URI] + cmd,
        capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f'virsh {" ".join(cmd)} failed: {result.stderr.strip()}')
    return result.stdout.strip()


def verify_golden_checksum():
    """Verify GOLDEN_IMAGE against its .sha256 before trusting it for a clone.

    #86: the golden image is the root of trust for every detonation guest --
    an unverified multi-GB file sitting on a shared spindle for months
    between rebuilds is exactly the thing worth hashing. build-with-retry.sh
    writes GOLDEN_IMAGE.sha256 once, right after a successful build.

    A full sha256 of a 25-35 GB file takes real time, and revert_to_golden()
    runs before every single detonation -- possibly several times an hour in
    a busy queue. Re-hashing an unchanged file that often is wasted work, so
    the result is cached against the image's mtime+size in a sentinel file;
    corruption between two reverts with no intervening rebuild is only
    caught on the next real re-verification, the accepted tradeoff for not
    paying the full hash cost on every revert. Same caching scheme as
    kvm_manage.sh's verify_golden_checksum() (shell, for manual/setup use);
    this is the one that actually guards the live detonation path.
    """
    sums = GOLDEN_IMAGE.with_suffix(GOLDEN_IMAGE.suffix + '.sha256')
    if not sums.exists():
        log.warning(f'No {sums} found -- skipping integrity check (run build-with-retry.sh to generate one)')
        return
    stat = GOLDEN_IMAGE.stat()
    current = f'{int(stat.st_mtime)}-{stat.st_size}'
    stamp = sums.with_suffix(sums.suffix + '.verified')
    if stamp.exists() and stamp.read_text().strip() == current:
        return
    log.info('Verifying golden image checksum (first use since last rebuild)...')
    expected = sums.read_text().split()[0].strip().lower()
    h = hashlib.sha256()
    with GOLDEN_IMAGE.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    actual = h.hexdigest()
    if actual != expected:
        raise RuntimeError(
            f'Golden image checksum mismatch: {GOLDEN_IMAGE} does not match {sums} '
            f'(expected {expected}, got {actual}). Refusing to clone -- every '
            f'detonation guest would inherit a corrupted or tampered image.'
        )
    stamp.write_text(current)
    log.info('Golden image checksum verified.')


def revert_to_golden(start: bool = True):
    """Reset the domain to a fresh clone of the golden image, and boot it
    unless `start` is False.

    virsh snapshot-revert (memory-state or disk-only) is not usable here: the
    domain's host-passthrough migratable='off' CPU config (deliberate, for
    anti-VM-detection fidelity -- see win11-kvm.xml) blocks memory-state
    snapshots outright, and disk-only snapshots hit a separate, reproducible
    QEMU/libvirt bug where a freshly spawned process fails to open the base
    golden image on the resulting multi-layer backing chain, even though file
    permissions are provably fine (see #358's investigation).

    The golden image is already never written to (nothing here ever opens it
    read-write), so "revert to golden" just means: throw away the per-run CoW
    clone and make a fresh one, then boot that. This is a cold boot every run
    rather than a memory-state resume -- slower, but with no snapshot-machinery
    failure mode. Every detonation still starts from the identical golden
    state, which is what makes runs comparable and the guest disposable.

    start=False is for detonate_inguest() (#490): the whole point of staging
    the sample via virt-copy-in is that it happens BEFORE the domain (and
    therefore qemu) ever opens the disk -- libguestfs and a running qemu
    process cannot both hold the same qcow2 open (confirmed live earlier
    this session installing LOLDrivers into the golden image: a libguestfs
    appliance crash resulted from exactly this). The caller is responsible
    for calling virsh(['start', VM_DOMAIN]) itself once staging is done.
    """
    log.info(f'Resetting {VM_DOMAIN} to a fresh clone of {GOLDEN_IMAGE}')
    verify_golden_checksum()
    subprocess.run([VIRSH_PATH, '--connect', LIBVIRT_URI, 'destroy', VM_DOMAIN],
                    capture_output=True, text=True)  # ignore: may already be stopped
    if VM_DISK.exists():
        VM_DISK.unlink()
    subprocess.run(
        ['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(GOLDEN_IMAGE), str(VM_DISK)],
        check=True, capture_output=True, text=True,
    )
    if start:
        virsh(['start', VM_DOMAIN])
        log.info('Domain reset and running')
    else:
        log.info('Fresh clone created; domain left stopped for offline staging')


def ntfsfix_disk(disk_path: Path):
    """Clear NTFS's "dirty" bit on `disk_path` so libguestfs can write to it.

    #490, found live: a domain that was ever hard-killed (`virsh destroy`,
    exactly what the watchdog path below does on a timeout) leaves its NTFS
    volume flagged dirty -- Windows' own crash-consistency marker, same as
    what a real power-cut leaves behind. libguestfs's ntfs-3g refuses to
    mount a dirty volume read-write and virt-copy-in fails outright with
    "Read-only file system", even though the disk is provably writable at
    the block-device level. A CLEAN Stop-Computer shutdown does not set this
    bit -- confirmed live the same way: virt-copy-in only ever failed after
    a forced kill. ntfsfix (libguestfs's, not a real Windows chkdsk) clears
    the marker without repairing anything else, and is safe to run
    unconditionally before every stage-for-next-run virt-copy-in regardless
    of how the previous run ended, since it's a no-op on an already-clean
    volume. Read-only operations (virt-cat, virt-ls, virt-copy-out) never
    need this -- only writes do.
    """
    subprocess.run(
        [GUESTFISH_PATH, '-a', str(disk_path), 'run', ':', 'ntfsfix', '/dev/sda3'],
        capture_output=True, text=True, timeout=120,
    )  # best-effort: a clean-shutdown disk has nothing to fix, ntfsfix errors are not fatal here


def winrm_run(ps_command: str, timeout: int = 60) -> dict:
    """Execute PowerShell command on the Windows VM via WinRM, bounded by
    `timeout` wall-clock seconds.

    #438: the `timeout` parameter used to be accepted and never used --
    session.run_ps() was called directly, completely unbounded. Confirmed
    live: two separate real detonation attempts against this exact image
    both failed at *exactly* their wait_for_winrm() deadline (120s, then
    300s after that was raised) with no "WinRM ready" log in between,
    while a plain external winrm.Session probe run by hand *during* that
    same 300s window succeeded immediately. That is the signature of one
    stuck session.run_ps() call eating the entire budget on its first
    attempt, not a real shortage of wait time -- WinRM was actually
    reachable well before the deadline, but wait_for_winrm()'s retry loop
    never got a second attempt to notice.
    session.run_ps() alone cannot be bounded by read_timeout_sec/
    operation_timeout_sec -- those only bound a single poll round-trip of
    WinRM's own long-poll Receive operation, not the overall call -- so
    the only way to actually bound it is to run it in a thread and give up
    waiting on that thread. Same pattern as verify_vm_detection.py's own
    winrm_run(), which already documents and solves this exact problem;
    ported here rather than re-derived.
    """
    if winrm is None:
        raise RuntimeError('pywinrm not installed. Run: pip install pywinrm')
    session = winrm.Session(
        VM_HOST,
        auth=(VM_USER, VM_PASS),
        transport='ntlm',
        server_cert_validation='ignore',
        read_timeout_sec=30, operation_timeout_sec=20,
    )
    import concurrent.futures
    # Deliberately not `with ThreadPoolExecutor(...) as pool:` -- that
    # form's __exit__ calls shutdown(wait=True), which blocks synchronously
    # until the abandoned thread finishes before the TimeoutError below can
    # even propagate, silently defeating the timeout this function exists
    # to provide (verify_vm_detection.py confirmed this live). No
    # shutdown() call at all is deliberate: the pool and its one thread are
    # simply dropped on timeout, since there is no way to forcibly kill a
    # thread blocked inside pywinrm's HTTP call anyway.
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = pool.submit(session.run_ps, ps_command)
    try:
        result = future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        raise TimeoutError(
            f'WinRM command did not return within {timeout}s -- likely hung '
            f'on the guest or mid-connect. The underlying thread is '
            f'abandoned, not killed.'
        )
    return {
        'stdout': result.std_out.decode('utf-8', errors='replace'),
        'stderr': result.std_err.decode('utf-8', errors='replace'),
        'status_code': result.status_code
    }


def wait_for_winrm(max_wait: int = 300):
    """Wait until WinRM is responsive.

    max_wait was 120 (#438): confirmed live against this exact image on
    this host, that is not enough. A real detonation attempt (the first
    one run through the newly-implemented hash-resolution handoff, #47)
    hit the 120s deadline and raised TimeoutError with no sign WinRM was
    ever close to answering -- not a near-miss, a real shortfall. This
    domain boots secure boot + TPM (swtpm) + a full AutoLogon ->
    FirstLogonCommands -> WinRM-enable chain on 16GB RAM, and
    kvm_manage.sh's own revert command already documents "~1-2min
    (cold boot)" for this -- 120s sits at the bottom edge of that range
    with no margin, not comfortably inside it, and this run landed on the
    wrong side of it. 300s gives real headroom above the documented
    range instead of another unexamined guess at the boundary.
    """
    deadline = time.time() + max_wait
    attempt = 0
    last_error = None
    while time.time() < deadline:
        attempt += 1
        try:
            result = winrm_run('Write-Output ready', timeout=10)
            if 'ready' in result['stdout']:
                log.info('WinRM ready (attempt %d)', attempt)
                return
            log.warning('WinRM attempt %d: connected but unexpected output: %r', attempt, result['stdout'])
        except Exception as exc:
            # #438: this used to be `except Exception: pass` -- every
            # attempt's real failure reason was thrown away, so two
            # separate real detonation failures (both dying at *exactly*
            # their deadline, both with WinRM independently confirmed
            # reachable during the same window via a manual probe) gave no
            # way to tell whether attempts were hanging, erroring, or
            # something else. Logging the exception is what makes the next
            # failure diagnostic instead of another blind guess.
            last_error = f'{type(exc).__name__}: {exc}'
            log.warning('WinRM attempt %d failed: %s', attempt, last_error)
        time.sleep(5)
    raise TimeoutError(
        f'WinRM not responsive after boot ({attempt} attempts over {max_wait}s); '
        f'last error: {last_error}'
    )


def copy_sample_to_vm(sample_path: Path, sha: str):
    """Copy sample to C:\\Samples\\ via SMB."""
    dest_name = f'{sha[:16]}.exe'
    # Mount SMB share and copy
    subprocess.run(
        ['smbclient', SAMPLE_SHARE, '-U', f'{VM_USER}%{VM_PASS}',
         '-c', f'put {sample_path} {dest_name}'],
        capture_output=True, timeout=60
    )
    log.info(f'Sample copied to VM as {dest_name}')
    return f'C:\\Samples\\{dest_name}'


def start_procmon():
    """Start ProcMon on Windows VM."""
    winrm_run(
        'Start-Process C:\\Tools\\SysinternalsSuite\\Procmon64.exe '
        '-ArgumentList "/AcceptEula /Quiet /BackingFile C:\\Logs\\procmon.pml" '
        '-WindowStyle Hidden'
    )
    log.info('ProcMon started')
    time.sleep(3)


def start_fakenet():
    """Start FakeNet-NG on Windows VM."""
    winrm_run(
        'Start-Process powershell '
        '-ArgumentList "-Command C:\\Tools\\FakeNet\\fakenet.exe '
        '-c C:\\Tools\\FakeNet\\configs\\honeypot_fakenet.ini '
        '-l C:\\Logs\\fakenet_log.txt" '
        '-WindowStyle Hidden'
    )
    log.info('FakeNet-NG started')
    time.sleep(5)


def run_and_wait_via_cim(command_line: str, poll_timeout: int = 60):
    """Launch `command_line` via Win32_Process.Create and poll until it
    exits, instead of `Start-Process -Wait`.

    #444: regshot_before() using `Start-Process ... -Wait` never returns
    within winrm_run()'s 60s bound -- the same failure mode already
    root-caused for the GHOSTS client launch (sandbox/ghosts/orchestrate):
    `Start-Process -Wait` (with or without output redirection) does not
    reliably signal completion back through this WinRM path, for reasons
    never fully root-caused. `Win32_Process.Create` via `Invoke-CimMethod`
    is the reliable launch mechanism instead -- it returns immediately with
    a PID, so waiting for completion has to be done explicitly here by
    polling `Get-Process`, rather than relying on the launch call itself to
    block.
    """
    # command_line is embedded in a PowerShell double-quoted string below;
    # any unescaped " in it closes that string early and corrupts the whole
    # expression -- confirmed live: Win32_Process.Create silently returned
    # nothing for a command_line containing raw quotes. PowerShell escapes
    # an embedded " as "" inside a double-quoted string.
    escaped_command_line = command_line.replace('"', '""')
    result = winrm_run(
        f'$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create '
        f'-Arguments @{{CommandLine="{escaped_command_line}"}}; '
        f'"PID:$($r.ProcessId) RC:$($r.ReturnValue)"'
    )
    m = re.search(r'PID:(\d+) RC:(\d+)', result['stdout'])
    if not m or m.group(2) != '0':
        raise RuntimeError(f'Win32_Process.Create failed for {command_line!r}: {result["stdout"]!r}')
    pid = m.group(1)

    deadline = time.time() + poll_timeout
    while time.time() < deadline:
        check = winrm_run(
            f'if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{"RUNNING"}} else {{"EXITED"}}'
        )
        if 'EXITED' in check['stdout']:
            return
        time.sleep(2)
    raise TimeoutError(f'PID {pid} ({command_line!r}) still running after {poll_timeout}s')


# #444: Regshot-x64-Unicode.exe is a GUI-only tool -- its own upstream
# ReadMe documents nothing but a click-through workflow (1st shot button,
# run the sample, 2nd shot button, Compare button); the `/s1 /na` and
# `/s2 /o ...` flags the original code passed were never a real, documented
# automation interface. Confirmed live two ways: launched via
# run_and_wait_via_cim (Session 0) the process never exits; launched via a
# scheduled task with LogonType Interactive (Session 1, Responding=True,
# matching the GHOSTS Session-0-launch fix) it *still* never exits after
# taking shot 1 -- it's genuinely designed to stay open holding shot-1
# state, not to run headless. `Start-Process ... -Wait` was never going to
# return regardless of transport quirks.
#
# Replaced with native reg.exe export + fc.exe diff: both are compiled
# console tools that actually exit on their own, so run_and_wait_via_cim's
# poll-for-exit works correctly against them (unlike Regshot). Exports
# HKLM\SOFTWARE and HKCU\Software in full -- no subtree filtering -- per
# explicit direction that every changed/new value must be visible;
# performance is not a constraint here. Measured live against this golden
# image: ~295K keys / 1M+ lines / 120MB for HKLM\SOFTWARE alone, dominated
# (>99.9%) by the Microsoft/Classes/WOW6432Node subtrees -- captured
# anyway, not excluded; #480 tracks a golden-image-baseline-cache approach
# to avoid recomputing/restoring that redundant bulk on every single run,
# and #481 tracks a better dedup technique for the resulting near-duplicate
# artifact files in general.
def _reg_export(hive_path: str, out_file: str):
    # No quotes around hive_path/out_file: run_and_wait_via_cim already
    # wraps the whole command_line in its own double-quoted
    # CommandLine="..." PowerShell string, and neither argument here ever
    # contains a space -- adding inner quotes closes that outer string
    # early at the first one, corrupting the PowerShell expression
    # (confirmed live: Win32_Process.Create silently returned nothing).
    run_and_wait_via_cim(
        f'cmd.exe /c reg.exe export {hive_path} {out_file} /y',
        poll_timeout=300,
    )


def regshot_before():
    _reg_export('HKLM\\SOFTWARE', 'C:\\Logs\\reg_hklm_before.reg')
    _reg_export('HKCU\\Software', 'C:\\Logs\\reg_hkcu_before.reg')
    log.info('Registry snapshot: before state exported')


# #295: Regshot's registry diff shows keys/values that changed, but doesn't
# specifically enumerate what got registered to run at startup/logon (Run
# keys, scheduled tasks, services, WMI subscriptions, Winlogon helper DLLs
# — all in Autoruns' scope). Sysinternals Suite (04-tools.ps1) already
# installs autorunsc.exe for Sysmon/Procmon; this is the first thing that
# actually invokes it.
_AUTORUNSC_RESOLVE = (
    "$autorunsc = @('C:\\Tools\\SysinternalsSuite\\autorunsc64.exe', "
    "'C:\\Tools\\SysinternalsSuite\\autorunsc.exe') "
    "| Where-Object { Test-Path $_ } | Select-Object -First 1; "
)


def autoruns_before():
    winrm_run(
        _AUTORUNSC_RESOLVE +
        '& $autorunsc -a * -c -accepteula > C:\\Logs\\autoruns_before.csv; '
        "Get-Service | ConvertTo-Csv -NoTypeInformation "
        "| Out-File C:\\Logs\\services_before.csv",
        timeout=120,
    )
    log.info('Autoruns + service list: first snapshot taken')


def autoruns_after():
    winrm_run(
        _AUTORUNSC_RESOLVE +
        '& $autorunsc -a * -c -accepteula > C:\\Logs\\autoruns_after.csv; '
        "Get-Service | ConvertTo-Csv -NoTypeInformation "
        "| Out-File C:\\Logs\\services_after.csv; "
        "Compare-Object -ReferenceObject (Get-Content C:\\Logs\\autoruns_before.csv) "
        "-DifferenceObject (Get-Content C:\\Logs\\autoruns_after.csv) "
        "| Out-File C:\\Logs\\autoruns_diff.txt; "
        "Compare-Object -ReferenceObject (Get-Content C:\\Logs\\services_before.csv) "
        "-DifferenceObject (Get-Content C:\\Logs\\services_after.csv) "
        "| Out-File C:\\Logs\\services_diff.txt",
        timeout=120,
    )
    log.info('Autoruns + service list: second snapshot + diff saved')


def execute_sample(vm_path: str):
    """Execute the sample on the Windows VM."""
    log.info(f'Executing sample: {vm_path}')
    winrm_run(
        f'$proc = Start-Process -FilePath "{vm_path}" '
        '-PassThru -WindowStyle Normal; '
        f'Write-Output "PID: $($proc.Id)"'
    )


def regshot_after():
    _reg_export('HKLM\\SOFTWARE', 'C:\\Logs\\reg_hklm_after.reg')
    _reg_export('HKCU\\Software', 'C:\\Logs\\reg_hkcu_after.reg')
    # fc.exe /n: native, fast, line-numbered diff -- no PowerShell per-line
    # pipeline overhead across files this large. .reg files are UTF-16LE;
    # /u tells fc.exe to compare as Unicode text rather than binary.
    run_and_wait_via_cim(
        'cmd.exe /c "('
        'echo === HKLM\\SOFTWARE === & '
        'fc.exe /n /u C:\\Logs\\reg_hklm_before.reg C:\\Logs\\reg_hklm_after.reg & '
        'echo === HKCU\\Software === & '
        'fc.exe /n /u C:\\Logs\\reg_hkcu_before.reg C:\\Logs\\reg_hkcu_after.reg'
        ') > C:\\Logs\\regshot_diff.txt"',
        poll_timeout=300,
    )
    log.info('Registry snapshot: after state exported, diff saved')


def stop_procmon():
    winrm_run('Stop-Process -Name Procmon64 -Force -ErrorAction SilentlyContinue')
    # Export to CSV. Originally assumed a too-short timeout (a real 30min
    # capture didn't finish exporting within 60s) -- that theory is wrong.
    # Confirmed live: a *tiny* (~20s) capture's export still hadn't finished
    # after 300s, in both Session 0 (CIM launch) and Session 1 (scheduled
    # task, LogonType Interactive) -- ruling out both "just needs more time
    # for a big file" and the Session-0-vs-interactive pattern that explained
    # Regshot's and the GHOSTS client's hangs. The process stays
    # Responding=True with no visible window/dialog the whole time, so it
    # isn't stuck on an un-dismissable prompt either. Root cause not found;
    # tracked as a real bug rather than guessed at further live. Not fatal:
    # a missing procmon.csv is far better than losing the entire report,
    # same philosophy as Regshot's MISSING marker when that tool wasn't
    # installed -- this is the one non-essential step in the whole sequence
    # (Sysmon + registry snapshots + autoruns diff cover most of the same
    # ground) and must not cost every other artifact a fully successful run
    # already produced.
    try:
        run_and_wait_via_cim(
            'C:\\Tools\\SysinternalsSuite\\Procmon64.exe '
            '/OpenLog C:\\Logs\\procmon.pml /SaveAs C:\\Logs\\procmon.csv /Quiet',
            poll_timeout=300,
        )
        log.info('ProcMon stopped + exported to CSV')
    except Exception:
        log.error('ProcMon CSV export failed or timed out -- continuing without it', exc_info=True)


def collect_artifacts(sha: str, out_dir: Path):
    """Copy all artifacts from Windows VM to local analysis dir."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # Export Sysmon EVTX
    winrm_run(
        'wevtutil epl Microsoft-Windows-Sysmon/Operational '
        'C:\\Logs\\sysmon.evtx'
    )
    # Export PowerShell ScriptBlock EVTX
    winrm_run(
        'wevtutil epl Microsoft-Windows-PowerShell/Operational '
        'C:\\Logs\\powershell_scriptblock.evtx'
    )

    # Mount share and download everything
    files_to_get = [
        'procmon.csv',
        'sysmon.evtx',
        'powershell_scriptblock.evtx',
        'regshot_diff.txt',
        # #480 tracks storing these efficiently (golden-image baseline
        # cache + ES pipeline); for now they're pulled as plain artifact
        # files like everything else here, full and unfiltered per #444.
        'reg_hklm_before.reg',
        'reg_hklm_after.reg',
        'reg_hkcu_before.reg',
        'reg_hkcu_after.reg',
        'fakenet_log.txt',
        # #295: persistence diff -- what the sample registered to run at
        # startup/logon, not just what Regshot's registry diff happened to
        # show.
        'autoruns_before.csv',
        'autoruns_after.csv',
        'autoruns_diff.txt',
        'services_before.csv',
        'services_after.csv',
        'services_diff.txt',
    ]
    for fname in files_to_get:
        subprocess.run(
            ['smbclient', LOGS_SHARE, '-U', f'{VM_USER}%{VM_PASS}',
             '-c', f'get {fname} {out_dir}/{fname}'],
            capture_output=True, timeout=60
        )

    # Get PS transcripts dir
    subprocess.run(
        ['smbclient', f'\\\\{VM_HOST}\\Logs', '-U', f'{VM_USER}%{VM_PASS}',
         '-c', 'recurse; mget PSTranscripts\\*'],
        cwd=str(out_dir), capture_output=True, timeout=60
    )

    # Get FakeNet downloaded files
    subprocess.run(
        ['smbclient', LOGS_SHARE, '-U', f'{VM_USER}%{VM_PASS}',
         '-c', 'recurse; mget fakenet_downloads\\*'],
        cwd=str(out_dir), capture_output=True, timeout=60
    )

    log.info(f'Artifacts collected to {out_dir}')


def capture_memory_dump(out_dir: Path):
    """#296: a `virsh dump --memory-only`, taken from the host while the
    guest is still running -- right after the observation window, before
    the sample is torn down -- and analyzed afterward with Volatility 3
    (windows.pslist, malfind, netscan). Unlike every other artifact this
    orchestrator collects (Sysmon EVTX, Procmon CSV, Regshot/Autoruns
    diffs), all written to disk inside a guest the sample has full control
    of, this crosses the same trust boundary the snapshot-revert already
    uses: virsh on the host, never anything the guest itself controls. It
    survives a sample that detects the sandbox and self-terminates cleanly
    before writing any of the guest-side artifacts.

    Best-effort: a dump failure (e.g. libvirt built without live-dump
    support) must not fail the whole detonation over one optional artifact.
    """
    mem_path = out_dir / 'memory.dmp'
    log.info('Capturing guest memory (virsh dump --memory-only)...')
    try:
        virsh(['dump', VM_DOMAIN, str(mem_path), '--memory-only'], timeout=600)
        log.info(f'Memory dump written: {mem_path}')
    except Exception:
        log.error('Memory dump failed; continuing without it', exc_info=True)


def post_process(out_dir: Path):
    """Steps 12-14 of the run cycle: IOCs, the readable report, then the
    dashboard-facing result JSON.

    All three are derived products. The artifacts in out_dir are the
    evidence, and they are already on disk by the time this runs — so a
    parser that chokes on a malformed EVTX must not be allowed to fail the
    detonation and make the worker retry a sample that already ran. Each
    step is logged and stepped over; re-running any of them by hand against
    out_dir is safe and idempotent.
    """
    try:
        from extract_iocs import extract_all
        extract_all(out_dir)
    except Exception:
        log.error('IOC extraction failed; artifacts are unaffected', exc_info=True)

    try:
        from generate_report import build_report
        build_report(out_dir)
    except Exception:
        log.error('Report generation failed; artifacts are unaffected', exc_info=True)

    # #53: every artifact-collection step above can succeed while the
    # dashboard still shows nothing at all -- it only reads
    # {ARTIFACT_DIR}/windows-{job}.json (flat, not the per-sha256 out_dir
    # these steps write into), and nothing wrote one until this. Found live
    # when a fully successful run produced report.html and every raw
    # artifact but never appeared on /sandbox.
    try:
        from export_result import write_result
        written = write_result(out_dir, ARTIFACT_DIR)
        log.info(f'Dashboard result written: {written}')
    except Exception:
        log.error('Dashboard result JSON export failed; other artifacts are unaffected', exc_info=True)


def observe_with_early_stop(requested_secs: int) -> float:
    """Wait up to `requested_secs`, but return early -- gracefully, not by
    raising -- if STOP_EARLY_SENTINEL appears during the wait.

    A plain `time.sleep(OBS_SECS)` (the previous implementation) can only be
    cut short by killing the process, which skips straight to detonate()'s
    cleanup revert and marks the whole run failed: regshot_after(),
    autoruns_after(), stop_procmon(), collect_artifacts(), and
    post_process() never run, so there is no report, just a
    .request.failed. That is fine for a genuine failure, wrong for
    deliberately shortening a run's observation time (e.g. while tuning
    OBSERVATION_SECS, or reacting to a sample that's clearly done
    interesting things already) -- exactly the "adjust the dynamic
    runtime" case this exists for.

    Polls in short increments instead of one blocking call, checking for
    the sentinel each time; on finding it, logs the shortfall, removes the
    sentinel (so it doesn't also cut short the *next* run), and returns
    control to detonate() at the exact point a full-duration sleep would
    have -- the rest of the sequence proceeds completely normally.

    Returns the number of seconds actually waited, for the caller to record
    in metadata.json alongside the requested duration.
    """
    poll_interval = 2
    elapsed = 0
    while elapsed < requested_secs:
        if STOP_EARLY_SENTINEL.exists():
            log.info(
                f'Observation cut short by {STOP_EARLY_SENTINEL} after '
                f'{elapsed}s (requested {requested_secs}s) -- proceeding '
                f'to collection as normal, not failing the run.'
            )
            try:
                STOP_EARLY_SENTINEL.unlink()
            except FileNotFoundError:
                pass
            return elapsed
        step = min(poll_interval, requested_secs - elapsed)
        time.sleep(step)
        elapsed += step
    return elapsed


def stage_job_offline(sample_path: Path, sha: str, obs_secs: int, sample_filename: str):
    """virt-copy-in the sample plus a job.json describing it into VM_DISK,
    while the domain is stopped and nothing else has the disk open.

    #490: this offline staging step, not a live SMB `put`, is what removes
    sample injection from the set of things a live authenticated channel
    does during a run. C:\\Analysis\\Logs and C:\\Analysis\\Samples already
    exist in the golden image itself (created by
    packer/scripts/11-detonation-orchestrator.ps1), so every fresh CoW
    clone inherits them -- no mkdir step needed here.
    """
    job = {'sha256': sha, 'sample_filename': sample_filename, 'observation_secs': obs_secs}
    with tempfile.TemporaryDirectory() as tmp:
        job_path = Path(tmp) / 'job.json'
        job_path.write_text(json.dumps(job))
        staged_sample = Path(tmp) / sample_filename
        shutil.copyfile(sample_path, staged_sample)

        ntfsfix_disk(VM_DISK)
        subprocess.run(
            [VIRT_COPY_IN_PATH, '-a', str(VM_DISK), str(job_path), '/Analysis'],
            check=True, capture_output=True, text=True, timeout=120,
        )
        subprocess.run(
            [VIRT_COPY_IN_PATH, '-a', str(VM_DISK), str(staged_sample), '/Analysis/Samples'],
            check=True, capture_output=True, text=True, timeout=120,
        )
    log.info(f'Staged job.json + {sample_filename} into {VM_DISK} (offline)')


def wait_for_domain_shutoff(obs_secs: int, buffer_secs: int) -> bool:
    """Poll `virsh domstate` (libvirt itself -- not a call into the guest)
    until the domain shuts itself off, up to `obs_secs + buffer_secs`.

    This is the watchdog #490's own issue text flags as the open problem:
    with no live channel to ask the guest anything, a clean self-initiated
    Stop-Computer within the deadline is the ONLY signal "the run genuinely
    completed" -- anything else (still running past the deadline) gets
    force-killed and is flagged as a timeout rather than silently producing
    an empty-looking result. Along the way, at approximately the point the
    guest's own observation window should have elapsed, take a best-effort
    memory dump -- the same virsh-level capture capture_memory_dump()
    always did, still available with no live channel since it's virsh, not
    WinRM.

    Returns True if the domain shut itself down cleanly, False if it had to
    be force-killed.
    """
    deadline = time.time() + obs_secs + buffer_secs
    dumped = False
    dump_at = time.time() + obs_secs
    poll_interval = 5
    while time.time() < deadline:
        state = virsh(['domstate', VM_DOMAIN])
        if 'shut off' in state:
            log.info('Domain self-shutdown -- run completed')
            return True
        if not dumped and time.time() >= dump_at:
            dumped = True
            capture_memory_dump(_CURRENT_OUT_DIR[0])
        time.sleep(poll_interval)

    log.error(
        f'Domain still running {obs_secs + buffer_secs}s after boot -- '
        f'treating as hung and force-killing (watchdog timeout)'
    )
    subprocess.run([VIRSH_PATH, '--connect', LIBVIRT_URI, 'destroy', VM_DOMAIN],
                    capture_output=True, text=True)
    return False


def collect_artifacts_offline(out_dir: Path):
    """virt-copy-out C:\\Analysis\\Logs back to the host, offline, once the
    domain is off (cleanly or via the watchdog).

    Whole-directory copy rather than an explicit per-file allowlist (the
    legacy collect_artifacts()'s approach, one smbclient `get` per file):
    the in-guest orchestrator already writes everything worth having under
    Logs\\, including orchestrator.log itself -- valuable specifically on a
    watchdog-timeout result, where it shows exactly which step the guest
    was on when it got force-killed. An allowlist would silently drop that
    diagnostic file along with anything else not anticipated in advance.
    """
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [VIRT_COPY_OUT_PATH, '-a', str(VM_DISK), '/Analysis/Logs', tmp],
            check=True, capture_output=True, text=True, timeout=300,
        )
        copied = Path(tmp) / 'Logs'
        if copied.exists():
            for item in copied.iterdir():
                dest = out_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, dest, dirs_exist_ok=True)
                else:
                    shutil.copyfile(item, dest)
    log.info(f'Artifacts collected (offline) to {out_dir}')


# Set once per detonate_inguest() call so wait_for_domain_shutoff()'s
# best-effort mid-run memory dump can reach the current run's out_dir
# without threading it through every function on the call stack for a
# single optional step.
_CURRENT_OUT_DIR = [None]


def detonate_inguest(sample_path: Path, sha: str, out: Path):
    """#490's default detonation path: stage offline, boot, watch libvirt
    for self-shutdown, collect offline. No WinRM call anywhere in here."""
    _CURRENT_OUT_DIR[0] = out
    sample_filename = f'{sha[:16]}.exe'

    revert_to_golden(start=False)
    stage_job_offline(sample_path, sha, OBS_SECS, sample_filename)
    virsh(['start', VM_DOMAIN])
    log.info(f'Domain booted with job staged; observing for up to {OBS_SECS + WATCHDOG_BUFFER_SECS}s')

    completed = wait_for_domain_shutoff(OBS_SECS, WATCHDOG_BUFFER_SECS)
    meta = json.loads((out / 'metadata.json').read_text())
    meta['run_status'] = 'completed' if completed else 'watchdog_timeout'
    (out / 'metadata.json').write_text(json.dumps(meta, indent=2))

    # ntfsfix before reading is never required (read-only ntfs-3g mounts
    # don't care about the dirty bit -- confirmed live), so no fix-up call
    # here, only before the next run's staging writes.
    collect_artifacts_offline(out)
    post_process(out)

    if not completed:
        raise RuntimeError(
            f'Watchdog timeout: domain did not self-shutdown within '
            f'{OBS_SECS + WATCHDOG_BUFFER_SECS}s. Partial artifacts (if any) '
            f'were still collected from {out}.'
        )


def detonate_legacy_winrm(sample_path: Path, sha: str, out: Path):
    """Pre-#490 path: drive the whole sequence over a live WinRM channel to
    the running guest, sample injected/results pulled over SMB. Preserved
    behind WINDOWS_SANDBOX_LEGACY_WINRM=1 as a rollback path -- see this
    module's docstring."""
    revert_to_golden()
    wait_for_winrm()
    vm_path = copy_sample_to_vm(sample_path, sha)
    start_fakenet()
    start_procmon()
    regshot_before()
    autoruns_before()

    execute_sample(vm_path)
    log.info(f'Observing for {OBS_SECS} seconds...')
    actual_secs = observe_with_early_stop(OBS_SECS)
    if actual_secs != OBS_SECS:
        meta = json.loads((out / 'metadata.json').read_text())
        meta['observation_secs_actual'] = actual_secs
        meta['observation_cut_short'] = True
        (out / 'metadata.json').write_text(json.dumps(meta, indent=2))

    capture_memory_dump(out)
    regshot_after()
    autoruns_after()
    stop_procmon()
    collect_artifacts(sha, out)
    post_process(out)


def detonate(sample_path: Path, results_dir: Path = None):
    if not sample_path.exists() or sample_path.name == '.gitkeep':
        return
    sha   = sha256_of(sample_path)
    out   = (results_dir or ARTIFACT_DIR) / sha

    mode = 'legacy WinRM' if LEGACY_WINRM_MODE else 'in-guest (#490)'
    log.info(f'=== Detonating: {sample_path} ({sha[:16]}...) [{mode}] ===')

    # Write metadata
    out.mkdir(parents=True, exist_ok=True)
    (out / 'metadata.json').write_text(json.dumps({
        'sha256':      sha,
        'filename':    sample_path.name,
        'detonated_at': datetime.now(timezone.utc).isoformat(),
        'observation_secs': OBS_SECS,
    }, indent=2))

    failed = None
    try:
        if LEGACY_WINRM_MODE:
            detonate_legacy_winrm(sample_path, sha, out)
        else:
            detonate_inguest(sample_path, sha, out)

    except Exception as e:
        # Recorded, then re-raised once the guest is safely back at the golden
        # snapshot. Swallowing this would let the worker retire the spool entry
        # as though a report had been produced.
        log.error('Detonation failed', exc_info=True)
        failed = e
    finally:
        # Always revert, including after a failed detonation: the guest has run
        # untrusted code and must never survive into the next sample.
        log.info('Resetting VM to golden image (cleanup)...')
        try:
            revert_to_golden()
        except Exception as e:
            log.error(f'VM revert failed: {e}')

    if failed is not None:
        raise failed

    log.info(f'Run complete. Artifacts: {out}')


def main():
    parser = argparse.ArgumentParser(description='Windows Sandbox Orchestrator')
    parser.add_argument('--file-list',   help='File with list of sample paths')
    parser.add_argument('--sample',      help='Single sample path')
    parser.add_argument('--filter-type', help='Only process files in this subfolder (PE, ELF...)')
    parser.add_argument('--results-dir',
                        help='Where to write per-sample artifact directories '
                             '(default: $WINDOWS_SANDBOX_RESULTS_DIR)')
    args = parser.parse_args()
    results_dir = Path(args.results_dir) if args.results_dir else ARTIFACT_DIR

    paths = []
    if args.file_list:
        with open(args.file_list) as f:
            paths = [Path(l.strip()) for l in f if l.strip()]
    elif args.sample:
        paths = [Path(args.sample)]
    else:
        paths = [p for p in Path('samples').rglob('*')
                 if p.is_file() and p.name != '.gitkeep']

    if args.filter_type:
        paths = [p for p in paths if args.filter_type.upper() in p.parts]

    failures = 0
    for p in paths:
        try:
            detonate(p, results_dir)
        except Exception as e:
            log.error(f'Error: {p}: {e}', exc_info=True)
            failures += 1
        time.sleep(5)

    # The spool worker keys off this exit code: a non-zero status keeps the
    # request on disk for inspection rather than retiring it as complete.
    if failures:
        log.error(f'{failures} of {len(paths)} sample(s) failed to detonate')
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
