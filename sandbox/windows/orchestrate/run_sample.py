#!/usr/bin/env python3
"""
run_sample.py — Windows 11 sandbox detonation orchestrator

Drives the VM through libvirt and the guest through WinRM:
1. Resets the domain to a fresh clone of the golden image
2. Copies sample to VM
3. Starts telemetry (ProcMon, FakeNet-NG)
4. Executes sample
5. Waits observation window
6. Collects all artifacts
7. Resets VM (cleanup)

Artifacts are written to the local results directory only. This orchestrator
performs no outbound network access and never pushes anywhere: the analysis
host has no route off the sandbox bridge, and the dashboard reads results from
the spool. See IMPLEMENTATION_PLAN.md "Host Constraints".

Requires:
  pip install pywinrm paramiko python-evtx
  libvirt with the golden domain defined (see IMPLEMENTATION_PLAN.md Phase 2)

Env vars:
  VM_HOST            IP of Windows VM (for WinRM)
  VM_USER            Windows username
  VM_PASS            Windows password
  LIBVIRT_URI        libvirt connection URI (default: qemu:///system)
  VM_DOMAIN          libvirt domain name (default: win11-sandbox)
  VIRSH_PATH         Path to the virsh binary (default: /usr/bin/virsh)
  GOLDEN_IMAGE       Path to the golden qcow2 (default:
                     /var/dockge/sandbox/golden-images/win11-analysis.qcow2)
  VM_DISK            Path to the per-run CoW clone (default:
                     /var/dockge/sandbox/vms/$VM_DOMAIN.qcow2)
  OBSERVATION_SECS   Seconds to observe (default: 1800 -- #297, 15-60min
                     recommended per RESEARCH.md; a short window is
                     defeated by a sample doing nothing more than a long
                     sleep before its real payload)
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
LIBVIRT_URI     = os.environ.get('LIBVIRT_URI',      'qemu:///system')
VM_DOMAIN       = os.environ.get('VM_DOMAIN',        'win11-sandbox')
GOLDEN_IMAGE    = Path(os.environ.get('GOLDEN_IMAGE',
                        '/var/dockge/sandbox/golden-images/win11-analysis.qcow2'))
VM_DISK         = Path(os.environ.get('VM_DISK',
                        f'/var/dockge/sandbox/vms/{VM_DOMAIN}.qcow2'))
OBS_SECS        = int(os.environ.get('OBSERVATION_SECS', '1800'))  # #297
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


def revert_to_golden():
    """Reset the domain to a fresh clone of the golden image and boot it.

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
    virsh(['start', VM_DOMAIN])
    log.info('Domain reset and running; waiting for WinRM')


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
    # Export to CSV
    run_and_wait_via_cim(
        'C:\\Tools\\SysinternalsSuite\\Procmon64.exe '
        '/OpenLog C:\\Logs\\procmon.pml /SaveAs C:\\Logs\\procmon.csv /Quiet'
    )
    log.info('ProcMon stopped + exported to CSV')


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
    """Steps 12 and 13 of the run cycle: IOCs, then the readable report.

    Both are derived products. The artifacts in out_dir are the evidence, and
    they are already on disk by the time this runs — so a parser that chokes on
    a malformed EVTX must not be allowed to fail the detonation and make the
    worker retry a sample that already ran. Each step is logged and stepped
    over; re-running either by hand against out_dir is safe and idempotent.
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


def detonate(sample_path: Path, results_dir: Path = None):
    if not sample_path.exists() or sample_path.name == '.gitkeep':
        return
    sha   = sha256_of(sample_path)
    out   = (results_dir or ARTIFACT_DIR) / sha

    log.info(f'=== Detonating: {sample_path} ({sha[:16]}...) ===')

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
        revert_to_golden()
        wait_for_winrm()
        vm_path = copy_sample_to_vm(sample_path, sha)
        start_fakenet()
        start_procmon()
        regshot_before()
        autoruns_before()

        execute_sample(vm_path)
        log.info(f'Observing for {OBS_SECS} seconds...')
        time.sleep(OBS_SECS)

        capture_memory_dump(out)
        regshot_after()
        autoruns_after()
        stop_procmon()
        collect_artifacts(sha, out)
        post_process(out)

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
