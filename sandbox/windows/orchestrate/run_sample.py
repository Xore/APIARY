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
    """Execute PowerShell command on the Windows VM via WinRM."""
    if winrm is None:
        raise RuntimeError('pywinrm not installed. Run: pip install pywinrm')
    session = winrm.Session(
        VM_HOST,
        auth=(VM_USER, VM_PASS),
        transport='ntlm',
        server_cert_validation='ignore'
    )
    result = session.run_ps(ps_command)
    return {
        'stdout': result.std_out.decode('utf-8', errors='replace'),
        'stderr': result.std_err.decode('utf-8', errors='replace'),
        'status_code': result.status_code
    }


def wait_for_winrm(max_wait: int = 120):
    """Wait until WinRM is responsive."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            result = winrm_run('Write-Output ready', timeout=10)
            if 'ready' in result['stdout']:
                log.info('WinRM ready')
                return
        except Exception:
            pass
        time.sleep(5)
    raise TimeoutError('WinRM not responsive after boot')


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


def regshot_before():
    winrm_run(
        'Start-Process C:\\Tools\\Regshot\\Regshot-x64-Unicode.exe '
        '-ArgumentList "/s1 /na" -Wait'
    )
    log.info('Regshot: first snapshot taken')


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
    winrm_run(
        'Start-Process C:\\Tools\\Regshot\\Regshot-x64-Unicode.exe '
        '-ArgumentList "/s2 /o C:\\Logs\\regshot_diff.txt" -Wait'
    )
    log.info('Regshot: second snapshot + diff saved')


def stop_procmon():
    winrm_run('Stop-Process -Name Procmon64 -Force -ErrorAction SilentlyContinue')
    # Export to CSV
    winrm_run(
        'Start-Process C:\\Tools\\SysinternalsSuite\\Procmon64.exe '
        '-ArgumentList "/OpenLog C:\\Logs\\procmon.pml '
        '/SaveAs C:\\Logs\\procmon.csv /Quiet" -Wait'
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
