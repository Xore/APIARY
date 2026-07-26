#!/usr/bin/env python3
"""
run_sample.py — Windows 11 sandbox detonation orchestrator

Controls the Windows 11 VM via WinRM:
1. Reverts to golden snapshot
2. Copies sample to VM
3. Starts telemetry (ProcMon, FakeNet-NG)
4. Executes sample
5. Waits observation window
6. Collects all artifacts
7. Reverts VM (cleanup)
8. Pushes artifacts to Xore/Honeypot

Requires:
  pip install pywinrm paramiko requests python-evtx

Env vars:
  VM_HOST            IP of Windows VM (for WinRM)
  VM_USER            Windows username
  VM_PASS            Windows password
  VMRUN_PATH         Path to vmrun binary (VMware)
  VMX_PATH           Path to .vmx file
  GOLDEN_SNAPSHOT    Snapshot name (default: SNAPSHOT_3_GOLDEN)
  OBSERVATION_SECS   Seconds to observe (default: 300)
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
VM_PASS         = os.environ.get('VM_PASS',          'malware')
VMRUN_PATH      = os.environ.get('VMRUN_PATH',       '/usr/bin/vmrun')
VMX_PATH        = os.environ.get('VMX_PATH',         '/vms/win11-analysis/win11.vmx')
GOLDEN_SNAP     = os.environ.get('GOLDEN_SNAPSHOT',  'SNAPSHOT_3_GOLDEN')
OBS_SECS        = int(os.environ.get('OBSERVATION_SECS', '300'))
ARTIFACT_DIR    = Path('reports/windows-sandbox')
SAMPLE_SHARE    = f'\\\\{VM_HOST}\\Samples'
LOGS_SHARE      = f'\\\\{VM_HOST}\\Logs'


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def vmrun(cmd: list) -> str:
    """Execute vmrun command."""
    result = subprocess.run([VMRUN_PATH] + cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f'vmrun failed: {result.stderr}')
    return result.stdout.strip()


def revert_to_golden():
    log.info(f'Reverting VM to snapshot: {GOLDEN_SNAP}')
    vmrun(['revertToSnapshot', VMX_PATH, GOLDEN_SNAP])
    vmrun(['start', VMX_PATH, 'nogui'])
    log.info('VM starting, waiting 60s for boot...')
    time.sleep(60)


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


def detonate(sample_path: Path):
    if not sample_path.exists() or sample_path.name == '.gitkeep':
        return
    sha   = sha256_of(sample_path)
    out   = ARTIFACT_DIR / sha

    log.info(f'=== Detonating: {sample_path} ({sha[:16]}...) ===')

    # Write metadata
    out.mkdir(parents=True, exist_ok=True)
    (out / 'metadata.json').write_text(json.dumps({
        'sha256':      sha,
        'filename':    sample_path.name,
        'detonated_at': datetime.now(timezone.utc).isoformat(),
        'observation_secs': OBS_SECS,
    }, indent=2))

    try:
        revert_to_golden()
        wait_for_winrm()
        vm_path = copy_sample_to_vm(sample_path, sha)
        start_fakenet()
        start_procmon()
        regshot_before()

        execute_sample(vm_path)
        log.info(f'Observing for {OBS_SECS} seconds...')
        time.sleep(OBS_SECS)

        regshot_after()
        stop_procmon()
        collect_artifacts(sha, out)

    except Exception as e:
        log.error(f'Detonation failed: {e}', exc_info=True)
    finally:
        # Always revert to clean state
        log.info('Reverting VM to golden snapshot (cleanup)...')
        try:
            vmrun(['revertToSnapshot', VMX_PATH, GOLDEN_SNAP])
        except Exception as e:
            log.error(f'VM revert failed: {e}')

    log.info(f'Run complete. Artifacts: {out}')


def main():
    parser = argparse.ArgumentParser(description='Windows Sandbox Orchestrator')
    parser.add_argument('--file-list',   help='File with list of sample paths')
    parser.add_argument('--sample',      help='Single sample path')
    parser.add_argument('--filter-type', help='Only process files in this subfolder (PE, ELF...)')
    args = parser.parse_args()

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

    for p in paths:
        try:
            detonate(p)
        except Exception as e:
            log.error(f'Error: {p}: {e}', exc_info=True)
        time.sleep(5)


if __name__ == '__main__':
    main()
