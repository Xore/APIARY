#!/usr/bin/env python3
"""
run_sample.py — GHOSTS sandbox detonation orchestrator (#328)

Drives win11-ghosts through libvirt and the guest through WinRM/SMB, same
shape as sandbox/windows/orchestrate/run_sample.py (the isolated Windows
route) with the differences #328 called for:

  - Revert targets win11-ghosts.qcow2 (#326), never win11-analysis.qcow2 --
    the two golden images are never mixed.
  - WinRM/SMB, not a new control channel: verified in #325/#326 that
    host-initiated connections to the guest (WinRM, SMB) are unaffected by
    the guest's own outbound firewall policy -- that policy only restricts
    traffic the guest itself originates (FORWARD/INPUT with the guest as
    source), not connections the host opens to it. The GHOSTS API's own
    machine-management surface has no submit-a-file primitive to replace
    this with; WinRM/SMB stays the delivery channel, same as every other
    guest in this repo, not a wider control surface than win11-sandbox has.
  - No ProcMon/FakeNet/Regshot noise-generation tooling -- GHOSTS' own
    client (started here, running the persona's baked-in timeline) is the
    activity generator for this guest, not a second, uncoordinated one.
    Sysmon (already installed on the shared golden-image base, #326) is
    still the process/network telemetry source.
  - GHOSTS' own activity log, pulled from Ghosts.Api's database via its
    REST surface, is collected as a first-class artifact: what did the NPC
    actually do during this run, for correlating against what the sample
    did. No other pipeline in this repo has an equivalent.
  - Writes windows-ghosts-<job>.json directly into GHOSTS_SANDBOX_RESULTS_DIR
    matching dashboard/sandbox.go's sandboxResult schema, "route":
    "windows-ghosts" so the dashboard's isolation-description branch (#327)
    renders correctly -- not a raw-artifacts-directory-plus-report.html
    shape needing a separate export step.

Requires: pip install pywinrm

Env vars:
  VM_HOST             IP of the GHOSTS guest (for WinRM/SMB). No pinned
                       DHCP reservation exists yet in the deployed
                       sandbox/ghosts/network.xml (#325/#327 tracked this
                       gap) -- override this if the guest's lease floats.
  VM_USER / VM_PASS    Guest credentials, same defaults as win11-sandbox
                       (the shared golden-image base, #326).
  LIBVIRT_URI          libvirt connection URI (default: qemu:///system)
  VM_DOMAIN            libvirt domain name (default: win11-ghosts)
  GOLDEN_IMAGE         Path to win11-ghosts.qcow2, never win11-analysis.qcow2
  VM_DISK              Path to the per-run CoW clone
  GHOSTS_API_ADDR      Ghosts.Api's fixed address (default: 10.20.30.1:5000,
                       #324/#325)
  OBSERVATION_SECS     Seconds to observe (default: 1800, matching
                       win11-sandbox's own #297 default)
"""

import os
import time
import json
import hashlib
import argparse
import logging
import subprocess
import urllib.request
from pathlib import Path
from datetime import datetime, timezone

try:
    import winrm
except ImportError:
    winrm = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

VM_HOST         = os.environ.get('VM_HOST',          '10.20.30.72')
VM_USER         = os.environ.get('VM_USER',          'analyst')
VM_PASS         = os.environ.get('VM_PASS',          'malware123!')
VIRSH_PATH      = os.environ.get('VIRSH_PATH',       '/usr/bin/virsh')
LIBVIRT_URI     = os.environ.get('LIBVIRT_URI',      'qemu:///system')
VM_DOMAIN       = os.environ.get('VM_DOMAIN',        'win11-ghosts')
GOLDEN_IMAGE    = Path(os.environ.get('GOLDEN_IMAGE',
                        '/var/dockge/sandbox/golden-images/win11-ghosts.qcow2'))
VM_DISK         = Path(os.environ.get('VM_DISK',
                        f'/var/dockge/sandbox/vms/{VM_DOMAIN}.qcow2'))
NVRAM           = Path(os.environ.get('VM_NVRAM',
                        f'/var/lib/libvirt/qemu/nvram/{VM_DOMAIN}_VARS.qcow2'))
OBS_SECS        = int(os.environ.get('OBSERVATION_SECS', '1800'))
GHOSTS_API_ADDR = os.environ.get('GHOSTS_API_ADDR', '10.20.30.1:5000')
ARTIFACT_DIR    = Path(os.environ.get('GHOSTS_SANDBOX_RESULTS_DIR', 'reports/windows-ghosts'))
SAMPLE_SHARE    = f'\\\\{VM_HOST}\\Samples'
LOGS_SHARE      = f'\\\\{VM_HOST}\\Logs'


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def virsh(cmd: list, timeout: int = 120) -> str:
    result = subprocess.run(
        [VIRSH_PATH, '--connect', LIBVIRT_URI] + cmd,
        capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f'virsh {" ".join(cmd)} failed: {result.stderr.strip()}')
    return result.stdout.strip()


def revert_to_golden():
    """Reset win11-ghosts to a fresh clone of win11-ghosts.qcow2 -- never
    win11-analysis.qcow2 (#326's own constraint). Same cold-boot-every-run
    reasoning as run_sample.py's version (#358): no virsh snapshot here."""
    log.info(f'Resetting {VM_DOMAIN} to a fresh clone of {GOLDEN_IMAGE}')
    if 'analysis' in GOLDEN_IMAGE.name:
        raise RuntimeError(f'refusing to revert against {GOLDEN_IMAGE} -- must be win11-ghosts.qcow2')
    subprocess.run([VIRSH_PATH, '--connect', LIBVIRT_URI, 'destroy', VM_DOMAIN],
                    capture_output=True, text=True)
    if VM_DISK.exists():
        VM_DISK.unlink()
    subprocess.run(
        ['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(GOLDEN_IMAGE), str(VM_DISK)],
        check=True, capture_output=True, text=True,
    )
    # Belt-and-braces for a libvirt nvram-template-conversion bug hit live
    # in #326/#327 on this host: `virsh start` on a domain whose nvram
    # doesn't exist yet fails ("conversion of the nvram template to
    # another target format is not supported"). Pre-create it by hand the
    # first time; a later run finds it already there and skips this.
    if not NVRAM.exists():
        subprocess.run(
            ['qemu-img', 'convert', '-f', 'raw', '-O', 'qcow2',
             '/usr/share/OVMF/OVMF_VARS_4M.ms.fd', str(NVRAM)],
            check=True, capture_output=True, text=True,
        )
    virsh(['start', VM_DOMAIN])
    log.info('Domain reset and running; waiting for WinRM')


def winrm_run(ps_command: str, timeout: int = 60) -> dict:
    if winrm is None:
        raise RuntimeError('pywinrm not installed. Run: pip install pywinrm')
    session = winrm.Session(
        VM_HOST, auth=(VM_USER, VM_PASS),
        transport='ntlm', server_cert_validation='ignore',
        read_timeout_sec=timeout + 10, operation_timeout_sec=timeout,
    )
    result = session.run_ps(ps_command)
    return {
        'stdout': result.std_out.decode('utf-8', errors='replace'),
        'stderr': result.std_err.decode('utf-8', errors='replace'),
        'status_code': result.status_code,
    }


def wait_for_winrm(max_wait: int = 300):
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            result = winrm_run('Write-Output ready', timeout=10)
            if 'ready' in result['stdout']:
                log.info('WinRM ready')
                return
        except Exception as e:
            log.debug(f'WinRM not ready yet: {e}')
        time.sleep(5)
    raise TimeoutError('WinRM not responsive after boot')


def copy_sample_to_vm(sample_path: Path, sha: str) -> str:
    dest_name = f'{sha[:16]}.exe'
    subprocess.run(
        ['smbclient', SAMPLE_SHARE, '-U', f'{VM_USER}%{VM_PASS}',
         '-c', f'put {sample_path} {dest_name}'],
        capture_output=True, timeout=60,
    )
    log.info(f'Sample copied to VM as {dest_name}')
    return f'C:\\Samples\\{dest_name}'


def start_ghosts_client():
    """Launch via WMI Win32_Process.Create, not Start-Process -- verified
    live in #326 that Start-Process (with or without output redirection)
    hangs indefinitely over this guest's WinRM path for reasons never
    root-caused; WMI Create is the reliable launch mechanism found there.
    Runs the persona's baked-in timeline (config/timeline.json, #326/#329)
    in the background for the rest of this run, same as a human using this
    workstation while the sample also runs."""
    ps = (
        'Invoke-CimMethod -ClassName Win32_Process -MethodName Create '
        '-Arguments @{ CommandLine = "C:\\ghosts\\Ghosts.Client.Universal.exe"; '
        'CurrentDirectory = "C:\\ghosts" }'
    )
    result = winrm_run(ps, timeout=30)
    log.info(f'GHOSTS client launch: {result["stdout"].strip()}')


def stop_persona_daemon():
    """#290's living-persona daemon and the GHOSTS client both drive
    mouse/keyboard/document activity on the same desktop -- confirmed live
    in #326 that running both isn't broken, but it's redundant CPU cost and
    uncoordinated activity neither #326 nor #329 tried to make sense of
    together. Disabled here, at detonation time, not baked out of the
    golden image -- the daemon still has a reason to exist on this image
    for anything that boots it without the GHOSTS client (a bare
    win11-ghosts.qcow2 clone used the way win11-sandbox is used, say)."""
    winrm_run(
        'Stop-Process -Name PersonaDaemon -Force -ErrorAction SilentlyContinue; '
        'Disable-ScheduledTask -TaskName "Windows Shell Experience Helper" '
        '-ErrorAction SilentlyContinue | Out-Null',
        timeout=30,
    )


def sysmon_snapshot(tag: str):
    winrm_run(
        f'wevtutil epl Microsoft-Windows-Sysmon/Operational C:\\Logs\\sysmon_{tag}.evtx '
        '-ErrorAction SilentlyContinue',
        timeout=30,
    )


def execute_sample(vm_path: str):
    log.info(f'Executing sample: {vm_path}')
    winrm_run(
        f'$proc = Start-Process -FilePath "{vm_path}" '
        '-PassThru -WindowStyle Normal; '
        f'Write-Output "PID: $($proc.Id)"',
        timeout=30,
    )


def fetch_ghosts_activity(machine_hint: str) -> dict:
    """GHOSTS' own record of what the NPC actually did during this run --
    pulled from Ghosts.Api, not the guest (the guest is untrusted the
    moment the sample runs; the API's database is not). Best-effort: a
    reachability problem here must not fail the whole detonation over one
    optional artifact, same principle as run_sample.py's memory-dump step.
    """
    try:
        with urllib.request.urlopen(
            f'http://{GHOSTS_API_ADDR}/api/machines?q=', timeout=10
        ) as resp:
            machines = json.loads(resp.read())
        match = next((m for m in machines if m.get('hostIp') == machine_hint), None)
        return match or {'error': f'no machine found with hostIp {machine_hint}'}
    except Exception as e:
        log.error(f'GHOSTS activity fetch failed: {e}', exc_info=True)
        return {'error': str(e)}


def collect_artifacts(sha: str, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    files_to_get = ['sysmon_before.evtx', 'sysmon_after.evtx']
    for fname in files_to_get:
        subprocess.run(
            ['smbclient', LOGS_SHARE, '-U', f'{VM_USER}%{VM_PASS}',
             '-c', f'get {fname} {out_dir}/{fname}'],
            capture_output=True, timeout=60,
        )
    ghosts_activity = fetch_ghosts_activity(VM_HOST)
    (out_dir / 'ghosts_activity.json').write_text(json.dumps(ghosts_activity, indent=2))
    log.info(f'Artifacts collected to {out_dir}')
    return ghosts_activity


def detonate(sample_path: Path, results_dir: Path):
    sha = sha256_of(sample_path)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    job = f'windows-ghosts-{stamp}-{sha[:12]}'
    out = results_dir / sha
    started_at = datetime.now(timezone.utc)

    log.info(f'=== Detonating (GHOSTS route): {sample_path} ({sha[:16]}...) ===')

    row = {
        'version': 1,
        'job': job,
        'sha256': sha,
        'capture_name': sample_path.name,
        'source': 'workbench',
        'requested_at': started_at.isoformat(),
        'route': 'windows-ghosts',
        'platform': 'Windows',
        'network': 'wan-permitted',
        'guest_started': False,
        'run_status': 'failed',
        'exit_status': 'unknown',
    }

    try:
        revert_to_golden()
        wait_for_winrm()
        row['guest_started'] = True
        stop_persona_daemon()
        vm_path = copy_sample_to_vm(sample_path, sha)
        start_ghosts_client()
        sysmon_snapshot('before')

        row['started_at'] = datetime.now(timezone.utc).isoformat()
        execute_sample(vm_path)
        log.info(f'Observing for {OBS_SECS} seconds...')
        time.sleep(OBS_SECS)

        sysmon_snapshot('after')
        ghosts_activity = collect_artifacts(sha, out)
        row['ghosts_activity'] = ghosts_activity
        row['exit_status'] = 'completed'
        row['run_status'] = 'completed'
    except Exception as e:
        log.error('Detonation failed', exc_info=True)
        row['failure_reason'] = str(e)
        row['exit_status'] = 'unknown'
        row['run_status'] = 'failed'
    finally:
        row['completed_at'] = datetime.now(timezone.utc).isoformat()
        row['duration_seconds'] = (datetime.now(timezone.utc) - started_at).total_seconds()
        log.info('Resetting VM to golden image (cleanup)...')
        try:
            revert_to_golden()
        except Exception as e:
            log.error(f'VM revert failed: {e}')

    results_dir.mkdir(parents=True, exist_ok=True)
    result_path = results_dir / f'{job}.json'
    result_path.write_text(json.dumps(row, indent=2))
    log.info(f'Result written: {result_path}')
    return row['run_status'] == 'completed'


def main():
    parser = argparse.ArgumentParser(description='GHOSTS Sandbox Orchestrator (#328)')
    parser.add_argument('--sample', required=True, help='Path to the sample to detonate')
    parser.add_argument('--results-dir',
                         help='Where to write the result JSON (default: $GHOSTS_SANDBOX_RESULTS_DIR)')
    args = parser.parse_args()
    results_dir = Path(args.results_dir) if args.results_dir else ARTIFACT_DIR

    sample_path = Path(args.sample)
    if not sample_path.exists():
        log.error(f'Sample not found: {sample_path}')
        return 1

    ok = detonate(sample_path, results_dir)
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
