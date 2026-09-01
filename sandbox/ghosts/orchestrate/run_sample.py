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
  VM_HOST             IP of the GHOSTS guest (for WinRM/SMB). Pinned by
                       sandbox/ghosts/network.xml's DHCP reservation
                       (MAC 00:1a:a0:3c:4d:6f -> 10.20.30.50, #327's
                       PR #425); the default below matches that pin, so
                       override only if the pin itself moves.
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

VM_HOST         = os.environ.get('VM_HOST',          '10.20.30.50')
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
# #956: 'Samples' -> 'Inbox' -- see windows/orchestrate/run_sample.py's own
# SAMPLE_SHARE comment for the full reasoning (win11-ghosts.qcow2 is
# forked from win11-analysis.qcow2, packer/scripts/04-tools.ps1's rename
# there is what actually creates 'Inbox' instead of 'Samples' on this
# image too).
SAMPLE_SHARE    = f'\\\\{VM_HOST}\\Inbox'
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
    result = subprocess.run(
        ['smbclient', SAMPLE_SHARE, '-U', f'{VM_USER}%{VM_PASS}',
         '-c', f'put {sample_path} {dest_name}'],
        capture_output=True, timeout=60,
    )
    # #2252: an SMB hiccup (share briefly unavailable post-boot, auth blip,
    # transient reset) used to return here unchecked -- the sample never
    # lands in C:\Inbox, but the caller has no way to know and the run
    # sails through to a false 'completed' result with every IOC field
    # empty. smbclient exits non-zero on a failed `put` inside `-c`.
    if result.returncode != 0:
        raise RuntimeError(
            f'smbclient put failed (rc={result.returncode}): '
            f'{result.stderr.decode(errors="replace").strip()}'
        )
    log.info(f'Sample copied to VM as {dest_name}')
    return f'C:\\Inbox\\{dest_name}'


GHOSTS_CLIENT_DIR  = r'C:\Program Files\Contoso\EndpointAgent'
GHOSTS_CLIENT_EXE  = GHOSTS_CLIENT_DIR + r'\EndpointAgent.exe'
GHOSTS_TASK_NAME   = 'Contoso Endpoint Agent Sync'


def start_ghosts_client():
    """Launch via a one-shot scheduled task with an Interactive-logon
    Principal, not WMI's Win32_Process.Create -- verified live in #326 that
    Start-Process (with or without output redirection) hangs indefinitely
    over this guest's WinRM path for reasons never root-caused, and
    Win32_Process.Create was adopted as the reliable alternative found
    there. #462 (found later, live-testing #329's persona timeline):
    WMI-launched processes always spawn in Session 0, invisible on the
    interactive console/VNC/RDP session an attacker who reaches this box
    would actually be looking at -- confirmed via `Get-Process | Select
    SessionId` showing 0 for a WMI-launched client while the real desktop
    session is 1. Session 0 also means the client's own Selenium/Chrome
    automation can never touch the interactive desktop's window station at
    all, which is a functional bug on top of the stealth one.

    Same fix shape as packer/scripts/07-living-persona.ps1's
    PersonaDaemon task (-Principal ... -LogonType Interactive) and
    packer/scripts/11-detonation-orchestrator.ps1's AtLogOn task -- a
    scheduled task with an explicit Interactive principal is this repo's
    proven way to get code running in the real session over WinRM, which
    itself always executes in Session 0. Registered and started
    immediately (Register-ScheduledTask + Start-ScheduledTask) rather than
    an AtLogOn trigger, since the guest is already logged in by the time
    detonation starts -- there is no future logon event to wait for.

    Task name and binary path are deliberately generic (#462) -- see
    Dockerfile.client-win and provision-golden-image.sh for the matching
    PE-metadata and install-path changes. Runs the persona's baked-in
    timeline (config/timeline.json, #326/#329) in the background for the
    rest of this run, same as a human using this workstation while the
    sample also runs."""
    ps = (
        f'$action = New-ScheduledTaskAction -Execute "{GHOSTS_CLIENT_EXE}" '
        f'-WorkingDirectory "{GHOSTS_CLIENT_DIR}"; '
        '$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date); '
        '$principal = New-ScheduledTaskPrincipal -UserId "analyst" -LogonType Interactive -RunLevel Highest; '
        '$settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero); '
        f'Register-ScheduledTask -TaskName "{GHOSTS_TASK_NAME}" '
        '-Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null; '
        f'Start-ScheduledTask -TaskName "{GHOSTS_TASK_NAME}"'
    )
    result = winrm_run(ps, timeout=30)
    log.info(f'GHOSTS client launch: {result["stdout"].strip()} {result["stderr"].strip()}')


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
    result = winrm_run(
        f'$proc = Start-Process -FilePath "{vm_path}" '
        '-PassThru -WindowStyle Normal; '
        f'Write-Output "PID: $($proc.Id)"',
        timeout=30,
    )
    # #2252: a delivery failure upstream (the sample never actually landed
    # in C:\Inbox) makes Start-Process error out ("cannot find path
    # C:\Inbox\<sha>.exe") -- both the non-zero status_code and the missing
    # "PID:" line were previously discarded, so this looked identical to a
    # real execution to every caller downstream.
    if result['status_code'] != 0 or 'PID:' not in result['stdout']:
        raise RuntimeError(
            f"execute_sample: Start-Process did not report a PID "
            f"(status_code={result['status_code']}): "
            f"stdout={result['stdout'].strip()!r} stderr={result['stderr'].strip()!r}"
        )


def get_guest_hostname() -> str:
    """The golden image bakes in a fixed persona hostname (e.g.
    acp-fin0142) -- ask the guest directly rather than hardcoding it, so
    this keeps working if the persona baked into the image ever changes."""
    result = winrm_run('$env:COMPUTERNAME', timeout=15)
    return result['stdout'].strip()


def fetch_ghosts_activity(hostname: str) -> dict:
    """GHOSTS' own record of what the NPC actually did during this run --
    pulled from Ghosts.Api, not the guest (the guest is untrusted the
    moment the sample runs; the API's database is not). Best-effort: a
    reachability problem here must not fail the whole detonation over one
    optional artifact, same principle as run_sample.py's memory-dump step.

    Matched by hostname, not hostIp (#806). Ghosts.Api's own
    ApplicationSettings.MatchMachinesBy is "name" -- confirmed live that a
    machine record's `hostIp` is set once at creation and never refreshed
    on later check-ins/heartbeats, even though `lastReportedUtc` updates
    correctly every time: a real, fresh heartbeat from this exact guest
    still showed `hostIp` frozen at a different address from over a day
    earlier, because DHCP -- this predates the network.xml pin, see this
    file's own VM_HOST docstring -- handed out a new lease in between.
    Querying by
    hostIp was therefore only ever going to match by coincidence -- this
    is why #806 found the real detonated machine "never appears in this
    list at all, under any IP": it was there all along, under its
    hostname, with a stale hostIp. Case-insensitive since Ghosts.Api
    lowercases `name` (confirmed live: $env:COMPUTERNAME returns
    "ACP-FIN0142", the API stores "acp-fin0142")."""
    try:
        with urllib.request.urlopen(
            f'http://{GHOSTS_API_ADDR}/api/machines?q=', timeout=10
        ) as resp:
            machines = json.loads(resp.read())
        hostname_lower = hostname.lower()
        match = next(
            (m for m in machines
             if (m.get('name') or '').lower() == hostname_lower
             or (m.get('host') or '').lower() == hostname_lower),
            None,
        )
        return match or {'error': f'no machine found with name {hostname}'}
    except Exception as e:
        log.error(f'GHOSTS activity fetch failed: {e}', exc_info=True)
        return {'error': str(e)}


def collect_artifacts(sha: str, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    files_to_get = ['sysmon_before.evtx', 'sysmon_after.evtx']
    for fname in files_to_get:
        result = subprocess.run(
            ['smbclient', LOGS_SHARE, '-U', f'{VM_USER}%{VM_PASS}',
             '-c', f'get {fname} {out_dir}/{fname}'],
            capture_output=True, timeout=60,
        )
        # #2252: an unchecked failure here left a missing sysmon evtx
        # silently absent -- the run still reported 'completed' with no
        # process/network telemetry to show for it. Same SMB path as
        # copy_sample_to_vm, so the same rc check applies.
        if result.returncode != 0:
            raise RuntimeError(
                f'smbclient get {fname} failed (rc={result.returncode}): '
                f'{result.stderr.decode(errors="replace").strip()}'
            )
    try:
        hostname = get_guest_hostname()
    except Exception as e:
        log.error(f'Could not read guest hostname for GHOSTS lookup: {e}')
        hostname = ''
    ghosts_activity = fetch_ghosts_activity(hostname) if hostname else {'error': 'could not determine guest hostname'}
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
