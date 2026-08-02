#!/usr/bin/env python3
"""
verify_vm_detection.py — post-build pafish/al-khaser verification pass (#298)

sandbox/windows_kimi/RESEARCH.md #1.2 makes the point that everything
win11-kvm.xml and packer/scripts/01-hardening.ps1 do (SMBIOS/CPUID/disk-serial/
NIC spoofing, Defender/telemetry/UAC disables) is reasoned-through hardening
against *known* checks. The only way to find out what's actually still
detectable is to run real detection tools inside the built guest: pafish
(https://github.com/a0rtega/pafish) and al-khaser
(https://github.com/LordNoteworthy/al-khaser).

Residual tells worth checking for even after everything currently in
win11-kvm.xml is applied (per RESEARCH.md #1.2):
  - rdtsc-forced VM-exit timing (no reliable KVM fix — the hardest one)
  - remaining virtio driver names anywhere in the guest
  - screen resolution (should read as 1920x1080, not a default headless size)
  - system uptime at analysis time

BLOCKED on the golden image existing (#47 and its sub-issues, same as most
of Phases 1-3) — there is nothing to boot and verify against yet. This
script is ready to run the moment win11-sandbox / GOLDEN_READY exists; it
is not itself blocked on anything else.

Usage:
  1. Download pafish.exe and al-khaser.exe (or build them) on the analysis
     host — they never touch the internet from inside the guest.
  2. Boot the golden snapshot (or a thin clone of it) with virsh, same as
     run_sample.py's revert_to_golden().
  3. python3 verify_vm_detection.py --pafish /path/to/pafish.exe \
       --al-khaser /path/to/al-khaser.exe

Writes a timestamped Markdown report to
sandbox/windows/docs/vm-detection-results/, matching the pattern
04-tools.ps1 already uses for C:\\golden_image_provenance.txt: a durable,
checked-in record of what was verified and when, not just a claim in a
comment. Re-run after every golden-image rebuild (#86's scheduled-rebuild
issue) since a later provisioner change could silently reintroduce a tell
one earlier script fixed.

Env vars (shared with run_sample.py):
  VM_HOST, VM_USER, VM_PASS, LIBVIRT_URI, VM_DOMAIN, GOLDEN_SNAPSHOT
"""

import os
import sys
import argparse
import logging
import subprocess
from pathlib import Path
from datetime import datetime, timezone

try:
    import winrm
except ImportError:
    winrm = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

VM_HOST     = os.environ.get('VM_HOST', '10.10.10.2')
VM_USER     = os.environ.get('VM_USER', 'analyst')
VM_PASS     = os.environ.get('VM_PASS', 'malware')
SAMPLE_SHARE = f'\\\\{VM_HOST}\\Samples'
LOGS_SHARE   = f'\\\\{VM_HOST}\\Logs'
RESULTS_DIR  = Path(__file__).resolve().parent.parent / 'docs' / 'vm-detection-results'


def winrm_run(ps_command: str, timeout: int = 300) -> dict:
    if winrm is None:
        raise RuntimeError('pywinrm not installed. Run: pip install pywinrm')
    session = winrm.Session(
        VM_HOST, auth=(VM_USER, VM_PASS),
        transport='ntlm', server_cert_validation='ignore',
    )
    result = session.run_ps(ps_command)
    return {
        'stdout': result.std_out.decode('utf-8', errors='replace'),
        'stderr': result.std_err.decode('utf-8', errors='replace'),
        'status_code': result.status_code,
    }


def push_tool(local_path: Path, remote_name: str):
    subprocess.run(
        ['smbclient', SAMPLE_SHARE, '-U', f'{VM_USER}%{VM_PASS}',
         '-c', f'put {local_path} {remote_name}'],
        check=True, capture_output=True, timeout=60,
    )
    log.info(f'Pushed {local_path} -> C:\\Samples\\{remote_name}')


def run_tool(remote_name: str, log_name: str) -> dict:
    log.info(f'Running C:\\Samples\\{remote_name} ...')
    return winrm_run(
        f'C:\\Samples\\{remote_name} > C:\\Logs\\{log_name} 2>&1; '
        f'Get-Content C:\\Logs\\{log_name} -Raw'
    )


def check_residual_tells() -> dict:
    """The specific checks RESEARCH.md #1.2 calls out beyond what pafish/
    al-khaser cover generically: screen resolution and system uptime."""
    res = winrm_run(
        "Add-Type -AssemblyName System.Windows.Forms; "
        "$s = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds; "
        "\"$($s.Width)x$($s.Height)\""
    )
    uptime = winrm_run(
        "(Get-Date) - (gcim Win32_OperatingSystem).LastBootUpTime "
        "| Select-Object -ExpandProperty TotalMinutes"
    )
    virtio = winrm_run(
        "Get-CimInstance Win32_PnPEntity | Where-Object { $_.Name -match 'virtio' } "
        "| Select-Object -ExpandProperty Name"
    )
    return {
        'screen_resolution': res['stdout'].strip(),
        'uptime_minutes': uptime['stdout'].strip(),
        'virtio_devices': virtio['stdout'].strip() or '(none found)',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--pafish', type=Path, help='Path to pafish.exe on the analysis host')
    parser.add_argument('--al-khaser', type=Path, help='Path to al-khaser.exe on the analysis host')
    args = parser.parse_args()

    if not args.pafish and not args.al_khaser:
        parser.error('at least one of --pafish / --al-khaser is required')

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H%M%SZ')
    report_path = RESULTS_DIR / f'{ts}.md'

    sections = [f'# VM detection verification — {ts}\n']

    if args.pafish:
        push_tool(args.pafish, 'pafish.exe')
        out = run_tool('pafish.exe', 'pafish_out.txt')
        sections.append('## pafish\n\n```\n' + out['stdout'] + '\n```\n')

    if args.al_khaser:
        push_tool(args.al_khaser, 'al-khaser.exe')
        out = run_tool('al-khaser.exe', 'al_khaser_out.txt')
        sections.append('## al-khaser\n\n```\n' + out['stdout'] + '\n```\n')

    tells = check_residual_tells()
    sections.append(
        '## Residual tells (RESEARCH.md #1.2)\n\n'
        f"- Screen resolution: `{tells['screen_resolution']}` (expected 1920x1080)\n"
        f"- System uptime: `{tells['uptime_minutes']}` minutes\n"
        f"- virtio-named devices: `{tells['virtio_devices']}`\n"
        '- rdtsc-forced VM-exit timing: not automatable from PowerShell — '
        'check pafish/al-khaser timing-check output above; no reliable KVM '
        'fix exists for this one per RESEARCH.md.\n'
    )

    report_path.write_text('\n'.join(sections))
    log.info(f'Report written: {report_path}')


if __name__ == '__main__':
    sys.exit(main())
