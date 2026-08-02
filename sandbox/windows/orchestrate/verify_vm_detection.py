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
script is ready to run the moment win11-sandbox exists; it is not itself
blocked on anything else.

Usage:
  1. Download pafish.exe and al-khaser.exe (or build them) on the analysis
     host — they never touch the internet from inside the guest.
  2. Boot a fresh clone of the golden image with virsh, same as
     run_sample.py's revert_to_golden() (see #358 for why this is a cold
     boot from a fresh CoW clone rather than a snapshot resume).
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
  VM_HOST, VM_USER, VM_PASS, LIBVIRT_URI, VM_DOMAIN, GOLDEN_IMAGE, VM_DISK
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
# Must match winrm_pass's actual default in packer/win11-analysis.pkr.hcl --
# same drift as run_sample.py's VM_PASS, fixed there in #358.
VM_PASS     = os.environ.get('VM_PASS', 'malware123!')
SAMPLE_SHARE = f'\\\\{VM_HOST}\\Samples'
LOGS_SHARE   = f'\\\\{VM_HOST}\\Logs'
RESULTS_DIR  = Path(__file__).resolve().parent.parent / 'docs' / 'vm-detection-results'


def winrm_run(ps_command: str, timeout: int = 300) -> dict:
    """Run a PowerShell command over WinRM, bounded by `timeout` wall-clock
    seconds.

    session.run_ps() alone does not bound this: WinRM's Receive operation is
    a long-poll the client keeps re-issuing for as long as the remote shell
    command hasn't exited, so a hung remote process (confirmed live: pafish
    waits on a keypress at the end that WinRM never provides, and hung with
    0% CPU for 20+ minutes) blocks here indefinitely no matter what
    read_timeout_sec/operation_timeout_sec are set to -- those only bound a
    single poll round-trip, not the overall loop. run_ps() itself has no
    timeout parameter, so the only way to actually bound it is to run it in
    a thread and give up waiting on that thread.
    """
    if winrm is None:
        raise RuntimeError('pywinrm not installed. Run: pip install pywinrm')
    session = winrm.Session(
        VM_HOST, auth=(VM_USER, VM_PASS),
        transport='ntlm', server_cert_validation='ignore',
        read_timeout_sec=30, operation_timeout_sec=20,
    )
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(session.run_ps, ps_command)
        try:
            result = future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise TimeoutError(
                f'WinRM command did not return within {timeout}s -- likely hung '
                f'on the guest (e.g. waiting on stdin). The underlying thread is '
                f'abandoned, not killed; the guest-side process may still be '
                f'running and should be checked/killed separately.'
            )
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
    """Run a tool on the guest and return its exit code plus captured output.

    Uses Start-Process -PassThru -Wait rather than plain redirection so a
    hard failure (e.g. STATUS_DLL_NOT_FOUND, confirmed live for al-khaser --
    this golden image has no Visual C++ Redistributable installed) is
    reported as a real, non-zero/negative exit code instead of silently
    looking identical to "ran fine and printed nothing."

    pafish (confirmed live) also waits on a keypress after finishing its
    checks; WinRM gives a launched process no interactive stdin, so without
    feeding it something it would finish its real work, write the log, and
    then hang forever at 0% CPU waiting for input that will never come.
    "echo." pipes a single blank line in via -RedirectStandardInput to
    satisfy that read and let the process actually exit.
    """
    log.info(f'Running C:\\Samples\\{remote_name} ...')
    stdin_path = f'C:\\Logs\\{log_name}.stdin'
    out = winrm_run(
        f'"`n" | Out-File -Encoding ascii -NoNewline {stdin_path}; '
        f'$p = Start-Process -FilePath C:\\Samples\\{remote_name} -PassThru -Wait '
        f'-WindowStyle Hidden -RedirectStandardInput {stdin_path} '
        f'-RedirectStandardOutput C:\\Logs\\{log_name} '
        f'-RedirectStandardError C:\\Logs\\{log_name}.stderr; '
        f'$p.ExitCode'
    )
    exit_code = out['stdout'].strip()
    body = winrm_run(
        f'Get-Content C:\\Logs\\{log_name} -Raw; "---STDERR---"; '
        f'Get-Content C:\\Logs\\{log_name}.stderr -Raw'
    )
    return {'exit_code': exit_code, 'stdout': body['stdout']}


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

    def render_section(name: str, out: dict) -> str:
        code = out['exit_code']
        if code not in ('0', ''):
            return (
                f'## {name}\n\n**FAILED to run — exit code {code}.** Not a '
                f'"no tells found" result; this tool did not actually execute. '
                f'Check the exit code against Windows NTSTATUS values (e.g. '
                f'-1073741515 / 0xC0000135 = STATUS_DLL_NOT_FOUND) before '
                f'trusting anything else in this report.\n\n```\n{out["stdout"]}\n```\n'
            )
        return f'## {name}\n\n```\n{out["stdout"]}\n```\n'

    if args.pafish:
        push_tool(args.pafish, 'pafish.exe')
        out = run_tool('pafish.exe', 'pafish_out.txt')
        sections.append(render_section('pafish', out))

    if args.al_khaser:
        push_tool(args.al_khaser, 'al-khaser.exe')
        out = run_tool('al-khaser.exe', 'al_khaser_out.txt')
        sections.append(render_section('al-khaser', out))

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
