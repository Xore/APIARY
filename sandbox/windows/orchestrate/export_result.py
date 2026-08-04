#!/usr/bin/env python3
"""Build the dashboard-compatible windows-{job}.json from a completed run.

#53's smoke test found the actual, previously-unknown gap in this pipeline:
every artifact-collection step works (registry snapshots, autoruns/services
diffs, Sysmon/PowerShell EVTX, IOC extraction, memory dump, report.html) but
nothing ever wrote a file matching dashboard/sandbox.go's `sandboxResult`
struct -- the one thing the dashboard actually reads to show anything on
/sandbox at all. A fully successful detonation was completely invisible to
the dashboard. This is the writer for that file, modeled directly on
sandbox/export-result.py (the Linux runner's equivalent, already proven
against the same Go struct) rather than designed from scratch.

Known gaps, deliberately not solved here (see #53's PR/issue thread):
  - No PE-forensics step exists in this pipeline (unlike the Linux runner's
    pe-forensics.json), so windows_forensics.detected stays False. Sections,
    imports, imphash, etc. are all unavailable until that's added.
  - No raw network pcap is captured for the Windows sandbox the way the
    Linux runner captures network.pcap/guest-network.pcap, so network_summary
    is built from Sysmon's own DNS/connection events (already parsed by
    extract_iocs.py) rather than a packet-level summary.
  - ioc_extracted.json's DNS/IP data includes this image's own decoy traffic
    (the living-persona daemon and traffic-noise generator, #290/#291 --
    e.g. *.acp-persona.net) alongside anything the sample actually did.
    Nothing here filters that out, so risk scoring below is a floor, not a
    verified signal -- a real fix needs the noise generator's own tagging
    (X-Persona-Noise header / MCGPersona UA, per tools/filter-pcap.sh) wired
    into this extraction, not just pcaps.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

MAX_TEXT = 32768
MAX_LINES = 200


def text(path: Path, limit=MAX_TEXT, encoding='utf-8'):
    try:
        return path.read_bytes()[:limit].decode(encoding, 'replace')
    except OSError:
        return ''


def lines(path: Path, limit=MAX_LINES, encoding='utf-8'):
    return text(path, 131072, encoding).splitlines()[:limit]


# PowerShell's Out-File/redirection default encoding is UTF-16LE with a BOM
# -- autoruns_diff.txt and services_diff.txt are both produced that way
# (Compare-Object | Out-File in run_sample.py). Reading them as UTF-8
# produces the interleaved-null-byte garbage this decodes correctly instead.
def ps_text(path: Path, limit=MAX_TEXT):
    return text(path, limit, encoding='utf-16')


def ps_lines(path: Path, limit=MAX_LINES):
    return lines(path, limit, encoding='utf-16')


def build_result(out_dir: Path) -> dict:
    meta = {}
    meta_path = out_dir / 'metadata.json'
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    sha256 = meta.get('sha256', out_dir.name)
    detonated_at = meta.get('detonated_at', '')
    completed_at = datetime.now(timezone.utc).isoformat()
    try:
        started = datetime.fromisoformat(detonated_at) if detonated_at else None
        completed = datetime.fromisoformat(completed_at)
        duration = max(0, round((completed - started).total_seconds(), 3)) if started else 0
    except ValueError:
        duration = 0

    ioc_summary = {}
    ioc_path = out_dir / 'ioc_extracted.json'
    if ioc_path.exists():
        try:
            ioc_summary = json.loads(ioc_path.read_text()).get('summary', {})
        except (json.JSONDecodeError, OSError):
            pass
    remote_ips = ioc_summary.get('unique_remote_ips', [])
    dns_domains = ioc_summary.get('unique_dns_domains', [])
    download_urls = ioc_summary.get('unique_download_urls', [])
    download_cradles = ioc_summary.get('ps_download_cradles', [])

    autoruns_diff = ps_lines(out_dir / 'autoruns_diff.txt')
    services_diff = ps_lines(out_dir / 'services_diff.txt')
    regshot_diff = lines(out_dir / 'regshot_diff.txt', 500)
    # regshot_diff.txt's fc.exe output is a line-numbered before/after dump,
    # not a clean added/removed list -- lines starting with a digit and a
    # colon are the actual differing content, "*****"/"Comparing files"
    # lines are fc.exe's own framing. Rough but good enough as a
    # changed-registry-entries signal for risk scoring and the changed_files
    # field, which nothing here treats as authoritative forensic detail
    # (regshot_diff.txt itself, pulled as an artifact, is that).
    regshot_changed = [ln for ln in regshot_diff if re.match(r'^\d+:', ln.strip())]

    techniques = []
    technique_ids = set()

    def technique(identifier, name, evidence):
        if identifier not in technique_ids:
            technique_ids.add(identifier)
            techniques.append({'id': identifier, 'name': name, 'evidence': evidence[:256]})

    if any('added' in ln.lower() or '<' in ln or '>' in ln for ln in autoruns_diff):
        technique('T1547', 'Boot or Logon Autostart Execution', 'autoruns diff shows a change')
    if any('added' in ln.lower() or '<' in ln or '>' in ln for ln in services_diff):
        technique('T1543.003', 'Windows Service', 'service list diff shows a change')
    if remote_ips and dns_domains:
        technique('T1071.004', 'DNS', 'DNS query accompanied by a network connection to a remote IP')
    if download_urls or download_cradles:
        technique('T1105', 'Ingress Tool Transfer', 'download URL or PowerShell download cradle observed')
    if download_cradles:
        technique('T1059.001', 'PowerShell', 'PowerShell ScriptBlock log shows a download cradle pattern')
    if len(regshot_changed) > 20:
        technique('T1112', 'Modify Registry', f'{len(regshot_changed)} registry lines changed')

    # Additive, capped risk score -- same shape as export-result.py's, with
    # Windows-appropriate signals substituted for the Linux syscall-based
    # ones. Deliberately conservative given the decoy-traffic caveat above:
    # DNS/IP presence alone (T1071.004) is NOT scored on its own, since this
    # image's own persona/noise traffic guarantees it fires on every run.
    risk_score = 5
    risk_score += min(20, len(regshot_changed) // 10)
    risk_score += 25 if any(t['id'] in ('T1547', 'T1543.003') for t in techniques) else 0
    risk_score += 20 if download_cradles else 0
    risk_score += 10 if download_urls else 0
    risk_score = min(100, risk_score)
    risk_level = ('critical' if risk_score >= 75 else 'high' if risk_score >= 50
                  else 'medium' if risk_score >= 25 else 'low')

    procmon_missing = not (out_dir / 'procmon.csv').exists()

    stamp = detonated_at.replace('-', '').replace(':', '').split('.')[0].replace('T', 'T') if detonated_at else \
        datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    job = f'windows-{stamp}-{sha256[:12]}'

    return {
        'version': 2,
        'job': job,
        'sha256': sha256,
        'capture_name': meta.get('filename', sha256),
        'source': '',
        'requested_at': detonated_at,
        'started_at': detonated_at,
        'completed_at': completed_at,
        'duration_seconds': duration,
        'exit_status': '0',
        # post_process() only runs from detonate()'s success path (a failed
        # run raises before ever reaching here, and run_pending.sh handles
        # that as .request.failed entirely outside this script) -- so by
        # construction, every result this writes really did complete.
        'run_status': 'completed',
        'guest_started': True,
        'failure_reason': '',
        'timeout_reason': '',
        'risk_score': risk_score,
        'risk_level': risk_level,
        'network': 'isolated',
        'route': 'windows',
        'file_type': 'PE',
        'platform': 'Windows',
        'analysis_path': 'dynamic',
        'execution_mode': 'native',
        'classification': {
            'code': 'pe',
            'label': 'Windows executable',
            'platform': 'Windows',
            'category': 'executable',
            'analysis_path': 'dynamic',
            'dynamic': True,
        },
        'hashes': {'md5': '', 'sha1': '', 'sha256': sha256},
        'stdout': '',
        'stderr': '',
        'runner_log': '',
        'changed_files': regshot_changed[:200],
        'sockets_before': [],
        'sockets_after': [],
        'top_syscalls': [],
        'network_summary': {
            'packets': 0,
            'bytes': 0,
            'protocols': {},
            'events': [],
            'attempts': [],
            'guest_packets': 0,
            'guest_pcap_bytes': 0,
            'guest_protocols': {},
            'guest_events': [],
            'dns_queries': dns_domains[:500],
            'dns_events': [],
        },
        # No PE-forensics step in this pipeline yet -- see module docstring.
        'windows_forensics': {'detected': False},
        'artifacts': {
            'kernel': '', 'exiftool': '', 'pe_objdump': '',
            'processes_before': [], 'processes_after': [],
            'host_tcpdump_log': '', 'guest_tcpdump_log': '',
            'classification_error': '', 'pe_forensics_error': '',
            'console_log': '', 'qemu_log': '',
            'domain_state': 'reverted to golden image',
            'qemu_status': '',
            'host_phase': ('completed (procmon.csv missing -- export failed or timed out, #502)'
                            if procmon_missing else 'completed'),
        },
        'techniques': techniques,
        'truncated': True,
    }


def write_result(out_dir: Path, results_dir: Path) -> Path:
    payload = build_result(out_dir)
    output = results_dir / f'{payload["job"]}.json'
    results_dir.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    output.chmod(0o640)
    return output


if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print('Usage: export_result.py <out_dir> <results_dir>')
        sys.exit(1)
    path = write_result(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f'wrote {path}')
