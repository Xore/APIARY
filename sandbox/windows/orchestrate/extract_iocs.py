#!/usr/bin/env python3
"""
extract_iocs.py — Parse all sandbox artifacts and extract IOCs

Processes:
  - sysmon.evtx (Event 22 = DNS, Event 3 = network, Event 1 = process)
  - powershell_scriptblock.evtx (Event 4104 = PS download URLs)
  - fakenet_log.txt (HTTP requests, downloaded files)
  - procmon.csv (file drops, registry changes)

Outputs:
  - ioc_extracted.json per run
  - Updates Xore/Honeypot/iocs/ips.txt and urls.txt

Requires: pip install python-evtx lxml
"""

import re
import json
import csv
import sys
import logging
from pathlib import Path
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Regex patterns
RE_IP    = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
RE_URL   = re.compile(r'https?://[^\s\'"<>)\]]+', re.IGNORECASE)
RE_DOMAIN= re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
# Private IP ranges (exclude these from C2 IOCs)
PRIVATE  = re.compile(
    r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.255)'
)


def parse_sysmon_evtx(evtx_path: Path) -> dict:
    """Parse Sysmon EVTX and extract DNS queries, network conns, process trees."""
    iocs = {'dns_queries': [], 'network_connections': [], 'processes': [],
            'dns_domains': set(), 'remote_ips': set()}
    try:
        from Evtx.Evtx import Evtx
        from Evtx.Views import evtx_file_xml_view
        import xml.etree.ElementTree as ET

        with Evtx(str(evtx_path)) as log_file:
            for xml_str, _ in evtx_file_xml_view(log_file):
                root = ET.fromstring(xml_str)
                ns   = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                eid  = root.find('.//e:EventID', ns)
                if eid is None:
                    continue
                eid_val = int(eid.text)
                data = {d.get('Name'): d.text
                        for d in root.findall('.//e:Data', ns)}

                if eid_val == 22:  # DNS Query
                    domain = data.get('QueryName', '')
                    iocs['dns_queries'].append({'domain': domain,
                                                'process': data.get('Image', ''),
                                                'pid': data.get('ProcessId', '')})
                    iocs['dns_domains'].add(domain)

                elif eid_val == 3:  # Network Connection
                    dst_ip = data.get('DestinationIp', '')
                    if dst_ip and not PRIVATE.match(dst_ip):
                        iocs['network_connections'].append({
                            'dst_ip':   dst_ip,
                            'dst_port': data.get('DestinationPort', ''),
                            'process':  data.get('Image', ''),
                            'protocol': data.get('Protocol', '')
                        })
                        iocs['remote_ips'].add(dst_ip)

                elif eid_val == 1:  # Process Create
                    iocs['processes'].append({
                        'image':    data.get('Image', ''),
                        'cmdline':  data.get('CommandLine', ''),
                        'parent':   data.get('ParentImage', ''),
                        'hashes':   data.get('Hashes', ''),
                    })
    except ImportError:
        log.warning('python-evtx not installed, skipping EVTX parse')
    except Exception as e:
        log.warning(f'EVTX parse error: {e}')

    iocs['dns_domains'] = list(iocs['dns_domains'])
    iocs['remote_ips']  = list(iocs['remote_ips'])
    return iocs


def parse_ps_scriptblock(evtx_path: Path) -> dict:
    """Extract URLs and suspicious patterns from PowerShell ScriptBlock logs."""
    iocs = {'ps_urls': [], 'ps_scripts': [], 'download_cradles': []}
    try:
        from Evtx.Evtx import Evtx
        from Evtx.Views import evtx_file_xml_view
        import xml.etree.ElementTree as ET

        CRADLE_PATTERNS = [
            r'DownloadString', r'DownloadFile', r'Invoke-WebRequest',
            r'IWR ', r'iex\s', r'Invoke-Expression', r'New-Object\s+Net\.WebClient',
            r'curl\s+http', r'wget\s+http', r'Start-BitsTransfer',
        ]
        cradle_re = re.compile('|'.join(CRADLE_PATTERNS), re.IGNORECASE)

        with Evtx(str(evtx_path)) as lf:
            for xml_str, _ in evtx_file_xml_view(lf):
                root = ET.fromstring(xml_str)
                ns   = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                eid  = root.find('.//e:EventID', ns)
                if eid is None or int(eid.text) != 4104:
                    continue
                script = ''
                for d in root.findall('.//e:Data', ns):
                    if d.get('Name') == 'ScriptBlockText':
                        script = d.text or ''
                        break

                if not script:
                    continue

                urls = RE_URL.findall(script)
                iocs['ps_urls'].extend(urls)

                if cradle_re.search(script):
                    iocs['download_cradles'].append({
                        'script_preview': script[:500],
                        'urls': urls,
                    })
    except ImportError:
        log.warning('python-evtx not installed, skipping PS log parse')
    except Exception as e:
        log.warning(f'PS EVTX parse error: {e}')

    iocs['ps_urls'] = list(set(iocs['ps_urls']))
    return iocs


def parse_fakenet_log(log_path: Path) -> dict:
    """Parse FakeNet-NG log for HTTP requests and downloaded content."""
    iocs = {'http_requests': [], 'downloaded_urls': []}
    if not log_path.exists():
        return iocs
    content = log_path.read_text(errors='replace')
    for url in RE_URL.findall(content):
        if url not in iocs['downloaded_urls']:
            iocs['downloaded_urls'].append(url)
    for line in content.splitlines():
        if 'GET ' in line or 'POST ' in line:
            iocs['http_requests'].append(line.strip())
    return iocs


def extract_all(run_dir: Path) -> dict:
    """Extract all IOCs from a run directory."""
    iocs = {
        'sha256':      run_dir.name,
        'extracted_at': datetime.now(timezone.utc).isoformat(),
        'sysmon':      {},
        'powershell':  {},
        'fakenet':     {},
    }

    sysmon_evtx = run_dir / 'sysmon.evtx'
    ps_evtx     = run_dir / 'powershell_scriptblock.evtx'
    fakenet_log = run_dir / 'fakenet_log.txt'

    if sysmon_evtx.exists():
        iocs['sysmon'] = parse_sysmon_evtx(sysmon_evtx)
    if ps_evtx.exists():
        iocs['powershell'] = parse_ps_scriptblock(ps_evtx)
    if fakenet_log.exists():
        iocs['fakenet'] = parse_fakenet_log(fakenet_log)

    # Combined unique IOCs
    all_ips     = set(iocs['sysmon'].get('remote_ips', []))
    all_domains = set(iocs['sysmon'].get('dns_domains', []))
    all_urls    = set(iocs['powershell'].get('ps_urls', []) +
                      iocs['fakenet'].get('downloaded_urls', []))

    iocs['summary'] = {
        'unique_remote_ips':    sorted(all_ips),
        'unique_dns_domains':   sorted(all_domains),
        'unique_download_urls': sorted(all_urls),
        'ps_download_cradles':  iocs['powershell'].get('download_cradles', []),
    }

    (run_dir / 'ioc_extracted.json').write_text(json.dumps(iocs, indent=2))
    log.info(f'IOCs extracted: {len(all_ips)} IPs, {len(all_domains)} domains, {len(all_urls)} URLs')
    return iocs


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: extract_iocs.py <run_dir>')
        sys.exit(1)
    logging.basicConfig(level=logging.INFO)
    result = extract_all(Path(sys.argv[1]))
    print(json.dumps(result['summary'], indent=2))
