#!/usr/bin/env python3
"""
scan_samples.py — honeypot-stack multi-scanner

Uploads extracted executables (NOT archives) to multiple scanner APIs:
  - VirusTotal v3        (70+ AV engines, hash lookup + upload)
  - MalwareBazaar        (abuse.ch, hash lookup + upload)
  - Hybrid-Analysis      (Falcon Sandbox, hash lookup + full sandbox)
  - CAPE Sandbox         (self-hosted or public, dynamic analysis)
  - Malshare             (hash lookup + upload)
  - Any.run              (interactive sandbox, optional)

Archive handling:
  - ZIP, ZIP with password, 7z, tar.gz, tar.bz2 are extracted
  - Each extracted file is scanned individually
  - Supported archive passwords: infected, malware, infected123, virus
  - Archives themselves are NOT uploaded (scanners see raw executables)

Usage:
  python3 scan_samples.py \
    --file-list /tmp/changed_files.txt \
    --output-dir reports/scanner/ \
    --archive-passwords infected,malware \
    --wait-results

Environment variables (set as GitHub secrets):
  VT_API_KEY            VirusTotal API key
  MALWAREBAZAAR_API_KEY MalwareBazaar API key
  HYBRID_ANALYSIS_KEY   Hybrid-Analysis API key
  MALSHARE_API_KEY      Malshare API key
  ANYRUN_API_KEY        Any.run API key (optional)
  CAPE_API_URL          CAPE URL (optional, e.g. http://cape.local:8000)
  CAPE_API_KEY          CAPE API key (optional)
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('scanner')

# ───────────────────────────────────────────────────────────────────
# Archive extensions — these will be extracted, not uploaded
ARCHIVE_EXTENSIONS = {
    '.zip', '.7z', '.tar', '.gz', '.bz2', '.xz',
    '.tgz', '.tbz2', '.rar'
}

# File type signatures that indicate an executable worth scanning
SCANNABLE_MAGIC = [
    b'MZ',           # Windows PE (EXE, DLL, SYS)
    b'\x7fELF',      # Linux ELF
    b'\xca\xfe\xba\xbe',  # Mach-O fat binary
    b'\xfe\xed\xfa\xce',  # Mach-O 32-bit
    b'\xfe\xed\xfa\xcf',  # Mach-O 64-bit
    b'PK\x03\x04',   # ZIP / DOCX / XLSX / JAR (include: Office macros, JARs)
    b'%PDF',         # PDF (often weaponized)
    b'{\\rtf',       # RTF (often weaponized)
    b'<script',      # Script
    b'#!/',          # Shell script
]

# Max file size to upload (32 MB for VT free; 64 MB for HA)
MAX_UPLOAD_BYTES = 32 * 1024 * 1024


# ───────────────────────────────────────────────────────────────────
# Hashing
# ───────────────────────────────────────────────────────────────────
def hash_file(path: Path) -> dict:
    sha256 = hashlib.sha256()
    sha1   = hashlib.sha1()
    md5    = hashlib.md5()
    data   = path.read_bytes()
    for h in (sha256, sha1, md5):
        h.update(data)
    return {
        'sha256': sha256.hexdigest(),
        'sha1':   sha1.hexdigest(),
        'md5':    md5.hexdigest(),
        'size':   len(data),
    }


def is_scannable(path: Path) -> bool:
    """Return True if file looks like something worth scanning (not text/config)."""
    try:
        header = path.read_bytes()[:8]
    except Exception:
        return False
    # Check against known binary magic bytes
    for magic in SCANNABLE_MAGIC:
        if header[:len(magic)] == magic:
            return True
    # Also allow anything without a clear text header > 512 bytes
    # (catches obfuscated scripts, polyglots)
    if len(header) >= 4 and not all(32 <= b < 127 or b in (9, 10, 13) for b in header):
        return True
    return False


# ───────────────────────────────────────────────────────────────────
# Archive extraction
# ───────────────────────────────────────────────────────────────────
def extract_archive(path: Path, passwords: list, tmpdir: Path) -> list:
    """
    Extract an archive and return list of extracted file Paths.
    Tries each password in order. Returns [] if not an archive or extraction fails.
    """
    suffix = path.suffix.lower()
    extracted = []
    dest = tmpdir / path.stem
    dest.mkdir(parents=True, exist_ok=True)

    if suffix in ('.zip',):
        # Try pyzipper (supports AES-encrypted zips)
        try:
            import pyzipper
            opened = False
            for pwd in ([''] + passwords):
                try:
                    with pyzipper.AESZipFile(path) as zf:
                        zf.extractall(dest, pwd=pwd.encode() if pwd else None)
                    opened = True
                    log.info(f'  Extracted ZIP: {path.name} (password={repr(pwd)})')
                    break
                except RuntimeError:
                    continue
            if not opened:
                log.warning(f'  Could not extract ZIP (bad password?): {path.name}')
                return []
        except Exception as e:
            log.warning(f'  ZIP extraction failed: {e}')
            return []

    elif suffix in ('.7z',):
        try:
            import py7zr
            for pwd in ([''] + passwords):
                try:
                    with py7zr.SevenZipFile(path, mode='r', password=pwd or None) as z:
                        z.extractall(dest)
                    log.info(f'  Extracted 7z: {path.name}')
                    break
                except Exception:
                    continue
        except Exception as e:
            log.warning(f'  7z extraction failed: {e}')
            return []

    elif suffix in ('.tar', '.gz', '.tgz', '.bz2', '.tbz2', '.xz'):
        import tarfile
        try:
            with tarfile.open(path) as tf:
                tf.extractall(dest)
            log.info(f'  Extracted tar: {path.name}')
        except Exception as e:
            log.warning(f'  tar extraction failed: {e}')
            return []

    elif suffix in ('.rar',):
        try:
            import rarfile
            for pwd in ([''] + passwords):
                try:
                    with rarfile.RarFile(path) as rf:
                        rf.extractall(dest, pwd=pwd or None)
                    log.info(f'  Extracted RAR: {path.name}')
                    break
                except rarfile.BadRarFile:
                    continue
        except Exception as e:
            log.warning(f'  RAR extraction failed: {e}')
            return []
    else:
        return []  # Not an archive

    # Collect all extracted files recursively
    for f in dest.rglob('*'):
        if f.is_file():
            extracted.append(f)
    return extracted


def expand_file(path: Path, passwords: list, tmpdir: Path) -> list:
    """
    Given a path, return the list of files to scan:
    - If archive: return extracted contents
    - If scannable: return [path] itself
    - Otherwise: return []
    """
    suffix = path.suffix.lower()
    if suffix in ARCHIVE_EXTENSIONS or suffix in ('.zip',):
        extracted = extract_archive(path, passwords, tmpdir)
        if extracted:
            # Recursively expand nested archives
            results = []
            for f in extracted:
                results.extend(expand_file(f, passwords, tmpdir))
            return results
        # If extraction failed, try scanning the archive itself
        return [path] if is_scannable(path) else []
    elif is_scannable(path):
        return [path]
    else:
        log.debug(f'  Skipping non-scannable file: {path.name}')
        return []


# ───────────────────────────────────────────────────────────────────
# Scanner: VirusTotal v3
# ───────────────────────────────────────────────────────────────────
class VirusTotalScanner:
    """VirusTotal v3 API — 70+ AV engines.
    Free tier: 4 requests/min, 500/day, 15.5k/month.
    Docs: https://developers.virustotal.com/reference
    """
    BASE = 'https://www.virustotal.com/api/v3'

    def __init__(self, api_key: str):
        self.key = api_key
        self.headers = {'x-apikey': api_key}
        self._last_request = 0

    def _rate_limit(self):
        # Free tier: max 4 req/min → sleep 15s between requests
        elapsed = time.time() - self._last_request
        if elapsed < 15:
            time.sleep(15 - elapsed)
        self._last_request = time.time()

    def lookup_hash(self, sha256: str) -> dict | None:
        """Return existing report if hash is known, else None."""
        self._rate_limit()
        r = requests.get(
            f'{self.BASE}/files/{sha256}',
            headers=self.headers,
            timeout=30
        )
        if r.status_code == 200:
            data = r.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            return {
                'source': 'virustotal',
                'known': True,
                'positives': stats.get('malicious', 0),
                'total': sum(stats.values()),
                'stats': stats,
                'names': data.get('names', []),
                'type_description': data.get('type_description', ''),
                'permalink': f'https://www.virustotal.com/gui/file/{sha256}',
            }
        return None

    def upload(self, path: Path) -> dict:
        """Upload file and return scan result."""
        self._rate_limit()
        size = path.stat().st_size
        if size > MAX_UPLOAD_BYTES:
            # VT large file upload: get upload URL first
            r = requests.get(
                f'{self.BASE}/files/upload_url',
                headers=self.headers, timeout=30
            )
            upload_url = r.json().get('data')
        else:
            upload_url = f'{self.BASE}/files'

        with open(path, 'rb') as fh:
            r = requests.post(
                upload_url,
                headers=self.headers,
                files={'file': (path.name, fh)},
                timeout=120
            )
        r.raise_for_status()
        analysis_id = r.json().get('data', {}).get('id')
        log.info(f'  VT upload OK → analysis_id={analysis_id}')
        return {'source': 'virustotal', 'known': False, 'analysis_id': analysis_id,
                'permalink': f'https://www.virustotal.com/gui/file-analysis/{analysis_id}'}

    def get_analysis(self, analysis_id: str, wait: bool = True) -> dict:
        """Poll analysis until complete."""
        url = f'{self.BASE}/analyses/{analysis_id}'
        for attempt in range(20):
            self._rate_limit()
            r = requests.get(url, headers=self.headers, timeout=30)
            data = r.json().get('data', {}).get('attributes', {})
            status = data.get('status')
            if status == 'completed':
                stats = data.get('stats', {})
                return {
                    'source': 'virustotal',
                    'status': 'completed',
                    'positives': stats.get('malicious', 0),
                    'total': sum(stats.values()),
                    'stats': stats,
                }
            if not wait:
                return {'source': 'virustotal', 'status': status}
            log.info(f'  VT analysis {status}, waiting... ({attempt+1}/20)')
            time.sleep(30)
        return {'source': 'virustotal', 'status': 'timeout'}

    def scan(self, path: Path, hashes: dict, wait: bool = True) -> dict:
        result = self.lookup_hash(hashes['sha256'])
        if result:
            log.info(f'  VT: hash known → {result["positives"]}/{result["total"]} detections')
            return result
        log.info(f'  VT: hash unknown, uploading {path.name}...')
        upload_result = self.upload(path)
        if wait and 'analysis_id' in upload_result:
            analysis = self.get_analysis(upload_result['analysis_id'], wait=True)
            upload_result.update(analysis)
        return upload_result


# ───────────────────────────────────────────────────────────────────
# Scanner: MalwareBazaar (abuse.ch)
# ───────────────────────────────────────────────────────────────────
class MalwareBazaarScanner:
    """abuse.ch MalwareBazaar API.
    Free. Upload malware samples to the community database.
    Docs: https://bazaar.abuse.ch/api/
    """
    BASE = 'https://mb-api.abuse.ch/api/v1/'

    def __init__(self, api_key: str):
        self.key = api_key

    def lookup_hash(self, sha256: str) -> dict | None:
        r = requests.post(
            self.BASE,
            data={'query': 'get_info', 'hash': sha256},
            timeout=30
        )
        data = r.json()
        if data.get('query_status') == 'hash_not_found':
            return None
        if data.get('query_status') == 'ok':
            info = data.get('data', [{}])[0]
            return {
                'source': 'malwarebazaar',
                'known': True,
                'file_type': info.get('file_type'),
                'file_name': info.get('file_name'),
                'tags': info.get('tags', []),
                'signature': info.get('signature'),
                'first_seen': info.get('first_seen'),
                'reporter': info.get('reporter'),
                'permalink': f'https://bazaar.abuse.ch/sample/{sha256}/',
            }
        return None

    def upload(self, path: Path, tags: list = None) -> dict:
        tags = tags or ['honeypot', 'honeypot-stack']
        with open(path, 'rb') as fh:
            r = requests.post(
                self.BASE,
                data={
                    'query': 'upload_sample',
                    'delivery_method': 'other',
                    'tags': json.dumps(tags),
                    'api_key': self.key,
                },
                files={'file': (path.name, fh)},
                timeout=120
            )
        data = r.json()
        if data.get('query_status') == 'sample_submitted':
            sha256 = data.get('data', {}).get('sha256_hash', '')
            return {
                'source': 'malwarebazaar',
                'known': False,
                'submitted': True,
                'sha256': sha256,
                'permalink': f'https://bazaar.abuse.ch/sample/{sha256}/',
            }
        return {'source': 'malwarebazaar', 'error': data.get('query_status')}

    def scan(self, path: Path, hashes: dict, **_) -> dict:
        result = self.lookup_hash(hashes['sha256'])
        if result:
            log.info(f'  MalwareBazaar: known → {result.get("signature", "unknown")}')
            return result
        log.info(f'  MalwareBazaar: uploading {path.name}...')
        return self.upload(path)


# ───────────────────────────────────────────────────────────────────
# Scanner: Hybrid-Analysis (Falcon Sandbox)
# ───────────────────────────────────────────────────────────────────
class HybridAnalysisScanner:
    """Hybrid-Analysis (Falcon Sandbox) API.
    Free tier available. Dynamic + static analysis.
    Docs: https://www.hybrid-analysis.com/docs/api/v2
    """
    BASE = 'https://www.hybrid-analysis.com/api/v2'

    def __init__(self, api_key: str):
        self.key = api_key
        self.headers = {
            'api-key': api_key,
            'User-Agent': 'Falcon Sandbox',
            'accept': 'application/json',
        }

    def lookup_hash(self, sha256: str) -> dict | None:
        r = requests.get(
            f'{self.BASE}/search/hash',
            params={'hash': sha256},
            headers=self.headers,
            timeout=30
        )
        if r.status_code == 200:
            results = r.json()
            if results:
                top = results[0]
                return {
                    'source': 'hybrid_analysis',
                    'known': True,
                    'verdict': top.get('verdict'),
                    'threat_score': top.get('threat_score'),
                    'av_detect': top.get('av_detect'),
                    'threat_level': top.get('threat_level_human'),
                    'job_id': top.get('job_id'),
                    'permalink': f'https://www.hybrid-analysis.com/sample/{sha256}',
                }
        return None

    def submit(self, path: Path, env_id: int = 120) -> dict:
        # env_id: 120=Windows 10 64-bit, 110=Windows 7 64-bit, 300=Linux
        with open(path, 'rb') as fh:
            r = requests.post(
                f'{self.BASE}/submit/file',
                headers=self.headers,
                data={
                    'environment_id': env_id,
                    'allow_community_access': True,
                    'comment': 'honeypot-stack automated submission',
                },
                files={'file': (path.name, fh)},
                timeout=120
            )
        if r.status_code in (200, 201):
            data = r.json()
            return {
                'source': 'hybrid_analysis',
                'known': False,
                'job_id': data.get('job_id'),
                'sha256': data.get('sha256'),
                'environment_id': env_id,
                'permalink': f'https://www.hybrid-analysis.com/sample/{data.get("sha256", "")}',
            }
        return {'source': 'hybrid_analysis', 'error': r.text[:200]}

    def scan(self, path: Path, hashes: dict, **_) -> dict:
        result = self.lookup_hash(hashes['sha256'])
        if result:
            log.info(f'  HybridAnalysis: known → verdict={result.get("verdict")}')
            return result
        log.info(f'  HybridAnalysis: submitting {path.name} (Win10 env)...')
        return self.submit(path)


# ───────────────────────────────────────────────────────────────────
# Scanner: Malshare
# ───────────────────────────────────────────────────────────────────
class MalshareScanner:
    """Malshare API — community malware repository.
    Free. 2000 req/day.
    Docs: https://malshare.com/doc.php
    """
    BASE = 'https://malshare.com/api.php'

    def __init__(self, api_key: str):
        self.key = api_key

    def lookup_hash(self, sha256: str) -> dict | None:
        r = requests.get(
            self.BASE,
            params={'api_key': self.key, 'action': 'details', 'hash': sha256},
            timeout=30
        )
        if r.status_code == 200 and r.json().get('SHA256'):
            data = r.json()
            return {
                'source': 'malshare',
                'known': True,
                'type': data.get('F_TYPE'),
                'sources': data.get('SOURCES', []),
                'permalink': f'https://malshare.com/sample.php?action=detail&hash={sha256}',
            }
        return None

    def upload(self, path: Path) -> dict:
        with open(path, 'rb') as fh:
            r = requests.post(
                self.BASE,
                params={'api_key': self.key, 'action': 'upload'},
                files={'upload': (path.name, fh)},
                timeout=120
            )
        if r.status_code == 200:
            return {'source': 'malshare', 'known': False, 'submitted': True}
        return {'source': 'malshare', 'error': r.text[:200]}

    def scan(self, path: Path, hashes: dict, **_) -> dict:
        result = self.lookup_hash(hashes['sha256'])
        if result:
            log.info(f'  Malshare: hash known')
            return result
        log.info(f'  Malshare: uploading {path.name}...')
        return self.upload(path)


# ───────────────────────────────────────────────────────────────────
# Scanner: CAPE Sandbox
# ───────────────────────────────────────────────────────────────────
class CAPESandboxScanner:
    """CAPE Sandbox API (self-hosted or public cape.wtf).
    Cuckoo fork with config extraction, YARA, memory dumps.
    Docs: https://capesandbox.com/apiv2/
    """

    def __init__(self, base_url: str, api_key: str = None):
        self.base = base_url.rstrip('/')
        self.headers = {}
        if api_key:
            self.headers['Authorization'] = f'Token {api_key}'

    def lookup_hash(self, sha256: str) -> dict | None:
        try:
            r = requests.get(
                f'{self.base}/apiv2/tasks/search/sha256/{sha256}/',
                headers=self.headers,
                timeout=30
            )
            if r.status_code == 200:
                data = r.json()
                if data.get('data'):
                    task = data['data'][0]
                    return {
                        'source': 'cape',
                        'known': True,
                        'task_id': task.get('id'),
                        'status': task.get('status'),
                        'score': task.get('malscore'),
                        'family': task.get('target', {}).get('file', {}).get('cape_type'),
                        'permalink': f'{self.base}/analysis/{task.get("id")}/summary/',
                    }
        except Exception:
            pass
        return None

    def submit(self, path: Path) -> dict:
        try:
            with open(path, 'rb') as fh:
                r = requests.post(
                    f'{self.base}/apiv2/tasks/create/file/',
                    headers=self.headers,
                    files={'file': (path.name, fh)},
                    data={'options': 'procmemdump=1,hollowshunter=1'},
                    timeout=120
                )
            if r.status_code == 200:
                task_id = r.json().get('data', {}).get('task_id')
                return {
                    'source': 'cape',
                    'known': False,
                    'task_id': task_id,
                    'permalink': f'{self.base}/analysis/{task_id}/summary/',
                }
        except Exception as e:
            return {'source': 'cape', 'error': str(e)}
        return {'source': 'cape', 'error': 'submission failed'}

    def scan(self, path: Path, hashes: dict, **_) -> dict:
        result = self.lookup_hash(hashes['sha256'])
        if result:
            log.info(f'  CAPE: known → task_id={result.get("task_id")} score={result.get("score")}')
            return result
        log.info(f'  CAPE: submitting {path.name}...')
        return self.submit(path)


# ───────────────────────────────────────────────────────────────────
# Scanner: Any.run
# ───────────────────────────────────────────────────────────────────
class AnyRunScanner:
    """Any.run interactive sandbox API.
    Paid tiers only for API. Interactive cloud sandbox.
    Docs: https://any.run/api-documentation/
    """
    BASE = 'https://api.any.run/v1'

    def __init__(self, api_key: str):
        self.headers = {
            'Authorization': f'API-Key {api_key}',
            'Content-Type': 'application/json',
        }

    def submit(self, path: Path, env_os: str = 'windows', env_bits: int = 64) -> dict:
        # Step 1: upload file to get fileUUID
        with open(path, 'rb') as fh:
            r = requests.post(
                f'{self.BASE}/file',
                headers={'Authorization': self.headers['Authorization']},
                files={'file': (path.name, fh)},
                timeout=120
            )
        if r.status_code not in (200, 201):
            return {'source': 'anyrun', 'error': r.text[:200]}
        file_uuid = r.json().get('data', {}).get('fileUUID')

        # Step 2: create task
        payload = {
            'env': {'OS': env_os, 'Bitness': env_bits, 'Type': 'complete'},
            'obj': {'type': 'file', 'fileUUID': file_uuid},
        }
        r2 = requests.post(
            f'{self.BASE}/analysis',
            headers=self.headers,
            json=payload,
            timeout=60
        )
        if r2.status_code in (200, 201):
            task_id = r2.json().get('data', {}).get('taskid')
            return {
                'source': 'anyrun',
                'task_id': task_id,
                'permalink': f'https://app.any.run/tasks/{task_id}',
            }
        return {'source': 'anyrun', 'error': r2.text[:200]}

    def scan(self, path: Path, hashes: dict, **_) -> dict:
        log.info(f'  Any.run: submitting {path.name}...')
        return self.submit(path)


# ───────────────────────────────────────────────────────────────────
# Main orchestrator
# ───────────────────────────────────────────────────────────────────
def build_scanners() -> list:
    """Instantiate all configured scanners (skip if API key not set)."""
    scanners = []
    if k := os.environ.get('VT_API_KEY'):
        scanners.append(VirusTotalScanner(k))
        log.info('[+] VirusTotal enabled')
    if k := os.environ.get('MALWAREBAZAAR_API_KEY'):
        scanners.append(MalwareBazaarScanner(k))
        log.info('[+] MalwareBazaar enabled')
    if k := os.environ.get('HYBRID_ANALYSIS_KEY'):
        scanners.append(HybridAnalysisScanner(k))
        log.info('[+] Hybrid-Analysis enabled')
    if k := os.environ.get('MALSHARE_API_KEY'):
        scanners.append(MalshareScanner(k))
        log.info('[+] Malshare enabled')
    if url := os.environ.get('CAPE_API_URL'):
        k = os.environ.get('CAPE_API_KEY', '')
        scanners.append(CAPESandboxScanner(url, k))
        log.info(f'[+] CAPE Sandbox enabled ({url})')
    if k := os.environ.get('ANYRUN_API_KEY'):
        scanners.append(AnyRunScanner(k))
        log.info('[+] Any.run enabled')
    if not scanners:
        log.error('No scanner API keys configured. Set at least VT_API_KEY.')
        sys.exit(1)
    return scanners


def scan_file(path: Path, scanners: list, output_dir: Path, wait: bool) -> dict:
    hashes = hash_file(path)
    sha256 = hashes['sha256']
    log.info(f'\nScanning: {path.name} ({sha256[:12]}...)  {hashes["size"]:,} bytes')

    report = {
        'file': str(path),
        'filename': path.name,
        'sha256': sha256,
        'sha1':   hashes['sha1'],
        'md5':    hashes['md5'],
        'size':   hashes['size'],
        'scanned_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'results': {},
    }

    for scanner in scanners:
        name = scanner.__class__.__name__
        try:
            result = scanner.scan(path, hashes, wait=wait)
            report['results'][name] = result
        except Exception as e:
            log.error(f'  {name} error: {e}')
            report['results'][name] = {'error': str(e)}

    # Write per-sample report
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / f'{sha256}.json'
    report_path.write_text(json.dumps(report, indent=2))
    log.info(f'  Report: {report_path}')
    return report


def main():
    parser = argparse.ArgumentParser(description='honeypot-stack multi-scanner')
    parser.add_argument('--file-list',   required=True, help='File with one path per line')
    parser.add_argument('--output-dir',  default='reports/scanner/', help='Output directory for JSON reports')
    parser.add_argument('--archive-passwords', default='infected,malware,infected123,virus',
                        help='Comma-separated archive passwords to try')
    parser.add_argument('--wait-results', action='store_true',
                        help='Wait for VT/HA analysis to complete before writing report')
    args = parser.parse_args()

    passwords = [p.strip() for p in args.archive_passwords.split(',') if p.strip()]
    output_dir = Path(args.output_dir)
    scanners = build_scanners()

    # Read file list
    file_list_path = Path(args.file_list)
    if not file_list_path.exists():
        log.error(f'File list not found: {file_list_path}')
        sys.exit(1)

    lines = [l.strip() for l in file_list_path.read_text().splitlines() if l.strip()]
    if not lines:
        log.info('No files to scan.')
        return

    log.info(f'Input files: {len(lines)}')
    log.info(f'Archive passwords: {passwords}')
    log.info(f'Scanners: {[s.__class__.__name__ for s in scanners]}')

    tmpdir = Path(tempfile.mkdtemp(prefix='honeypot_scan_'))
    all_reports = []

    try:
        for line in lines:
            path = Path(line)
            if not path.exists():
                log.warning(f'File not found, skipping: {path}')
                continue

            # Expand archives → individual files
            to_scan = expand_file(path, passwords, tmpdir)
            if not to_scan:
                log.info(f'Skipping (not scannable / empty): {path.name}')
                continue

            for f in to_scan:
                if f.stat().st_size == 0:
                    log.info(f'  Skipping empty file: {f.name}')
                    continue
                report = scan_file(f, scanners, output_dir, wait=args.wait_results)
                all_reports.append(report)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # Summary
    log.info(f'\n{"="*60}')
    log.info(f'Scanned {len(all_reports)} file(s):')
    for r in all_reports:
        vt = r['results'].get('VirusTotalScanner', {})
        pos = vt.get('positives', '?')
        total = vt.get('total', '?')
        log.info(f'  {r["sha256"][:16]}... {r["filename"]:30s}  VT: {pos}/{total}')
    log.info(f'Reports in: {output_dir}')


if __name__ == '__main__':
    main()
