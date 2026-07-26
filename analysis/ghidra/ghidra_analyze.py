#!/usr/bin/env python3
"""
ghidra_analyze.py — GitHub Actions integration script
Submits samples to the Ghidra REST service, runs AI triage via Rev\u00b7Deck,
and saves all artifacts to reports/ghidra/<sha256>/

Usage:
  python3 ghidra_analyze.py --file-list /tmp/changed_files.txt
  python3 ghidra_analyze.py --sample samples/ELF/deadbeef...

Environment:
  GHIDRA_API_BASE   (default: http://127.0.0.1:9090)
  REVDECK_API_BASE  (default: http://127.0.0.1:5000)  optional
  LLM_TRIAGE        (default: 1) set 0 to skip Rev\u00b7Deck AI step
"""

import os
import sys
import json
import time
import hashlib
import argparse
import logging
from pathlib import Path

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

GHIDRA_API  = os.environ.get('GHIDRA_API_BASE', 'http://127.0.0.1:9090')
REVDECK_API = os.environ.get('REVDECK_API_BASE', 'http://127.0.0.1:5000')
LLM_TRIAGE  = os.environ.get('LLM_TRIAGE', '1') == '1'
REPORT_DIR  = Path('reports/ghidra')


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def ghidra_health_check() -> bool:
    try:
        r = requests.get(f'{GHIDRA_API}/readyz', timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def ghidra_submit(path: Path) -> str | None:
    """Upload binary; return analysis_id."""
    with open(path, 'rb') as f:
        r = requests.post(
            f'{GHIDRA_API}/analyze',
            files={'file': (path.name, f, 'application/octet-stream')},
            data={'analysis_timeout': '1800'},
            timeout=120
        )
    if r.status_code == 200:
        return r.json().get('analysis_id')
    log.warning(f'Ghidra submit failed: {r.status_code} {r.text[:200]}')
    return None


def ghidra_wait(analysis_id: str, max_wait: int = 1800) -> bool:
    """Poll until completed or timeout."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            r = requests.get(f'{GHIDRA_API}/analyses/{analysis_id}/status', timeout=15)
            status = r.json().get('status', '')
            log.info(f'Ghidra status: {status}')
            if status == 'completed':
                return True
            if status == 'failed':
                log.error('Ghidra analysis failed')
                return False
        except Exception as e:
            log.warning(f'Ghidra poll error: {e}')
        time.sleep(20)
    log.warning('Ghidra analysis timed out')
    return False


def ghidra_export(analysis_id: str, out_dir: Path):
    """Download all available artifacts."""
    out_dir.mkdir(parents=True, exist_ok=True)
    endpoints = {
        'functions.json': f'/functions?analysis_id={analysis_id}',
        'strings.json':   f'/strings?analysis_id={analysis_id}',
        'imports.json':   f'/imports?analysis_id={analysis_id}',
    }
    for filename, endpoint in endpoints.items():
        try:
            r = requests.get(f'{GHIDRA_API}{endpoint}', timeout=60)
            if r.status_code == 200:
                (out_dir / filename).write_text(json.dumps(r.json(), indent=2))
                log.info(f'Saved {filename}')
        except Exception as e:
            log.warning(f'Export {filename} failed: {e}')

    # Decompile top 10 functions by caller count
    try:
        funcs = requests.get(f'{GHIDRA_API}/functions?analysis_id={analysis_id}', timeout=30).json()
        top   = sorted([f for f in funcs if not f.get('is_thunk')],
                       key=lambda x: -x.get('caller_count', 0))[:10]
        decomps = []
        for fn in top:
            addr = fn.get('address')
            try:
                rd = requests.get(f'{GHIDRA_API}/decompile/{addr}?analysis_id={analysis_id}', timeout=30)
                if rd.status_code == 200:
                    decomps.append({'address': addr, 'name': fn.get('name'), **rd.json()})
                time.sleep(1)
            except Exception as e:
                log.warning(f'Decompile {addr} failed: {e}')
        (out_dir / 'decompiled.json').write_text(json.dumps(decomps, indent=2))
        log.info(f'Decompiled {len(decomps)} functions')
    except Exception as e:
        log.warning(f'Decompile export failed: {e}')


def revdeck_triage(path: Path, out_dir: Path) -> dict | None:
    """Upload to Rev\u00b7Deck and run autonomous program_triage + suspicious_behavior."""
    if not LLM_TRIAGE:
        return None
    try:
        # Check Rev\u00b7Deck health
        r = requests.get(f'{REVDECK_API}/readyz', timeout=5)
        if r.status_code != 200:
            log.warning('Rev\u00b7Deck not available, skipping AI triage')
            return None
    except Exception:
        log.warning('Rev\u00b7Deck unreachable, skipping AI triage')
        return None

    # Upload binary
    with open(path, 'rb') as f:
        upload_r = requests.post(
            f'{REVDECK_API}/api/upload',
            files={'file': (path.name, f)},
            timeout=120
        )
    if upload_r.status_code != 200:
        log.warning(f'Rev\u00b7Deck upload failed: {upload_r.status_code}')
        return None

    job_id = upload_r.json().get('job_id')
    log.info(f'Rev\u00b7Deck job_id={job_id}')

    # Run workflows
    results = {}
    for workflow in ['program_triage', 'suspicious_behavior', 'attack_surface_triage']:
        try:
            wr = requests.post(
                f'{REVDECK_API}/api/chat',
                json={'job_id': job_id, 'workflow': workflow, 'mode': 'autonomous', 'step_budget': 10},
                timeout=300
            )
            if wr.status_code == 200:
                results[workflow] = wr.json()
                log.info(f'Rev\u00b7Deck {workflow} complete')
        except Exception as e:
            log.warning(f'Rev\u00b7Deck {workflow} failed: {e}')

    (out_dir / 'revdeck_triage.json').write_text(json.dumps(results, indent=2))
    return results


def analyze_sample(sample_path: Path):
    if not sample_path.exists() or sample_path.name == '.gitkeep':
        return

    sha   = sha256_of(sample_path)
    out   = REPORT_DIR / sha
    out.mkdir(parents=True, exist_ok=True)

    log.info(f'--- Ghidra analysis: {sample_path} ({sha[:16]}...) ---')

    if not ghidra_health_check():
        log.error('Ghidra service unreachable. Is docker-compose.ghidra.yml up?')
        return

    aid = ghidra_submit(sample_path)
    if not aid:
        return

    if not ghidra_wait(aid):
        return

    ghidra_export(aid, out)
    revdeck_triage(sample_path, out)

    log.info(f'Ghidra artifacts saved to {out}/')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file-list')
    parser.add_argument('--sample')
    args = parser.parse_args()

    paths = []
    if args.file_list:
        with open(args.file_list) as f:
            paths = [Path(l.strip()) for l in f if l.strip()]
    elif args.sample:
        paths = [Path(args.sample)]
    else:
        paths = [p for p in Path('samples').rglob('*') if p.is_file() and p.name != '.gitkeep']

    for p in paths:
        try:
            analyze_sample(p)
        except Exception as e:
            log.error(f'Error: {p}: {e}', exc_info=True)


if __name__ == '__main__':
    main()
