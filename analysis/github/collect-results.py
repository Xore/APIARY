#!/usr/bin/env python3
"""collect-results.py -- poll Xore/honeypot for pending publications and pull
their scanner verdicts back into GITHUB_ANALYSIS_RESULTS_DIR.

Runs on a timer (honeypot-github-collect.timer), not on publication -- polling
GitHub is not the analyst's click path and must not block the submit button.
Reads *.pending records publish-sample.sh writes (sha256, commit, sensor,
bucket), resolves the analyze.yml run for that commit, waits for it to
conclude, then reads the results analyze.yml commits back into the same repo
(reports/scanner/{sha256}.json, iocs/families.csv, yara-rules/auto/) straight
off the local clone rather than the GitHub API, since that's already the
credentialed, rate-limit-free copy publish-sample.sh pushed from.

Stdlib only, matching analysis/ghidra/worker/ghidra-worker.py's reasoning:
this runs on the host outside any container, and a worker that needs pip
install before it can drain a queue is a worker that will be broken after the
next OS upgrade.
"""
from __future__ import annotations

import csv
import fcntl
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

RESULT_VERSION = 1

GITHUB_REPO = os.environ.get("GITHUB_REPO", "Xore/honeypot")
GITHUB_CLONE = Path(os.environ.get("GITHUB_CLONE", "/var/lib/honeypot-github/repo"))
GH_PAT = os.environ.get("GH_PAT", "")
# Distinct from GITHUB_ANALYSIS_REQUEST_DIR (incoming .request markers)
# despite the similar name -- explicit on purpose, matching
# process-github-requests.sh, after a dirname-based derivation here once
# quietly computed the same path as the request spool itself.
PENDING_DIR = Path(os.environ.get("GITHUB_ANALYSIS_PENDING_DIR", "/var/lib/honeypot-github/pending"))
RESULTS_DIR = Path(os.environ.get("GITHUB_ANALYSIS_RESULTS_DIR", "/var/lib/honeypot-github/results"))
MAX_WAIT = int(os.environ.get("GITHUB_ANALYSIS_MAX_WAIT", "5400"))
POLL_INTERVAL = int(os.environ.get("GITHUB_ANALYSIS_POLL_INTERVAL", "30"))
LOCK_FILE = Path(os.environ.get("GITHUB_ANALYSIS_LOCK", "/run/lock/honeypot-github-collect.lock"))
API_BASE = f"https://api.github.com/repos/{GITHUB_REPO}"


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CollectError(RuntimeError):
    """Anything that means this sample's result could not be resolved yet."""


def api_get(path: str) -> dict:
    req = urllib.request.Request(f"{API_BASE}{path}")
    req.add_header("Accept", "application/vnd.github+json")
    if GH_PAT:
        req.add_header("Authorization", f"Bearer {GH_PAT}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise CollectError(f"GET {path} -> HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise CollectError(f"GET {path} -> {e}") from e


def find_run(commit: str) -> dict | None:
    """The analyze.yml run triggered by our push, if GitHub has scheduled it yet."""
    data = api_get(f"/actions/runs?head_sha={commit}&per_page=5")
    for run in data.get("workflow_runs", []):
        if run.get("path", "").endswith("analyze.yml"):
            return run
    return None


def git_pull() -> str:
    """Fast-forward the local clone to origin/main and return the resulting
    HEAD commit -- the ref the PDF (and everything else build_result() reads
    off disk) actually exists at. This is deliberately NOT the same as the
    original push commit publish-sample.sh recorded: analyze.yml commits the
    scanner JSON, YARA rules and PDF report in its own *later* commit, after
    the original push. Using the stale push commit to build a
    raw.githubusercontent.com URL 404s, because that file did not exist yet
    at that commit (#255)."""
    subprocess.run(
        ["git", "-C", str(GITHUB_CLONE), "fetch", "--quiet", "origin"],
        check=True, timeout=120,
    )
    subprocess.run(
        ["git", "-C", str(GITHUB_CLONE), "reset", "--quiet", "--hard", "origin/main"],
        check=True, timeout=60,
    )
    return subprocess.run(
        ["git", "-C", str(GITHUB_CLONE), "rev-parse", "HEAD"],
        check=True, timeout=30, capture_output=True, text=True,
    ).stdout.strip()


def family_for(sha256: str) -> str:
    path = GITHUB_CLONE / "iocs" / "families.csv"
    if not path.is_file():
        return ""
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            if row and row[0].lower() == sha256:
                return row[1] if len(row) > 1 else ""
    return ""


def auto_rules_for(sha256: str) -> list:
    auto_dir = GITHUB_CLONE / "yara-rules" / "auto"
    if not auto_dir.is_dir():
        return []
    hits = []
    for rule_file in sorted(auto_dir.glob("*.yar")):
        try:
            if sha256 in rule_file.read_text(errors="replace"):
                hits.append(rule_file.name)
        except OSError:
            continue
    return hits


def safe_stem(name: str) -> str:
    """Byte-for-byte match of Xore/honeypot's report.py::_safe_stem, since the
    per-sample PDF filename this has to guess is built with it. Confirmed
    against a real committed report (#255): the scanner JSON's own "filename"
    is the *original* captured name from inside the pushed zip (e.g. "ChatGPT
    Installer.exe", unrelated to the zip's own {sha256}.zip outer name), and
    the real PDF is "ChatGPT_Installer.exe-<date>.pdf" -- the space replaced
    by report.py's sanitizer, not the zip's basename at all.
    """
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
    return stem or "sample"


def normalize_scanners(results: dict) -> list:
    """Xore/honeypot's analyze_samples.py writes one dict per scanner class
    under a top-level "results" key (not a "scanners" list), and marks
    per-scanner success as "_ok" (underscore-prefixed), not "ok" -- confirmed
    against a real committed report (#255). Flattens that into the normalized
    shape dashboard/github_analysis.go's githubAnalysisScanner expects.
    """
    normalized = []
    for name, r in (results or {}).items():
        if not isinstance(r, dict):
            continue
        normalized.append({
            "source": r.get("source") or name,
            "ok": bool(r.get("_ok", False)),
            "positives": r.get("positives") or 0,
            "total": r.get("total") or 0,
            "suspicious": bool(r.get("suspicious")),
            "permalink": r.get("permalink") or "",
            "error": r.get("error") or "",
        })
    return normalized


def build_result(pending: dict, run: dict, report_commit: str) -> dict:
    sha256 = pending["sha256"]
    scanner_path = GITHUB_CLONE / "reports" / "scanner" / f"{sha256}.json"
    if not scanner_path.is_file():
        raise CollectError(f"run concluded but {scanner_path} was never committed")
    scanner = json.loads(scanner_path.read_text())

    scanners = normalize_scanners(scanner.get("results", {}))
    total = sum(s["total"] for s in scanners if s["ok"]) or None
    malicious = sum(1 for s in scanners if s["ok"] and s["positives"] > 0)
    level = "clean"
    if malicious >= 10:
        level = "high"
    elif malicious >= 3:
        level = "medium"
    elif malicious >= 1:
        level = "low"

    sample_glob = list((GITHUB_CLONE / "samples" / pending.get("bucket", "")).glob(f"{sha256}.*"))
    sample_path = f"samples/{pending.get('bucket','')}/{sample_glob[0].name}" if sample_glob else ""

    # Xore/honeypot's report.py names the per-sample PDF
    # "{safe_stem(original filename)}-{scan-date}.pdf", flat under
    # reports/pdf/samples/ (no bucket subdirectory). The "original filename"
    # is scanner["filename"] -- the name inside the pushed zip, as analyze_
    # samples.py saw it after unzipping, which has nothing to do with the
    # zip's own {sha256}.zip outer name. scan_date is scanned_at[:10] from
    # this same scanner JSON. Confirmed against a real committed report and
    # PDF (#255); the previous guess (the zip's basename, nested by bucket,
    # no date) never matched a real file.
    scan_date = (scanner.get("scanned_at") or "")[:10]
    original_name = scanner.get("filename") or ""
    pdf_name = f"{safe_stem(original_name)}-{scan_date}.pdf" if original_name and scan_date else None
    pdf_path = GITHUB_CLONE / "reports" / "pdf" / "samples" / pdf_name if pdf_name else None
    report_pdf = f"reports/pdf/samples/{pdf_name}" if pdf_path and pdf_path.is_file() else None

    return {
        "version": RESULT_VERSION,
        "sha256": sha256,
        "requested_at": pending.get("requested_at", ""),
        "started_at": pending.get("requested_at", ""),
        "completed_at": now(),
        "exit_status": "ok",
        "commit": pending.get("commit", ""),
        # The commit the PDF/scanner report actually exist at, not the
        # original push commit above -- see git_pull()'s docstring.
        "report_commit": report_commit,
        "run_id": run.get("id"),
        "run_url": run.get("html_url", ""),
        "sample_path": sample_path,
        "family": family_for(sha256),
        "verdict": {
            "malicious": malicious,
            "suspicious": sum(1 for s in scanners if s.get("ok") and s.get("suspicious")),
            "total": total or 0,
            "level": level,
        },
        "scanners": scanners,
        "yara_auto_rules": auto_rules_for(sha256),
        "report_pdf": report_pdf,
    }


def write_result(sha256: str, payload: dict) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    final = RESULTS_DIR / f"{sha256}.json"
    tmp = RESULTS_DIR / f".{sha256}.json.tmp"
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True))
    tmp.chmod(0o600)
    os.replace(tmp, final)


def write_status(counts: dict) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    status = {"version": RESULT_VERSION, "updated_at": now(), **counts}
    tmp = RESULTS_DIR / ".status.json.tmp"
    tmp.write_text(json.dumps(status, indent=2, sort_keys=True))
    tmp.chmod(0o600)
    os.replace(tmp, RESULTS_DIR / "status.json")


def process_one(pending_file: Path) -> str:
    pending = json.loads(pending_file.read_text())
    sha256 = pending["sha256"]
    commit = pending.get("commit", "")
    requested_at = pending.get("requested_at", now())

    elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(requested_at.replace("Z", "+00:00"))).total_seconds()
    if elapsed > MAX_WAIT:
        write_result(sha256, {
            "version": RESULT_VERSION, "sha256": sha256, "requested_at": requested_at,
            "started_at": requested_at, "completed_at": now(), "exit_status": "timeout",
            "commit": commit,
        })
        pending_file.unlink()
        return "timeout"

    try:
        run = find_run(commit)
    except CollectError as e:
        log(f"  [.] {sha256}: {e} (will retry)")
        return "running"

    if run is None:
        return "running"  # Actions has not scheduled the run yet.
    status = run.get("status")
    if status != "completed":
        return "running"

    conclusion = run.get("conclusion")
    if conclusion != "success":
        write_result(sha256, {
            "version": RESULT_VERSION, "sha256": sha256, "requested_at": requested_at,
            "started_at": requested_at, "completed_at": now(), "exit_status": "failed",
            "commit": commit, "run_id": run.get("id"), "run_url": run.get("html_url", ""),
        })
        pending_file.unlink()
        return "failed"

    try:
        report_commit = git_pull()
        result = build_result(pending, run, report_commit)
    except CollectError as e:
        log(f"  [!] {sha256}: {e}")
        return "running"

    write_result(sha256, result)
    pending_file.unlink()
    return "done"


def drain() -> int:
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    counts = {"queued": 0, "running": 0, "done": 0, "failed": 0, "timeout": 0}
    for pending_file in sorted(PENDING_DIR.glob("*.pending")):
        try:
            outcome = process_one(pending_file)
        except Exception as e:  # noqa: BLE001 - one bad record must not wedge the drain
            log(f"  [!] {pending_file.name}: unexpected error: {e}")
            outcome = "running"
        counts[outcome] = counts.get(outcome, 0) + 1
        log(f"  {pending_file.stem}: {outcome}")

    write_status(counts)
    log(f"drained: {counts}")
    return 0


def main() -> int:
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    lock = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return 0
    return drain()


if __name__ == "__main__":
    sys.exit(main())
