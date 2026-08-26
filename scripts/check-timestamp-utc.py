#!/usr/bin/env python3
"""Fail CI when a Z-suffixed timestamp is emitted from process-local time.

A trailing "Z" claims UTC by ISO-8601 convention. Every emitter of such a
stamp must therefore produce genuine UTC through an explicit source --
time.gmtime(), a timezone.utc-aware datetime, or `date -u` -- because
bare strftime() and date render process-local wall clock, and sensors in
this stack deliberately run pinned non-UTC zones (mailoney's container
sets TZ=Europe/Berlin). The bug class looks cosmetic and is anything but:
the label is load-bearing downstream. #2197 shipped exactly this defect --
ip-enrichment-worker parses sensor stamps as RFC3339 UTC for its
portbridge join (backend-service/src/ip_enrichment/sensors.rs), so a
Berlin wall-clock Z widened the time-since-dial window by the DST offset
and re-opened the wrong-attribution ambiguity #1917 had shrunk.

Deliberately grep-level and line-based -- the acceptance criterion in
#2197 asks for exactly that shape, so the next vendored-sensor patch gets
caught by the same mechanical scan that catches this one -- with three
honest limitations kept visible rather than hidden:

- only single-line calls are inspected; a call spanning lines is
  invisible here (none exists today);
- parse-side formats (strptime, NaiveDateTime::parse_from_str) are exempt
  by construction: a parser consuming a string that already carries Z
  cannot localize it, so only *emission* is policed;
- anything correct-but-unmatchable takes an inline waiver comment,
  `utc-verified: <reason>`, so the justification lives beside the code it
  excuses instead of in this script.

Rust chrono `.format()` calls are out of scope: they share the visual
suffix but take their zone from the datetime value itself (Utc::now()
etc.), and a template-level scan cannot see that value's type.

Usage: python scripts/check-timestamp-utc.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {"vendor", "node_modules"}
MAX_BYTES = 2_000_000

# Emission sites: a Python/C-family strftime(...) call on this line whose
# format string carries the Z claim.
STRFTIME_LINE = re.compile(r"\bstrftime\s*\(")
# Shell `date` carrying the same format. Matched on any line touching date
# and %SZ together, so prose examples get policed right along with code.
DATE_LINE = re.compile(r"\bdate\b")
# Explicit UTC sources acceptable on the same logical line.
PY_OK = re.compile(r"\bgmtime\b|timezone\.utc|datetime\.UTC|\butcnow\b")
SH_OK = re.compile(r"\bdate\s+(?:-[a-zA-Z]*u|--utc)")
# Inline exemption: the reason travels with the excused line.
WAIVER = "utc-verified"


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [
        Path(line)
        for line in result.stdout.splitlines()
        if line and SKIP_DIRS.isdisjoint(Path(line).parts)
    ]


def line_findings(rel: str, lineno: int, text: str) -> list[str]:
    where = f"{rel}:{lineno}"
    if WAIVER in text or "%SZ" not in text:
        return []
    # Python/C-family emission call...
    py_rule = bool(STRFTIME_LINE.search(text))
    # ...or a shell `date`. Excluded when the line already matched the
    # Python rule, so one call cannot be policed twice.
    sh_rule = bool(DATE_LINE.search(text)) and not py_rule
    if not (py_rule or sh_rule):
        return []
    if PY_OK.search(text) or SH_OK.search(text):
        return []
    return [
        f"{where}: Z-suffixed stamp rendered without an explicit UTC "
        f"source (gmtime/timezone.utc/date -u), or a utc-verified waiver: {text.strip()}"
    ]


def main() -> int:
    findings: list[str] = []
    scanned = 0
    for path in tracked_files():
        rel = path.as_posix()
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if len(raw.encode("utf-8", errors="replace")) > MAX_BYTES:
            continue
        scanned += 1
        for lineno, text in enumerate(raw.splitlines(), start=1):
            findings.extend(line_findings(rel, lineno, text))

    if findings:
        print("Timestamp UTC-source check failed:", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        print(
            f"{len(findings)} finding(s) across {scanned} scanned files.",
            file=sys.stderr,
        )
        return 1
    print(f"Timestamp UTC-source check passed ({scanned} files scanned).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
