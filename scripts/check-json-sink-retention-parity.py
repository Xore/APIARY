#!/usr/bin/env python3
"""Fail CI when a JSON-emitting /logs directory lacks either retention half.

The #120 contract is two-sided: each JSON-emitting sensor self-rotates its
sink into generations with a digit-leading suffix, and
honeypot-utilities' log-maintenance.sh prunes those generations once they
age past the shared window. #2196 shipped because mailoney broke BOTH
halves at once -- its sink appended forever AND no pruner glob existed --
and nothing structural would have caught either omission; only a person
reading compose volumes next to pruner code next to vendored sensors
could connect them. This script is that connection, checked mechanically
on every push.

The ROWS ledger below is deliberately hand-written rather than inferred:
it documents WHERE each half lives for every rotating sink we know about,
so adding a sensor means adding one reviewable row, and forgetting either
half fails here naming exactly which half is missing. Two sides per row:

- "writer": where the rotation implementation itself lives, proven by a
  grep token in that subtree (a knob name or rotate() definition);
- "glob": the exact pruner find-line fragment log-maintenance.sh must
  carry for that directory.

The reverse check keeps the ledger honest too: every `find /logs/<dir>`
line in the pruner must be claimed by some row, so pruning coverage
cannot silently grow an unledgered entry (or lose one).

Usage: python scripts/check-json-sink-retention-parity.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAINTENANCE = ROOT / "arcane" / "home" / "honeypot-utilities" / "analysis" / "log-maintenance.sh"
SKIP_DIRS = {"vendor", "node_modules"}

# One row per self-rotating JSON directory under /logs.
# "writer" is (subtree to search, proof tokens); tokens are strings the
# rotation implementation cannot sensibly drop without stopping being one.
# http-honeypot's single binary serves both http.json and api.json (#120:
# see its persona_test.go) -- hence two rows sharing one writer.
ROWS = [
    {
        "dir": "/logs/cowrie",
        "globs": ["'cowrie.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-cowrie", ["CowrieDailyLogFile"]),
    },
    {
        "dir": "/logs/multipot",
        "globs": ["'multipot.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-multipot/multipot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/http-honeypot",
        "globs": ["'http.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-http/http-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/api-honeypot",
        "globs": ["'api.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-http/http-honeypot",
                   ["LOG_MAX_BYTES", "func (l *logger) rotate()"]),
    },
    {
        "dir": "/logs/enriched",
        "globs": ["'*.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dashboard/backend-service/src/ip_enrichment",
                   ["OUTPUT_MAX_BYTES"]),
    },
    {
        "dir": "/logs/dionaea",
        "globs": ["'dionaea.json.[0-9]*'", "'dionaea_incident.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-dionaea/dionaea",
                   ["DIONAEA_LOG_MAX_BYTES"]),
    },
    {
        "dir": "/logs/mailoney",
        "globs": ["'mailoney.json.[0-9]*'"],
        "writer": ("arcane/home/honeypot-mailoney/mailoney",
                   ["MAILONEY_JSON_MAX_BYTES"]),
    },
]


def tree_contains(rel_root: str, needle: str) -> bool:
    base = ROOT / rel_root
    if base.is_file():
        return needle in base.read_text(encoding="utf-8", errors="replace")
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        if SKIP_DIRS.intersection(path.parts):
            continue
        try:
            if needle in path.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


def main() -> int:
    findings: list[str] = []
    maintenance_text = MAINTENANCE.read_text()

    for row in ROWS:
        row_id = f"{row['dir']} ({', '.join(row['globs'])})"
        for glob in row["globs"]:
            if glob not in maintenance_text:
                findings.append(
                    f"pruner half missing: {MAINTENANCE.relative_to(ROOT)} has "
                    f"no find line using {glob} for {row['dir']}"
                )
        rel_root, tokens = row["writer"]
        for token in tokens:
            if not tree_contains(rel_root, token):
                findings.append(
                    f"writer half missing: no rotation implementation carrying "
                    f"{token!r} found under {rel_root} (row {row_id})"
                )

    # Reverse direction: claim every find line the pruner actually carries.
    find_dirs = sorted(set(re.findall(r"\bfind\s+(/logs/\S+?)\s+", maintenance_text)))
    for find_dir in find_dirs:
        if not any(find_dir == row["dir"] or find_dir.startswith(row["dir"] + "/")
                   for row in ROWS):
            findings.append(
                f"unledgered pruner line: log-maintenance.sh runs `find {find_dir}` "
                f"but no ROW claims it -- add a parity row for it"
            )

    if findings:
        print("JSON sink retention parity check failed:", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print(f"JSON sink retention parity check passed "
          f"({len(ROWS)} directories, both halves present).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
