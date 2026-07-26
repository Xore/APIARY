#!/usr/bin/env python3
"""Fail CI when public-repository deployment secrets or private artifacts appear."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_DOTENV = {
    Path(".env.example"),
    Path("vps/.env.example"),
    Path("cowrie/honeyfs/opt/nexusai-inference/.env"),
}
SKIP_PREFIXES = (
    "dashboard/vendor/",
    "dashboard/frontend/node_modules/",
    ".git/",
)
FORBIDDEN_LITERALS = {
    "xore.rocks": "deployment-specific public domain",
    "87.106.162.235": "deployment-specific VPS address",
    "192.168.42.250": "deployment-specific home-server address",
    "changeme123": "known default password",
}
PATTERNS = (
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bgh[opsu]_[A-Za-z0-9]{30,}\b"), "GitHub token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (re.compile(r"(?m)^[ \t]*[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY)[ \t]*=[ \t]*(?!(?:CHANGE_ME|DECOY_ONLY|\$\{|$))[^#\s]{8,}"), "literal credential assignment"),
    (re.compile(r"(?i)https?://[^/\s:@]+:[^/\s@]+@"), "credential embedded in URL"),
)
BINARY_SUFFIXES = {
    ".pcap", ".pcapng", ".qcow2", ".img", ".p12", ".pfx", ".key", ".pem",
}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return [Path(line) for line in result.stdout.splitlines() if line]


def main() -> int:
    findings: list[str] = []
    for relative in tracked_files():
        posix = relative.as_posix()
        if posix.startswith(SKIP_PREFIXES):
            continue
        if posix == "scripts/check-public-leaks.py":
            continue
        if relative.suffix.lower() in BINARY_SUFFIXES:
            findings.append(f"{posix}: private/runtime binary must not be committed")
            continue
        if relative.name == ".env" and relative not in ALLOWED_DOTENV:
            findings.append(f"{posix}: deployment .env must not be committed")
            continue
        path = ROOT / relative
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        lowered = content.lower()
        for literal, reason in FORBIDDEN_LITERALS.items():
            if literal.lower() in lowered:
                findings.append(f"{posix}: contains {reason} ({literal})")
        for pattern, reason in PATTERNS:
            for match in pattern.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                findings.append(f"{posix}:{line}: possible {reason}")

    if findings:
        print("Public-repository safety check failed:", file=sys.stderr)
        for finding in sorted(set(findings)):
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print("Public-repository safety check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
