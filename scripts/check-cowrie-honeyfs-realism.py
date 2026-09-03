#!/usr/bin/env python3
"""Guard the four mechanical tells #2424 found in cowrie's decoy honeyfs and
#2885 confirmed two of three were still unfixed after #2424 closed.

#2424's own body asked for this guard and never wrote it -- the gap is what
let two of its three findings regress silently past a closed issue. Four
checks, each a real tell a tool (hashcat/john, ssh-keygen, or a stock
Debian/Ubuntu account table) would notice on the live honeypot:

1. every tracked SSH key (authorized_keys entries and standalone *.pub
   files) under honeypot-cowrie parses as a well-formed key;
2. every $6$ (sha512crypt) shadow hash body is exactly 86 characters --
   anything shorter is not a hash any real crypt(3) implementation emits;
3. every passwd primary GID has a matching /etc/group entry;
4. every passwd account has a matching /etc/shadow row.

Usage: python scripts/check-cowrie-honeyfs-realism.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COWRIE = ROOT / "arcane" / "home" / "honeypot-cowrie"
HONEYFS = COWRIE / "cowrie" / "honeyfs"
PASSWD = HONEYFS / "etc" / "passwd"
SHADOW = HONEYFS / "etc" / "shadow"
GROUP = HONEYFS / "etc" / "group"


def check_ssh_keys() -> list[str]:
    findings = []
    candidates = sorted(
        p for p in COWRIE.rglob("*")
        if p.is_file() and (p.name == "authorized_keys" or p.suffix == ".pub")
    )
    if not candidates:
        findings.append("no authorized_keys/*.pub files found under "
                         f"{COWRIE.relative_to(ROOT)} -- check the glob, not "
                         "a pass")
        return findings
    for path in candidates:
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            proc = subprocess.run(
                ["ssh-keygen", "-l", "-f", "/dev/stdin"],
                input=line, capture_output=True, text=True,
            )
            if proc.returncode != 0:
                findings.append(
                    f"{path.relative_to(ROOT)}:{lineno} does not parse as a "
                    f"valid SSH key: {proc.stderr.strip()}"
                )
    return findings


def check_shadow_hash_lengths() -> list[str]:
    findings = []
    for lineno, line in enumerate(SHADOW.read_text().splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split(":")
        if len(fields) < 2:
            continue
        user, hashfield = fields[0], fields[1]
        if not hashfield.startswith("$6$"):
            continue
        parts = hashfield.split("$")
        # $6$<salt>$<body> -- parts = ['', '6', salt, body]
        if len(parts) != 4:
            findings.append(
                f"{SHADOW.relative_to(ROOT)}:{lineno} ({user}) has a "
                f"malformed $6$ field: {hashfield!r}"
            )
            continue
        body = parts[3]
        if len(body) != 86:
            findings.append(
                f"{SHADOW.relative_to(ROOT)}:{lineno} ({user}) sha512crypt "
                f"body is {len(body)} chars, need 86: {hashfield!r}"
            )
    return findings


def check_gid_closure() -> list[str]:
    passwd_gids = {line.split(":")[3] for line in PASSWD.read_text().splitlines() if line.strip()}
    group_gids = {line.split(":")[2] for line in GROUP.read_text().splitlines() if line.strip()}
    missing = sorted(passwd_gids - group_gids, key=int)
    if missing:
        return [
            f"{len(missing)} passwd primary GID(s) with no matching "
            f"{GROUP.relative_to(ROOT)} entry: {', '.join(missing)}"
        ]
    return []


def check_shadow_account_closure() -> list[str]:
    passwd_users = {line.split(":")[0] for line in PASSWD.read_text().splitlines() if line.strip()}
    shadow_users = {line.split(":")[0] for line in SHADOW.read_text().splitlines() if line.strip()}
    missing = sorted(passwd_users - shadow_users)
    if missing:
        return [
            f"{len(missing)} passwd account(s) with no matching "
            f"{SHADOW.relative_to(ROOT)} row: {', '.join(missing)}"
        ]
    return []


def main() -> int:
    findings: list[str] = []
    findings += check_ssh_keys()
    findings += check_shadow_hash_lengths()
    findings += check_gid_closure()
    findings += check_shadow_account_closure()

    if findings:
        print("Cowrie honeyfs realism check failed:")
        for f in findings:
            print(f"  - {f}")
        return 1

    print("Cowrie honeyfs realism check passed "
          "(SSH keys parse, $6$ bodies are 86 chars, "
          "passwd/group and passwd/shadow closures hold).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
