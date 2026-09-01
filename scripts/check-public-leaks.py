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
    # #1502: moved under arcane/home/honeypot-cowrie/ along with the rest
    # of cowrie/'s build context -- still a decoy honeyfs file for
    # attackers to find, not a real credential.
    Path("arcane/home/honeypot-cowrie/cowrie/honeyfs/opt/nexusai-inference/.env"),
}
# #2285 follow-up: a regression test for the no-self-harbor fix has to
# assemble the forbidden literals somewhere to assert the runtime
# `_literal()` works as advertised, which means the test file contains
# the literal strings as fixtures -- the same strings the gate just
# stopped exempting its own source from. The two contracts (the checker
# doesn't self-harbor; the test for that checker still verifies the
# runtime assembly produces the right values) need a third contract
# (the test files are explicit fixtures, not policy violations) or the
# new check would block its own proof of correctness. Same shape as
# ALLOWED_DOTENV above: an explicit, commented, fail-closed set, and
# the path must be a tests/ file under tests/docs/ that exists at
# scan time. (The set is read at runtime, so renaming or moving a
# listed file re-surfaces the failure on the next CI run -- no
# path-string coupling like the old self-skip.)
ALLOWED_LITERAL_FIXTURE_FILES = {
    Path("tests/docs/test_2285_public_leaks_no_self_harbor.py"),
    # #2604 follow-up: this file's own contract is that a planted
    # copy of a forbidden literal in a tracked file gets flagged, so
    # the test necessarily contains the public-domain literal as a
    # fixture value (assertion text spelled out, value assembled via
    # the same fragment trick this module uses for the lookup dict).
    Path("tests/docs/test_2604_check_public_leaks_fixture_allowlist.py"),
}
SKIP_PREFIXES = (".git/",)


def _literal(*fragments: str) -> str:
    # #2285: fragments are joined at runtime, split at arbitrary offsets
    # (never at a word/segment boundary) so the assembled value never
    # appears as a contiguous, greppable substring in this file's own
    # source text -- this script used to be the single committed harbor
    # for exactly the values it exists to ban.
    return "".join(fragments)


def forbidden_literals() -> dict[str, str]:
    return {
        _literal("xo", "re.ro", "cks"): "deployment-specific public domain",
        _literal("87.1", "06.16", "2.235"): "deployment-specific VPS address",
        _literal("192.1", "68.4", "2.250"): "deployment-specific home-server address",
        _literal("chang", "eme1", "23"): "known default password",
    }


PATTERNS = (
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\bgh[opsu]_[A-Za-z0-9]{30,}\b"), "GitHub token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    # #1502: two exemptions added generating the new per-stack .env.example
    # files. "<ARCANE_API_TOKEN>" tripped this before (?:"?<) existed --
    # install-homeserver.conf.example's own established convention for
    # every unfilled answer-file placeholder (VPS_SSH_KEY, BACKUP_HOST_KEY,
    # ...) is a bare or quoted <PLACEHOLDER>, same template-not-a-secret
    # shape CHANGE_ME/DECOY_ONLY already covered; just never had a
    # PASSWORD/SECRET/TOKEN/API_KEY-named var use it before. Separately,
    # ARKIME_PASSWORD_SECRET's own compose-file default of
    # "change-me-in-env" (arcane/home/honeypot-elk/compose.yml/init.yml, predates
    # #1502) never matched this pattern while embedded inline in a YAML
    # list item -- generating a real per-stack .env.example put it at the
    # start of a line for the first time. (?i:change.?me) covers that,
    # CHANGE_ME's own different casing/separator, and bare "changeme"
    # (no separator -- vendor/ghosts-src's own upstream .env.example
    # convention, #1506) in one exemption. \$\( alongside \$\{ exempts
    # command-substitution-generated secrets (e.g. install-homeserver.sh's
    # `$(openssl rand ...)` bootstrap values, #1504) the same way variable
    # expansion was already exempt. The `\"?` before `\$[\{\(]` matches a
    # *quoted* expansion default too -- `FOO_TOKEN="${FOO_TOKEN:-}"`, the
    # idiomatic shell form for "use the env value or an empty default" --
    # which is as much a not-a-literal as the bare `${...}`/`$(...)` cases
    # and which the sibling `\"?<` placeholder exemption already tolerates a
    # leading quote for.
    (re.compile(r"(?m)^[ \t]*[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY)[ \t]*=[ \t]*(?!(?:(?i:change.?me)|DECOY_ONLY|\"?\$[\{\(]|\"?<|$))[^#\s]{8,}"), "literal credential assignment"),
    (re.compile(r"(?i)https?://[^/\s:@]+:[^/\s@]+@(?P<host>[^/\s:@?#]+)"),
     "credential embedded in URL"),
)

# #2290: a match whose host is an RFC 2606 / RFC 6761 reserved name is not a
# leak and cannot become one -- `.example`, `.test`, `.invalid` and
# `.localhost` are guaranteed never to resolve to anyone's service, so a
# credential written against one is unusable by construction.
#
# This exists because redaction code has to be tested, and testing it means
# committing a URL that *looks* like a credential so the sanitiser can be
# shown removing it. Without an exemption the only ways to land such a test
# are to assemble the string from fragments or to drop the assertion -- the
# first is obfuscation that defeats the gate for real leaks too and teaches
# the next author to do the same, the second removes the proof that
# redaction works. Naming the reserved-host case keeps the gate honest and
# the fixture readable.
#
# Deliberately narrow: it keys on the reason string, so it applies to this
# one pattern and not to private keys, GitHub/AWS/Slack tokens, or literal
# credential assignments, none of which are made harmless by the hostname
# they sit near. RESERVED_TLDS is the same tuple the VPS Traefik host rule
# below already trusts for the same reason.
URL_CREDENTIAL_REASON = "credential embedded in URL"


def _is_exempt(reason: str, match: "re.Match[str]") -> bool:
    """True when a pattern hit is provably not a real leak."""
    if reason != URL_CREDENTIAL_REASON:
        return False
    host = (match.groupdict().get("host") or "").lower().rstrip(".")
    return host.endswith(RESERVED_TLDS)
# #1920: the VPS Traefik config is not documentation -- install-vps.sh
# provisions the live router set straight out of it, so a real hostname
# committed here is a smoke test that resolves somebody's production DNS
# instead of failing loudly on a reinstall. forbidden_literals() above only
# catches the one domain we already know about; this catches the next one.
# RFC 2606/6761 reserves these names for exactly this purpose.
RESERVED_TLDS = (".example", ".test", ".invalid", ".localhost")
GENERIC_DOMAIN_GLOBS = ("vps/traefik/*.yml", "vps/traefik/*.yaml")
HOST_RULE = re.compile(r"Host\(`([^`]+)`\)")

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
    skipped_non_text: list[str] = []
    literals = forbidden_literals()
    for relative in tracked_files():
        posix = relative.as_posix()
        if posix.startswith(SKIP_PREFIXES):
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
            # #2285: was a bare `continue` -- any non-suffix-blocked binary
            # (a .woff, a renamed dump, ...) skipped every pattern below
            # with zero trace. Collected and reported after the scan so
            # the gate's paranoia covers what it could NOT check too, not
            # just what it did.
            skipped_non_text.append(posix)
            continue
        # Regression test for the #2285 no-self-harbor fix: the file
        # contains the literal values as fixtures, asserted under a
        # different test. Skip ONLY the literal-content scan here so the
        # gate doesn't block its own proof of correctness. The pattern
        # scan below still runs -- a private-key or AWS-key fixture in
        # this exact file would still be flagged.
        if relative not in ALLOWED_LITERAL_FIXTURE_FILES:
            lowered = content.lower()
            for literal, reason in literals.items():
                if literal.lower() in lowered:
                    findings.append(f"{posix}: contains {reason} ({literal})")
        for pattern, reason in PATTERNS:
            for match in pattern.finditer(content):
                if _is_exempt(reason, match):
                    continue
                line = content.count("\n", 0, match.start()) + 1
                findings.append(f"{posix}:{line}: possible {reason}")
        if any(relative.match(glob) for glob in GENERIC_DOMAIN_GLOBS):
            for match in HOST_RULE.finditer(content):
                host = match.group(1)
                if host.endswith(RESERVED_TLDS):
                    continue
                line = content.count("\n", 0, match.start()) + 1
                findings.append(
                    f"{posix}:{line}: Host(`{host}`) is a real domain -- "
                    "tracked VPS routers must use a reserved example domain "
                    "so a reinstall smoke test cannot resolve live DNS"
                )

    if skipped_non_text:
        print(
            f"Skipped {len(skipped_non_text)} non-text file(s) "
            "(binary or undecodable as UTF-8, not scanned for leaks):",
            file=sys.stderr,
        )
        for posix in sorted(skipped_non_text):
            print(f"  - {posix}", file=sys.stderr)

    if findings:
        print("Public-repository safety check failed:", file=sys.stderr)
        for finding in sorted(set(findings)):
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print("Public-repository safety check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
