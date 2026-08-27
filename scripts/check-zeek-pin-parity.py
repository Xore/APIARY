#!/usr/bin/env python3
"""Fail CI when the two Zeek Containerfiles' build pins disagree or float.

vps/zeek/Containerfile (prod sensor) and dev/sensing-lab/Containerfile (lab
harness) build the same parser set on purpose: #1727's parity argument -- what
the lab measures is only evidence for production if production runs the same
parsers. #2456 found both files floating: the base image tag, ja4, and every
ICSNPP parser resolved to whatever upstream shipped at rebuild time, so two
rebuilds months apart could silently change fingerprint or parser behavior,
and the lab/prod equivalence that evidence comparisons rest on held only by
luck. (hassh was the deliberate counterexample: #1821 pinned it and patched
it, and the two files had already drifted around even that.)

This checker pins the invariant in code, three rules:

1. both files' single FROM line must be byte-identical and carry a
   @sha256:<64hex> manifest-list digest;
2. every `zkg install` invocation in either file must carry exactly one
   --version <40hex commit sha> (one --version applies to a whole zkg
   invocation, which is why the Containerfiles install one parser per call);
3. the two files must install the same set of sources at the same pins --
   a component pinned in one file but floating or differing in the other is
   exactly the drift the pins exist to prevent.

Index-name spellings are canonicalized through the table below so installing
`zeek/foxio/ja4` in one file and its URL in the other still compares equal.

Honest limitations, kept visible rather than hidden:

- offline by design -- it does not verify a pin still exists upstream (zkg
  fails the build loudly on a dead sha) or that the base tag has not moved
  past its digest since the pin was recorded (docs/CONTAINER-UPDATES.md is
  the deliberate periodic procedure for that; #2316 is the watching gap);
- shell parsing is deliberately shallow: continuation-joined RUN lines split
  on `&&`, flags are single-dash tokens, no quoting. The installs these
  files contain are flat enough for that, and anything cleverer in them
  deserves review anyway.

Usage: python scripts/check-zeek-pin-parity.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = [
    ROOT / "vps" / "zeek" / "Containerfile",
    ROOT / "dev" / "sensing-lab" / "Containerfile",
]

# zkg accepts index names (zeek/<owner>/<package>) or git URLs for the same
# source. Map each index spelling to the URL it resolves to so a file that
# switches spelling does not masquerade as a different package.
INDEX_TO_URL = {
    "zeek/foxio/ja4": "https://github.com/FoxIO-LLC/ja4",
}

FROM_RE = re.compile(r"^FROM\s+(\S+)$")
DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")


def logical_lines(text: str) -> list[str]:
    """Strip comment lines, then join backslash continuations."""
    body = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    joined = re.sub(r"\\\s*\n\s*", " ", body)
    return [line.strip() for line in joined.splitlines() if line.strip()]


def split_commands(line: str) -> list[str]:
    """One logical RUN line -> its `&&`-separated commands, RUN prefix gone."""
    out = []
    for i, chunk in enumerate(line.split("&&")):
        chunk = chunk.strip()
        if i == 0 and chunk.upper().startswith("RUN "):
            chunk = chunk[4:].strip()
        if chunk:
            out.append(chunk)
    return out


def parse_file(path: Path) -> tuple[list[str], dict[str, str]]:
    """Return (from_images, {canonical source: pinned sha})."""
    text = path.read_text(encoding="utf-8")
    froms: list[str] = []
    pins: dict[str, str] = {}

    for line in logical_lines(text):
        if FROM_RE.match(line):
            froms.append(line.split(None, 1)[1].strip())
        for command in split_commands(line) if line.upper().startswith("RUN ") else []:
            tokens = command.split()
            if not tokens or tokens[0] != "zkg" or len(tokens) < 2 or tokens[1] != "install":
                continue
            rest = tokens[2:]
            version: str | None = None
            sources: list[str] = []
            i = 0
            while i < len(rest):
                token = rest[i]
                if token == "--version":
                    if version is not None or i + 1 >= len(rest):
                        raise SystemExit(
                            f"{path.name}: malformed --version in: {command}"
                        )
                    version = rest[i + 1]
                    i += 2
                elif token.startswith("--"):
                    i += 1
                else:
                    sources.append(token)
                    i += 1
            if not sources:
                raise SystemExit(f"{path.name}: zkg install with no source: {command}")
            if version is None or not COMMIT_RE.match(version):
                raise SystemExit(
                    f"{path.name}: zkg install is missing a commit-sha pin "
                    f"(--version <40-hex sha>): {command}"
                )
            for source in sources:
                key = INDEX_TO_URL.get(source, source)
                if key in pins and pins[key] != version:
                    raise SystemExit(
                        f"{path.name}: {source} pinned to two different shas"
                    )
                pins[key] = version
    return froms, pins


def main() -> int:
    failures: list[str] = []
    parsed = {path: parse_file(path) for path in FILES}

    for path, (froms, _) in parsed.items():
        if len(froms) != 1:
            failures.append(f"{path.name}: expected exactly one FROM line, found {len(froms)}")
        elif not DIGEST_RE.search(froms[0]):
            failures.append(
                f"{path.name}: FROM is not digest-pinned "
                f"(expected ...@sha256:<64 hex>): {froms[0]}"
            )

    from_values = {path.name: (froms[0] if len(froms) == 1 else None) for path, (froms, _) in parsed.items()}
    if len(set(from_values.values())) > 1:
        failures.append(
            "FROM lines differ across files (lab/prod must share one base "
            f"digest): {from_values}"
        )

    pins = {path.name: data for path, (_, data) in parsed.items()}
    names = [path.name for path in FILES]
    a, b = names[0], names[1]
    if set(pins[a]) != set(pins[b]):
        only_a = sorted(set(pins[a]) - set(pins[b]))
        only_b = sorted(set(pins[b]) - set(pins[a]))
        failures.append(
            f"package sets differ: only in {a}: {only_a or '{}'}; "
            f"only in {b}: {only_b or '{}'}"
        )
    for key in sorted(set(pins[a]) & set(pins[b])):
        if pins[a][key] != pins[b][key]:
            failures.append(
                f"{key} pinned to {pins[a][key][:12]} in {a} but "
                f"{pins[b][key][:12]} in {b}"
            )

    if failures:
        print("zeek build pin parity FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"base (both files): {from_values[a]}")
    for key in sorted(pins[a]):
        print(f"  {key} -> {pins[a][key]}")
    print(f"pin parity OK across {a} and {b} ({len(pins[a])} components)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
