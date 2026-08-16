#!/usr/bin/env python3
"""Diff every event-kind string a homegrown Go sensor can emit against
dashboard/classify.go's per-sensor section, to find kinds with no explicit
case and no generic fallback line (#789).

Only covers the sensors this repo owns the source for (dnp3-honeypot,
citrix-honeypot, cisco-asa-honeypot, dicompot, rdp-honeypot, dns-honeypot,
endlessh-honeypot, http-honeypot, multipot) -- cowrie/dionaea/tanner are
vendored upstream projects with no source in this repo to grep, and their
coverage has to be checked against upstream's documented event vocabulary
instead (see #789's own audit notes).

This is a *report*, not an auto-fixer: some flagged kinds are legitimately
covered by a generic "kind + detail" fallback line that this script cannot
prove handles every value, only that such a line exists in the section at
all. Read the flagged section by hand before deciding it's a real gap.

Known heuristic blind spot, manually verified clean rather than fixed in
code: rdp-honeypot's section never assigns a local `kind` variable at all --
after its one "listening" skip-check, every other event unconditionally
gets the same "connect" detail line. That shape has no `kind`-based
fallback for this script to find, so it always reports rdp-honeypot's
non-listening kind as a "GAP" even though the source shows it is handled.
Confirmed by hand 2026-08-06 against rdp-honeypot/main.go; no real gap.

Usage: scripts/audit-sensor-event-coverage.py
"""
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
# #1502: dashboard/ and every sensor dir below moved under arcane/home/.
CLASSIFY_GO = REPO_ROOT / "arcane/home/honeypot-dashboard/dashboard" / "classify.go"

# sensor dir (also KNOWN_CLEAN's lookup key -- keep it the short name, not
# the #1502 arcane/home/ path) -> (actual directory to scan, classify.go
# section marker substring from the "---- name ----" comment headers
# already used to organise that file).
SENSORS = {
    "dnp3-honeypot": ("arcane/home/honeypot-dnp3/dnp3-honeypot", "dnp3-honeypot"),
    "citrix-honeypot": ("arcane/home/honeypot-citrix-honeypot/citrix-honeypot", "citrix-honeypot"),
    "cisco-asa-honeypot": ("arcane/home/honeypot-cisco-asa-honeypot/cisco-asa-honeypot", "cisco-asa-honeypot"),
    "dicompot": ("arcane/home/honeypot-dicompot/dicompot", "dicompot"),
    "rdp-honeypot": ("arcane/home/honeypot-rdp-honeypot/rdp-honeypot", "rdp-honeypot"),
    "dns-honeypot": ("arcane/home/honeypot-dns-honeypot/dns-honeypot", "dns-honeypot"),
    "endlessh-honeypot": ("arcane/home/honeypot-endlessh/endlessh-honeypot", "endlessh"),
    "http-honeypot": ("arcane/home/honeypot-http/http-honeypot", "http-honeypot"),
    "multipot": ("arcane/home/honeypot-multipot/multipot", "multipot"),
}

# Matches the two literal-assignment shapes this codebase's sensors use:
#   Event: "kind"            (struct literal field)
#   x.Event = "kind"         (later mutation, e.g. dnp3's malformed_frame)
EVENT_LITERAL_RE = re.compile(r'\bEvent:\s*"([a-zA-Z0-9_]+)"|\.Event\s*=\s*"([a-zA-Z0-9_]+)"')

# The shared h.log2(r, "kind", path, data) helper convention (citrix,
# cisco-asa): kind is the second positional argument.
LOG2_LITERAL_RE = re.compile(r'\.log2\(\s*\w+\s*,\s*"([a-zA-Z0-9_]+)"')

# A dynamically-built kind ("method_" + strings.ToLower(...)) cannot be
# resolved statically -- flagged separately, not silently dropped.
DYNAMIC_KIND_RE = re.compile(r'\.log2\(\s*\w+\s*,\s*"[a-zA-Z0-9_]*"\s*\+')


def emitted_kinds(sensor_dir: str):
    literal, dynamic_prefixes = set(), set()
    base = REPO_ROOT / sensor_dir
    for go_file in base.glob("*.go"):
        if go_file.name.endswith("_test.go"):
            continue
        text = go_file.read_text()
        for m in EVENT_LITERAL_RE.finditer(text):
            literal.add(m.group(1) or m.group(2))
        for m in LOG2_LITERAL_RE.finditer(text):
            literal.add(m.group(1))
        for m in DYNAMIC_KIND_RE.finditer(text):
            # Report the fixed prefix before the "+" as a hint, e.g. "method_".
            prefix = re.search(r'"([a-zA-Z0-9_]*)"\s*\+', m.group(0))
            if prefix:
                dynamic_prefixes.add(prefix.group(1) + "*")
    return literal, dynamic_prefixes


def classify_section(marker: str) -> str:
    text = CLASSIFY_GO.read_text()
    lines = text.splitlines()
    starts = [i for i, l in enumerate(lines) if l.strip().startswith("// ----") and marker in l]
    if not starts:
        return ""
    start = starts[0]
    rest_markers = [i for i in range(start + 1, len(lines)) if lines[i].strip().startswith("// ----")]
    end = rest_markers[0] if rest_markers else len(lines)
    return "\n".join(lines[start:end])


def matched_kinds(section: str):
    kinds = set()
    for m in re.finditer(r'case\s+"([a-zA-Z0-9_]+)"', section):
        kinds.add(m.group(1))
    # Both `kind == "x"` (a local alias) and the unaliased
    # `str(e["event"]) == "x"` form (e.g. rdp-honeypot's listening skip).
    for m in re.finditer(r'(?:kind|str\(e\["event"\]\))\s*==\s*"([a-zA-Z0-9_]+)"', section):
        kinds.add(m.group(1))
    for m in re.finditer(r'\.Event\]\s*==\s*"([a-zA-Z0-9_]+)"', section):
        kinds.add(m.group(1))
    return kinds


# Kinds manually verified handled despite tripping every heuristic above --
# see the module docstring for why each one's shape defeats detection.
# Keep this list to cases with a written, dated justification; it exists to
# stop a known-clean sensor from permanently failing CI, not to silence real
# gaps found later.
KNOWN_CLEAN = {
    ("rdp-honeypot", "connect"),  # no `kind` variable at all; single unconditional detail line
}


def has_generic_fallback(section: str) -> bool:
    # A switch's `default:` case, or a detail/action line built from the
    # `kind` variable on either side of a "+" concatenation (citrix/cisco-asa
    # put kind first, multipot's `ev.proto + " " + kind` puts it last).
    # Heuristic, not exhaustive -- verify_needed rows still say "check by hand".
    if "default:" in section:
        return True
    if re.search(r'kind\s*\+', section) or re.search(r'\+\s*kind\b', section):
        return True
    # A bare `ev.detail = kind` (or via a lookup table that itself falls
    # back to `= kind`, e.g. dicompot's dicomEventLabels[kind]) -- every
    # kind gets *some* detail line even with no explicit case or "+".
    return bool(re.search(r'=\s*kind\b', section))


def main():
    any_gap = False
    for sensor_dir, (actual_dir, marker) in SENSORS.items():
        if not (REPO_ROOT / actual_dir).is_dir():
            print(f"SKIP  {sensor_dir}: directory not found")
            continue
        emitted, dynamic = emitted_kinds(actual_dir)
        section = classify_section(marker)
        if not section:
            print(f"SKIP  {sensor_dir}: no classify.go section found for marker {marker!r}")
            continue
        matched = matched_kinds(section)
        fallback = has_generic_fallback(section)
        known_clean = {kind for (sensor, kind) in KNOWN_CLEAN if sensor == sensor_dir}
        gaps = sorted(emitted - matched - known_clean)
        print(f"\n{sensor_dir} ({len(emitted)} emitted kind(s), {len(matched)} explicit case(s) in classify.go, generic fallback: {fallback})")
        if dynamic:
            print(f"  dynamic (not statically resolvable, check by hand): {sorted(dynamic)}")
        if known_clean & emitted:
            print(f"  (manually verified clean, see KNOWN_CLEAN: {sorted(known_clean & emitted)})")
        if not gaps:
            print("  OK -- every emitted kind has an explicit case")
        elif fallback:
            print(f"  no explicit case, but a generic fallback exists -- verify by hand: {gaps}")
        else:
            print(f"  GAP -- no explicit case and no generic fallback: {gaps}")
            any_gap = True

    print()
    if any_gap:
        print("Gaps found above need a human read of the classify.go section before filing anything -- this script only proves 'no case', not 'silently dropped'.")
        sys.exit(1)
    print("No unambiguous gaps found in the sensors this script covers.")


if __name__ == "__main__":
    main()
