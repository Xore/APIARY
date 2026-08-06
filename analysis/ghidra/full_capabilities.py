#!/usr/bin/env python3
"""Inventory every environment variable the Ghidra analysis pipeline reads,
report whether each one is currently on/off/configured, and let an operator
apply it -- directly or via a named preset (#800).

This session found three pipeline features that existed in code but were
never actually turned on in the real deployment (#796 graphviz, #797
Rev·Deck, #799 capa signatures) -- each for a different reason, each
discovered only by an operator noticing something missing on a results page.
The point of this script is that the *next* one gets caught by running it,
not by noticing a gap months later.

The variable list is not hand-maintained: it comes from grepping every
pipeline source file (below) for `os.environ.get(...)`/`os.getenv(...)`
calls, so it stays accurate as the pipeline grows. Descriptions come from
the comment block immediately above each assignment, since that convention
is already followed throughout this pipeline (see e.g. REVDECK_API_BASE in
worker/ghidra-worker.py).

Usage:
    analysis/ghidra/full_capabilities.py                     show current state
    analysis/ghidra/full_capabilities.py --set KEY=VALUE      apply one override
    analysis/ghidra/full_capabilities.py --preset all-on      apply a preset
    analysis/ghidra/full_capabilities.py --env-file PATH      default /etc/default/honeypot-ghidra

Presets:
    all-on    turn on every optional feature this pipeline supports, with
              the same loopback defaults docs/analysis/ghidra/*.md use
    minimal   turn off every optional feature; only deterministic Ghidra
              output remains
    defaults  remove every override this script or an operator has made;
              back to whatever the process defaults in source are
"""
import argparse
import os
import re
import sys
from pathlib import Path

PIPELINE_DIR = Path(__file__).resolve().parent

# Every source file actually deployed as part of the running pipeline.
# benchmarks/ is deliberately excluded -- those are one-off offline
# evaluation scripts, not something a running install ever executes.
SOURCE_FILES = [
    PIPELINE_DIR / "worker" / "ghidra-worker.py",
    PIPELINE_DIR / "worker" / "gpu-queue-drain.py",
    PIPELINE_DIR / "service" / "server.py",
    PIPELINE_DIR / "service" / "export_json.py",
    PIPELINE_DIR / "statictools" / "server.py",
    PIPELINE_DIR / "report" / "generate_report.py",
]

DEFAULT_ENV_FILE = "/etc/default/honeypot-ghidra"

# getenv("NAME", default) or getenv("NAME") -- default may be a quoted
# string, a call like os.environ.get(...).rstrip("/"), or absent entirely.
# Matched non-greedily across the assignment's own line; the value on the
# right of "=" is kept as source text, not evaluated, so python-only
# constructs are never eval()'d against an operator's own environment.
ASSIGN_RE = re.compile(
    r'^(?P<var>[A-Z][A-Z0-9_]*)\s*=\s*'
    r'(?:int\(|float\(|)\s*'
    r'os\.(?:environ\.get|getenv)\(\s*["\'](?P<name>[A-Z][A-Z0-9_]*)["\']'
    r'(?:\s*,\s*(?P<default>"[^"]*"|\'[^\']*\'))?',
    re.MULTILINE,
)


def extract(path: Path):
    """Yield (name, default_literal, description, source_file) for every
    os.environ.get(...)/os.getenv(...) call in path, reading the comment
    block immediately preceding the assignment as its description."""
    if not path.is_file():
        return
    lines = path.read_text().splitlines()
    text = "\n".join(lines)
    for match in ASSIGN_RE.finditer(text):
        name = match.group("name")
        default_raw = match.group("default")
        default = default_raw[1:-1] if default_raw else ""
        line_no = text.count("\n", 0, match.start())
        comment_lines = []
        i = line_no - 1
        while i >= 0 and lines[i].strip().startswith("#"):
            comment_lines.insert(0, lines[i].strip().lstrip("#").strip())
            i -= 1
        yield name, default, " ".join(comment_lines), path.relative_to(PIPELINE_DIR.parent.parent)


def load_env_file(path: Path):
    """Parse a simple KEY=VALUE shell-style env file (no export, no
    expansion) -- the same shape install-analysis-host.sh writes and
    honeypot-ghidra-worker.service's EnvironmentFile= reads."""
    values = {}
    if not path.is_file():
        return values
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def is_gate(default: str, description: str) -> bool:
    """Best-effort classification: a feature toggle, not just a tunable
    timeout/path. True when the code's own default is empty (this
    pipeline's established "empty disables it" convention -- see
    REVDECK_API_BASE, STATICTOOLS_API_BASE, GHIDRA_TRIAGE_API_BASE) or
    the surrounding comment says so explicitly."""
    if default == "":
        return True
    lowered = description.lower()
    return "empty" in lowered and ("disable" in lowered or "off" in lowered or "switch" in lowered)


def inventory():
    seen = {}
    for path in SOURCE_FILES:
        for name, default, description, source in extract(path):
            if name not in seen:
                seen[name] = {
                    "default": default,
                    "description": description,
                    "source": str(source),
                    "gate": is_gate(default, description),
                }
    return seen


def show(env_values, inv):
    on, off, configured = [], [], []
    for name in sorted(inv):
        meta = inv[name]
        current = env_values.get(name, meta["default"])
        row = (name, current, meta["default"], meta["source"], meta["description"])
        if meta["gate"]:
            (on if current else off).append(row)
        else:
            configured.append(row)

    def _print(rows):
        for name, current, default, source, description in rows:
            shown = current if current else "(empty)"
            print(f"  {name:<32} = {shown}")
            if description:
                print(f"      {description[:110]}")
            print(f"      source: {source}, code default: {default or '(empty)'}")

    print(f"ON  ({len(on)} feature{'s' if len(on) != 1 else ''} currently enabled)")
    _print(on)
    print(f"\nOFF ({len(off)} feature{'s' if len(off) != 1 else ''} currently disabled)")
    _print(off)
    print(f"\nOther tunables ({len(configured)})")
    _print(configured)


# Presets need domain knowledge of what a "sensible on" value actually is
# (a real loopback endpoint, not just any non-empty string) -- that is a
# different concern from the auto-discovered inventory above, and is the
# one place this script is deliberately hand-maintained. Kept intentionally
# small: only the true feature gates, matching the same defaults
# docs/analysis/ghidra/*.md and worker/honeypot-ghidra.default.example use.
PRESETS = {
    "all-on": {
        "STATICTOOLS_API_BASE": "http://127.0.0.1:9091",
        "GHIDRA_TRIAGE_API_BASE": "http://127.0.0.1:11434/v1",
        "REVDECK_API_BASE": "http://127.0.0.1:19500",
    },
    "minimal": {
        "STATICTOOLS_API_BASE": "",
        "GHIDRA_TRIAGE_API_BASE": "",
        "REVDECK_API_BASE": "",
    },
}


def apply(env_file: Path, overrides: dict):
    if not overrides:
        return
    lines = env_file.read_text().splitlines() if env_file.is_file() else []
    remaining = dict(overrides)
    for i, raw in enumerate(lines):
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if key in remaining:
            lines[i] = f"{key}={remaining.pop(key)}"
    for key, value in remaining.items():
        lines.append(f"{key}={value}")
    env_file.write_text("\n".join(lines) + "\n")
    for key, value in overrides.items():
        print(f"  {key}={value or '(empty)'}")
    print(f"\nWrote {env_file}. Restart the worker for this to take effect:")
    print("  sudo systemctl restart honeypot-ghidra-worker.service")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", default=DEFAULT_ENV_FILE)
    parser.add_argument("--set", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--preset", choices=["all-on", "minimal", "defaults"])
    args = parser.parse_args()

    env_file = Path(args.env_file)
    inv = inventory()
    env_values = load_env_file(env_file)

    if args.preset == "defaults":
        gate_names = {name for name, meta in inv.items() if meta["gate"]}
        remaining = [line for line in (env_file.read_text().splitlines() if env_file.is_file() else [])
                     if line.split("=", 1)[0].strip() not in gate_names]
        env_file.write_text("\n".join(remaining) + ("\n" if remaining else ""))
        print(f"Removed overrides for: {', '.join(sorted(gate_names))}")
        return
    if args.preset:
        apply(env_file, PRESETS[args.preset])
        return
    if args.set:
        overrides = {}
        for item in args.set:
            if "=" not in item:
                sys.exit(f"--set expects KEY=VALUE, got {item!r}")
            key, _, value = item.partition("=")
            overrides[key.strip()] = value.strip()
        apply(env_file, overrides)
        return

    show(env_values, inv)


if __name__ == "__main__":
    main()
