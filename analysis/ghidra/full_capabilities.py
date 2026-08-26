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
calls, so it stays accurate as the pipeline grows. That claim is enforced,
not aspirational: tests/test_full_capabilities.py re-scans the same files
with an independently written pattern and fails when either side sees a
name the other doesn't (this module once missed 8 of 59 real reads that
way -- #2064). Descriptions come from the comment block immediately above
each assignment, since that convention is already followed throughout this
pipeline (see e.g. REVDECK_API_BASE in worker/ghidra-worker.py).

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

# Two extraction passes (#2064: a single narrow assignment shape silently
# hid 8 of 59 real reads -- Path()-wrapped paths, underscore-named module
# vars, kwargs-nested argparse defaults).
#
# Pass 1 (ASSIGN_RE): the classic `VAR = os.environ.get(...)` statement,
# generalized -- underscore-leading variable names are allowed, and instead
# of whitelisting int(/float( individually, any chain of simple call
# wrappers between "=" and the read is consumed (`Path(`, `int(`,
# `.rstrip(...) callers' variable assignments, `os.path.join(` nesting and
# friends all appear in this pipeline). \s inside the chain/argument gaps
# spans newlines, so a one-var-per-call site wrapped across lines still
# attributes to its preceding comment block. The default may be a quoted
# string or absent; the value is kept as source text, never evaluated --
# python-only constructs are never eval()'d against an operator's own
# environment.
ASSIGN_RE = re.compile(
    r'^(?P<var>[A-Za-z_][A-Za-z0-9_.]*)\s*=\s*'
    r'(?:[A-Za-z_][A-Za-z0-9_.]*\(\s*)*'
    r'os\.(?:environ\.get|getenv)\(\s*["\'](?P<name>[A-Z][A-Z0-9_]*)["\']'
    r'(?:\s*,\s*(?P<default>"[^"]*"|\'[^\']*\'))?',
    re.MULTILINE,
)

# Pass 2 (BARE_RE fallback): every remaining literal read whose opening the
# assignment-shaped pass couldn't reach -- e.g. a kwarg default deep inside
# an argparse parser.add_argument(default=os.environ.get("GHIDRA_RESULTS_DIR",
# ...)) spanning lines, or a ternary buried mid-expression. It contributes
# name + code-default only (the enclosing statement isn't a clean
# VAR = read), attributed to whatever comment block precedes the site; a
# name already caught by pass 1 is skipped so nothing yields twice.
BARE_RE = re.compile(
    r'os\.(?:environ\.get|getenv)\(\s*["\'](?P<name>[A-Z][A-Z0-9_]*)["\']'
    r'(?:\s*,\s*(?P<default>"[^"]*"|\'[^\']*\'))?'
)


def _source_label(path: Path):
    """Repo-relative attribution for pipeline sources; anything extracted
    from outside the tree (tests probing miss shapes against synthetic
    files) keeps its own absolute path rather than raising."""
    try:
        return str(path.relative_to(PIPELINE_DIR.parent.parent))
    except ValueError:
        return str(path)


def _comment_block(lines, line_no):
    """Comment lines immediately above zero-based index line_no, joined --
    the description convention used throughout the pipeline."""
    out = []
    i = line_no - 1
    while i >= 0 and lines[i].strip().startswith("#"):
        out.insert(0, lines[i].strip().lstrip("#").strip())
        i -= 1
    return " ".join(out)


def extract(path: Path):
    """Yield (name, default_literal, description, source_file) for every
    os.environ.get(...)/os.getenv(...) call in path: pass-1 assignment
    shapes first (full wrapper/var context), then pass-2 fallback for any
    literal read site the assignment shape can't reach. A fallback hit whose
    opening overlaps a pass-1 match contributes nothing twice; hits inside
    '#' comment lines are ignored so documented examples never invent keys."""
    if not path.is_file():
        return
    lines = path.read_text().splitlines()
    text = "\n".join(lines)

    spans = []
    for match in ASSIGN_RE.finditer(text):
        name = match.group("name")
        default_raw = match.group("default")
        default = default_raw[1:-1] if default_raw else ""
        spans.append((match.start(), match.end()))
        line_no = text.count("\n", 0, match.start())
        yield name, default, _comment_block(lines, line_no), \
            _source_label(path)

    for match in BARE_RE.finditer(text):
        start = match.start()
        if any(lo <= start < hi for lo, hi in spans):
            continue
        hit_line = text.count("\n", 0, start)
        if lines[hit_line].strip().startswith("#"):
            continue
        name = match.group("name")
        default_raw = match.group("default")
        default = default_raw[1:-1] if default_raw else ""
        yield name, default, _comment_block(lines, hit_line), \
            _source_label(path)


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


def _write_env_file(env_file: Path, lines):
    """Land env-file contents atomically (#2064): systemd reads this file's
    directory as its EnvironmentFile, and a plain write_text can leave it
    truncated mid-write at exactly the moment the worker restarts -- observed
    as a half-applied override that looks like a feature silently flipping.
    tmp + os.replace is the same treatment evaluate-models.py already uses;
    the temp file inherits the original file's mode so 0600 secrets don't
    get widened to 0644 by a rewrite."""
    tmp = env_file.with_name("." + env_file.name + ".tmp")
    try:
        tmp.write_text("\n".join(lines) + ("\n" if lines else ""))
        try:
            os.chmod(tmp, os.stat(env_file).st_mode & 0o777)
        except FileNotFoundError:
            pass  # creating a brand-new env file -- sensible default applies
        os.replace(tmp, env_file)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def apply(env_file: Path, overrides: dict):
    if not overrides:
        return
    original = env_file.read_text().splitlines() if env_file.is_file() else []
    remaining = dict(overrides)
    lines = []
    # First occurrence of a managed key is rewritten in place; any LATER
    # duplicate is dropped outright. Leaving one behind replicates the bug
    # this fixes: systemd's EnvironmentFile lets the last line win, so a
    # stale duplicate below the freshly-written value would silently keep
    # overriding the intended setting forever.
    dropped_dupes = False
    for raw in original:
        stripped = raw.strip()
        is_assign = bool(stripped) and not stripped.startswith("#") and "=" in stripped
        key = stripped.split("=", 1)[0].strip() if is_assign else None
        if key in remaining:
            lines.append(f"{key}={remaining.pop(key)}")
        elif is_assign and key in overrides:
            dropped_dupes = True
        else:
            lines.append(raw)
    for key, value in remaining.items():
        lines.append(f"{key}={value}")
    _write_env_file(env_file, lines)
    for key, value in overrides.items():
        print(f"  {key}={value or '(empty)'}")
    if dropped_dupes:
        print("  (removed stale duplicate lines; EnvironmentFile last-one-wins let them outrank the rewrite)")
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
        _write_env_file(env_file, remaining)
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
