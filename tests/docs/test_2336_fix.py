#!/usr/bin/env python3
"""Regression test for #2336: ZEEK_PROXY_* consumed with empty defaults and
undocumented in the honeypot-elk env example.

On a fresh host, `${ZEEK_PROXY_IFACE:-}` defaulting silently to empty meant
zeek-proxy bound af_packet-less on whatever the kernel picked as "default"
and degraded capture with log errors instead of failing fast -- silently
collecting partial session data that later reached the dashboard as if
complete (the #1677 class, minus even documentation).

The fix is two-part and lives in arcane/home/honeypot-elk/:
1. .env.example documents ZEEK_PROXY_IFACE with an explanatory comment
   (it has no safe default -- the comment says so and says why).
2. compose.yml's zeek-proxy entrypoint gates boot on the variable being
   non-empty, exiting non-zero with a named cause instead of sniffing the
   wrong interface.

This test parses both files directly rather than hardcoding a copy of the
shell gate, so it fails if either half of the contract drifts: the entrypoint
script is extracted live from compose.yml and actually executed under `sh`
to prove the gate really exits non-zero, not just that the right substrings
are present in the YAML.
"""
import os
import pathlib
import re
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
STACK_DIR = REPO_ROOT / "arcane" / "home" / "honeypot-elk"
COMPOSE_YML = STACK_DIR / "compose.yml"
ENV_EXAMPLE = STACK_DIR / ".env.example"

INTERP = re.compile(r"(?<!\$)\$\{(ZEEK_PROXY_[A-Za-z0-9_]+)")
KEY_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=")


def _compose_text():
    return COMPOSE_YML.read_text(encoding="utf-8")


def _zeek_proxy_vars_interpolated():
    """Every ZEEK_PROXY_* name compose.yml interpolates via ${...}, ignoring
    comment lines and the container-local $${...} shell-escape form."""
    found = set()
    for line in _compose_text().splitlines():
        if line.lstrip().startswith("#"):
            continue
        found.update(INTERP.findall(line))
    return found


def _documented_keys():
    found = set()
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        match = KEY_LINE.match(line.strip())
        if match:
            found.add(match.group(1))
    return found


def _zeek_proxy_service_block():
    """The zeek-proxy service's own text, from its key to the next line
    dedented back to service level (a sibling service) or below (a
    top-level compose key like `networks:`)."""
    lines = _compose_text().splitlines()
    start = next((i for i, l in enumerate(lines) if re.match(r"^  zeek-proxy:\s*$", l)), None)
    assert start is not None, f"no top-level `zeek-proxy:` service found in {COMPOSE_YML}"
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.strip() == "":
            block.append(line)
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= 2:
            break
        block.append(line)
    return "\n".join(block)


def _extract_literal_block(block_text, anchor_regex):
    """Contents of a YAML `|` literal block scalar, dedented, given a regex
    matching the `- |` indicator line."""
    lines = block_text.splitlines()
    anchor_idx = next((i for i, l in enumerate(lines) if re.match(anchor_regex, l)), None)
    assert anchor_idx is not None, f"no line matching {anchor_regex!r} in service block"
    base_indent = None
    content = []
    for line in lines[anchor_idx + 1:]:
        if line.strip() == "":
            content.append("")
            continue
        indent = len(line) - len(line.lstrip(" "))
        if base_indent is None:
            base_indent = indent
        elif indent < base_indent:
            break
        content.append(line[base_indent:])
    return "\n".join(content)


def _first_if_block(script_text, assign_prefix):
    """The iface assignment line through the first standalone `fi` after
    it -- i.e. just the unset/empty gate, not the rest of the startup
    script (interface-existence check, af_packet/libpcap selection, exec)."""
    lines = script_text.splitlines()
    start = next(i for i, l in enumerate(lines) if l.strip().startswith(assign_prefix))
    end = next(i for i, l in enumerate(lines[start:], start) if l.strip() == "fi")
    return "\n".join(lines[start:end + 1])


def _iface_gate_script():
    block = _zeek_proxy_service_block()
    raw = _extract_literal_block(block, r"^\s*-\s*\|\s*$")
    script = raw.replace("$$", "$")  # undo compose's shell-escape for $${...}
    return _first_if_block(script, 'iface="${ZEEK_PROXY_IFACE')


def test_compose_and_env_example_exist():
    assert COMPOSE_YML.exists(), f"missing {COMPOSE_YML}"
    assert ENV_EXAMPLE.exists(), f"missing {ENV_EXAMPLE}"


def test_every_zeek_proxy_var_is_documented_in_env_example():
    compose_vars = _zeek_proxy_vars_interpolated()
    assert compose_vars, "expected at least one ZEEK_PROXY_* var interpolated in compose.yml"
    missing = compose_vars - _documented_keys()
    assert not missing, (
        f"ZEEK_PROXY_* vars interpolated in {COMPOSE_YML.name} but undocumented in "
        f"{ENV_EXAMPLE.name}: {sorted(missing)} (#2336)"
    )


def test_zeek_proxy_env_entries_have_an_explanatory_comment():
    lines = ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
    zeek_keys = [m.group(1) for m in (KEY_LINE.match(l.strip()) for l in lines) if m and m.group(1).startswith("ZEEK_PROXY_")]
    assert zeek_keys, f"no ZEEK_PROXY_* key found in {ENV_EXAMPLE}"
    for i, line in enumerate(lines):
        match = KEY_LINE.match(line.strip())
        if not match or not match.group(1).startswith("ZEEK_PROXY_"):
            continue
        name = match.group(1)
        preceding = lines[i - 1].strip() if i > 0 else ""
        assert preceding.startswith("#") and len(preceding.lstrip("#").strip()) > 0, (
            f"{name} in {ENV_EXAMPLE.name} has no explanatory comment directly above it (#2336)"
        )


def test_zeek_proxy_service_has_a_startup_gate():
    block = _zeek_proxy_service_block()
    assert any(key in block for key in ("entrypoint:", "command:", "healthcheck:")), (
        "zeek-proxy service has no entrypoint/command/healthcheck to gate boot on (#2336)"
    )
    assert "ZEEK_PROXY_IFACE" in block, "zeek-proxy service never references ZEEK_PROXY_IFACE (#2336)"
    assert "exit 1" in block, "zeek-proxy startup gate has no non-zero exit path (#2336)"


def test_gate_script_exits_nonzero_when_iface_unset():
    gate = _iface_gate_script()
    env = {k: v for k, v in os.environ.items() if k != "ZEEK_PROXY_IFACE"}
    result = subprocess.run(["sh", "-c", gate], env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 1, (
        f"gate did not exit non-zero for unset ZEEK_PROXY_IFACE (#2336); "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "ZEEK_PROXY_IFACE" in result.stderr, f"error message doesn't name the missing variable: {result.stderr!r}"


def test_gate_script_exits_nonzero_when_iface_empty_string():
    gate = _iface_gate_script()
    env = {k: v for k, v in os.environ.items() if k != "ZEEK_PROXY_IFACE"}
    env["ZEEK_PROXY_IFACE"] = ""
    result = subprocess.run(["sh", "-c", gate], env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 1, (
        f"gate did not exit non-zero for empty ZEEK_PROXY_IFACE (#2336); "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "ZEEK_PROXY_IFACE" in result.stderr


def test_gate_script_does_not_block_a_real_interface():
    """The gate must trip only on empty/unset, never on a legitimately
    configured, existing interface -- `lo` is present on every Linux host."""
    gate = _iface_gate_script()
    env = {k: v for k, v in os.environ.items() if k != "ZEEK_PROXY_IFACE"}
    env["ZEEK_PROXY_IFACE"] = "lo"
    result = subprocess.run(["sh", "-c", gate], env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, (
        f"gate incorrectly rejected a non-empty ZEEK_PROXY_IFACE (#2336); stderr={result.stderr!r}"
    )
    assert "is unset" not in result.stderr


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
