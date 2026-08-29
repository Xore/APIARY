#!/usr/bin/env python3
"""Regression test for #2329: OLLAMA_URL must be wired and the
backend-service must join the network that carries the ollama alias,
so the split-stack semantic-search route is actually reachable.

The deployed split-stack compose joined backend-service to only
honeynet and set OLLAMA_URL nowhere, while ollama publishes on
http://ollama:11434 only via an analysis/ghidra network alias. So:
unset → "available": false forever; even a correctly-set value
pointed at an address unreachable from backend's sole network.

The fix in two parts (landed in this PR):
1. arcane/home/honeypot-dashboard-backend/compose.yml: set
   OLLAMA_URL=http://ollama:11434 on the backend-service, and add
   honeypot-llm to the service's networks.
2. arcane/home/honeypot-dashboard/compose.yml: drop the now-unused
   honeypot-llm network entry (the dashboard never owned that
   network; it was a leftover from when the dashboard tried and
   failed to bridge ollama from the analysis/ghidra compose).

This test asserts the source-level contract for both parts.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BACKEND_COMPOSE = (
    REPO_ROOT
    / "arcane/home/honeypot-dashboard-backend/compose.yml"
)
DASHBOARD_COMPOSE = (
    REPO_ROOT / "arcane/home/honeypot-dashboard/compose.yml"
)


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def test_backend_compose_sets_ollama_url():
    """backend-service must have OLLAMA_URL=http://ollama:11434 in
    its environment block. The bare 'ollama' alias is the only
    value ollama_url() (llm_search.rs) will accept: anything else
    is rejected as a hardening measure, so the value has to be
    exactly the alias the analysis/ghidra compose publishes."""
    text = _read(BACKEND_COMPOSE)
    # Find the OLLAMA_URL line in the backend-service environment
    m = re.search(
        r"^\s*-\s*OLLAMA_URL=http://ollama:11434\s*$",
        text,
        re.MULTILINE,
    )
    assert m, (
        "honeypot-dashboard-backend compose must set "
        "OLLAMA_URL=http://ollama:11434 on backend-service"
    )


def test_backend_compose_joins_honeypot_llm():
    """backend-service must join the honeypot-llm network so the
    ollama alias is actually reachable (DNS resolution is per-
    network, not global)."""
    text = _read(BACKEND_COMPOSE)
    # The networks block under backend-service must list honeypot-llm
    assert "networks:" in text
    # Find the backend-service block and check its networks
    # (best-effort: a coarse substring is sufficient since the
    # compose file is small and the network name is unique)
    assert "honeypot-llm" in text, (
        "backend-service must join the honeypot-llm network so the "
        "ollama alias is reachable from the backend container"
    )


def test_dashboard_compose_does_not_define_honeypot_llm():
    """The dashboard compose must not define honeypot-llm itself --
    it was a leftover that future operators could mistake for the
    source of truth. The network is owned by analysis/ghidra's
    compose (external: true there)."""
    text = _read(DASHBOARD_COMPOSE)
    # The dashboard compose should not contain a `honeypot-llm:`
    # network definition (any indentation). The substring
    # `honeypot-llm:` would still match network references in
    # `external: true` lookups, so we anchor on the YAML key syntax.
    assert not re.search(
        r"^(\s+)honeypot-llm:\s*$",
        text,
        re.MULTILINE,
    ), (
        "honeypot-dashboard compose must not define honeypot-llm "
        "as a top-level network -- it is owned by analysis/ghidra "
        "(external: true there); a local definition would mislead "
        "future operators into thinking the dashboard owns it"
    )


def test_dashboard_compose_does_not_reference_honeypot_llm_network():
    """Stronger check: the dashboard compose must not reference the
    honeypot-llm network at all. The network is consumed (via
    external: true) by the analysis/ghidra and honeypot-dashboard-
    backend composes; the dashboard frontend never needed it."""
    text = _read(DASHBOARD_COMPOSE)
    assert "honeypot-llm" not in text, (
        "honeypot-dashboard compose must not reference honeypot-llm "
        "at all -- the network is consumed by the backend-service "
        "and the analysis/ghidra compose, not by the dashboard"
    )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
