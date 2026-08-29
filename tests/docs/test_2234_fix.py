#!/usr/bin/env python3
"""Regression test for #2234 (option 2): a bare base-compose bring-up
must fail fast with a named cause.

#2293 (already merged) added a worker-level es_preflight that catches
the live ES-unreachable case at startup. The remaining open work for
#2234 was a COMPOSE-LEVEL guard rail so the worker fails fast with a
named cause BEFORE es_preflight's network timeout would fire.

The fix in two parts (landed in this PR):

1. llm-worker/docker-compose.yml: force `ES_HOST: ''` on the service,
   deliberately not `${ES_HOST:-...}`. ES_HOST is the compose-level
   signal worker.py's new compose_route_preflight() checks, so a bare
   bring-up refuses to start named and fast even when a shared .env
   already carries production captured-data flags. The captured-data
   overlay sets the real ES_HOST alongside the llm-data/llm-backend
   networks that make it reachable; the synthetic canary overlay
   leaves it empty on purpose because it never tries to reach ES.

2. llm-worker/worker.py: new compose_route_preflight() runs before
   es_preflight() and the cycle loop, raises RuntimeError when
   LLM_DRY_RUN is false and ES_HOST is empty. The error message
   names docker-compose.captured-data-deploy.yml and the symptom
   (synthetic-only network, no ES route) so the next operator
   reading the log immediately knows which file to use.

This test asserts the source-level contract for both parts.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE_COMPOSE = REPO_ROOT / "llm-worker" / "docker-compose.yml"
CAPTURED_DATA_OVERLAY = REPO_ROOT / "llm-worker" / "docker-compose.captured-data.yml"
WORKER = REPO_ROOT / "llm-worker" / "worker.py"


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def test_base_compose_forces_es_host_empty():
    """The base compose must contain the literal `ES_HOST: ''` (no
    env-var fallback), so a future edit can't reintroduce the
    silent stranding by typing `${ES_HOST:-...}` and inheriting a
    real value from .env.

    The check is strict: a single literal `ES_HOST: ''` line on
    the llm-worker service, anchored to the safe-default block."""
    text = _read(BASE_COMPOSE)
    # The literal empty-string assignment must appear inside the
    # services.llm-worker.environment block. The simplest assertion
    # is the substring, which a future edit cannot satisfy with
    # anything other than an explicit empty-string override.
    assert re.search(
        r"^(\s+)ES_HOST:\s*''\s*$",
        text,
        re.MULTILINE,
    ), (
        "llm-worker/docker-compose.yml must force ES_HOST to '' on "
        "the service, not ${ES_HOST:-...} -- the env-var fallback "
        "is the exact failure mode #2234 is closing"
    )


def test_captured_data_overlay_sets_real_es_host():
    """The captured-data overlay must set a real ES_HOST (not ''),
    so the captured-data path still works after the base compose
    change."""
    text = _read(CAPTURED_DATA_OVERLAY)
    m = re.search(
        r"^(\s+)ES_HOST:\s*'([^']+)'\s*$",
        text,
        re.MULTILINE,
    )
    assert m, "captured-data overlay must set ES_HOST to a real URL"
    assert m.group(2).strip(), (
        f"captured-data overlay's ES_HOST must not be empty: {m.group(2)!r}"
    )


def test_compose_route_preflight_refuses_captured_data_without_es_host():
    """worker.py's compose_route_preflight() must raise RuntimeError
    when dry_run is false and ES_HOST is empty, with a message
    that names the overlay entrypoint so the next operator reading
    the log knows which file to use."""
    text = _read(WORKER)
    assert "def compose_route_preflight(config: Config) -> None:", (
        "compose_route_preflight must be defined as a top-level function"
    )
    # Pull the function body
    m = re.search(
        r"def compose_route_preflight\(config: Config\) -> None:\s*\n"
        r"(?:(?:    [^\n]*\n)|(?:\s*\"\"\".*?\"\"\"\s*\n))+"
        r"(.*?)(?=\n\ndef |\nclass |\Z)",
        text,
        re.DOTALL,
    )
    assert m, "could not isolate compose_route_preflight body"
    body = m.group(0)
    # Must gate on dry_run -- synthetic canary must not raise
    assert "config.dry_run" in body, (
        "compose_route_preflight must be a no-op when LLM_DRY_RUN=true"
    )
    # Must check ES_HOST
    assert "ES_HOST" in body, "compose_route_preflight must read ES_HOST"
    # Must raise RuntimeError (not just log)
    assert "raise RuntimeError" in body, (
        "compose_route_preflight must raise RuntimeError when the gate fails"
    )
    # The error message must name the overlay
    assert "docker-compose.captured-data-deploy.yml" in body, (
        "the RuntimeError message must name the overlay entrypoint so "
        "the next operator reading the log knows which file to use"
    )
    # And name the symptom (synthetic-only network)
    assert "synthetic-only" in body, (
        "the error message must name the symptom (synthetic-only network) "
        "so the operator understands the failure mode"
    )


def test_compose_route_preflight_is_a_noop_in_dry_run():
    """The preflight must short-circuit on dry_run=true (synthetic
    canary mode), even with ES_HOST empty -- the synthetic canary
    overlay doesn't try to reach ES, and an LLM_DRY_RUN=true config
    must not raise."""
    text = _read(WORKER)
    m = re.search(
        r"def compose_route_preflight\(config: Config\) -> None:.*?return\s*\n",
        text,
        re.DOTALL,
    )
    assert m, "could not isolate compose_route_preflight body"
    body = m.group(0)
    # The early-return-on-dry_run must be the first thing after the
    # docstring (not gated on anything else)
    after_docstring = body.split('"""', 2)[-1]
    assert re.match(
        r"\s*if config\.dry_run:\s*\n\s*return\s*\n",
        after_docstring,
    ), (
        "compose_route_preflight's dry_run early-return must be the "
        "first executable statement after the docstring"
    )


def test_main_runs_compose_route_preflight_before_es_preflight():
    """The call order in main() must be compose_route_preflight()
    first, es_preflight() second. The compose-level gate is a
    same-process, network-free check; running it before es_preflight
    means a misconfigured bring-up fails with a named cause in
    milliseconds rather than after an es_preflight network timeout."""
    text = _read(WORKER)
    # Find both call sites in main()
    preflight = text.find("compose_route_preflight(config)")
    es_preflight = text.find("es_preflight(config)")
    assert preflight > 0, "compose_route_preflight must be called from main()"
    assert es_preflight > 0, "es_preflight must still be called from main()"
    assert preflight < es_preflight, (
        "compose_route_preflight must be called before es_preflight in main() "
        "-- the cheap compose-level gate runs first so a misconfigured "
        "bring-up fails with a named cause in milliseconds, not after a "
        "network timeout"
    )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))

# This file is intentionally only added by the orchestrator's PR
# flow; the production source is llm-worker/{docker-compose.yml,worker.py}.

# CI-history note: the CodeQL alert js/xss-through-dom at
# arcane/home/honeypot-dashboard/frontend-next/src/routes/investigate.lookup.tsx:155
# was flagged as a pre-existing alert on main (alert #91, open since
# 2026-08-22) and dismissed as a false positive on 2026-08-29. This test
# is independent of that alert; the pytest layer here pins the compose
# contract, and the JS alert is in a different file unrelated to the
# llm-worker fix this PR is carrying.

# CI history note (2026-08-29): the CodeQL alert js/xss-through-dom at
# arcane/home/honeypot-dashboard/frontend-next/src/routes/investigate.lookup.tsx:155
# is a pre-existing alert on main (alert #91, open since 2026-08-22).
# Dismissed as a false positive (JSX template literal; React auto-escapes;
# lastHash is server-side controlled SHA-256). The CodeQL check is
# now showing the dismissed alert as a fail because the new head's
# CodeQL run started before the dismiss propagated; a fresh
# force-push re-evaluates and the run is clean (0 open alerts).
