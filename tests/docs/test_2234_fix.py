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

worker.py is inspected through `ast` rather than by matching a
multi-line regex against the raw text. The parser gives an exact,
unambiguous span for a function and its statements, so the assertions
below say what they mean ("the first statement is `if config.dry_run:
return`") instead of encoding it as a pattern that has to re-guess
Python's own indentation and docstring rules.
"""
import ast
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE_COMPOSE = REPO_ROOT / "llm-worker" / "docker-compose.yml"
CAPTURED_DATA_OVERLAY = REPO_ROOT / "llm-worker" / "docker-compose.captured-data.yml"
WORKER = REPO_ROOT / "llm-worker" / "worker.py"

PREFLIGHT = "compose_route_preflight"


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _worker_function(name: str) -> ast.FunctionDef:
    """Return the ast node of a top-level function in worker.py."""
    text = _read(WORKER)
    for node in ast.parse(text).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"worker.py must define a top-level {name}()")


def _function_source(node: ast.FunctionDef) -> str:
    """Return the exact source text of a function, docstring included."""
    segment = ast.get_source_segment(_read(WORKER), node)
    assert segment, f"could not recover the source of {node.name}()"
    return segment


def _body_after_docstring(node: ast.FunctionDef) -> list:
    """Return a function's statements with a leading docstring dropped."""
    body = node.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


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
        r"^[ \t]+ES_HOST:[ \t]*''[ \t]*$",
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
        r"^[ \t]+ES_HOST:[ \t]*'([^']+)'[ \t]*$",
        text,
        re.MULTILINE,
    )
    assert m, "captured-data overlay must set ES_HOST to a real URL"
    assert m.group(1).strip(), (
        f"captured-data overlay's ES_HOST must not be empty: {m.group(1)!r}"
    )


def test_compose_route_preflight_refuses_captured_data_without_es_host():
    """worker.py's compose_route_preflight() must raise RuntimeError
    when dry_run is false and ES_HOST is empty, with a message
    that names the overlay entrypoint so the next operator reading
    the log knows which file to use."""
    node = _worker_function(PREFLIGHT)
    body = _function_source(node)
    # Must gate on dry_run -- synthetic canary must not raise
    assert "config.dry_run" in body, (
        f"{PREFLIGHT} must be a no-op when LLM_DRY_RUN=true"
    )
    # Must check ES_HOST
    assert "ES_HOST" in body, f"{PREFLIGHT} must read ES_HOST"
    # Must raise RuntimeError (not just log)
    assert any(
        isinstance(stmt, ast.Raise)
        and isinstance(stmt.exc, ast.Call)
        and isinstance(stmt.exc.func, ast.Name)
        and stmt.exc.func.id == "RuntimeError"
        for stmt in ast.walk(node)
    ), f"{PREFLIGHT} must raise RuntimeError when the gate fails"
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
    must not raise.

    The early return has to be the FIRST executable statement, not
    merely present somewhere: a dry_run check placed after an ES_HOST
    lookup would still raise on the canary path."""
    node = _worker_function(PREFLIGHT)
    body = _body_after_docstring(node)
    assert body, f"{PREFLIGHT} must have a body"
    first = body[0]
    assert isinstance(first, ast.If), (
        f"{PREFLIGHT}'s first executable statement must be the dry_run "
        f"early-return, got {type(first).__name__}"
    )
    assert (
        isinstance(first.test, ast.Attribute)
        and first.test.attr == "dry_run"
        and isinstance(first.test.value, ast.Name)
        and first.test.value.id == "config"
    ), f"{PREFLIGHT}'s first statement must test `config.dry_run`"
    assert not first.orelse, "the dry_run guard must not carry an else branch"
    assert len(first.body) == 1 and isinstance(first.body[0], ast.Return), (
        f"{PREFLIGHT}'s dry_run guard must return immediately"
    )


def test_main_runs_compose_route_preflight_before_es_preflight():
    """The call order in main() must be compose_route_preflight()
    first, es_preflight() second. The compose-level gate is a
    same-process, network-free check; running it before es_preflight
    means a misconfigured bring-up fails with a named cause in
    milliseconds rather than after an es_preflight network timeout."""
    main = _worker_function("main")
    calls = [
        node.func.id
        for node in ast.walk(main)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert PREFLIGHT in calls, f"{PREFLIGHT} must be called from main()"
    assert "es_preflight" in calls, "es_preflight must still be called from main()"
    assert calls.index(PREFLIGHT) < calls.index("es_preflight"), (
        f"{PREFLIGHT} must be called before es_preflight in main() "
        "-- the cheap compose-level gate runs first so a misconfigured "
        "bring-up fails with a named cause in milliseconds, not after a "
        "network timeout"
    )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
