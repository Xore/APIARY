#!/usr/bin/env python3
"""Regression test for #2433: honeypot-sentrypeer/.env.example marked HP_BIND
as "REQUIRED: no default in compose.yml", while compose.yml actually carries
the fleet-standard ${HP_BIND:-10.8.0.2} fallback on both port bindings.

An operator following the (wrong) "required" comment would believe leaving
HP_BIND unset fails the stack; it actually starts silently bound to
10.8.0.2 like every sibling sensor. This test pins the two files back into
agreement: compose.yml must keep the :-10.8.0.2 default, and .env.example
must describe HP_BIND as optional with that same default, matching the
wording already used by honeypot-endlessh/-galah/-http/-elk/-canarytokens.
"""
import pathlib
import re
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
STACK_DIR = REPO_ROOT / "arcane" / "home" / "honeypot-sentrypeer"
COMPOSE_YML = STACK_DIR / "compose.yml"
ENV_EXAMPLE = STACK_DIR / ".env.example"

KEY_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
COMMENT_LINE = re.compile(r"^\s*#")


def _compose_text():
    return COMPOSE_YML.read_text(encoding="utf-8")


def _compose_interpolated_text():
    """compose.yml with whole-line comments stripped, i.e. only what Compose
    actually interpolates.

    The header comment references a *sibling* stack's binding in prose
    (dionaea's generic ``${HP_BIND}:5060``, written without a default because
    it names the variable, not that file's literal line) -- that is
    documentation, not configuration, and must not be held to this stack's
    own port-binding contract.
    """
    return "\n".join(
        line
        for line in _compose_text().splitlines()
        if not COMMENT_LINE.match(line)
    )


def _env_example_text():
    return ENV_EXAMPLE.read_text(encoding="utf-8")


def _documented_hp_bind():
    """(comment-line-above, key=value line) for HP_BIND in .env.example."""
    lines = _env_example_text().splitlines()
    for i, line in enumerate(lines):
        match = KEY_LINE.match(line.strip())
        if match and match.group(1) == "HP_BIND":
            preceding = lines[i - 1].strip() if i > 0 else ""
            return preceding, line.strip()
    return None, None


def test_compose_and_env_example_exist():
    assert COMPOSE_YML.exists(), f"missing {COMPOSE_YML}"
    assert ENV_EXAMPLE.exists(), f"missing {ENV_EXAMPLE}"


def test_compose_still_defaults_hp_bind_to_tunnel_address():
    """Guards the other half of the contract: if compose.yml ever drops the
    :-10.8.0.2 fallback (making HP_BIND genuinely required), this test's
    partner assertion below must be updated too -- it should not silently
    drift back out of sync."""
    text = _compose_interpolated_text()
    binds = re.findall(r"\$\{HP_BIND(:-[^}]*)?\}", text)
    assert binds, f"no ${{HP_BIND...}} interpolation found in {COMPOSE_YML}"
    for suffix in binds:
        assert suffix == ":-10.8.0.2", (
            f"expected every HP_BIND interpolation in {COMPOSE_YML.name} to carry "
            f"the fleet-standard :-10.8.0.2 fallback, found '${{HP_BIND{suffix}}}' (#2433)"
        )


def test_env_example_does_not_claim_hp_bind_is_required():
    comment, _ = _documented_hp_bind()
    assert comment is not None, f"HP_BIND not documented in {ENV_EXAMPLE}"
    assert "REQUIRED" not in comment.upper(), (
        f"{ENV_EXAMPLE.name} still marks HP_BIND as required, but compose.yml provides "
        f"a :-10.8.0.2 default (#2433): comment reads {comment!r}"
    )


def test_env_example_hp_bind_matches_compose_default():
    comment, key_line = _documented_hp_bind()
    assert key_line == "HP_BIND=10.8.0.2", (
        f"{ENV_EXAMPLE.name}'s HP_BIND line should match compose.yml's default "
        f"value verbatim, got {key_line!r} (#2433)"
    )
    assert "optional" in comment.lower() and "10.8.0.2" in comment, (
        f"{ENV_EXAMPLE.name}'s HP_BIND comment should state it's optional and name "
        f"the '10.8.0.2' default, matching the fleet-standard wording used by sibling "
        f"stacks (endlessh/galah/http/elk/canarytokens), got {comment!r} (#2433)"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
