#!/usr/bin/env python3
"""Regression test for #2225: llm-worker/docker-compose.captured-data-deploy.yml
(#1751) is the entrypoint live redeploys authorized under #83 actually run --
`docker compose -f llm-worker/docker-compose.captured-data-deploy.yml up -d`,
via an `include:`, not a stacked `-f base -f overlay` pair. Neither CI gate
that catches broken compose ever ran against it: deploy.yml's manifest loop
validates the manifest's `dockerComposePath` (the safe base, not the
authorized entrypoint), and quality.yml's "Validate home and VPS Compose"
step validated `-f` pairs for every #83 overlay except this one. A bad
include path or an invalid key in the entrypoint sailed through both and
would first surface as a failed or silently mis-scoped live redeploy -- how
#1751's incident happened in the first place.

This pins two things: the entrypoint is validated by the same "Validate home
and VPS Compose" matrix row that already validates llm-worker's main compose
(catches syntax breakage), and that row also asserts the resolved config
still carries the captured-data authorization -- ES_HOST set, both
honeypot-llm-data/honeypot-llm networks attached, both :ro payload mounts
present (catches a silently-truncated `include:` list, which is syntactically
valid but resolves back to synthetic-only).
"""
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
QUALITY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "quality.yml"
DEPLOY_ENTRYPOINT = REPO_ROOT / "llm-worker" / "docker-compose.captured-data-deploy.yml"
STEP_NAME = "Validate home and VPS Compose"


def _validate_compose_row():
    yaml = pytest.importorskip("yaml", reason="PyYAML not installed; workflow parse skipped")
    workflow = yaml.safe_load(QUALITY_WORKFLOW.read_text(encoding="utf-8"))
    rows = workflow["jobs"]["scripts-and-compose"]["strategy"]["matrix"]["include"]
    matches = [row for row in rows if row.get("name") == STEP_NAME]
    assert len(matches) == 1, (
        f"expected exactly one {STEP_NAME!r} row in scripts-and-compose's "
        f"matrix, found {len(matches)}"
    )
    return matches[0]


def test_deploy_entrypoint_file_exists():
    assert DEPLOY_ENTRYPOINT.is_file(), (
        "llm-worker/docker-compose.captured-data-deploy.yml is gone -- #1751's "
        "authorization record for captured-data deploys must stay in the repo "
        "(deleting it is meant to be the deliberate way back to synthetic-only, "
        "not an accident)."
    )


def test_deploy_entrypoint_validated_in_same_gate_as_main_compose():
    """The core #2225 fix: same matrix row, same `docker compose ... config`
    treatment as llm-worker/docker-compose.yml, not a separate/skipped gate."""
    row = _validate_compose_row()
    run = row.get("run", "")
    assert "llm-worker/docker-compose.yml" in run, (
        f"{STEP_NAME!r} no longer validates llm-worker/docker-compose.yml -- "
        f"can't compare treatment against the captured-data entrypoint."
    )
    assert (
        "docker compose -f llm-worker/docker-compose.captured-data-deploy.yml"
        " config --quiet" in run
    ), (
        f"{STEP_NAME!r} does not run `docker compose -f "
        f"llm-worker/docker-compose.captured-data-deploy.yml config --quiet`. "
        f"This is the only entrypoint live redeploys authorized under #83 "
        f"actually use (#1751); without this line a bad `include:` path or "
        f"an invalid key sails through CI and only surfaces at redeploy (#2225)."
    )


def test_deploy_entrypoint_gate_asserts_authorization_survived():
    """Syntactic validity isn't enough: stripping an include still resolves to
    valid, synthetic-only config. The gate must also check the resolved model
    still carries what the entrypoint exists to authorize."""
    row = _validate_compose_row()
    run = row.get("run", "")
    assert "config --format json" in run, (
        f"{STEP_NAME!r} validates the entrypoint's syntax but never inspects "
        f"the resolved model -- a stripped `include:` entry (e.g. losing "
        f"docker-compose.captured-data.yml) still resolves to valid, "
        f"synthetic-only config and would pass silently (#2225)."
    )
    for needle in (
        'environment.ES_HOST',
        "honeypot-llm-data",
        "honeypot-llm",
        "/payloads/cowrie",
        "/payloads/scripts",
    ):
        assert needle in run, (
            f"{STEP_NAME!r}'s resolved-config check no longer mentions "
            f"{needle!r} -- the authorization assertion (#2225) must cover "
            f"ES_HOST, both captured-data networks, and both read-only "
            f"payload mounts, or a silently-truncated include chain stops "
            f"being detectable."
        )


def test_deploy_entrypoint_gate_via_grep():
    """Dependency-free control: the tests/docs/ CI row only installs pytest
    (see quality.yml), so this must pass even where PyYAML is absent and the
    tests above are skipped."""
    lines = QUALITY_WORKFLOW.read_text(encoding="utf-8").splitlines()
    step_index = next(
        i for i, line in enumerate(lines) if line.strip() == f"- name: {STEP_NAME}"
    )
    next_row_index = next(
        (
            i
            for i, line in enumerate(lines[step_index + 1 :], start=step_index + 1)
            if line.strip().startswith("- name:")
        ),
        len(lines),
    )
    block = "\n".join(lines[step_index:next_row_index])
    assert "llm-worker/docker-compose.captured-data-deploy.yml" in block, (
        f"{STEP_NAME!r} row does not mention "
        f"llm-worker/docker-compose.captured-data-deploy.yml (#2225)."
    )
    assert "config --quiet" in block and "config --format json" in block, (
        f"{STEP_NAME!r} row must both syntax-validate the captured-data "
        f"entrypoint (`config --quiet`) and inspect its resolved model "
        f"(`config --format json`) so a truncated `include:` list is caught "
        f"too, not just YAML breakage (#2225)."
    )


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
