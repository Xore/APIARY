#!/usr/bin/env python3
"""Regression test for #2639: the buildx builder docker/setup-buildx-action@v4
creates in containers.yml must be cleaned up at job end.

Matrix rows serialize behind the single self-hosted runner instance
(containers.yml's comment on the `build` job). Without an explicit
stop+rm, a builder that survives a graceful_stop leaks into the next
row's `docker buildx build --cache-to=type=gha` and aborts its cache
export -- observed on three different rows (citrix-honeypot,
dashboard-next, vps-portbridge) on 2026-08-29.

Checked against the parsed step structure, not a whole-file substring,
so a `cleanup: true` that lands under the wrong step (e.g. build-push-
action) would not pass this test.
"""
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTAINERS_WORKFLOW = REPO_ROOT / ".github/workflows/containers.yml"


def _buildx_step(workflow: dict) -> dict:
    steps = workflow["jobs"]["build"]["steps"]
    matches = [s for s in steps if s.get("uses", "").startswith("docker/setup-buildx-action@")]
    assert len(matches) == 1, (
        "expected exactly one docker/setup-buildx-action step in the "
        f"`build` job, found {len(matches)}"
    )
    return matches[0]


def test_buildx_step_requests_cleanup():
    yaml = pytest.importorskip("yaml", reason="PyYAML not installed; workflow parse skipped")
    workflow = yaml.safe_load(CONTAINERS_WORKFLOW.read_text(encoding="utf-8"))
    step = _buildx_step(workflow)
    assert step.get("with", {}).get("cleanup") is True, (
        "docker/setup-buildx-action must set `cleanup: true` -- without it, a "
        "builder left behind by a graceful_stop leaks into the next matrix "
        "row's GHA cache export and aborts it (#2639)"
    )


def test_buildx_step_requests_cleanup_via_grep():
    """Dependency-free control: the tests/docs/ CI row only installs
    pytest (see quality.yml), so this must pass even where PyYAML is
    absent and the test above is skipped."""
    lines = CONTAINERS_WORKFLOW.read_text(encoding="utf-8").splitlines()
    buildx_index = next(
        i for i, line in enumerate(lines) if "docker/setup-buildx-action@" in line
    )
    next_step_index = next(
        (
            i
            for i, line in enumerate(lines[buildx_index + 1 :], start=buildx_index + 1)
            if line.strip().startswith("- uses:")
        ),
        len(lines),
    )
    block = lines[buildx_index:next_step_index]
    assert any("cleanup: true" in line for line in block), (
        "docker/setup-buildx-action step must have `cleanup: true` in its "
        f"with: block (#2639); got:\n{chr(10).join(block)}"
    )


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
