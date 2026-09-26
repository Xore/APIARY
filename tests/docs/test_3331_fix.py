#!/usr/bin/env python3
"""Regression test for #3331: the frontend-next gates ran on a node major
the image does not ship.

frontend-next's Dockerfile builds and runs on node:22-alpine, while all four
frontend jobs in quality.yml (frontend-next, frontend-next-cloud,
frontend-next-browser, frontend-next-browser-cloud) pinned setup-node to
"24". The only Node 22 coverage in the workflow was the #1816 lockfile-install
step, so the typecheck, the 179 unit tests, the production build, the
generated route-tree diff and both Playwright matrices had never executed on
the node that serves the artifact.

The fix pins those jobs to the Dockerfile's own FROM line via
scripts/node-runtime-major.sh rather than to a literal, so an image bump
moves CI in the same commit. What that makes worth pinning is the wiring,
not the number:

- every frontend job resolves the version from the script, and does so
  BEFORE setup-node consumes it (a resolve after setup-node is a step that
  never runs and a pin that silently reverts to whatever was there);
- no frontend job carries a hardcoded node major or a hardcoded node image
  again, which is the state the issue describes;
- the resolve step actually reads frontend-next's Dockerfile.

Deliberately NOT asserted here: that the two numbers match. That is
scripts/tests/test_node_runtime_major.py's job, and restating it here would
only duplicate the derivation. What is asserted is that CI no longer decides
the number on its own.

The dependency-free half matters: quality.yml's tests/docs row installs only
pytest (line ~1059), so every assertion below has a PyYAML-free control.
"""
import pathlib
import re
import stat
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
QUALITY_WORKFLOW = REPO_ROOT / ".github/workflows/quality.yml"
SCRIPT = REPO_ROOT / "scripts/node-runtime-major.sh"
DOCKERFILE_REL = "arcane/home/honeypot-dashboard/frontend-next/Dockerfile"

FRONTEND_JOBS = (
    "frontend-next",
    "frontend-next-cloud",
    "frontend-next-browser",
    "frontend-next-browser-cloud",
)

RESOLVE_STEP_ID = "node-runtime"
DERIVED_VERSION = "${{ steps." + RESOLVE_STEP_ID + ".outputs.node-version }}"
DERIVED_IMAGE = "${{ steps." + RESOLVE_STEP_ID + ".outputs.node-image }}"

_workflow_text = QUALITY_WORKFLOW.read_text(encoding="utf-8")
_lines = _workflow_text.splitlines()


def _job_block(job: str) -> list[str]:
    """The lines of one job, by indentation.

    Jobs sit at two spaces; the body runs until the next line that is
    indented exactly two spaces and then a non-space. A substring search for
    "\\n  " would be wrong here -- it also matches the first two spaces of a
    six-space step line, so the body would stop at the first step and every
    "this text is absent" assertion below would pass vacuously.
    """
    start = next(
        (
            i
            for i, line in enumerate(_lines)
            if line == f"  {job}:"
        ),
        None,
    )
    assert start is not None, f"job {job} not found in {QUALITY_WORKFLOW.name}"
    body = []
    for line in _lines[start + 1 :]:
        if line.strip() and not line.startswith("   "):
            break
        body.append(line)
    return body


def _workflow():
    yaml = pytest.importorskip("yaml", reason="PyYAML not installed; workflow parse skipped")
    return yaml.safe_load(_workflow_text)


# --------------------------------------------------------------------------
# The script the whole fix rests on.
# --------------------------------------------------------------------------


def test_derive_script_is_present_and_executable():
    assert SCRIPT.is_file(), f"{SCRIPT} is missing; the frontend jobs invoke it"
    mode = SCRIPT.stat().st_mode
    assert mode & stat.S_IXUSR, (
        f"{SCRIPT.name} lost its executable bit. quality.yml calls it as "
        f"./{SCRIPT.name} rather than through bash, so a non-executable file "
        f"fails the job with a bare permission error (#3331)."
    )


def test_derive_script_runs_and_names_a_major():
    """The script must work on the real Dockerfile, not just on fixtures."""
    proc = subprocess.run(
        ["bash", str(SCRIPT), str(REPO_ROOT / DOCKERFILE_REL)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        f"the derive script failed on {DOCKERFILE_REL}:\n{proc.stderr}\n"
        f"If the image moved off node, teach the script that runtime rather "
        f"than deleting the call."
    )
    assert re.search(r"\bnode \d+ \(node:", proc.stdout), (
        f"expected a derived major and image on stdout, got: {proc.stdout!r}"
    )


# --------------------------------------------------------------------------
# Every frontend job derives, and derives before it consumes.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("job", FRONTEND_JOBS)
def test_frontend_job_derives_the_version_before_setup_node(job):
    workflow = _workflow()
    steps = workflow["jobs"][job]["steps"]

    resolve_indexes = [
        i for i, s in enumerate(steps) if s.get("id") == RESOLVE_STEP_ID
    ]
    assert len(resolve_indexes) == 1, (
        f"{job} must have exactly one step with id '{RESOLVE_STEP_ID}' to "
        f"resolve the node major, found {len(resolve_indexes)}"
    )
    assert DOCKERFILE_REL in steps[resolve_indexes[0]].get("run", ""), (
        f"{job}'s resolve step must read {DOCKERFILE_REL}; got "
        f"{steps[resolve_indexes[0]].get('run')!r}. Deriving from any other "
        f"file would reintroduce the drift (#3331)."
    )

    setup_indexes = [
        i for i, s in enumerate(steps) if "actions/setup-node" in s.get("uses", "")
    ]
    assert len(setup_indexes) == 1, (
        f"{job} must have exactly one setup-node step, found {len(setup_indexes)}"
    )
    assert resolve_indexes[0] < setup_indexes[0], (
        f"{job} resolves the node major at step {resolve_indexes[0]} but "
        f"consumes it at step {setup_indexes[0]}. A resolve that runs after "
        f"setup-node leaves the output empty and silently reverts the pin to "
        f"setup-node's default (#3331)."
    )

    assert steps[setup_indexes[0]]["with"]["node-version"] == DERIVED_VERSION, (
        f"{job} must pass the derived node major to setup-node, not a literal. "
        f"A hardcoded major is the exact defect #3331 reports: it drifted away "
        f"from the image while every job still reported green."
    )


def test_no_frontend_job_hardcodes_a_node_major():
    """Belt and braces on the same invariant, without PyYAML.

    Scoped to the four jobs' own text: the two design-lab jobs and the
    OIDC suites legitimately pin their own node (see the inert-matrix-entry
    note in quality.yml), and this is not their test.
    """
    for job in FRONTEND_JOBS:
        body = "\n".join(_job_block(job))
        assert body, f"_job_block({job}) returned nothing; the extractor is broken"
        assert not re.search(r"node-version:\s*[\"']?\d", body), (
            f"{job} pins node-version to a literal again. It must read the "
            f"Dockerfile's FROM line so the image and the gate cannot drift "
            f"apart a second time (#3331)."
        )


@pytest.mark.parametrize("job", FRONTEND_JOBS)
def test_derive_precedes_setup_node_without_yaml(job):
    """Dependency-free control for the ordering half of the invariant.

    The tests/docs CI row installs only pytest, so the parsed-workflow
    assertions above skip there. A resolve step that lands after setup-node
    is a silent regression -- the output is empty, setup-node falls back to
    its default, and every job still reports green -- so the ordering is
    worth a check that runs without PyYAML.
    """
    body = _job_block(job)
    resolve = next(
        (i for i, line in enumerate(body) if f"id: {RESOLVE_STEP_ID}" in line),
        None,
    )
    setup = next(
        (
            i
            for i, line in enumerate(body)
            if "actions/setup-node" in line and line.strip().startswith("- uses:")
        ),
        None,
    )
    assert resolve is not None, (
        f"{job} has no step with id '{RESOLVE_STEP_ID}' to derive the node major (#3331)"
    )
    assert setup is not None, f"{job} has no setup-node step"
    assert resolve < setup, (
        f"{job} resolves the node major at body line {resolve} but consumes it "
        f"at line {setup}. setup-node runs first, reads an empty output, and "
        f"uses its default -- which is how a green job ends up testing a node "
        f"nobody ships (#3331)."
    )
    assert any(
        line.strip() == f"node-version: {DERIVED_VERSION}" for line in body[setup:]
    ), (
        f"{job}'s setup-node does not consume {DERIVED_VERSION}; the derive is "
        f"wired to nothing (#3331)"
    )


def test_lockfile_step_uses_the_derived_image():
    """The #1816 check is the other half of the same invariant.

    It already ran the image's npm; what was hardcoded was the image's name.
    Leaving that literal behind would have meant the workflow still carried a
    hand-written node version for the one step that cares most about the
    runtime, and a bump would test node 24's npm against a node 22 build.
    """
    workflow = _workflow()
    for job in ("frontend-next", "frontend-next-cloud"):
        runs = [
            s.get("run", "")
            for s in workflow["jobs"][job]["steps"]
            if "npm ci --no-audit --no-fund" in s.get("run", "")
            and "docker run" in s.get("run", "")
        ]
        assert runs, f"{job} no longer runs `npm ci` inside the builder image (#1816)"
        for run in runs:
            assert DERIVED_IMAGE in run, (
                f"{job}'s lockfile step names the builder image literally; it "
                f"must use {DERIVED_IMAGE} so the tag tracks the Dockerfile (#3331)."
            )


def test_frontend_jobs_still_cover_the_gate_steps():
    """The derive must not have cost the job any of its checks.

    A refactor that quietly dropped `npm test` or `npm run build` from the
    blocking job would satisfy every assertion above -- the jobs would still
    derive correctly while testing nothing.
    """
    workflow = _workflow()
    for job in ("frontend-next", "frontend-next-cloud"):
        runs = "\n".join(
            s.get("run", "") for s in workflow["jobs"][job]["steps"] if s.get("run")
        )
        for expected in ("npm ci", "npm run typecheck", "npm test", "npm run build"):
            assert expected in runs, f"{job} no longer runs `{expected}` (#3331)"
    for job in ("frontend-next-browser", "frontend-next-browser-cloud"):
        runs = "\n".join(
            s.get("run", "") for s in workflow["jobs"][job]["steps"] if s.get("run")
        )
        assert "npm run build" in runs, f"{job} no longer runs `npm run build` (#3331)"
        assert "npm run test:browser" in runs, (
            f"{job} no longer runs `npm run test:browser` (#3331)"
        )


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
