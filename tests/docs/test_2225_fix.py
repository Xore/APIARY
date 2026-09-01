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

This pins three things: the entrypoint is validated by the same "Validate home
and VPS Compose" matrix row that already validates llm-worker's main compose
(catches syntax breakage); that row also asserts the resolved config still
carries the captured-data authorization -- ES_HOST set, both
honeypot-llm-data/honeypot-llm networks attached, both :ro payload mounts
present (catches a silently-truncated `include:` list, which is syntactically
valid but resolves back to synthetic-only); and the entrypoint's `include:`
keeps the shape that actually composes the two files.

That last one is what the gate caught on its first run, and it was a real
defect in the entrypoint, not in the check. Each entry under `include:` is an
*independent* model imported into the including file's model on its own --
entries do not override one another the way `-f base -f overlay` does. With

    include:
      - docker-compose.yml
      - docker-compose.captured-data.yml

the base claims `services.llm-worker` first, the overlay's identically-named
service is dropped, and the base's deliberate `ES_HOST: ''` (#2234) survives:
a live `docker compose -f ...captured-data-deploy.yml up -d` came back
synthetic-only while looking correct, which is #1751's failure mode. A single
entry with a list-valued `path:` is the documented way to merge several files
into one included model, i.e. the same override chain as `-f a -f b`.
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


def test_deploy_entrypoint_include_merges_both_files():
    """The #2225 gate's first red run: `include:` entries are independent
    models, not override layers, so two entries drop the overlay's
    services.llm-worker and resolve back to synthetic-only. Both files have to
    arrive through one entry's list-valued `path:`."""
    yaml = pytest.importorskip("yaml", reason="PyYAML not installed; compose parse skipped")
    model = yaml.safe_load(DEPLOY_ENTRYPOINT.read_text(encoding="utf-8"))
    include = model.get("include")
    assert isinstance(include, list) and len(include) == 1, (
        "docker-compose.captured-data-deploy.yml must declare exactly one "
        "`include:` entry. Separate entries are independent models imported "
        "one by one -- the first to claim services.llm-worker keeps it, the "
        "captured-data overlay is silently dropped, and the base's "
        "`ES_HOST: ''` survives into a supposedly captured-data deploy "
        f"(#2225, #1751). Found: {include!r}"
    )
    paths = include[0].get("path") if isinstance(include[0], dict) else include[0]
    assert paths == ["docker-compose.yml", "docker-compose.captured-data.yml"], (
        "the single `include:` entry's `path:` must be the ordered list "
        "[docker-compose.yml, docker-compose.captured-data.yml] -- a list-valued "
        "`path` is what merges several files into one included model, i.e. the "
        "same override chain as `-f base -f overlay`, with the captured-data "
        f"overlay last so its ES_HOST/networks/mounts win (#2225). Found: {paths!r}"
    )


def test_deploy_entrypoint_include_shape_via_grep():
    """Dependency-free control for the test above, same reason as
    test_deploy_entrypoint_gate_via_grep."""
    text = DEPLOY_ENTRYPOINT.read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    include_index = next(
        (i for i, line in enumerate(lines) if line.strip() == "include:"), None
    )
    assert include_index is not None, (
        "docker-compose.captured-data-deploy.yml no longer has a top-level "
        "`include:` -- it is #1751's written-down authorization record and "
        "composes the base with the captured-data overlay (#2225)."
    )
    body = "\n".join(lines[include_index + 1 :])
    assert "- path:" in body, (
        "docker-compose.captured-data-deploy.yml's `include:` must use one "
        "entry with a list-valued `path:`. Listing the two files as separate "
        "`include:` entries imports them as independent models: the overlay's "
        "services.llm-worker loses to the base's, `ES_HOST: ''` survives, and "
        "the deploy comes back synthetic-only while looking correct (#2225)."
    )
    for included in ("docker-compose.yml", "docker-compose.captured-data.yml"):
        assert f"- {included}" in body, (
            f"docker-compose.captured-data-deploy.yml's `include:` no longer "
            f"lists {included} -- both files must be in the merged path list, "
            f"base first, or the resolved model is not the authorized "
            f"captured-data topology (#2225)."
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
    resolve_lines = [line for line in run.splitlines() if "config --format json" in line]
    assert len(resolve_lines) == 1, (
        f"expected exactly one `config --format json` command in {STEP_NAME!r}, "
        f"found {len(resolve_lines)}"
    )
    resolve = resolve_lines[0]
    assert (
        "-f llm-worker/docker-compose.captured-data-deploy.yml" in resolve
    ), (
        f"{STEP_NAME!r}'s resolved-config check must resolve "
        f"llm-worker/docker-compose.captured-data-deploy.yml -- that is the "
        f"single file live redeploys point at (#1751)."
    )
    for stacked in (
        "llm-worker/docker-compose.yml",
        "llm-worker/docker-compose.captured-data.yml",
    ):
        assert stacked not in resolve, (
            f"{STEP_NAME!r}'s resolved-config check also passes -f {stacked}. "
            f"That supplies the captured-data authorization from the command "
            f"line, so the assertions below pass no matter what the "
            f"entrypoint's `include:` resolves to -- exactly the hole that let "
            f"a broken include chain look green (#2225). Resolve the "
            f"entrypoint alone, the way the deploy command does."
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
