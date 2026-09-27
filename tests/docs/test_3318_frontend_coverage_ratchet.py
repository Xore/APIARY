#!/usr/bin/env python3
"""#3318: the frontend-next coverage ratchet is a real gate, not a decoration.

The ratchet is the deliverable, and a gate nobody can trust is worse than no
gate: a number checked once and never re-checked, a threshold in a file nobody
reads, a coverage step that was deleted in a later cleanup. So what this file
pins is the *wiring* and the gate's own decision logic, in the same spirit as
test_3331_fix.py pinning the node-major derivation.

The sharpest case it exists for: with 7,359 measured lines, a real regression
of seven covered lines moves the line percentage from 10.95% to 10.94%. A
percentage gate with any tolerance at all stays green through that. The
covered-count condition is what catches it, and the assertion
`test_seven_covered_lines_still_fails` below is that case, kept as a test rather
than as a claim in a comment.

What is deliberately NOT asserted here: that the committed baseline still equals
what today's tree measures. That is a measurement, not a property -- it is what
`npm run test:coverage` and the CI step are for, and pinning it in a test would
mean re-running the frontend's suite from a Python test on every change. What IS
asserted is that the baseline is internally consistent (its own percentages
match its own counts), that it is not set somewhere flattering, and that the
tolerances cannot be widened into meaninglessness without a failing test.

No PyYAML, no node: the workflow assertions read the file as text and the logic
assertions import the gate directly, so this runs in the same dependency-free
tests/docs row as every other meta-claim in this directory.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FRONTEND = REPO_ROOT / "arcane/home/honeypot-dashboard/frontend-next"
SCRIPT = REPO_ROOT / "scripts/check-frontend-next-coverage.py"
QUALITY_WORKFLOW = REPO_ROOT / ".github/workflows/quality.yml"
VITEST_CONFIG = FRONTEND / "vitest.config.ts"
BASELINE = FRONTEND / "coverage-baseline.json"
PACKAGE_JSON = FRONTEND / "package.json"
GITIGNORE = FRONTEND / ".gitignore"

FRONTEND_JOBS = ("frontend-next", "frontend-next-cloud")

_spec = importlib.util.spec_from_file_location("check_frontend_next_coverage", SCRIPT)
gate = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None and _spec.loader.exec_module(gate) is None

_workflow_text = QUALITY_WORKFLOW.read_text(encoding="utf-8")
_lines = _workflow_text.splitlines()
_config_text = VITEST_CONFIG.read_text(encoding="utf-8")


def _job_block(job: str) -> list[str]:
    """The lines of one job, by indentation.

    Same shape as test_3331_fix.py's helper, and for the same reason: a
    substring search for "\\n  " also matches the first two spaces of a
    six-space step line, so the body would stop at the first step and every
    "this is absent" assertion below would pass vacuously.
    """
    start = next((i for i, line in enumerate(_lines) if line == f"  {job}:"), None)
    assert start is not None, f"job {job} not found in {QUALITY_WORKFLOW.name}"
    body = []
    for line in _lines[start + 1 :]:
        if line.strip() and not line.startswith("   "):
            break
        body.append(line)
    return body


# --------------------------------------------------------------------------
# Glob semantics. The guard's whole value is in matching exactly what vitest
# matches, and its one catastrophic failure mode is matching too little.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern,rel,expected",
    [
        # `**` spans zero or more directories, which is the case fnmatch gets
        # wrong and the one the real config depends on: src/lib/prefs.test.ts
        # matches, and so would a test sitting directly in src/.
        ("src/**/*.test.ts", "src/lib/prefs.test.ts", True),
        ("src/**/*.test.ts", "src/prefs.test.ts", True),
        ("src/**/*.test.ts", "src/routes/auth/logout.test.ts", True),
        # ...and a test file that is not under src/ is not collected.
        ("src/**/*.test.ts", "e2e/dashboard.test.ts", False),
        ("src/**/*.test.ts", "notes/prefs.test.ts", False),
        # A non-test file must not be mistaken for a test file.
        ("src/**/*.test.ts", "src/lib/prefs.ts", False),
        ("src/**/*.test.ts", "src/lib/prefs.test.tsx", False),
        # An anchored pattern must not match a path that merely ends the same.
        ("src/**/*.test.ts", "other/src/lib/prefs.test.ts", False),
    ],
)
def test_glob_matching_agrees_with_vitest(pattern: str, rel: str, expected: bool):
    assert (gate.glob_to_regex(pattern).match(rel) is not None) is expected


def test_include_globs_are_read_from_the_config_not_restated():
    globs = gate.read_include_globs(VITEST_CONFIG)
    assert globs == ["src/**/*.test.ts", "src/**/*.test.tsx"], (
        f"the discovery guard reads {globs} out of {VITEST_CONFIG.name}; if the "
        f"config's include changed, this is the read that has to follow it."
    )


@pytest.mark.parametrize(
    "text,why",
    [
        ("export default defineConfig({})\n", "no include: block at all"),
        ("test: { include: [] },\n", "an include: block with no globs in it"),
    ],
)
def test_an_unreadable_glob_list_is_an_error_not_an_empty_match_set(tmp_path, text, why):
    """A guard that cannot see its own globs must not report a clean tree."""
    config = tmp_path / "vitest.config.ts"
    config.write_text(text, encoding="utf-8")
    with pytest.raises(gate.GateError):
        gate.read_include_globs(config)


def test_a_test_file_outside_the_globs_is_reported(tmp_path):
    (tmp_path / "src/lib").mkdir(parents=True)
    (tmp_path / "src/lib/ok.test.ts").write_text("", encoding="utf-8")
    (tmp_path / "src/lib/also-ok.test.tsx").write_text("", encoding="utf-8")
    (tmp_path / "stray").mkdir()
    (tmp_path / "stray/never-runs.test.ts").write_text("", encoding="utf-8")
    # Playwright's own files are not vitest's, and flagging them would be a
    # false positive on a correct tree.
    (tmp_path / "e2e").mkdir()
    (tmp_path / "e2e/dashboard.spec.ts").write_text("", encoding="utf-8")
    # Installed dependencies and build output are not source of ours.
    (tmp_path / "node_modules/pkg").mkdir(parents=True)
    (tmp_path / "node_modules/pkg/vendor.test.ts").write_text("", encoding="utf-8")

    missed = gate.undiscovered_tests(tmp_path, ["src/**/*.test.ts", "src/**/*.test.tsx"])
    assert missed == ["stray/never-runs.test.ts"], (
        f"expected only the stray file, got {missed}"
    )


def test_the_real_tree_has_no_undiscovered_test_file():
    globs = gate.read_include_globs(VITEST_CONFIG)
    assert gate.undiscovered_tests(FRONTEND, globs) == [], (
        "a test file in frontend-next that vitest's include globs do not "
        "collect. It has never run, so whatever it asserts is not asserted."
    )
    # And the guard is looking at a real tree, not an empty one -- otherwise
    # the assertion above is vacuous.
    assert sum(1 for _ in gate.iter_test_files(FRONTEND)) >= 20


# --------------------------------------------------------------------------
# The ratchet decision itself.
# --------------------------------------------------------------------------


def _summary(lines_covered, lines_total, branch_covered, branch_total):
    return {
        "lines": {"covered": lines_covered, "total": lines_total, "pct": lines_covered / lines_total * 100},
        "branches": {
            "covered": branch_covered,
            "total": branch_total,
            "pct": branch_covered / branch_total * 100,
        },
    }


BASELINE_SUMMARY = _summary(806, 7359, 346, 7250)


def test_measurement_equal_to_baseline_passes():
    assert gate.check_ratchet(BASELINE_SUMMARY, BASELINE_SUMMARY, 0.5, 0) == []


def test_coverage_that_improved_passes():
    better = _summary(900, 7359, 400, 7250)
    assert gate.check_ratchet(BASELINE_SUMMARY, better, 0.5, 0) == []


def test_a_percentage_drop_past_the_tolerance_fails():
    """40 covered lines and 12 covered branches stop existing.

    Three errors, not four: the branch percentage (4.61% against a 4.77%
    baseline) is a 0.16-point drop and stays inside the 0.5-point allowance,
    while the branch *count* is down 12. That asymmetry is the whole argument
    for carrying the count condition, so the number of errors is asserted
    rather than assumed.
    """
    worse = _summary(766, 7359, 334, 7250)
    errors = gate.check_ratchet(BASELINE_SUMMARY, worse, 0.5, 0)
    assert len(errors) == 3, errors
    assert any("coverage lines dropped" in e for e in errors)
    assert any("covered lines regressed" in e for e in errors)
    assert any("covered branches regressed" in e for e in errors)
    assert not any("coverage branches dropped" in e for e in errors)


def test_seven_covered_lines_still_fails():
    """The case that makes the covered-count condition worth having.

    Measured, not hypothetical: adding one seven-line untested module to src/
    moved a real run from 10.95% to 10.94% lines. A percentage gate with any
    tolerance at all calls that green.
    """
    seven_lines = _summary(799, 7366, 346, 7250)
    pct = seven_lines["lines"]["pct"]
    assert 0 < BASELINE_SUMMARY["lines"]["pct"] - pct < 0.5, (
        "this fixture has to be a drop the percentage tolerance cannot see, or "
        f"it is not testing what it claims to (drop was {BASELINE_SUMMARY['lines']['pct'] - pct:.4f} points)"
    )
    assert gate.check_ratchet(BASELINE_SUMMARY, seven_lines, 0.5, 0), (
        "a drop in covered lines must fail even when the percentage barely moves"
    )
    # ...and the same drop with the covered-count condition removed would pass,
    # which is why that condition exists and why this test is here.
    assert not [e for e in gate.check_ratchet(BASELINE_SUMMARY, seven_lines, 0.5, 7) if "regressed" in e]


def test_each_metric_is_reported_separately():
    """A change that trades branches for lines cannot hide in an average."""
    only_branches = _summary(900, 7359, 100, 7250)
    errors = gate.check_ratchet(BASELINE_SUMMARY, only_branches, 0.5, 0)
    assert any("covered branches regressed" in e for e in errors)
    assert not any("covered lines regressed" in e for e in errors)


# --------------------------------------------------------------------------
# The gate end to end, through its real command line.
# --------------------------------------------------------------------------


def _write_inputs(tmp_path, measured=None, baseline=None, config_text=None):
    frontend = tmp_path / "frontend-next"
    (frontend / "src/lib").mkdir(parents=True)
    (frontend / "src/lib/prefs.test.ts").write_text("", encoding="utf-8")
    (frontend / "vitest.config.ts").write_text(
        config_text
        or "export default defineConfig({ test: { include: ['src/**/*.test.ts'] } })\n",
        encoding="utf-8",
    )
    measured_path = frontend / "coverage/coverage-summary.json"
    measured_path.parent.mkdir(parents=True)
    measured_path.write_text(json.dumps({"total": measured or BASELINE_SUMMARY}), encoding="utf-8")
    baseline_path = frontend / "coverage-baseline.json"
    baseline_path.write_text(
        json.dumps({"tolerancePoints": 0.5, "toleranceCounts": 0, "total": baseline or BASELINE_SUMMARY}),
        encoding="utf-8",
    )
    return frontend


def _run(frontend):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--frontend", str(frontend)],
        capture_output=True,
        text=True,
    )


def test_gate_exits_zero_at_the_baseline(tmp_path):
    assert _run(_write_inputs(tmp_path)).returncode == 0


def test_gate_exits_nonzero_when_the_measurement_drops(tmp_path):
    frontend = _write_inputs(tmp_path, measured=_summary(700, 7359, 300, 7250))
    proc = _run(frontend)
    assert proc.returncode == 1
    assert "::error::coverage lines dropped" in proc.stdout


def test_gate_exits_nonzero_on_an_undiscovered_test_file(tmp_path):
    frontend = _write_inputs(tmp_path)
    (frontend / "outside").mkdir()
    (frontend / "outside/stray.test.ts").write_text("", encoding="utf-8")
    proc = _run(frontend)
    assert proc.returncode == 1
    assert "no `include:` glob" in proc.stdout


def test_gate_fails_closed_when_the_measurement_is_missing(tmp_path):
    """No summary means no evidence, and no evidence must not read as a pass."""
    frontend = _write_inputs(tmp_path)
    (frontend / "coverage/coverage-summary.json").unlink()
    proc = _run(frontend)
    assert proc.returncode == 2
    assert "::error::" in proc.stdout


def test_gate_fails_closed_on_a_summary_it_cannot_read(tmp_path):
    """A summary missing a metric is not a summary the gate can compare."""
    frontend = _write_inputs(tmp_path)
    (frontend / "coverage/coverage-summary.json").write_text(
        json.dumps({"total": {"lines": {"covered": 1, "total": 2}}}), encoding="utf-8"
    )
    proc = _run(frontend)
    assert proc.returncode == 2
    assert "has no lines.pct" in proc.stdout, proc.stdout


def test_gate_fails_closed_on_a_summary_with_no_total_block(tmp_path):
    frontend = _write_inputs(tmp_path)
    (frontend / "coverage/coverage-summary.json").write_text(
        json.dumps({"src/lib/prefs.ts": {}}), encoding="utf-8"
    )
    proc = _run(frontend)
    assert proc.returncode == 2
    assert "no `total` block" in proc.stdout


def test_gate_has_no_flag_that_could_widen_it():
    """The update path is a commit, so the CLI must not offer an alternative.

    A `--tolerance` or `--update` flag would let a later commit lower the gate
    without touching the baseline anyone reads in review. Scanned from the
    argparse calls rather than the raw text, because the module docstring
    *names* those flags in order to say they do not exist.
    """
    source = SCRIPT.read_text(encoding="utf-8")
    flags = set(re.findall(r'add_argument\(\s*"(--[a-z-]+)"', source))
    assert flags == {"--frontend", "--baseline", "--measured", "--vitest-config"}, flags
    for flag in flags:
        assert not re.search(r"update|toler|write|threshold|accept", flag), (
            f"{SCRIPT.name} grows {flag}: the committed baseline is the only "
            f"place the gate's strictness is allowed to change."
        )
    # ...and the override flags that remain exist so the tests above can point
    # the gate at fixtures. The command line CI uses passes none of them, which
    # test_the_gate_runs_in_ci asserts.
    assert "--tolerance" not in flags and "--update" not in flags


# --------------------------------------------------------------------------
# The measurement, as committed.
# --------------------------------------------------------------------------


def test_the_baseline_is_internally_consistent():
    """Its own percentages must follow from its own counts.

    This is what stops a hand-edited baseline: editing `covered` without
    `pct`, or the reverse, fails here rather than producing a gate that compares
    a real measurement against a number nothing ever computed.
    """
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    for metric in ("lines", "statements", "functions", "branches"):
        block = baseline["total"][metric]
        assert block["covered"] <= block["total"], metric
        recomputed = block["covered"] / block["total"] * 100
        assert abs(recomputed - block["pct"]) < 0.01, (
            f"{metric}: recorded {block['pct']}%, but {block['covered']}/"
            f"{block['total']} is {recomputed:.2f}%"
        )
    assert baseline["issue"] == 3318
    assert "node:22-alpine" in baseline["runtime"], (
        "the baseline says nothing about the runtime it was measured on"
    )


def test_the_baseline_tolerances_are_small_and_both_are_present():
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    assert 0 < baseline["tolerancePoints"] <= 1, (
        "a percentage allowance over a point stops being a ratchet"
    )
    assert baseline["toleranceCounts"] == 0, (
        "the covered-count allowance is what makes a seven-line regression "
        "visible; opening it up re-hides exactly that"
    )


def test_coverage_is_collected_over_src_only():
    assert "include: ['src/**']" in _config_text, (
        "the issue asks for src/ coverage only; widening the include is the "
        "way to make the number mean something narrower than it says"
    )
    assert "provider: 'v8'" in _config_text
    assert "all: true" in _config_text, (
        "without all:true, an untested file reports nothing at all instead of "
        "0%, and the drop the ratchet exists to catch is invisible"
    )
    assert "json-summary" in _config_text, (
        "json-summary is the machine-readable half the ratchet reads"
    )
    # Test files are excluded so they cannot inflate the figure, and the
    # generated route tree with them. Both must be named in the config, where
    # a reviewer can see them, rather than hidden in a glob nobody reads.
    assert "src/**/*.test.ts" in _config_text
    assert "src/routeTree.gen.ts" in _config_text
    # No thresholds block: a threshold in the vitest config is a constant that
    # file owns, so editing it down would be a one-line silent regression. The
    # word appears in the config's own comment saying there isn't one, so the
    # assertion is for the key.
    assert not re.search(r"(?m)^\s*thresholds\s*:", _config_text), (
        "vitest must not own a threshold; the ratchet compares the measured "
        "summary against the committed baseline instead"
    )


def test_the_coverage_script_and_dev_dependency_are_declared():
    package = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    assert package["scripts"]["test:coverage"] == "vitest run --coverage"
    coverage_v8 = package["devDependencies"]["@vitest/coverage-v8"]
    vitest = package["devDependencies"]["vitest"]
    assert coverage_v8.split(".")[0] == vitest.split(".")[0], (
        f"@vitest/coverage-v8 {coverage_v8} does not match vitest {vitest}: the "
        f"coverage provider is versioned with the runner it instruments"
    )
    lock = json.loads((FRONTEND / "package-lock.json").read_text(encoding="utf-8"))
    assert "node_modules/@vitest/coverage-v8" in lock["packages"], (
        "the lockfile has no entry for @vitest/coverage-v8, so `npm ci` -- the "
        "install CI actually runs -- would not install it and the coverage step "
        "would fail on a fresh runner"
    )


def test_coverage_output_is_never_committed():
    ignored = GITIGNORE.read_text(encoding="utf-8")
    assert re.search(r"(?m)^coverage/$", ignored), (
        "coverage/ must stay ignored: a committed report is a coverage claim "
        "about nobody's tree. The baseline is the separate committed file."
    )
    # ...and the baseline must not be swept up by that same rule.
    assert not re.search(r"(?m)^coverage-baseline\.json$", ignored)


# --------------------------------------------------------------------------
# The wiring in CI.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("job", FRONTEND_JOBS)
def test_the_gate_runs_in_ci(job):
    body = "\n".join(_job_block(job))
    assert "run: npm run test:coverage" in body, f"{job} does not measure coverage"
    assert "run: python3 scripts/check-frontend-next-coverage.py" in body, (
        f"{job} measures coverage but never gates on it -- which is the state "
        f"#3318 describes, only with a number attached"
    )
    # The measurement must come before the gate, or the gate reads the
    # previous run's summary.
    assert body.index("npm run test:coverage") < body.index(
        "check-frontend-next-coverage.py"
    ), f"{job} gates before it measures"
    # The step must be the plain default-path invocation. A --measured or
    # --baseline argument here would let the workflow point the gate at a file
    # the run did not just produce.
    assert "check-frontend-next-coverage.py --" not in body, (
        f"{job} passes an argument to the gate; the measured path and the "
        f"baseline are the script's own defaults"
    )


@pytest.mark.parametrize("job", FRONTEND_JOBS)
def test_the_report_is_published(job):
    body = "\n".join(_job_block(job))
    assert "name: frontend-next-coverage-${{ github.run_id }}-${{ github.run_attempt }}" in body
    assert "path: arcane/home/honeypot-dashboard/frontend-next/coverage/" in body, (
        f"{job} must name the report directory explicitly -- upload-artifact "
        f"v4.4+ skips hidden paths, and an unnamed path is not a closed set"
    )
    assert "if-no-files-found: error" in body, (
        f"{job} uploads the coverage report with a non-fatal missing-file "
        f"policy, so 'the report was published' would be a claim nothing checks"
    )


def test_the_twins_agree_step_for_step():
    """The pair convention (#2565): a red result must mean the same thing
    wherever it ran, so the two jobs' steps are compared, not trusted."""
    homeserver, cloud = (_job_block(job) for job in FRONTEND_JOBS)
    step_lines = lambda body: [  # noqa: E731
        line.strip() for line in body if re.match(r"^\s*(- run:|- name:|- uses:)", line)
    ]
    assert step_lines(homeserver) == step_lines(cloud), (
        "the frontend-next pair's steps have diverged; the #3318 steps must "
        "exist on both or a green twin would be reporting a gate the other "
        "executor never ran"
    )


@pytest.mark.parametrize("job", FRONTEND_JOBS)
def test_the_existing_test_run_is_still_there(job):
    """#3318 adds a gate. It must not have cost anything the job already ran."""
    body = "\n".join(_job_block(job))
    assert re.search(r"(?m)^\s*- run: npm test\s*$", body), (
        f"{job} no longer runs the plain `npm test`; the coverage run is an "
        f"addition, not a replacement"
    )
    assert "npm run typecheck" in body
    assert "npm run build" in body
    assert "git diff --exit-code -- arcane/home/honeypot-dashboard/frontend-next/src/routeTree.gen.ts" in body


def test_the_gate_is_pinned_into_the_required_status_check():
    """The frontend-next pair is already in quality-gate's needs; assert the
    ratchet is inside those jobs rather than a workflow nothing waits on."""
    gate_block = "\n".join(_job_block("quality-gate"))
    for job in FRONTEND_JOBS:
        assert re.search(rf"(?m)^\s+- {job}$", gate_block), (
            f"{job} is not in quality-gate's needs, so nothing waits for it"
        )


def test_no_new_action_was_introduced_unpinned():
    """The coverage report is published with the upload-artifact SHA the
    workflow already used, so this diff adds no new action to pin."""
    for job in FRONTEND_JOBS:
        body = "\n".join(_job_block(job))
        pins = re.findall(r"uses: (\S+)@([^\s#]+)", body)
        assert pins, job
        for action, ref in pins:
            assert re.fullmatch(r"[0-9a-f]{40}", ref), (
                f"{job}: {action} is not pinned to a full commit SHA ({ref})"
            )
    before = {
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
    }
    homeserver = "\n".join(_job_block(FRONTEND_JOBS[0]))
    used = {
        f"{action}@{ref}" for action, ref in re.findall(r"uses: (\S+)@([^\s#]+)", homeserver)
    }
    assert used <= before, f"new action introduced: {used - before}"
