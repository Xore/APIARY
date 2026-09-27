#!/usr/bin/env python3
"""Regression tests for #3380: a configured registry mirror that is not
actually deployed must not be handed to buildkit as if it were.

What #3380 found, and what could quietly undo the fix:

* `CI_REGISTRY_MIRROR` is a repository VARIABLE describing a per-HOST fact
  ("this executor runs a Docker Hub pull-through cache at this address"). A
  variable can only be global, and since #3379 the `honeypot-ci` pool spans
  two boxes (the homeserver and `precision`). The old step took the variable
  at face value, so the config it wrote asserted a mirror on every executor
  in the pool regardless of whether that box had ever run
  install-registry-mirror.sh.
* the resulting failure mode was silent in the worst way: buildkit falls
  back to docker.io, so the run stayed GREEN while the #2819 pull-through
  cache was never in effect, every base image was pulled from Hub directly,
  and each of the tree's 74 non-scratch `FROM` lines first paid a
  connect-refused round trip against the dead address;
* worse, 5555 is not necessarily a dead port -- on the homeserver it is also
  where the multipot honeypot listens, on the WireGuard address -- so
  "something answers" is not the same as "a registry answers";
* a probe alone is not the fix if the probe is optional: the value has to
  gate what gets written, and the disagreement has to be announced rather
  than absorbed.

The tests also pin the properties the fix must NOT cost, because each of
them was load-bearing before #3380: the #2819 routing gate that keeps a
GitHub-hosted fallback runner off a LAN address, the always-written config
file (an unset `buildkitd-config` is a different failure), and the
fail-safe posture -- a dead mirror is an accelerator that is gone, not a
reason to fail the build, exactly as ci-router.yml documents.

The tests/docs/ CI row installs pytest and nothing else (see quality.yml),
so every PyYAML-backed assertion is paired with a dependency-free text
check, the same harness test_2639_fix.py established.
"""
from __future__ import annotations

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTAINERS = REPO_ROOT / ".github/workflows/containers.yml"
INSTALLER = REPO_ROOT / "scripts/github-ci-runner/install-registry-mirror.sh"
CI_DOC = REPO_ROOT / "docs/CI-CD.md"

# The one place in the step that may decide the mirror is usable.
PROBE_PATH = "/v2/"


def _load(path: pathlib.Path) -> dict:
    yaml = pytest.importorskip("yaml", reason="PyYAML not installed; workflow parse skipped")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _buildkit_step() -> dict:
    workflow = _load(CONTAINERS)
    matches = [s for s in workflow["jobs"]["build"]["steps"] if s.get("id") == "buildkit"]
    assert len(matches) == 1, (
        f"expected exactly one `id: buildkit` step, found {len(matches)}"
    )
    return matches[0]


def _run() -> str:
    return _buildkit_step()["run"]


# ------------------------------------------------------------ the probe ----


def test_the_configured_address_is_probed_before_it_is_trusted():
    """The whole fix: a mirror address is a claim about the box, so the box
    gets asked. Reading the variable and believing it is what #3380 reports."""
    run = _run()
    assert "curl" in run, (
        "the buildkit step must probe the configured mirror before writing it "
        "into the buildkitd config (#3380)"
    )
    assert re.search(r"curl[\s\S]{0,300}?\$\{?MIRROR", run), (
        "the probe must dial the address from CI_REGISTRY_MIRROR (#3380); got "
        "no curl invocation that interpolates $MIRROR"
    )
    assert PROBE_PATH in run, (
        f"the probe must ask the registry API base {PROBE_PATH!r} (#3380) -- the "
        "same question install-registry-mirror.sh gates its own success on"
    )


def test_the_probe_is_against_the_executor_not_a_lookup_table():
    """It has to be a real dial, bounded so an unroutable address cannot
    spend the row's timeout-minutes budget on connect attempts."""
    run = _run()
    assert re.search(r"--connect-timeout\s+\d", run) and re.search(r"--max-time\s+\d", run), (
        "the mirror probe must bound both connect and total time (#3380): a "
        "probe without a ceiling hangs for the runner's own timeout on a host "
        "where the address blackholes rather than refuses"
    )


def test_only_a_200_makes_the_mirror_usable():
    """A port that answers is not a registry. On the homeserver 5555 is also
    the multipot honeypot's, so `something is listening` must not qualify."""
    run = _run()
    verdicts = re.findall(r'if \[ "\$\{?probe\}?" = "([^"]+)" \]', run)
    assert verdicts == ["200"], (
        "the mirror must be gated on an exact 200 from the registry API, not a "
        f"prefix/loose match (#3380); found verdict(s) {verdicts}"
    )


def test_the_written_config_is_keyed_to_the_verdict_not_the_variable():
    """The dangerous shape is a `mirrors = ["$MIRROR"]` emitted whenever the
    variable is non-empty. It has to interpolate the *verified* value."""
    run = _run()
    assert not re.search(r'mirrors = \[\\"\$MIRROR\\"\]', run), (
        "the buildkitd config interpolates the raw variable, so an "
        "unreachable mirror is still written into it (#3380)"
    )
    assert 'mirrors = [\\"$mirror\\"]' in run, (
        "the buildkitd config must interpolate the probed/verified mirror "
        "value (#3380)"
    )
    # ...and that value is only ever assigned from the variable on a 200.
    assignments = re.findall(r'^\s*mirror="([^"]*)"$', run, re.M)
    assert assignments[0] == "", (
        f"`mirror` must start empty so an unprobed run cannot inherit it "
        f"(#3380); got {assignments[0]!r}"
    )
    assert f'mirror="$MIRROR"' in run, (
        "the verified mirror must be carried from the variable after a 200 (#3380)"
    )
    verdict_pos = run.index('= "200"')
    assert run.index('mirror="$MIRROR"') > verdict_pos, (
        "the variable may only be adopted as the mirror after the 200 verdict "
        "(#3380) -- otherwise the probe is decorative"
    )


def test_the_probe_result_cannot_abort_the_step_under_set_e():
    """`set -euo pipefail` is still on, and `curl` exits non-zero on "
    "connection refused -- which is precisely the #3380 case. Unguarded, the
    step would abort and take all 18 rows with it."""
    run = _run()
    assert "set -euo pipefail" in run, "the step must keep its strict-mode preamble"
    assert re.search(r"curl[\s\S]{0,300}?\|\|\s*probe=", run), (
        "the curl probe must be guarded with `|| probe=...`; a bare curl under "
        "`set -e` exits the step on connection refused -- turning the #3380 "
        "case into 18 red rows instead of an honest no-mirror config"
    )


# ------------------------------------------------- announced, not silent ----


def test_a_dead_mirror_is_announced_in_the_run_annotations():
    """The original complaint is that the run was green and said nothing."""
    run = _run()
    assert "::warning" in run, (
        "an unreachable mirror must raise a run annotation (#3380): a green "
        "build with a silently absent cache is exactly the reported symptom"
    )
    warning = next(ln for ln in run.splitlines() if "::warning" in ln)
    assert "CI_REGISTRY_MIRROR" in warning, (
        "the annotation must name the variable that is wrong, or the operator "
        f"cannot act on it (#3380); got: {warning!r}"
    )
    assert "install-registry-mirror.sh" in warning, (
        "the annotation must name the remediation script (#3380)"
    )


def test_the_summary_records_the_verdict_and_both_remedies():
    run = _run()
    assert "GITHUB_STEP_SUMMARY" in run, (
        "the dead-mirror case must be recorded in the job summary so it "
        "aggregates on the run page instead of scrolling past in one row's log "
        "(#3380)"
    )
    assert "install-registry-mirror.sh" in run and "gh variable delete" in run, (
        "#3380 offers two ways out (deploy the mirror, or unset the variable); "
        "the run must state both, since which one is right depends on the box"
    )


def test_a_dead_mirror_does_not_fail_the_build():
    """Degrade, do not fail. The cache is an accelerator; the authenticated
    Hub login from #2819 is what protects against `toomanyrequests`. Failing
    18 rows over a missing cache would be a worse regression than the one
    #3380 reports, and would contradict ci-router.yml's documented fail-safe
    ("routing can degrade CI's speed, never its pass/fail correctness")."""
    run = _run()
    dead_mirror_branch = run[run.index('::warning') : run.index("fi", run.index('::warning'))]
    assert not re.search(r"exit\s+1", dead_mirror_branch), (
        "the dead-mirror path must not exit non-zero (#3380); a missing "
        "accelerator must degrade CI's speed, not its pass/fail correctness"
    )
    assert re.search(r"exit\s+1", run) is None, (
        "the step should have no explicit exit 1 at all: a probe result is "
        "never a reason to fail the row (#3380)"
    )


# ------------------------------------------- properties the fix must not cost ----


def test_the_homeserver_routing_gate_is_preserved():
    """#2819: a GitHub-hosted fallback runner cannot dial a LAN address, so
    the variable must still be gated on ci-target before anything else."""
    env = _buildkit_step().get("env", {})
    mirror_expr = str(env.get("MIRROR", ""))
    assert "needs.ci-target.outputs.homeserver == 'true'" in mirror_expr, (
        "MIRROR must stay gated on the ci-target router (#2819); got "
        f"{mirror_expr!r}"
    )
    assert "vars.CI_REGISTRY_MIRROR" in mirror_expr, (
        f"MIRROR must still come from vars.CI_REGISTRY_MIRROR (#2819); got {mirror_expr!r}"
    )


def test_the_config_file_is_always_written_and_always_advertised():
    """buildkitd-config must never be unset: an unset config file is a
    different failure from an empty one, and the step comment says so."""
    run = _run()
    assert 'echo "config=$cfg" >>"$GITHUB_OUTPUT"' in run, (
        "the step must always advertise the config path, whichever branch it "
        "took (#3380) -- otherwise a dead mirror can leave buildkitd-config unset"
    )
    for branch in re.findall(r'>\s*"\$cfg"', run):
        assert branch == '>"$cfg"'
    assert run.count('>"$cfg"') >= 2, (
        "both the mirror config and the no-mirror config must be written to "
        "$cfg (#3380)"
    )


def test_the_no_mirror_config_is_still_honest_about_which_case_it_is():
    """Two different situations produce the empty config -- variable unset
    (nobody claims a mirror exists) and variable set but dead (this host has
    none). Reading the file back should not conflate them."""
    run = _run()
    assert re.search(
        r'echo .# no registry mirror[^\n]*>\s*"\$cfg"'
        r'[\s\S]{0,200}?CI_REGISTRY_MIRROR is unset', run
    ), (
        "the empty config must record whether the variable is unset or was "
        "verified dead (#3380) -- the two mean different things to whoever "
        "reads the file next"
    )


# ----------------------------------------- the installer and the probe agree ----


def test_the_probe_asks_the_installer_the_question_the_installer_answered():
    """Two different liveness questions for the same service drift, and the
    drift is invisible -- the mirror would be 'healthy' by one definition
    while the workflow discarded it by the other."""
    run = _run()
    installer = INSTALLER.read_text(encoding="utf-8")
    workflow_probe = re.search(r"curl[\s\S]{0,300}?/v2/", run)
    installer_probe = re.search(r"curl[^\n]*/v2/", installer)
    assert workflow_probe and installer_probe, (
        "both the workflow and the installer must probe the registry API base "
        f"{PROBE_PATH!r} (#3380)"
    )


def test_the_installer_does_not_claim_the_workflow_verifies_for_it():
    """The installer's header tells an operator that setting the variable is
    what makes the mirror take effect. Since #3380 the workflow verifies that
    claim per-run, so the header must not send the next operator to a
    variable-only fix that the run will now quietly override."""
    header = INSTALLER.read_text(encoding="utf-8")[:4000]
    assert "3380" in header, (
        "install-registry-mirror.sh's header should note #3380 -- the address "
        "is now verified per-run on the executor, so a variable set on a host "
        "that never got this script is reported rather than believed"
    )


# ------------------------------------------------------------- the docs ----


def test_the_docs_describe_the_verification():
    doc = CI_DOC.read_text(encoding="utf-8")
    section = doc[doc.index("Docker Hub authentication and the pull-through cache") :]
    assert "3380" in section[:6000], (
        "docs/CI-CD.md's pull-through-cache section must carry #3380's "
        "per-host verification -- an operator reading it needs to know the "
        "address is probed, not trusted"
    )
    for phrase in ("per-host", "probe"):
        assert phrase in section[:6000], (
            f"the section must explain that the mirror address is a {phrase}, "
            "not a repository-wide constant"
        )


# ---------------------------------------- dependency-free controls (no PyYAML) ----


def test_the_probe_survives_a_grep_for_its_own_invariants():
    """Runs even where PyYAML is absent."""
    text = CONTAINERS.read_text(encoding="utf-8")
    assert "curl" in text, "containers.yml lost the mirror probe (#3380)"
    assert re.search(r"curl[\s\S]{0,300}?\|\|\s*probe=", text), (
        "containers.yml: the probe lost its non-fatal guard (#3380)"
    )
    assert re.search(r'if \[ "\$\{?probe\}?" = "200" \]', text), (
        "containers.yml: the 200 verdict gate is gone (#3380)"
    )
    assert 'mirrors = [\\"$mirror\\"]' in text, (
        "containers.yml: the config interpolates the raw variable again (#3380)"
    )
    assert "::warning" in text, "containers.yml: the dead-mirror annotation is gone (#3380)"


def test_no_workflow_ships_an_unverified_mirror_config():
    """The property, checked across every workflow rather than just the file
    that was edited: a `mirrors = [...]` line must be gated on a verdict."""
    offenders = []
    for path in sorted((REPO_ROOT / ".github/workflows").glob("*.yml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for ln in text.splitlines():
            if "mirrors = [" in ln and "$MIRROR" in ln and "$mirror" not in ln:
                offenders.append(f"{path.name}: {ln.strip()}")
    assert offenders == [], (
        "a buildkit mirror config interpolated straight from CI_REGISTRY_MIRROR "
        f"is unverified by construction (#3380): {offenders}"
    )


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
