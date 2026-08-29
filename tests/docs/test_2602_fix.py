#!/usr/bin/env python3
"""Regression test for #2602: install-deploy-runner.sh's DEPLOY_DIRS list had
drifted from reality since #1502.

#1502 ("Phase 2 - installer + CI now drive off the Arcane manifest")
collapsed .github/workflows/deploy.yml's `home` job down to two
`destination=` assignments (/opt/stacks/apiary, a tree rsync, and
/var/dockge/stacks/honeypot-arcane, a single `cp` of one compose file) ten
days after install-deploy-runner.sh shipped with a seven-entry DEPLOY_DIRS
matching the *old* deploy.yml. Five of those seven no longer exist on a
post-#1502 host and just printed noise; the sixth,
/var/dockge/stacks/honeypot-keycloak, DOES exist under the Arcane layout
(stacks mirror there) and got a gratuitous recursive `chown` to
github-deploy-runner:deploy-runner on every run -- a production identity
stack directory mutated by a tool whose entire documented purpose is a
narrow, precise blast radius (#1143).

WHAT THIS TEST ASSERTS, AND WHY

Like #2368's fix, the failure mode here is disagreement *between files*
(the script's static list vs. deploy.yml's actual destinations), so a test
that just hand-lists the one expected path proves far less than a test that
derives the expectation from deploy.yml itself and cross-checks it. The
tree-rsync-vs-single-file-cp distinction the script's own comment already
claimed to follow is what actually decides which destinations need the
ownership fix, so `_deploy_destinations()` below implements exactly that
distinction (a step's block containing the literal `"$destination/"` rsync
target vs. one that only ever does `cp ... "$destination/<file>"` or
`install -d "$destination"`) and the primary test asserts DEPLOY_DIRS
equals the tree-rsync subset -- in either direction, so both a stale
leftover and a missing new entry fail loudly.

The final test runs the actual #1143 ownership-fix loop, extracted
verbatim from the script (not re-typed here), against a sandbox that
mimics a post-#1502 host -- apiary side by side with a honeypot-keycloak
directory that exists but is no longer a destination -- and checks real
ctimes rather than mocking `chown` out, so it proves the fixed list
produces zero mutations outside apiary, not just that the list looks right
on paper.
"""
from __future__ import annotations

import pathlib
import re
import shlex
import subprocess
import time

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts/github-ci-runner/install-deploy-runner.sh"
DEPLOY_YML = REPO_ROOT / ".github/workflows/deploy.yml"

SCRIPT_TEXT = SCRIPT.read_text(encoding="utf-8")
DEPLOY_YML_TEXT = DEPLOY_YML.read_text(encoding="utf-8")

# The seven pre-#1502 paths the original DEPLOY_DIRS carried. Pinned by
# name so a regression (the exact bug #2602 reports) fails loudly even if
# deploy.yml is edited in a way that would otherwise mask it.
STALE_PRE_1502_PATHS = {
    "/opt/stacks/honeypot-init",
    "/var/dockge/stacks/honeypot-keycloak",
    "/opt/stacks/honeypot-payload-analysis",
    "/opt/stacks/honeypot-utilities",
    "/opt/stacks/honeypot-elk",
    "/opt/stacks/honeypot-dashboard",
}


def _home_job_text() -> str:
    """Isolate the `home:` job body in deploy.yml (between the `home:` and
    `vps:` job keys), the same slice-by-anchor approach #2368's test uses
    for docker-compose.yml's `services:` block."""
    try:
        start = DEPLOY_YML_TEXT.index("\n  home:\n")
        end = DEPLOY_YML_TEXT.index("\n  vps:\n", start)
    except ValueError as exc:
        raise AssertionError(
            "could not isolate the `home:` job between `  home:` and `  vps:` "
            "in deploy.yml -- job structure changed, update this test"
        ) from exc
    return DEPLOY_YML_TEXT[start:end]


def _deploy_destinations() -> list[tuple[str, bool]]:
    """Parse every `destination=` assignment out of the home job, split into
    per-step blocks on `- name:` headers, paired with whether that step's
    block performs a tree rsync (contains the literal rsync-target string
    `"$destination/"`) as opposed to a single-file `cp`/`install -d` use of
    the same variable (e.g. `"$destination/compose.yml"` or bare
    `"$destination"`, neither of which end in `/"`)."""
    body = _home_job_text()
    starts = [m.start() for m in re.finditer(r"^[ \t]*- name:", body, re.MULTILINE)]
    assert starts, "no `- name:` steps found in the home job -- structure changed"
    bounds = starts + [len(body)]
    results = []
    for i in range(len(starts)):
        step = body[bounds[i]:bounds[i + 1]]
        dest_match = re.search(r"^[ \t]*destination=(\S+)\s*$", step, re.MULTILINE)
        if not dest_match:
            continue
        is_tree_rsync = '"$destination/"' in step
        results.append((dest_match.group(1), is_tree_rsync))
    return results


def _deploy_dirs() -> list[str]:
    m = re.search(r"DEPLOY_DIRS=\(\n(.*?)\n\)", SCRIPT_TEXT, re.DOTALL)
    assert m, "could not find DEPLOY_DIRS=(...) in install-deploy-runner.sh"
    return [line.strip() for line in m.group(1).splitlines() if line.strip()]


def _extract_ownership_loop() -> str:
    """Pull the #1143 ownership-fix loop verbatim out of the script -- the
    behavioral test below runs the real loop text, not a re-implementation
    of it, so it can only pass if the script's actual current logic is
    safe."""
    m = re.search(
        r'(^for dir in "\$\{DEPLOY_DIRS\[@\]\}"; do\n.*?\n^done\n)',
        SCRIPT_TEXT,
        re.DOTALL | re.MULTILINE,
    )
    assert m, "could not find the #1143 ownership-fix loop in install-deploy-runner.sh"
    return m.group(1)


# Parsed once at import so tests run against what the files actually say.
DEPLOY_DESTINATIONS = _deploy_destinations()
DEPLOY_DIRS = _deploy_dirs()


def test_deploy_dirs_matches_tree_rsync_destinations_in_deploy_yml():
    """The core #2602 contract: DEPLOY_DIRS must be exactly the destinations
    deploy.yml's home job actually rsyncs a tree into -- no more (stale
    pre-#1502 paths, the keycloak over-chown) and no less (a future tree
    destination added to deploy.yml without a matching DEPLOY_DIRS entry)."""
    assert DEPLOY_DESTINATIONS, "no destination= assignments found in deploy.yml's home job"
    expected = {path for path, is_tree in DEPLOY_DESTINATIONS if is_tree}
    assert set(DEPLOY_DIRS) == expected, (
        "DEPLOY_DIRS in install-deploy-runner.sh has diverged from the "
        "tree-rsync destination= targets in .github/workflows/deploy.yml "
        f"-- #2602.\n  DEPLOY_DIRS only: {sorted(set(DEPLOY_DIRS) - expected)}\n"
        f"  deploy.yml tree targets only: {sorted(expected - set(DEPLOY_DIRS))}"
    )


def test_deploy_dirs_has_no_duplicates():
    assert len(DEPLOY_DIRS) == len(set(DEPLOY_DIRS))


@pytest.mark.parametrize("path", sorted(STALE_PRE_1502_PATHS))
def test_stale_pre_1502_path_stays_out_of_deploy_dirs(path):
    """None of the seven pre-#1502 paths may come back as a stale leftover."""
    assert path not in DEPLOY_DIRS, (
        f"{path} is back in DEPLOY_DIRS -- this was one of the seven "
        "pre-#1502 paths #2602 removed. If deploy.yml genuinely writes a "
        "tree there again this is a deliberate re-add (update this test's "
        "pin list too); otherwise it is the same staleness bug recurring."
    )


def test_honeypot_arcane_is_a_single_file_cp_and_stays_out_of_deploy_dirs():
    """honeypot-arcane is deploy.yml's other current destination=, but its
    step only `cp`s one compose.yml into an `install -d`'d directory --
    never an `rsync ... "$destination/"` tree copy -- so it must not gain
    the ownership-fix treatment apiary gets."""
    destinations = dict(DEPLOY_DESTINATIONS)
    assert "/var/dockge/stacks/honeypot-arcane" in destinations, (
        "honeypot-arcane's destination= assignment went missing from "
        "deploy.yml -- update this test's premise"
    )
    assert destinations["/var/dockge/stacks/honeypot-arcane"] is False, (
        'honeypot-arcane\'s step now performs a tree rsync into "$destination/" '
        "-- it may need to be added to DEPLOY_DIRS deliberately, not left out "
        "by this now-stale test"
    )
    assert "/var/dockge/stacks/honeypot-arcane" not in DEPLOY_DIRS


def test_header_comment_points_future_rederivation_at_deploy_yml():
    """Acceptance criterion: the comment must send a future maintainer back
    to deploy.yml's destination= lines instead of trusting this list's own
    history (the trust that caused #2602)."""
    idx = SCRIPT_TEXT.find("DEPLOY_DIRS=(")
    assert idx != -1
    preceding = SCRIPT_TEXT[:idx]
    ref = preceding.rfind(".github/workflows/deploy.yml")
    assert ref != -1, (
        "the comment above DEPLOY_DIRS must name .github/workflows/deploy.yml "
        "so a future re-derivation has somewhere to look"
    )
    assert idx - ref < 2000, (
        "the .github/workflows/deploy.yml reference is too far from "
        "DEPLOY_DIRS to plausibly be its re-derivation instructions"
    )
    # A window around the reference rather than a fixed direction: "grep
    # destination= .github/workflows/deploy.yml" names destination= first,
    # "destination= in .github/workflows/deploy.yml's home job" names it
    # after -- either phrasing satisfies the acceptance criterion.
    window = preceding[max(0, ref - 200):idx]
    assert "destination=" in window, (
        "the re-derivation pointer must name destination= specifically, "
        "not just the workflow file in general"
    )


def test_ownership_fix_loop_leaves_keycloak_untouched_on_simulated_post_1502_host(tmp_path):
    """Runs the actual #1143 ownership-fix loop, extracted verbatim from the
    script, against a sandbox mimicking a post-#1502 host: the real
    remaining DEPLOY_DIRS entry (apiary) alongside a honeypot-keycloak
    directory that exists on disk (mirrored under the Arcane layout) but is
    no longer a deploy.yml destination. Uses the real `chown` binary
    (retargeted at the test's own user:group, which needs no root) rather
    than a stub, so the assertion is a real ctime check -- proof of what the
    loop actually did to the filesystem, not of what a mock recorded."""
    apiary = tmp_path / "opt/stacks/apiary"
    (apiary / "state/secrets").mkdir(parents=True)
    (apiary / "dashboard-state").mkdir(parents=True)
    (apiary / "logs").mkdir(parents=True)
    (apiary / "sub/state").mkdir(parents=True)
    plain_file = apiary / "docker-compose.yml"
    plain_file.write_text("services: {}\n")
    state_file = apiary / "state/secrets/postgres-password"
    state_file.write_text("s3cr3t\n")
    dashboard_state_file = apiary / "dashboard-state/cache.db"
    dashboard_state_file.write_text("x")
    logs_file = apiary / "logs/app.log"
    logs_file.write_text("x")
    nested_state_file = apiary / "sub/state/deep.txt"
    nested_state_file.write_text("x")

    keycloak = tmp_path / "var/dockge/stacks/honeypot-keycloak"
    (keycloak / "state/keycloak/secrets").mkdir(parents=True)
    keycloak_secret = keycloak / "state/keycloak/secrets/postgres-password"
    keycloak_secret.write_text("do-not-touch\n")
    keycloak_plain_file = keycloak / "compose.yml"
    keycloak_plain_file.write_text("services: {}\n")

    watched = [
        plain_file, state_file, dashboard_state_file, logs_file,
        nested_state_file, keycloak_secret, keycloak_plain_file,
    ]
    before = {p: p.stat().st_ctime_ns for p in watched}
    time.sleep(0.05)

    runner_user = subprocess.run(
        ["id", "-un"], check=True, capture_output=True, text=True
    ).stdout.strip()
    runner_group = subprocess.run(
        ["id", "-gn"], check=True, capture_output=True, text=True
    ).stdout.strip()

    harness = tmp_path / "harness.sh"
    harness.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"RUNNER_USER={shlex.quote(runner_user)}\n"
        f"RUNNER_GROUP={shlex.quote(runner_group)}\n"
        f"DEPLOY_DIRS=({shlex.quote(str(apiary))})\n"
        "STATE_SUBTREE_NAMES=(state dashboard-state logs)\n"
        "\n" + _extract_ownership_loop()
    )

    result = subprocess.run(
        ["bash", str(harness)], capture_output=True, text=True, cwd=str(tmp_path)
    )
    assert result.returncode == 0, (
        f"ownership-fix loop failed: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "honeypot-keycloak" not in result.stdout, (
        "the loop printed something about honeypot-keycloak -- it must never "
        "even be visited any more"
    )

    after = {p: p.stat().st_ctime_ns for p in watched}

    assert after[plain_file] > before[plain_file], (
        "apiary's own plain file was never chowned -- the harness extraction "
        "is broken and every other assertion here would false-pass"
    )
    for pruned in (state_file, dashboard_state_file, logs_file, nested_state_file):
        assert after[pruned] == before[pruned], (
            f"{pruned} under a pruned state/dashboard-state/logs subtree was "
            "touched by the ownership fix"
        )
    for untouched in (keycloak_secret, keycloak_plain_file):
        assert after[untouched] == before[untouched], (
            f"{untouched} under honeypot-keycloak was touched by the "
            "ownership-fix loop -- #2602's central regression: this stack "
            "directory must receive zero mutations now that it is not a "
            "deploy.yml destination"
        )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
