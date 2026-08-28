#!/usr/bin/env python3
"""Regression test for #2294: install-vps.sh staging rsync was missing the
secrets/ exclude added to deploy.yml by #1184.

scripts/install-vps.sh's step_stage_vps_dir() claims to stage vps/ into
/root/vps/ "matching .github/workflows/deploy.yml's own rsync exactly (same
excludes)". deploy.yml's VPS job carries four excludes (.env,
traefik/certs/, traefik/dynamic.yml, secrets/) -- the last one was added by
#1184 after --delete-delay took down all seven oauth2-proxy gateways by
deleting secrets/, which is git-ignored and never present in the checkout,
so rsync sees it as "absent from the source" and deletes it from the
target. install-vps.sh never inherited that exclude, so its own
--delete-delay rsync (run on every `--force-rerun-from stage-vps-dir`)
replayed the same deletion locally against a live, populated
/root/vps/secrets/.

The fix adds --exclude 'secrets/' to step_stage_vps_dir's rsync invocation.
"""
import pathlib
import re
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALL_VPS_SH = REPO_ROOT / "scripts" / "install-vps.sh"
DEPLOY_YML = REPO_ROOT / ".github" / "workflows" / "deploy.yml"


def _extract_excludes(block_text):
    return re.findall(r"--exclude '([^']+)'", block_text)


def _install_vps_stage_block():
    text = INSTALL_VPS_SH.read_text(encoding="utf-8")
    m = re.search(r"^step_stage_vps_dir\(\)\s*\{\n(.*?)^\}\s*$", text, re.MULTILINE | re.DOTALL)
    assert m, f"step_stage_vps_dir() function not found in {INSTALL_VPS_SH}"
    return m.group(1)


def _deploy_yml_vps_stage_block():
    text = DEPLOY_YML.read_text(encoding="utf-8")
    # Anchored on `-az` (not the home job's `-a`) and the /root/vps/ target,
    # which uniquely identifies the VPS job's staging rsync -- deploy.yml's
    # other rsync (home job, top of file) excludes a different, unrelated
    # set of paths (.git/, .github/, logs/, state/, ...).
    m = re.search(r"rsync -az --delete-delay \\.*?/root/vps/\"", text, re.DOTALL)
    assert m, f"VPS job's staging rsync not found in {DEPLOY_YML}"
    return m.group(0)


INSTALL_EXCLUDES = _extract_excludes(_install_vps_stage_block())
DEPLOY_EXCLUDES = _extract_excludes(_deploy_yml_vps_stage_block())


def test_install_vps_sh_exists():
    assert INSTALL_VPS_SH.exists(), f"not found: {INSTALL_VPS_SH}"


def test_install_vps_excludes_secrets_dir():
    assert "secrets/" in INSTALL_EXCLUDES, (
        f"step_stage_vps_dir's rsync excludes {INSTALL_EXCLUDES!r}, missing "
        "'secrets/' -- without it, --delete-delay treats the git-ignored, "
        "never-checked-out secrets/ directory as absent from the source and "
        "deletes /root/vps/secrets/ on every rerun (#1184's incident, "
        "replayed locally by #2294)"
    )


def test_install_vps_exclude_list_matches_deploy_yml_vps_job():
    assert set(INSTALL_EXCLUDES) == set(DEPLOY_EXCLUDES), (
        f"install-vps.sh excludes {INSTALL_EXCLUDES!r} but deploy.yml's VPS "
        f"job excludes {DEPLOY_EXCLUDES!r} -- step_stage_vps_dir's own "
        "comment claims these match deploy.yml's rsync 'exactly (same "
        "excludes)'; keep the two lists in lockstep (#2294)"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="uses the real rsync binary")
def test_rsync_dry_run_reports_no_deletions_under_secrets(tmp_path):
    """Acceptance criterion: a dry-run `rsync -an --delete-delay` with the
    staging options reports no deletions under secrets/."""
    src = tmp_path / "repo-vps"
    src.mkdir()
    (src / "docker-compose.yml").write_text("services: {}\n")
    secrets_dir = tmp_path / "root-vps" / "secrets" / "oidc"
    secrets_dir.mkdir(parents=True)
    (secrets_dir / "kibana-cookie-secret").write_text("super-secret\n")
    dest = tmp_path / "root-vps"

    exclude_args = [arg for pattern in INSTALL_EXCLUDES for arg in ("--exclude", pattern)]
    result = subprocess.run(
        ["rsync", "-azn", "--delete-delay", "-i", *exclude_args, f"{src}/", f"{dest}/"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"rsync dry-run failed: {result.stderr}"
    deleting_lines = [line for line in result.stdout.splitlines() if "deleting" in line]
    secret_deletions = [line for line in deleting_lines if "secrets" in line]
    assert not secret_deletions, (
        f"dry-run reports deletions under secrets/: {secret_deletions!r} -- "
        "the staging rsync would wipe live gateway OIDC secrets on a rerun (#2294)"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="uses the real rsync binary")
def test_rerun_leaves_populated_secrets_dir_byte_identical(tmp_path):
    """Acceptance criterion: re-running `--force-rerun-from stage-vps-dir`
    on a host with a populated /root/vps/secrets/ leaves every file
    byte-identical afterward."""
    src = tmp_path / "repo-vps"
    src.mkdir()
    (src / "docker-compose.yml").write_text("services: {}\n")
    dest = tmp_path / "root-vps"
    secrets_dir = dest / "secrets" / "oidc"
    secrets_dir.mkdir(parents=True)
    secret_file = secrets_dir / "kibana-cookie-secret"
    secret_file.write_text("super-secret\n")

    exclude_args = [arg for pattern in INSTALL_EXCLUDES for arg in ("--exclude", pattern)]
    for _ in range(2):  # a rerun must be idempotent, not just survive a first pass
        result = subprocess.run(
            ["rsync", "-az", "--delete-delay", *exclude_args, f"{src}/", f"{dest}/"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"rsync failed: {result.stderr}"

    assert secret_file.exists(), (
        "secrets/oidc/kibana-cookie-secret was deleted by the staging rsync "
        "rerun (#2294) -- client secrets can only be recovered from "
        "Keycloak's own stored value, never regenerated"
    )
    assert secret_file.read_text() == "super-secret\n"
    assert (dest / "docker-compose.yml").exists()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
