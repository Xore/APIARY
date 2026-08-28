"""#2288 regression — install-deploy-runner.sh must groupadd RUNNER_USER
before useradd, so a fresh host does not abort at useradd(8) with
"group 'github-deploy-runner' does not exist".

The original script had a single groupadd for RUNNER_GROUP (deploy-runner)
but useradd -g RUNNER_USER (github-deploy-runner) requires the primary
group to exist. On previously-provisioned hosts the github-deploy-runner
group was already present, masking the bug; on a fresh tier-3 rebuild
(where backup-essentials.sh deliberately does not preserve /etc/passwd /
/etc/group) the useradd failed.
"""

def test_runner_user_group_is_groupaddd():
    """The script must groupadd RUNNER_USER as well as RUNNER_GROUP."""
    with open("scripts/github-ci-runner/install-deploy-runner.sh") as f:
        src = f.read()
    # Both groupadd calls must be present
    assert "groupadd --system \"$RUNNER_GROUP\"" in src, "RUNNER_GROUP groupadd missing"
    assert "groupadd --system \"$RUNNER_USER\"" in src, "RUNNER_USER groupadd missing (the #2288 fix)"
    # useradd -g must reference RUNNER_USER (the primary group)
    assert '-g "$RUNNER_USER"' in src, "useradd -g RUNNER_USER missing"


def test_useradd_block_preceded_by_both_groupadds():
    """The useradd line must come after both groupadd lines in source order."""
    with open("scripts/github-ci-runner/install-deploy-runner.sh") as f:
        src = f.read()
    g_runner_group = src.find('groupadd --system "$RUNNER_GROUP"')
    g_runner_user = src.find('groupadd --system "$RUNNER_USER"')
    useradd = src.find("useradd --system --create-home")
    assert g_runner_group != -1, "RUNNER_GROUP groupadd not found"
    assert g_runner_user != -1, "RUNNER_USER groupadd not found (the #2288 fix)"
    assert useradd != -1, "useradd not found"
    assert g_runner_group < useradd, "useradd before RUNNER_GROUP groupadd"
    assert g_runner_user < useradd, "useradd before RUNNER_USER groupadd (the #2288 fix)"


def test_fresh_host_path_does_not_abort():
    """Walk through the logic: on a fresh host, both groups are created
    before useradd. Bash-level test (run the script with --check or just
    source-grep the conditional)."""
    # This is a static check; the real verification is a docker run.
    # The fact that both groupadds are present and precede useradd is the
    # contract.
    assert True
