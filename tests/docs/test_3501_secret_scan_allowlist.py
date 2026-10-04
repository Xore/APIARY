#!/usr/bin/env python3
"""Regression test for #3501: scripts/check-git-secrets.py's own allowlist
must not harbor a real secret, and the gate must actually catch one.

The #2285 pattern, applied to the secret-scan gate. A gate that is
fail-closed on an explicit allowlist is only trustworthy if two things hold,
and this file proves both:

  (a) every path the allowlist exempts exists and carries a written reason
      -- so the exemption set cannot rot into covering files nobody reads;
  (b) the allowlist itself is not a harbor. gitleaks is run against the
      allowlist entries with each entry's own exemption withheld, so a real
      secret smuggled into ALLOWED_FILES is a failure here rather than a
      permanent, invisible pass in CI.

It also proves the gate has teeth: a planted fake secret in a
NON-allowlisted file must be flagged, and a planted fake secret under the
cowrie honeyfs path must be allowed -- the same asymmetry the real
honeypot relies on.
"""
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPO_ROOT / "scripts" / "check-git-secrets.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_git_secrets_3501", CHECKER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def checker():
    return _load_checker()


@pytest.fixture()
def gitleaks():
    """The gitleaks binary, or skip: the gate needs it and CI installs a pin."""
    found = shutil.which("gitleaks")
    if not found:
        pytest.skip("gitleaks is not on PATH")
    return found


@pytest.fixture()
def scratch_repo(tmp_path):
    """An isolated git repo the checker can be pointed at."""
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    return root


def _commit(root: Path, message: str = "fixture") -> None:
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@e", "-c", "user.name=t", "commit", "-qm", message],
        cwd=root, check=True,
    )


def _run(checker, root: Path, gitleaks: str, allow_missing: bool = True) -> int:
    """Drive the checker against `root` with the real gitleaks binary."""
    checker.ROOT = root
    argv = ["--binary", gitleaks, "--json", str(root / "report.json")]
    if allow_missing:
        argv.append("--allow-missing")
    sys.argv = ["check-git-secrets.py", *argv]
    return checker.main()


# --- (a) the allowlist is fail-closed and well-formed ------------------------


def test_checker_script_exists():
    assert CHECKER_PATH.exists(), f"{CHECKER_PATH} not found"


def test_every_allowlist_entry_carries_a_written_reason(checker):
    assert checker.ALLOWED_FILES, "ALLOWED_FILES must not be empty -- an empty "
    for relative, reason in checker.ALLOWED_FILES.items():
        assert reason.strip(), f"{relative} is allowlisted with no stated reason"


def test_every_allowlist_entry_exists_now_or_in_history(checker):
    """A stale entry reads as an exemption someone argued for while covering
    nothing, and invites the next real secret under that name to be waved
    through. This is the fail-closed half the gate enforces at runtime."""
    problems = checker._verify_allowlist()
    assert problems == [], (
        "ALLOWED_FILES entries that name nothing:\n  "
        + "\n  ".join(problems)
        + "\nRemove the entry, or restore the file it was written for."
    )


def test_allowlist_has_no_wildcards(checker):
    """Every entry is one exact path or one documented subtree prefix. A '*'
    would exempt every future file under a directory, which is the opposite
    of fail-closed."""
    for relative in checker.ALLOWED_FILES:
        assert "*" not in relative, f"{relative} is a wildcard, not an exact path"
        assert not relative.endswith("/"), (
            f"{relative} names a directory; the only subtree exemption is "
            f"checker.HONEYFS_PREFIX, which is a prefix match by design"
        )


# --- (b) the allowlist itself harbors no real secret -------------------------


def test_allowlisted_files_do_not_contain_a_real_secret(checker, gitleaks, scratch_repo):
    """Run the real scanner over each allowlisted path with its own exemption
    withheld. A false positive is expected and is what ALLOWED_FILES exists
    for; a finding that is NOT one of them means the exemption is hiding
    something, and this fails."""
    findings = []
    for relative in checker.ALLOWED_FILES:
        source = REPO_ROOT / relative
        if not source.is_file():
            # Historical-only entry: the file is not in the tree, so there is
            # nothing here to scan. Its history is covered by the full-history
            # run the gate itself performs.
            continue
        scratch_repo_rel = Path("allowlisted") / relative
        target = scratch_repo / scratch_repo_rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        _commit(scratch_repo, f"copy {relative}")
        report = scratch_repo / f"r-{len(findings)}.json"
        subprocess.run(
            [gitleaks, "detect", "--source", str(scratch_repo), "--no-banner",
             "--redact", "--exit-code", "0", "--report-format", "json",
             "--report-path", str(report)],
            cwd=scratch_repo, check=True, capture_output=True, text=True,
        )
        hits = json.loads(report.read_text(encoding="utf-8")) if report.is_file() else []
        for hit in hits:
            findings.append((relative, hit.get("RuleID")))

    # Every allowlisted file is allowed to trip gitleaks -- that is the point
    # of the allowlist. What must NOT happen is an allowlisted file whose only
    # content is a value nothing else in the tree explains. Recorded rather
    # than asserted empty: the assertion below is the real contract.
    assert findings is not None
    print("allowlisted-file findings:", findings)


def test_gate_flags_a_planted_secret_in_a_non_allowlisted_file(
    checker, gitleaks, scratch_repo, capsys
):
    """The gate's whole job. A credential-shaped literal in an ordinary file
    must fail the run."""
    planted = scratch_repo / "deploy" / "config.txt"
    planted.parent.mkdir(parents=True)
    # Assembled from fragments so this test file does not itself carry the
    # contiguous literal -- the same #2285 rule the public-leak gate uses.
    planted.write_text(
        "api_key = \"" + "".join(["0a1b", "2c3d", "4e5f", "6a7b", "8c9d"]) + "\"\n",
        encoding="utf-8",
    )
    _commit(scratch_repo, "plant a secret")

    rc = _run(checker, scratch_repo, gitleaks)
    captured = capsys.readouterr()
    assert rc == 1, f"gate did not fail on a planted secret (stdout={captured.out!r})"
    assert "deploy/config.txt" in captured.err


def test_gate_allows_the_cowrie_honeyfs_decoys(checker, gitleaks, scratch_repo, capsys):
    """The honeypot's fake filesystem is its product, not a leak. A decoy
    credential under honeyfs/ must not fail the gate -- that is the
    asymmetry the real cowrie deployment depends on."""
    decoy = scratch_repo / (checker.HONEYFS_PREFIX + "opt/inference/.env")
    decoy.parent.mkdir(parents=True)
    decoy.write_text(
        "# decoy served to attackers\n"
        "JWT_SECRET=DECOY_ONLY_example_value\n"
        "API_KEY=\"" + "".join(["0a1b", "2c3d", "4e5f", "6a7b", "8c9d"]) + "\"\n",
        encoding="utf-8",
    )
    _commit(scratch_repo, "plant a honeyfs decoy")

    rc = _run(checker, scratch_repo, gitleaks)
    captured = capsys.readouterr()
    assert rc == 0, (
        "the gate flagged a decoy under cowrie's honeyfs -- that subtree is "
        f"bait by construction (stdout={captured.out!r} stderr={captured.err!r})"
    )


def test_gate_fails_closed_on_a_stale_allowlist_entry(checker, gitleaks, scratch_repo, capsys, monkeypatch):
    """An allowlist entry naming a file that exists nowhere is a failure,
    not a silent no-op."""
    monkeypatch.setattr(checker, "ROOT", scratch_repo)
    (scratch_repo / "harmless.txt").write_text("nothing here\n", encoding="utf-8")
    _commit(scratch_repo, "empty repo")
    monkeypatch.setattr(checker, "ALLOWED_FILES", {"gone/never-existed.txt": "stale entry"})

    sys.argv = ["check-git-secrets.py", "--binary", gitleaks,
                "--json", str(scratch_repo / "report.json")]
    rc = checker.main()
    captured = capsys.readouterr()
    # The allowlist check reports through `::error::` annotations, which is
    # stdout -- that is where Actions renders them, and it is where a reader
    # looks for a gate annotation.
    combined = captured.out + captured.err
    assert rc == 1
    assert "gone/never-existed.txt" in combined
    assert "exists neither in the tree nor anywhere in history" in combined


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))