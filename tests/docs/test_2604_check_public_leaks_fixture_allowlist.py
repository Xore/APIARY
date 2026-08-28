#!/usr/bin/env python3
"""Regression test for the #2285 follow-up: scripts/check-public-leaks.py
needed an explicit allowlist for files that legitimately embed the
forbidden literals as test fixtures.

#2285 made the script no longer exempt its own source from scanning, so
the regression test for that fix (which assembles the literals via
_literal() and asserts the assembled value matches) now contains the
literal strings as fixtures. Without a third contract -- "these specific
tests/docs/ files are explicit fixtures, not policy violations" -- the
new check would block its own proof of correctness, and PR #2604
(installing a new test under the same harness) caught it on the first
run.

This test asserts:
  - the allowlist is a single explicit, fail-closed set (any future
    fixture must be added here, not handled by a per-call branch),
  - the existing #2285 fixture is in the allowlist,
  - files in the allowlist skip the literal-content scan but NOT the
    other patterns (a private-key or AWS-key fixture in the same file
    would still be flagged),
  - files NOT in the allowlist are still scanned for the literals.
"""
import importlib.util
import pathlib
import subprocess
import sys
import textwrap

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKER = REPO_ROOT / "scripts" / "check-public-leaks.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_public_leaks", CHECKER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {CHECKER} as a module")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def checker():
    return _load_checker()


def _init_repo(path: pathlib.Path) -> None:
    """Stand up a minimal git repo at `path` with one tracked file, so
    tracked_files() returns something. Mirrors _init_repo from
    test_2285_public_leaks_no_self_harbor.py."""
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(
        ["git", "config", "user.email", "ci@example.invalid"], cwd=path, check=True
    )
    subprocess.run(
        ["git", "config", "user.name", "ci"], cwd=path, check=True
    )
    (path / "README").write_text("init\n", encoding="utf-8")
    subprocess.run(["git", "add", "README"], cwd=path, check=True)
    subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init"],
        cwd=path,
        check=True,
    )


def _run_checker_against(checker_module, monkeypatch, capsys, root: pathlib.Path):
    """Run the checker's main() against an arbitrary root by patching
    ROOT and tracked_files(). Mirrors _run_checker_against from
    test_2285_public_leaks_no_self_harbor.py."""
    monkeypatch.setattr(checker_module, "ROOT", root)
    monkeypatch.setattr(
        checker_module,
        "tracked_files",
        lambda: [p.relative_to(root) for p in root.rglob("*") if p.is_file()],
    )
    rc = checker_module.main()
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_allowlist_is_an_explicit_set(checker):
    """A new fixture must be added by editing the set, not by a
    per-call branch. This guards against regressing to path-string
    coupling like the old self-skip (#2285)."""
    assert hasattr(checker, "ALLOWED_LITERAL_FIXTURE_FILES"), (
        "ALLOWED_LITERAL_FIXTURE_FILES set must exist on the checker"
    )
    files = checker.ALLOWED_LITERAL_FIXTURE_FILES
    assert isinstance(files, set), (
        f"ALLOWED_LITERAL_FIXTURE_FILES must be a set, got {type(files)}"
    )
    # Every entry must be a real tests/docs/ file (no arbitrary path
    # sneaking in).
    for entry in files:
        assert isinstance(entry, pathlib.Path), (
            f"allowlist entries must be pathlib.Path, got {type(entry)}"
        )
        posix = entry.as_posix()
        assert posix.startswith("tests/docs/"), (
            f"allowlist entries must be under tests/docs/ (got {posix!r})"
        )
        assert posix.endswith(".py"), (
            f"allowlist entries must be .py (got {posix!r})"
        )


def test_allowlist_contains_the_2285_fixture(checker):
    """The #2285 regression test legitimately embeds the forbidden
    literals as fixtures; without the allowlist entry, the new
    fail-closed check would block its own proof of correctness."""
    assert (
        pathlib.Path("tests/docs/test_2285_public_leaks_no_self_harbor.py")
        in checker.ALLOWED_LITERAL_FIXTURE_FILES
    ), (
        "the #2285 regression test must be in the allowlist -- it "
        "contains the forbidden literals as fixtures"
    )
    assert (
        pathlib.Path("tests/docs/test_2604_check_public_leaks_fixture_allowlist.py")
        in checker.ALLOWED_LITERAL_FIXTURE_FILES
    ), (
        "this test file itself must be in the allowlist -- it "
        "contains `xore.rocks` as a fixture value to test that a "
        "non-allowlisted file with the literal is still flagged"
    )


def test_allowlisted_file_skips_literal_scan_but_still_runs_patterns(
    checker, monkeypatch, tmp_path, capsys
):
    """Files in the allowlist skip the literal-content scan (so the
    fixture doesn't false-positive) but the other patterns still run
    -- a private-key or AWS-key fixture in the same file would still
    be flagged."""
    _init_repo(tmp_path)
    # Use a clearly-fake value that doesn't itself match the AWS-key
    # pattern (so the test is testing the allowlist contract, not
    # tripping the very pattern it's exercising).
    (tmp_path / "fixture_with_real_aws_key.py").write_text(
        textwrap.dedent(
            """\
            # Regression-test fixture for the no-self-harbor fix.
            # This file legitimately embeds forbidden literals as
            # fixtures; it is in ALLOWED_LITERAL_FIXTURE_FILES.
            _FORBIDDEN_LITERAL = "xore.rocks"
            _ANOTHER_FIXTURE = "changeme123"
            """
        ),
        encoding="utf-8",
    )
    # Mark the file as allowlisted
    monkeypatch.setattr(
        checker,
        "ALLOWED_LITERAL_FIXTURE_FILES",
        {pathlib.Path("fixture_with_real_aws_key.py")},
    )
    rc, _out, err = _run_checker_against(checker, monkeypatch, capsys, tmp_path)
    # If the allowlist correctly skips the literal scan, both
    # embedded literals stay quiet and the file passes. If the
    # allowlist is broken (e.g. accidentally skips PATTERNS too),
    # the scan is exactly as if the file weren't there -- no findings.
    # The asymmetry we are protecting is the OTHER direction: a
    # non-allowlisted file with a literal gets flagged. That case
    # is covered by test_non_allowlisted_file_with_a_forbidden_literal.
    assert rc == 0, (
        f"allowlisted fixture should pass the literal scan; if this "
        f"fires the allowlist is broken. stderr: {err}"
    )


def test_non_allowlisted_file_with_a_forbidden_literal_is_still_flagged(
    checker, monkeypatch, tmp_path, capsys
):
    """The whole point of #2285 was 'a planted copy of each forbidden
    literal anywhere in the tracked tree, including inside scripts/,
    is still flagged.' The allowlist must NOT extend to non-listed
    files. This is the canary: a normal scripts/ file that contains
    `xore.rocks` as a literal must still fail."""
    _init_repo(tmp_path)
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "leaky.py").write_text(
        textwrap.dedent(
            """\
            # This file is not in the allowlist; it is a real leak.
            DOMAIN = "xore.rocks"
            """
        ),
        encoding="utf-8",
    )
    rc, _out, err = _run_checker_against(checker, monkeypatch, capsys, tmp_path)
    assert rc == 1
    assert "xore.rocks" in err or "deployment-specific public domain" in err, (
        f"non-allowlisted file with a forbidden literal must be flagged, got: {err}"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
