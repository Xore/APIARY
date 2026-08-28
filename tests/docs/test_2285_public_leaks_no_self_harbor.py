#!/usr/bin/env python3
"""Regression test for #2285: scripts/check-public-leaks.py was itself the
single committed harbor for the values it exists to ban.

FORBIDDEN_LITERALS used to embed the production domain and VPS address as
plain string literals, and the scanner exempted its own path
(`if posix == "scripts/check-public-leaks.py": continue`) purely so CI
would stay green despite those literals sitting in the file it scans. Two
consequences: a one-token `git grep` of any forbidden value recovered the
deployment endpoint from any clone at any commit, and the exemption was
keyed to one exact path string, so renaming/moving the script would
either break coverage of the (moved) file or silently stop scanning it
while the literals stayed put.

The fix assembles each forbidden literal at runtime from fragments that are
never written contiguously in the source (see `_literal()` /
`forbidden_literals()`), which makes the self-skip unnecessary: the
checker's own source no longer contains any of the values it bans, so
scanning itself like any other tracked file produces no false positive.
The self-skip is removed entirely rather than keyed off `Path(__file__)`,
so coverage cannot depend on this script's name or location.

Separately, files that fail UTF-8 decoding used to be dropped with a bare
`continue` -- invisible in the check's output. They are now collected and
reported as a "Skipped N non-text file(s)" notice.
"""
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = REPO_ROOT / "scripts" / "check-public-leaks.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_public_leaks_2285", CHECKER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def checker():
    return _load_checker()


def _init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)


def _run_checker_against(checker_module, monkeypatch, capsys, root: Path):
    monkeypatch.setattr(checker_module, "ROOT", root)
    rc = checker_module.main()
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def test_checker_script_exists():
    assert CHECKER_PATH.exists(), f"{CHECKER_PATH} not found"


def test_forbidden_literal_reasons_cover_the_known_set(checker):
    # Reason labels are descriptive, not sensitive -- safe to assert on
    # directly, unlike the assembled literal values themselves.
    reasons = set(checker.forbidden_literals().values())
    assert reasons == {
        "deployment-specific public domain",
        "deployment-specific VPS address",
        "deployment-specific home-server address",
        "known default password",
    }


# --- (a) literals are unrecoverable by inspection ---------------------------


def test_forbidden_literals_not_grep_visible_in_tracked_tree(checker):
    """git grep for the assembled value of every forbidden literal must
    return nothing in the tracked tree outside the explicit fixture
    allowlist -- values are only ever built at runtime from fragments,
    never written contiguously anywhere except in tests/docs/ files
    that need them as fixtures to verify the runtime check itself
    (see ALLOWED_LITERAL_FIXTURE_FILES in scripts/check-public-leaks.py
    for the allowlist contract; the same allowlist gates this grep)."""
    literals = checker.forbidden_literals()
    assert len(literals) == 4
    # Build a git pathspec exclusion list from the runtime allowlist
    # so the test mirrors the gate: both must agree on which files
    # legitimately embed the literals.
    allowed = {p.as_posix() for p in checker.ALLOWED_LITERAL_FIXTURE_FILES}
    assert allowed, "ALLOWED_LITERAL_FIXTURE_FILES must list at least the test that asserts its own allowlisted status"
    pathspec_excludes = [f":!{p}" for p in sorted(allowed)]
    for literal in literals:
        result = subprocess.run(
            ["git", "grep", "-F", "-i", "--", literal, *pathspec_excludes],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1, (
            f"git grep found {literal!r} committed outside the "
            f"ALLOWED_LITERAL_FIXTURE_FILES allowlist "
            f"(stdout: {result.stdout!r}) -- a forbidden literal must "
            f"never appear contiguously in tracked source except in the "
            f"explicit fixture allowlist, including inside the checker "
            f"that bans it"
        )


def test_checker_source_has_no_contiguous_forbidden_literal(checker):
    """Defense in depth against test_forbidden_literals_not_grep_visible_in_tracked_tree
    relying on git's own matching semantics: read the checker's source text
    directly and assert no assembled literal appears in it verbatim."""
    source = CHECKER_PATH.read_text(encoding="utf-8")
    for literal in checker.forbidden_literals():
        assert literal not in source, (
            f"{literal!r} appears verbatim in {CHECKER_PATH} -- it must be "
            "assembled from fragments at runtime, not written as a plain "
            "string literal"
        )


# --- (b) no path-string self-skip coupling ----------------------------------


def test_no_hardcoded_self_path_skip_in_source():
    source = CHECKER_PATH.read_text(encoding="utf-8")
    assert "check-public-leaks.py" not in source, (
        f"{CHECKER_PATH} still special-cases its own filename somewhere -- "
        "coverage must not depend on the script's path or name"
    )


def test_planted_literal_at_the_checkers_own_path_is_still_flagged(
    checker, monkeypatch, tmp_path, capsys
):
    """A file living at the exact path scripts/check-public-leaks.py used
    to be exempt from every check (the old self-skip). Plant a forbidden
    literal at that same relative path in an isolated tree and confirm it
    is flagged like any other file."""
    _init_repo(tmp_path)
    domain = next(
        literal
        for literal, reason in checker.forbidden_literals().items()
        if reason == "deployment-specific public domain"
    )
    target = tmp_path / "scripts" / "check-public-leaks.py"
    target.parent.mkdir(parents=True)
    target.write_text(f"# planted for #2285 regression test: {domain}\n", encoding="utf-8")

    rc, _out, err = _run_checker_against(checker, monkeypatch, capsys, tmp_path)

    assert rc == 1
    assert "scripts/check-public-leaks.py" in err
    assert "deployment-specific public domain" in err


def test_renaming_the_script_does_not_change_which_files_are_covered(
    checker, monkeypatch, tmp_path, capsys
):
    """Coverage must be rule-driven, not filename-driven: a forbidden
    literal planted under a completely different name/location is caught
    exactly the same way, proving there is no special-cased path left."""
    _init_repo(tmp_path)
    vps_address = next(
        literal
        for literal, reason in checker.forbidden_literals().items()
        if reason == "deployment-specific VPS address"
    )
    renamed = tmp_path / "scripts" / "leak-scanner-renamed.py"
    renamed.parent.mkdir(parents=True)
    renamed.write_text(f"# planted for #2285 regression test: {vps_address}\n", encoding="utf-8")

    rc, _out, err = _run_checker_against(checker, monkeypatch, capsys, tmp_path)

    assert rc == 1
    assert "leak-scanner-renamed.py" in err
    assert "deployment-specific VPS address" in err


# --- (c) non-UTF-8 skips are observable -------------------------------------


def test_non_utf8_file_produces_a_visible_skip_notice(checker, monkeypatch, tmp_path, capsys):
    _init_repo(tmp_path)
    bad = tmp_path / "not-utf8.dat"
    bad.write_bytes(b"\xff\xfe\x00bad-bytes-not-valid-utf8")

    rc, out, err = _run_checker_against(checker, monkeypatch, capsys, tmp_path)

    assert rc == 0, "a lone undecodable file must not itself fail the gate"
    combined = (out + err).lower()
    assert "skipped 1 non-text file" in combined
    assert "not-utf8.dat" in (out + err)


def test_non_utf8_skip_count_matches_number_of_undecodable_files(
    checker, monkeypatch, tmp_path, capsys
):
    _init_repo(tmp_path)
    for name in ("first.dat", "second.dat"):
        (tmp_path / name).write_bytes(b"\xff\xfe\x00\x01")

    rc, out, err = _run_checker_against(checker, monkeypatch, capsys, tmp_path)

    combined = out + err
    assert "skipped 2 non-text file" in combined.lower()
    assert "first.dat" in combined
    assert "second.dat" in combined


def test_non_utf8_skip_is_not_silently_swallowed_alongside_real_findings(
    checker, monkeypatch, tmp_path, capsys
):
    """The skip notice must still surface even when the run also fails for
    an unrelated reason -- it must not be conditioned on the pass/fail
    branch."""
    _init_repo(tmp_path)
    (tmp_path / "not-utf8.dat").write_bytes(b"\xff\xfe\x00\x01")
    domain = next(
        literal
        for literal, reason in checker.forbidden_literals().items()
        if reason == "deployment-specific public domain"
    )
    (tmp_path / "leaky.txt").write_text(domain, encoding="utf-8")

    rc, _out, err = _run_checker_against(checker, monkeypatch, capsys, tmp_path)

    assert rc == 1
    assert "skipped 1 non-text file" in err.lower()
    assert "not-utf8.dat" in err
    assert "leaky.txt" in err


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
