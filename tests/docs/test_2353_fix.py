#!/usr/bin/env python3
"""Regression test for #2353: docs/ARCHITECTURE.md's status-basis block
claimed "the only compose profile in the repo is the optional on-demand
`geoip-update` maintenance job." Eight distinct compose profile groups
exist repo-wide (geoip-update, threat-intel, mitm, test, blackhole,
file-extract, revdeck, legacy) -- the sentence undercounted by roughly
eight-to-one, in the one paragraph whose job is to be trustworthy without
re-checking.

The fix rewrites the claim to (a) scope the "no profile gating" statement
to the dashboard serving path, where it is actually true, and (b) point
at `grep -rn 'profiles:' --include='*.yml'` as the source of truth for
the rest, rather than hardcoding a list that rots the next time a profile
is added or removed. This file pins both halves: the doc's own
enumeration must match the real repo inventory in *both* directions
(nothing missing, nothing stale), and the dashboard compose files it
claims are ungated must actually carry no live `profiles:` key.
"""
import pathlib
import re
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC_PATH = REPO_ROOT / "docs" / "ARCHITECTURE.md"
DYNAMIC_YML = REPO_ROOT / "vps" / "traefik" / "dynamic.yml"
SELF_RELPATH = "tests/docs/test_2353_fix.py"

DASHBOARD_COMPOSE_FILES = [
    "arcane/home/honeypot-dashboard/compose.yml",
    "arcane/home/honeypot-dashboard-backend/compose.yml",
]

# Old false claim the fix must remove.
STALE_CLAIM = "the only compose profile in the repo is"

PROFILES_RE = re.compile(r"profiles:\s*\[([^\]]*)\]")


def _tracked_yml_files():
    """Repo-tracked *.yml files, relative to REPO_ROOT.

    `git ls-files` rather than a filesystem walk: a developer checkout
    carries untracked sibling worktrees under `.orchestrator/worktrees/`,
    each holding its own copy of every compose file on some other branch,
    which would otherwise inflate or corrupt the profile inventory.
    """
    try:
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "-z", "*.yml"],
            capture_output=True, check=True, text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:  # pragma: no cover
        pytest.skip(f"git ls-files unavailable: {exc}")
    return [p for p in out.split("\0") if p]


def _live_profile_names(text):
    """Distinct profile names from real (non-comment) `profiles:` lines."""
    names = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = PROFILES_RE.search(line)
        if not m:
            continue
        for token in m.group(1).split(","):
            names.add(token.strip().strip("'\"").strip())
    return names


def _repo_profile_inventory():
    """Every distinct compose profile name in the tracked repo."""
    names = set()
    for relpath in _tracked_yml_files():
        path = REPO_ROOT / relpath
        if not path.is_file() or path.is_symlink():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        names |= _live_profile_names(text)
    return names


def _doc_text():
    return DOC_PATH.read_text(encoding="utf-8")


def test_doc_path_exists():
    assert DOC_PATH.exists(), f"doc not found at {DOC_PATH}"


def test_stale_only_profile_claim_is_gone():
    text = _doc_text()
    assert STALE_CLAIM not in text, (
        f"{DOC_PATH} still claims {STALE_CLAIM!r} -- eight distinct "
        "compose profile groups exist repo-wide (#2353), not one."
    )


def test_dashboard_serving_path_actually_has_no_profile_gating():
    """The one part of the old claim that was true must stay true, and
    must be what the rewritten sentence actually asserts."""
    for relpath in DASHBOARD_COMPOSE_FILES:
        path = REPO_ROOT / relpath
        assert path.is_file(), f"{relpath} not found"
        live = _live_profile_names(path.read_text(encoding="utf-8"))
        assert not live, (
            f"{relpath} carries a live `profiles:` key ({live}) -- "
            f"{DOC_PATH} claims the dashboard serving path has no "
            "profile gating left"
        )


def test_doc_enumeration_matches_real_repo_inventory():
    """Whatever profile names the doc lists must be exactly the real
    on-disk set -- neither undercounting (#2353's bug) nor listing a
    profile that has since been retired (the same rot, backwards)."""
    real = _repo_profile_inventory()
    text = _doc_text()
    # Pull the doc's own parenthetical enumeration, e.g.
    # "(`geoip-update`, `threat-intel`, ...)"
    m = re.search(r"eight distinct groups\s*\(([^)]*)\)", text)
    assert m, (
        f"{DOC_PATH} no longer enumerates the profile groups it claims "
        "exist -- has the status-basis paragraph been reworded? If so, "
        "this test needs updating alongside it, not deleting."
    )
    listed = {tok.strip().strip("`'\"") for tok in m.group(1).split(",")}
    missing = real - listed
    extra = listed - real
    assert not missing, (
        f"{DOC_PATH} undercounts compose profiles -- on disk but not "
        f"listed: {sorted(missing)} (#2353 regression)"
    )
    assert not extra, (
        f"{DOC_PATH} lists compose profiles that no longer exist on "
        f"disk: {sorted(extra)} -- the enumeration has gone stale"
    )


def test_doc_points_at_the_grep_that_finds_profiles():
    """The rewritten sentence must give readers a live source of truth,
    not just a hardcoded list that can rot the same way again."""
    text = _doc_text()
    assert "profiles:" in text and "grep" in text.lower(), (
        f"{DOC_PATH} should point at a grep for `profiles:` so the next "
        "added/removed profile doesn't silently invalidate the sentence "
        "again (#2353)"
    )


def test_dynamic_yml_no_longer_claims_next_tier_is_uncutover():
    """#2353's second half: the #1608 addendum must not still say the
    BFF host-split is a no-op because dashboard-next isn't cut over --
    #1628 completed that cutover 2026-08-22."""
    assert DYNAMIC_YML.is_file(), f"{DYNAMIC_YML} not found"
    text = DYNAMIC_YML.read_text(encoding="utf-8")
    stale_phrases = [
        "dashboard-next isn't cut over yet",
        'still behind compose.yml\'s `profiles: ["next"]`',
    ]
    offending = [p for p in stale_phrases if p in text]
    assert not offending, (
        f"{DYNAMIC_YML} still asserts {offending} -- #1628 completed the "
        "dashboard-next cutover on 2026-08-22, this router no longer has "
        "a profile gate to be behind."
    )


def test_no_tracked_file_asserts_still_behind_next_profile():
    """Acceptance criterion: a grep for `profiles: ["next"]` across
    comments and configs comes back empty or annotated as historical.
    Only files that pair the literal with present-tense "isn't"/"still
    behind" language (rather than documenting the past removal) fail."""
    offenders = []
    for relpath in _tracked_yml_files() + ["docs/DASHBOARD-CUTOVER.md",
                                            "docs/ARCHITECTURE.md"]:
        path = REPO_ROOT / relpath
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if 'profiles: ["next"]' not in text:
            continue
        if "isn't cut over" in text or "isn't cutover" in text:
            offenders.append(relpath)
    assert not offenders, (
        f"these tracked files still assert dashboard-next isn't cut "
        f"over, alongside a `profiles: [\"next\"]` reference: {offenders} "
        "-- #1628 completed the cutover 2026-08-22 (#2353)"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
