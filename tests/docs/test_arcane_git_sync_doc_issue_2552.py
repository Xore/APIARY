#!/usr/bin/env python3
"""Regression test for #2552: docs/ARCANE-GIT-SYNC.md's stack counts and its
maxSyncFiles justification must stay consistent with the real manifest and
the real repo tree, not drift back to stale literals (39/33+6, or a
`dashboard/vendor/` path that no longer exists) after the next stack is
added or removed.
"""
import json
import pathlib
import re
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC_PATH = REPO_ROOT / "docs" / "ARCANE-GIT-SYNC.md"
MANIFEST_PATH = REPO_ROOT / "arcane" / "manifests" / "home-production.json"

HONEYPOT_COUNT_RE = re.compile(r"The (\d+) `honeypot-\*` stacks live under")


def _manifest_entries():
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def test_doc_path_exists():
    assert DOC_PATH.exists(), f"doc not found at {DOC_PATH}"


def test_honeypot_stack_count_matches_manifest():
    entries = _manifest_entries()
    honeypot_count = sum(
        1
        for e in entries
        if e.get("dockerComposePath", "").startswith("arcane/home/honeypot-")
    )
    other_count = len(entries) - honeypot_count

    text = DOC_PATH.read_text(encoding="utf-8")
    matches = HONEYPOT_COUNT_RE.findall(text)
    assert matches, (
        f"no '- The N `honeypot-*` stacks live under' bullet found in {DOC_PATH} "
        "-- has this section been restructured?"
    )
    for doc_count in matches:
        assert int(doc_count) == honeypot_count, (
            f"{DOC_PATH} claims {doc_count} `honeypot-*` stacks, but "
            f"{MANIFEST_PATH.name} has {honeypot_count} entries under "
            f"arcane/home/honeypot-* (plus {other_count} others, "
            f"{len(entries)} total)"
        )


def test_maxsyncfiles_bullet_does_not_cite_removed_path():
    text = DOC_PATH.read_text(encoding="utf-8")
    # dashboard/vendor/ is gone (#1659) -- fine to mention as history, but
    # only if the bullet also names the real current directory it replaced
    # it with, and that directory must actually exist.
    if "dashboard/vendor/" in text:
        assert "arcane/home/honeypot-dashboard" in text, (
            f"{DOC_PATH} still cites the removed dashboard/vendor/ tree "
            "without pointing at the real current honeypot-dashboard path"
        )
        real_path = REPO_ROOT / "arcane" / "home" / "honeypot-dashboard"
        assert real_path.is_dir(), (
            f"{DOC_PATH}'s maxSyncFiles bullet points at {real_path}, "
            "which does not exist"
        )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
