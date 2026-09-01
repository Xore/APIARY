#!/usr/bin/env python3
"""Regression test for #2577: the dangling `honeypot-wordpot` gitops_sync
row in Arcane's live store.

#2381 retired the `honeypot-wordpot` stack and dropped it from
`arcane/manifests/home-production.json`, but the sync + project records
#1502's migration created for it were never removed from Arcane's own
store, leaving 38 live `gitops_syncs` rows against 37 manifest entries.

This test cannot reach the live homeserver store (offline-runnable, per
house rules -- this repo never touches the running Arcane instance from a
test), so it exercises `scripts/cleanup-arcane-dangling-gitops-syncs.py`'s
pure diff/plan logic against a fixture standing in for the real 38-row
store: the real 37-entry manifest, plus one synthetic
`honeypot-wordpot` row shaped like the orphan the issue describes.
"""
import importlib.util
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "cleanup-arcane-dangling-gitops-syncs.py"
MANIFEST_PATH = REPO_ROOT / "arcane" / "manifests" / "home-production.json"


def _load_module():
    spec = importlib.util.spec_from_file_location("cleanup_arcane_dangling_gitops_syncs_2577", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mod():
    return _load_module()


@pytest.fixture
def manifest_entries():
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _live_syncs_with_orphan(manifest_entries):
    """38-row fixture: one live sync per manifest entry, plus the dangling
    honeypot-wordpot row the issue describes (tracked path retired by
    #2381, sync/project records left behind).
    """
    live = [
        {"id": f"sync-{i}", "name": e["syncName"], "projectId": f"project-{i}"}
        for i, e in enumerate(manifest_entries)
    ]
    live.append(
        {
            "id": "sync-orphan-wordpot",
            "name": "honeypot-wordpot",
            "projectId": "3c5caee1-f8f2-4aff-b1e4-49a7df9c33e7",
        }
    )
    return live


def test_script_path_exists():
    assert SCRIPT_PATH.exists(), f"cleanup script not found at {SCRIPT_PATH}"


def test_manifest_has_no_wordpot_entry(manifest_entries):
    # #2381 already dropped it from the manifest -- the bug is purely a
    # live-store leftover, not a manifest regression.
    names = {e["syncName"] for e in manifest_entries}
    assert "honeypot-wordpot" not in names
    assert len(manifest_entries) == 37


def test_dangling_sync_names_finds_only_wordpot(mod, manifest_entries):
    manifest_names = mod.manifest_sync_names(MANIFEST_PATH)
    live = _live_syncs_with_orphan(manifest_entries)

    dangling = mod.dangling_sync_names(live, manifest_names)

    assert dangling == {"honeypot-wordpot"}


def test_dangling_sync_names_is_idempotent_once_clean(mod, manifest_entries):
    # Rerunning after the orphan is gone must find nothing left to do --
    # the migration is safe to run more than once.
    manifest_names = mod.manifest_sync_names(MANIFEST_PATH)
    live_clean = [
        {"id": f"sync-{i}", "name": e["syncName"], "projectId": f"project-{i}"}
        for i, e in enumerate(manifest_entries)
    ]

    assert mod.dangling_sync_names(live_clean, manifest_names) == set()


def test_plan_deletions_carries_sync_and_project_ids(mod, manifest_entries):
    live = _live_syncs_with_orphan(manifest_entries)

    plan = mod.plan_deletions(live, mod.manifest_sync_names(MANIFEST_PATH))

    assert len(plan) == 1
    assert plan[0]["name"] == "honeypot-wordpot"
    assert plan[0]["id"] == "sync-orphan-wordpot"
    assert plan[0]["projectId"] == "3c5caee1-f8f2-4aff-b1e4-49a7df9c33e7"


def test_live_store_matches_manifest_after_removing_orphan(mod, manifest_entries):
    # This is the acceptance criterion from the issue: after the
    # migration, live rows (37) == manifest entries (37), and the
    # remaining names match exactly.
    manifest_names = mod.manifest_sync_names(MANIFEST_PATH)
    live = _live_syncs_with_orphan(manifest_entries)

    dangling = mod.dangling_sync_names(live, manifest_names)
    live_after = [s for s in live if s["name"] not in dangling]

    assert len(live_after) == 37
    assert len(live_after) == len(manifest_entries)
    assert {s["name"] for s in live_after} == manifest_names


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
