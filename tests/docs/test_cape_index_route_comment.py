"""Regression test for #2554.

The /cape index route's header comment used to describe the page as an
empty stub pending the CAPE host worker (#1612, closed 2026-08-18). The
component has implemented a full StoreListPage over cape-analysis-v1 since
before that closure; this pins the comment to present-tense wiring so it
cannot drift back to describing a future state that already arrived.
"""
from pathlib import Path
import re

CAPE_INDEX_ROUTE = (
    Path(__file__).resolve().parents[2]
    / "arcane"
    / "home"
    / "honeypot-dashboard"
    / "frontend-next"
    / "src"
    / "routes"
    / "cape.index.tsx"
)


def _header_comment() -> str:
    lines = CAPE_INDEX_ROUTE.read_text(encoding="utf-8").splitlines()
    # Lines 5-6 (1-indexed) are the route's CAPE description comment, right
    # after the #2127 .index-leaf rationale block and before the imports.
    return "\n".join(lines[4:6])


def test_cape_index_comment_drops_empty_until_wording():
    assert re.search(r"Empty until", _header_comment()) is None


def test_cape_index_comment_drops_submissions_land_with_wording():
    assert re.search(r"submissions land with", _header_comment()) is None


def test_cape_index_comment_describes_current_store_wiring():
    assert "cape-analysis-v1" in _header_comment()
