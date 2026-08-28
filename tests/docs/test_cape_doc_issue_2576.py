#!/usr/bin/env python3
"""Regression test for #2576: CAPE detail page is service-token gated, not admin-gated.

Asserts docs/sandbox/cape/IMPLEMENTATION_PLAN.md describes the real access
control on /cape/{sha256}: the page itself sits behind normal session auth,
and the backing /api/v1/cape/{sha} call carries the same require_service_token
middleware as every other /api/v1 detail route -- not a nonexistent admin/role
check on that path (a real admin-role requirement does exist elsewhere, on
the Workbench "cape" analyzer entry that triggers a detonation, which is a
different gate from viewing an existing result).
"""
import pathlib
import re
import sys

import pytest

DOC_PATH = pathlib.Path(__file__).resolve().parents[2] / "docs" / "sandbox" / "cape" / "IMPLEMENTATION_PLAN.md"

# Catches "admin-gated", "admin gated", "admin-only", "admin-restricted" and
# reflowed/adjacent variants -- not just the one exact phrase this doc used
# to carry, which a rewrap or a synonym swap would slip past a plain
# substring check.
ADMIN_GATE_RE = re.compile(r"admin[-\s]?(gated|only|restricted)", re.IGNORECASE)

# The wiring table's "Detail page" row is the one place this doc describes
# /cape/{sha256}'s access control; anchoring the positive assertion to that
# exact row (rather than searching the whole file for a loose phrase) means
# deleting or gutting the row fails the test instead of passing it by
# accident.
DETAIL_ROW_RE = re.compile(r"^\|\s*Detail page\s*\|", re.IGNORECASE)

EXPECTED_PHRASE = "service-token gated"


def test_doc_path_exists():
    assert DOC_PATH.exists(), f"CAPE implementation plan doc not found at {DOC_PATH}"


def test_cape_doc_does_not_mention_admin_gated():
    text = DOC_PATH.read_text(encoding="utf-8")
    matches = ADMIN_GATE_RE.findall(text)
    assert not matches, (
        f"{DOC_PATH} still claims an admin/role gate on the CAPE detail "
        f"route ({matches!r}) that doesn't exist -- see require_service_token "
        "in backend-service/src/main.rs"
    )


def test_cape_doc_describes_service_token_gated_for_cape():
    lines = DOC_PATH.read_text(encoding="utf-8").splitlines()
    detail_rows = [line for line in lines if DETAIL_ROW_RE.match(line)]
    assert detail_rows, (
        f"no wiring-table 'Detail page' row found in {DOC_PATH} -- "
        "has the table been restructured?"
    )
    assert len(detail_rows) == 1, (
        f"expected exactly one 'Detail page' row in {DOC_PATH}, found {len(detail_rows)}"
    )
    row = detail_rows[0]
    assert "cape" in row.lower(), f"'Detail page' row no longer mentions CAPE: {row!r}"
    assert EXPECTED_PHRASE in row, (
        f"'Detail page' row does not describe it as {EXPECTED_PHRASE!r}: {row!r}"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
