#!/usr/bin/env python3
"""Regression test for #2573: dashboard-next /reports settled-body gates
were truthiness-only.

reports.tsx pulls `definitions` out of the settled fetchDefinitions() body
(`const next = result?.definitions`) in two places: the loader's initial
`.then()` handler and refreshDefinitions(). `serviceJSON()`
(lib/backend.server.ts) does a bare `(await response.json()) as T` with no
runtime shape check, so `next` is only guaranteed to be
`ReportDefinition[]` at the type level -- at runtime it can be any JSON
value the backend or a misroute happens to send back.

Both gates used to test only `if (!next)`, which is truthy for any
non-empty, non-array JSON value (an object, a non-empty string, a number).
Such a value would flow into setDefinitions() and then into
`definitions.map(...)` / `definitions.length` / `next.some(...)`, none of
which exist on a plain object or a string -- a client-render crash on
/reports, the same failure mode #2178 already fixed for the `undefined`
case but left open for any other non-array truthy shape.

The fix changes both gates to `if (!Array.isArray(next))`, which rejects
null/undefined *and* every non-array truthy shape while still accepting a
real (possibly empty) ReportDefinition[] array.
"""
import pathlib
import re
import sys

import pytest

REPORTS_ROUTE = (
    pathlib.Path(__file__).resolve().parents[2]
    / "arcane"
    / "home"
    / "honeypot-dashboard"
    / "frontend-next"
    / "src"
    / "routes"
    / "reports.tsx"
)

# Both gate sites extract the settled body the same way. Anchoring on this
# exact assignment (rather than a loose "next" search) means the test finds
# the real gate sites even if unrelated code elsewhere in the file also
# happens to use a variable named `next`.
DEFINITIONS_EXTRACTION = "const next = result?.definitions"

# The bug: a gate that only rejects falsy values, not non-array shapes.
BARE_TRUTHY_GATE_RE = re.compile(r"if\s*\(\s*!\s*next\s*\)")

# The fix: a gate that rejects anything that isn't actually an array.
ARRAY_SHAPE_GATE = "if (!Array.isArray(next))"


def test_reports_route_exists():
    assert REPORTS_ROUTE.exists(), f"reports.tsx not found at {REPORTS_ROUTE}"


def test_definitions_settled_body_is_extracted_in_two_places():
    text = REPORTS_ROUTE.read_text(encoding="utf-8")
    occurrences = text.count(DEFINITIONS_EXTRACTION)
    assert occurrences == 2, (
        f"expected the settled-body extraction {DEFINITIONS_EXTRACTION!r} in "
        f"exactly 2 places (the loader effect and refreshDefinitions), found "
        f"{occurrences} -- has one of the gate sites moved or been removed?"
    )


def test_both_definitions_gates_check_array_shape():
    text = REPORTS_ROUTE.read_text(encoding="utf-8")
    occurrences = text.count(ARRAY_SHAPE_GATE)
    assert occurrences == 2, (
        f"expected {ARRAY_SHAPE_GATE!r} to guard both settled-body gates "
        f"(2 occurrences), found {occurrences} -- a non-array truthy "
        "`definitions` body (an object, a string, ...) will reach "
        "setDefinitions() and crash on .map()/.length/.some()"
    )


def test_no_bare_truthiness_only_gate_regression():
    text = REPORTS_ROUTE.read_text(encoding="utf-8")
    matches = BARE_TRUTHY_GATE_RE.findall(text)
    assert not matches, (
        f"{REPORTS_ROUTE} regressed to a truthiness-only gate ({matches!r}) "
        "-- a non-array truthy `definitions` body would pass this check "
        "incorrectly (see #2573); the gate must use Array.isArray(next)"
    )


def _gate_follows_extraction(text: str, extraction_index: int) -> bool:
    """The Array.isArray gate for a given extraction site must appear
    within the next couple of statements, not just anywhere in the file --
    otherwise this test could pass with the real gate left unfixed and an
    unrelated Array.isArray call elsewhere satisfying the count check."""
    window = text[extraction_index : extraction_index + 200]
    return ARRAY_SHAPE_GATE in window


def test_array_shape_gate_immediately_follows_each_extraction():
    text = REPORTS_ROUTE.read_text(encoding="utf-8")
    sites = [m.start() for m in re.finditer(re.escape(DEFINITIONS_EXTRACTION), text)]
    assert len(sites) == 2, "expected exactly 2 extraction sites (see other test)"
    for index in sites:
        assert _gate_follows_extraction(text, index), (
            f"settled-body extraction at offset {index} is not immediately "
            f"followed by {ARRAY_SHAPE_GATE!r} -- the array-shape check must "
            "gate the same `next` it extracts, not merely exist somewhere "
            "else in the file"
        )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
