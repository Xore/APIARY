#!/usr/bin/env python3
"""Regression test for #3450: a browser-origin PDF event is known-origin.

The canarytoken live-fire audit had no list of origins it accepts, so every
`adobe_pdf` event whose client nobody could name was escalated as an
anomaly -- and each escalation re-derived the same wrong conclusion from the
same observation: "no Adobe/Foxit-class reader is installed here, so this
event is unexplained". Three review passes went that way before the premise
was found to be false. Niklas' recollection on 2026-09-28 (#3450, closing
#2136's reader link) is that the 2026-08-17 PDF fire was opened by a
browser's built-in PDF viewer, and browser-class viewers deliberately do not
execute embedded JavaScript and never open the tracking URL.

Nothing in code classifies an event's origin -- traced and confirmed: the
adapter (canarytokens-adapter/main.go) copies `src_data` through verbatim,
the http-router (canarytokens-http-router/main.go) snapshots the user agent
only to forward it in the alert payload, the dashboard backend
(canarytokens.rs) mints and lists tokens without a verdict, and the
frontend route renders the fired-token table with no classification. The
"unexplained" verdict is produced by a human reading the procedure, so the
procedure is where the correction has to live -- and it is procedure prose,
which is exactly the kind of claim this repo's other tests/docs gates exist to
keep from rotting back into a wrong version of itself (cf. #2826, whose
exemptions asserted a mechanism nothing checked).

So this pins the claims, not an implementation:

1. the audit has a known-origin list, and browser built-in PDF viewers
   (Chrome/Edge/Firefox) are on it as never-a-finding;
2. the procedure states the reason -- a browser-class viewer cannot open the
   tracking URL, so an unresolvable PDF event with a browser origin is
   expected behaviour, not a finding;
3. the escalation rule is stated the other way round too: only an origin
   *outside* the list is an unexplained event;
4. the retired "no real reader => unexplained" gate is gone, and named as
   retired rather than merely deleted;
5. the 2026-08-17 event's origin is recorded as a browser-class viewer by
   recollection, and nothing claims that event was re-observed -- #3450's
   third residual item is that no re-run is required or possible, so a doc
   edit must not quietly become one.
"""
import pathlib
import re
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKLIST = REPO_ROOT / "docs" / "canarytoken-live-fire-checklist.md"

# The three viewers #3450 actually established. Deliberately not a broader
# "browser-ish" set: adding a viewer is a claim about a client, and this list
# is what is known, not what is plausible.
BROWSER_VIEWERS = ("Chrome", "Edge", "Firefox")

# The gate #3450 retired, in the words this file used before it. Each one
# re-escalates a browser-origin PDF event, so each one must not come back.
RETIRED_GATE = (
    "do not treat a PDF row as passing until someone fills it in from a real reader",
    "what opened it is unknown",
    "triggering client is unknown",
    "its client-used column stays blank",
    "the real-reader test this checklist asks for has still not been run",
)


def _text() -> str:
    return CHECKLIST.read_text(encoding="utf-8")


def _flat(text: str) -> str:
    """Whitespace-collapsed text, so a claim is matched across line wraps.

    The checklist is hard-wrapped, so "never resolves" is really "never\\nresolves"
    in the file. Collapsing also makes the *negative* checks below stronger: a
    retired gate cannot hide from them by straddling a line break.
    """
    return re.sub(r"\s+", " ", text)


def _section(heading: str) -> str:
    """The body of one ATX heading, up to the next heading of any level.

    Pinned to the checklist's own ``## Known origins`` spelling so a rename
    that drops the classification fails loudly here rather than silently
    leaving the audit without a list.
    """
    lines = _text().splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == heading:
            start = index
            break
    assert start is not None, f"{heading!r} is gone from {CHECKLIST.name}"
    body = []
    for line in lines[start + 1:]:
        if line.startswith("#"):
            break
        body.append(line)
    return "\n".join(body)


def _flat_section(heading: str) -> str:
    """A section's body with its line wraps collapsed -- for prose claims."""
    return _flat(_section(heading))


def test_the_audit_has_a_known_origin_list():
    section = _section("## Known origins")
    assert "#3450" in section, (
        "the known-origin list must cite the issue that established it, or a "
        "later reader cannot tell an evidence-backed list from an invented one"
    )
    # The list has to be a list: a headed section whose origin rows are
    # markdown table rows, not prose that happens to mention browsers.
    rows = [line for line in section.splitlines()
            if line.startswith("| Browser built-in PDF viewer")]
    assert len(rows) == 1, (
        "the browser built-in viewer must be one row of the known-origin "
        f"table, so it is classified rather than merely mentioned; found {rows!r}"
    )


def test_browser_built_in_viewers_are_known_origin_and_never_a_finding():
    row = next(line for line in _section("## Known origins").splitlines()
               if line.startswith("| Browser built-in PDF viewer"))
    cells = [cell.strip() for cell in row.strip("|").split("|")]
    verdict = cells[-1]
    assert len(cells) == 3, f"known-origin row lost a column: {cells!r}"
    for viewer in BROWSER_VIEWERS:
        assert viewer in row, f"{viewer} is missing from the known-origin row: {row!r}"
    assert re.search(r"known-origin", verdict, re.I), verdict
    assert re.search(r"never a finding|not a finding", verdict, re.I), (
        f"the browser origin's verdict must say it is not a finding, got {verdict!r}"
    )


def test_the_tracking_url_rule_is_stated_as_expected_behaviour():
    section = _flat_section("## Known origins")
    assert re.search(r"do(?:es)? not (?:execute|open)", section, re.I), (
        "the procedure must say a browser-class viewer does not execute "
        "embedded JavaScript -- that is the mechanism behind the rule"
    )
    assert re.search(r"tracking URL", section), (
        "the rule has to name the tracking URL, or 'will not fire' reads as a "
        "vague claim about PDF viewers generally"
    )
    assert re.search(r"expected behaviour, not a finding", section, re.I), (
        "the exact verdict #3450 asks for -- an unresolvable PDF event with a "
        "browser origin is expected behaviour, not a finding -- must be "
        "stated in those terms"
    )
    # ...and stated for the unresolvable case specifically, not just in the
    # abstract: "never a finding" alone would also cover a browser that did
    # resolve, which is a different claim.
    assert re.search(r"never resolves", section), (
        "the rule must be stated for the event that never resolves -- that is "
        "the case a future audit will hit"
    )


def test_only_an_origin_outside_the_list_is_unexplained():
    text = _flat(_text())
    assert re.search(
        r"escalated as unexplained when its origin is not on this list", text
    ), (
        "the escalation rule is the load-bearing half of #3450: an origin on "
        "the list is an explanation, so only an origin off it is unexplained"
    )
    assert re.search(
        r"does not mean [\"']unexplained[\"']", text
    ), (
        "the client-used column being blank must be stated as 'not observed', "
        "not as 'unexplained' -- that conflation is what re-escalated rows"
    )


def test_the_retired_missing_reader_gate_is_gone():
    # Both sides folded: a gate that reappears with different capitalisation
    # (or straddling a line wrap) is the same retired gate, not a new one.
    haystack = _flat(_text()).lower()
    for gate in RETIRED_GATE:
        folded = _flat(gate).lower()
        assert folded not in haystack, (
            f"the retired gate {gate!r} is back in the checklist; #3450 "
            "established its premise false, so it must not re-escalate "
            "browser-origin PDF events"
        )


def test_the_retired_inference_is_named_rather_than_silently_dropped():
    # Deleting the wrong rule is not enough: an auditor who remembers the old
    # text has to be able to find out that it was retired, and why, without
    # opening the issue.
    section = _flat_section("## Known origins")
    assert re.search(r"retired", section, re.I), (
        "the known-origin section must name the retirement explicitly"
    )
    assert re.search(r"false", section, re.I), (
        "it must say the retired premise is known false, not merely that the "
        "old wording is gone"
    )
    assert re.search(r"no Adobe/Foxit-class reader", section), (
        "the retired inference must be quoted in the procedure, so the next "
        "auditor recognises the conclusion they are about to re-derive"
    )


def test_the_2026_08_17_origin_is_recorded_as_a_recollection():
    text = _flat(_text())
    assert re.search(r"origin:.*browser built-in PDF viewer", text), (
        "the 2026-08-17 event's record must carry its origin, or the audit "
        "still has a blank to fill and will re-ask the question"
    )
    assert re.search(r"origin:.*(?:recalled|recollection)", text), (
        "that origin is a recollection, not an observation, and must be "
        "labelled as one -- #3450 resolves the event without a re-run, so the "
        "doc must not dress it up as a fresh measurement"
    )
    assert re.search(r"reader-class client is recorded as ever having resolved", text), (
        "the residual gap must be stated as 'no reader-class client is on "
        "record', which is the honest and permanent form of it, rather than "
        "as the old 'which client opened it' question"
    )


def test_nothing_claims_the_2026_08_17_event_was_re_observed():
    # #3450 item 3: no re-run is required or possible. A future lane must not
    # satisfy the "real reader" question by re-running the historical event,
    # so the procedure has to say the origin stands without one.
    text = _flat(_text())
    assert re.search(r"not by re-running the event|not re-run and cannot", text), (
        "the procedure must state that the origin was established without "
        "re-running the 2026-08-17 event"
    )
    for claim in ("re-ran the 2026-08-17", "re-run of the 2026-08-17",
                  "re-verified the origin"):
        assert claim not in text, (
            f"{claim!r} would claim a re-run #3450 says is neither required "
            "nor possible"
        )


def test_the_known_origin_table_is_well_formed():
    rows = [line for line in _section("## Known origins").splitlines()
            if line.startswith("|")]
    assert len(rows) >= 4, (
        f"known-origin table lost rows: {rows!r} -- every accepted origin "
        "class needs a row, or the list is a partial one that reads as complete"
    )
    for row in rows:
        cells = row.strip().strip("|").split("|")
        assert len(cells) == 3, f"row is not origin/recognise-as/verdict: {row!r}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
