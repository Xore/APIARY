#!/usr/bin/env python3
"""Regression tests for #3215: the offline FMC management-audit contract.

#3215 asks for a normalizer for an authorized Cisco Secure FMC management-audit
export -- principal/role, session, operation, object identifier, result,
timestamp, before/after metadata, plus asset and maintenance context -- and
does so under a hard boundary that is easy to lose the moment a doc stops being
read closely:

  **Requests are not completed changes.** A decoy HTTP log records that a
  request arrived. An appliance's own audit stream is the only thing in this
  fleet that can say an operation *finished*. Collapsing the two is the single
  error that turns a detection index into a false-alarm generator, and it is
  invisible until someone pages an operator about a policy change that never
  happened. #3214 says the same thing from the other side of the boundary: a
  decoy "can log the *request*; only a trusted audit stream from a real
  appliance can establish the *outcome*".

Everything below pins the *document*, because Niklas's call on #3215 was
contract-only: no ingestion pipeline, no normalizer, no connector, no reader of
a live audit stream, no index, no worker. A doc-only change has exactly one
failure mode worth testing -- that the contract quietly stops saying the thing
that made it safe -- and that is what these assertions are for. There is no
behaviour here to assert, so nothing here asserts any.

Each test is named after the property it protects, so deleting one to make a
suite green fails this file, and none of them can be satisfied by a doc that
merely mentions the right words: the field test parses the field table, the
reachability test walks the link, and the out-of-scope test requires a stated
reason beside every excluded class of material.

The `tests/docs/` CI row installs pytest and nothing else (see quality.yml), so
everything below is stdlib plus pytest.
"""
from __future__ import annotations

import pathlib
import re
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC = REPO_ROOT / "docs" / "FMC-MANAGEMENT-AUDIT-CONTRACT.md"
DOC_MAP = REPO_ROOT / "docs" / "README.md"
SENSORS = REPO_ROOT / "docs" / "SENSORS.md"

# The decision doc that owns the *decoy* half of this boundary, delivered on
# its own branch (#3214). Referenced by issue and title, never by repo path:
# that note is not on this branch yet, and a link to a file that does not exist
# here would fail `scripts/check-doc-paths-exist.py` for a reason that has
# nothing to do with this contract. The point of the reference is that this
# contract *defers* to that note's product-identity call rather than restating
# it, because a second, slightly different copy of a product boundary is how the
# two drift apart.
FMC_PERSONA_ISSUE = "#3214"
FMC_PERSONA_TITLE = "inert management persona"

# The fields #3215 names, mapped to the contract's own field paths. The names
# are this contract's, and are deliberately NOT the decoy envelope's -- see
# `test_the_record_does_not_borrow_the_decoy_envelope`.
ISSUE_FIELDS = (
    "principal",
    "session",
    "operation",
    "object",
    "result",
    "timestamp",
    "change",
    "asset",
    "maintenance",
)

# Classes of material the contract must exclude by name, with a reason beside
# each. The issue's own wording is "keep certificate material, private keys,
# passwords and tokens out of routine records"; the contract's job is to say why
# and to say it structurally, not to leave it to a reviewer's memory.
EXCLUDED_MATERIAL = (
    "certificate",
    "private key",
    "password",
    "token",
)


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def _doc() -> str:
    if not DOC.exists():
        pytest.fail(
            f"{DOC.relative_to(REPO_ROOT)} is gone. #3215's deliverable is the "
            "contract itself; without it the issue is unanswered, not just "
            "undocumented."
        )
    return _read(DOC)


def _section(text: str, heading: str) -> str:
    """The body of one `## `/`### ` section, heading-to-next-heading.

    Scoped on purpose: several of the properties below are *section-local* (a
    reason must sit beside the excluded material, not somewhere else in the
    file), and a whole-file substring search cannot tell the difference between
    a contract that says it and one that mentions it once in a footnote.

    Returned with its line structure intact, because the table and clause
    assertions below parse it as lines. Use `_flat()` for phrase checks.
    """
    pattern = re.compile(
        rf"^#+ {re.escape(heading)}\s*$(.*?)(?=^#{{1,6}} |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(text)
    assert match, f"no '{heading}' section in {DOC.name}"
    return match.group(1)


def _flat(text: str) -> str:
    """Whitespace-collapsed, for phrase assertions only.

    These docs are hard-wrapped near 80 columns, so a phrase like "no appliance
    access" is routinely split across a line break. Asserting against the raw
    text would assert that the author happened to break the line in the right
    place, which is a formatting accident and not a contract.
    """
    return re.sub(r"\s+", " ", text)


# ------------------------------------------- the deliverable is a contract ----


def test_the_contract_exists_and_states_it_is_not_an_implementation():
    """The operator's call was contract-only, so the doc has to say so itself.

    A contract that reads like a build plan is how a doc-only issue quietly
    becomes a half-built feature: the next reader takes the field table as a
    description of something that exists and wires it up.
    """
    text = _doc()
    assert text.lstrip().startswith("#"), f"{DOC.name} has no top-level title"
    said = _flat(text).lower()
    assert any(
        phrase in said for phrase in ("no implementation", "not implemented", "doc-only", "doc only")
    ), (
        f"{DOC.name} never says the deliverable is a document and not a build -- a "
        "contract that reads like a build plan is how a doc-only issue becomes a "
        "half-built feature"
    )
    # ...and it must not claim the index, the worker or the connector exists.
    for not_built in ("no normalizer", "no connector", "no index is created"):
        assert not_built in said, (
            f"{DOC.name} does not say '{not_built}' -- a reader needs to be told "
            "which of the issue's nouns are deliberately absent"
        )


def test_the_contract_adds_no_sensor_compose_entry_or_decoy():
    """No new sensor, no compose entry, no decoy, no port publication.

    Checked against the tree rather than against the doc's own account of
    itself: a doc that claims to be doc-only while a stack exists would satisfy
    every prose assertion above.
    """
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.splitlines()

    # No FMC-named file anywhere outside the documentation that describes the
    # contract. `docs/` is excluded by path because that is where this contract
    # and #3214's note live.
    offenders = [
        p
        for p in tracked
        if "fmc" in p.lower() and not p.startswith("docs/") and not p.startswith("tests/")
    ]
    assert not offenders, f"#3215 must not add a sensor or stack: {offenders}"

    # No compose file anywhere may carry an FMC service.
    for name in tracked:
        if not name.endswith((".yml", ".yaml")):
            continue
        body = (REPO_ROOT / name).read_text(encoding="utf-8", errors="replace").lower()
        assert "fmc" not in body, f"{name} mentions FMC -- #3215 adds no compose entry"

    # And the sensor table itself has no FMC row. #3214 already annotated the
    # ASA row's *notes* with the FMC distinction, so this reads the sensor-name
    # cell rather than the whole line.
    table_rows = re.findall(r"^\|\s*\*\*(.+?)\*\*\s*\|", _read(SENSORS), re.MULTILINE)
    assert table_rows, "SENSORS.md's sensor table no longer parses -- check this test"
    for sensor in table_rows:
        assert "fmc" not in sensor.lower(), (
            f"SENSORS.md lists {sensor!r} as a sensor; #3215 adds no sensor"
        )


def test_the_contract_is_reachable_from_the_documentation_map():
    """A contract nobody can find is not a contract.

    `scripts/check-docs-reachable.py` already fails CI on an unreachable doc,
    but it cannot tell *why* a doc exists. This asserts the map names it, which
    is the reader's actual entry point.
    """
    assert DOC.name in _read(DOC_MAP), (
        f"{DOC.name} is not linked from docs/README.md; #3215's contract is "
        "invisible to anyone starting at the documentation map"
    )


# ------------------------------------------------- the shape of the record ----


FIELD_ROW = r"^\|\s*`([a-z_.]+)`\s*\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|"


def _field_rows() -> list[tuple[str, str, str, str, str]]:
    """The field table as (field, type, may carry, never carries, when absent).

    Parsed rather than grepped: a contract that mentions "session" in prose and
    never gives it a type has not specified a shape, and the missing type is
    exactly where a future normalizer would invent one. The five columns are
    the two halves of the boundary (may carry / never carries) plus the null
    policy, which is a third thing and the one #3213 exists to protect.
    """
    rows = re.findall(FIELD_ROW, _section(_doc(), "The normalized record"), re.MULTILINE)
    assert rows, "the normalized-record table no longer parses as a five-column field table"
    return [(name, *(c.strip() for c in rest)) for name, *rest in rows]


def test_every_field_the_issue_names_has_a_specified_shape():
    """All nine groups, each with a type and a stated null policy."""
    rows = _field_rows()
    fields = {name for name, *_ in rows}
    for top in ISSUE_FIELDS:
        matching = {f for f in fields if f.split(".")[0] == top}
        assert matching, (
            f"the issue names {top!r} but the field table specifies no field under "
            f"it (table has: {sorted(fields)})"
        )

    for name, type_cell, _carries, _never, when_absent in rows:
        assert type_cell, f"{name} has no declared type"
        assert when_absent, (
            f"{name} has no stated null policy -- 'absent' and 'unknown' are the "
            "distinction #3213 exists to protect, so each field must say what a "
            "missing value means"
        )


def test_the_field_table_separates_what_a_field_may_carry_from_what_it_may_never_carry():
    """Each field states both halves, and the negative half is a prohibition.

    The "may carry" half is the contract; the "never carries" half is the
    boundary. A table with only the first is how a `before`/`after` blob ends up
    holding a private key nobody reviewed, because the contract described the
    happy path and left the exclusion to whoever wrote the normalizer.
    """
    for name, _type_cell, carries, never_carries, _when_absent in _field_rows():
        assert carries, f"{name} does not say what it may carry"
        assert never_carries, f"{name} states what it carries but not what it may never carry"
        assert never_carries.lower().startswith(("never", "no ")), (
            f"{name}'s negative column is a description, not a prohibition: "
            f"{never_carries!r}"
        )


def test_the_record_does_not_borrow_the_decoy_envelope():
    """Its own namespace, its own index, and no `event.sensor`.

    An audit record is not a sensor event, and reusing `honeypot.*` for it would
    put appliance audit rows inside the decoy stream where the fingerprint
    promotion, the GeoIP pass and the source-health pivots all assume the
    document describes something an attacker touched. The precedent for a
    non-decoy source with its own index and its own allowlist already exists in
    this tree, and the contract cites it rather than inventing a pattern.
    """
    text = _doc()
    shape = _section(text, "The normalized record")
    assert "honeypot." not in shape, (
        "the record is specified in the decoy envelope; an audit export is a "
        "different class of evidence and needs its own namespace"
    )
    assert "event.sensor" in text, (
        "the contract must say what it does with the decoy stream's sensor "
        "discriminator -- silence here is what a later PR would misread as "
        "permission to set it"
    )
    assert "auth-events-worker" in text, (
        "the contract must cite the existing non-decoy source it mirrors "
        "(own index, own allowlist, stable source id as the document id)"
    )


# ------------------------------------------- the three promotions it forbids ----


@pytest.mark.parametrize(
    "invariant, phrase",
    [
        ("requests-only", "requests-only"),
        ("simulated-to-real", "simulated"),
        ("unknown-stays-unknown", "unknown"),
    ],
)
def test_the_three_promotions_the_issue_forbids_are_named_as_invariants(
    invariant, phrase
):
    """Each forbidden promotion is named, and each carries the reason.

    The issue's criteria are not "handle these cases correctly", they are "these
    conversions must not happen". A contract that describes the happy path and
    leaves these three implicit is the version that gets implemented wrong.
    """
    section = _section(_doc(), "Promotions that must never happen")
    flat = _flat(section).lower()
    assert phrase in flat, f"the '{invariant}' promotion is not named"
    assert "never" in flat, "the section does not state the prohibition"


def test_maintenance_context_is_explicit_and_never_a_path_substring():
    """The issue's own criterion: explicit maintenance context, not path matching.

    A scheduled certificate renewal and an unexpected admin creation differ in
    their *declared* context -- a change record, a window, an authorising human
    -- and often not at all in their paths. Inferring one from a substring is
    how a real intrusion gets filed as routine maintenance, which is the worst
    available outcome: silent, plausible, and self-erasing on the next renewal.
    """
    text = _doc()
    section = _section(text, "Maintenance context")
    flat = _flat(section).lower()
    assert "substring" in flat, (
        "the maintenance section must reject substring/path inference explicitly"
    )
    for field in ("maintenance.ticket", "maintenance.window_start"):
        assert field in text, f"{field} is not part of the specified shape"
    assert any(word in flat for word in ("suppress", "hidden", "dropped")), (
        "the section must say a maintenance-flagged record stays in the index -- "
        "suppression as deletion would be a second, undocumented way to lose "
        "evidence"
    )


# ------------------------------------------------------ the excluded material ----


def test_certificate_material_keys_passwords_and_tokens_are_out_of_scope_with_reasons():
    """Named, and each with a stated reason.

    Four classes, four reasons. A bare list of prohibited nouns is not a
    boundary -- it tells a reader what is banned and not why, so the first
    convenient exception ("just the fingerprint") arrives with nothing to push
    back on. The reasons are what make the fingerprint/counter-example below
    decidable rather than arbitrary.
    """
    text = _doc()
    section = _section(text, "Out of scope, explicitly")
    flat = _flat(section).lower()
    for material in EXCLUDED_MATERIAL:
        assert material in flat, f"{material!r} is not excluded by name"

    # Clause boundaries are the numbered markers themselves, not line breaks:
    # these clauses are hard-wrapped, so a per-line split would measure the
    # first line of each reason and call it too short.
    starts = [m.start() for m in re.finditer(r"(?m)^\s*\d+\.\s+", section)]
    clauses = [section[a:b] for a, b in zip(starts, starts[1:] + [len(section)])]
    assert len(clauses) >= len(EXCLUDED_MATERIAL), (
        f"expected at least {len(EXCLUDED_MATERIAL)} numbered exclusion clauses, "
        f"found {len(clauses)}"
    )
    for material in EXCLUDED_MATERIAL:
        clause = next((_flat(c) for c in clauses if material in c.lower()), None)
        assert clause, f"no numbered clause excludes {material!r} with its own reason"
        # A label is not a reason. 25 words is a floor chosen to exclude
        # "Certificate material is out of scope." and to admit a sentence that
        # says why -- the reason is what makes the next boundary case
        # (a fingerprint? a serial? a validity window?) decidable rather than
        # arbitrary.
        assert len(clause.split()) >= 25, (
            f"the clause excluding {material!r} is too short to carry a reason: "
            f"{clause!r}"
        )

    # The boundary has to be structural, because the one field where the leak
    # would land is a free-form before/after blob no value-filter can police.
    assert "allowlist" in flat or "allow list" in flat, (
        "the exclusion must be an allowlist at the mapping level, not a filter "
        "over values -- a value filter cannot tell a truncated PEM from an "
        "opaque token inside vendor-supplied metadata"
    )


# ------------------------------------------- identity, and the honest remainder ----


def test_the_fmc_identity_is_kept_distinct_from_the_asa_persona():
    """FMC is the management console; `cisco-asa-honeypot` is a data-plane decoy.

    #3214 owns that distinction and this contract defers to it rather than
    restating it, because a second, slightly different copy of a product
    boundary is how the two drift. So: the note is cited by issue and title, and
    this doc says what it does *not* touch.
    """
    text = _doc()
    flat = _flat(text)
    assert FMC_PERSONA_ISSUE in flat, (
        f"the contract must cite {FMC_PERSONA_ISSUE}; FMC-vs-ASA is that issue's "
        "decision and duplicating it invites the two to disagree"
    )
    assert FMC_PERSONA_TITLE in flat, (
        f"the contract must name the {FMC_PERSONA_TITLE!r} note it defers to, so a "
        "reader can find the decision being cited"
    )
    identity = _flat(_section(text, "FMC is not the ASA persona")).lower()
    assert "cisco-asa-honeypot" in identity, (
        "the identity section must name the sensor it must not borrow"
    )
    assert "3214" in identity, "the identity section must attribute the decision"
    for untouched in ("persona", "sensor"):
        assert untouched in identity, (
            f"the identity section must say the existing {untouched} stays as it is"
        )
    # No CVE-named operation, and no vendor-default-credential claim: #3214's
    # P-5 and F-3 carry over to any record that mentions the product.
    for claim in ("cisco123", "admin/cisco", "CVE-2026-20079", "CVE-2026-20131"):
        assert claim not in text, (
            f"{claim!r} is a vendor claim this fleet has explicitly declined to "
            "make; a normalization contract has no reason to introduce one"
        )


def test_the_source_dependent_half_is_left_open_rather_than_invented():
    """#3215 is blocked on an authorized export, and the doc must not pretend.

    The honest move, and the one the issue's own disposition demands, is to
    specify the target shape and the invariants that hold regardless of what an
    export looks like, then name each source-dependent question with the
    evidence that would settle it. Writing plausible field names for a source
    nobody has read is how a contract becomes fiction -- and a reader cannot
    tell fiction from specification once it is in a table.
    """
    text = _doc()
    section = _section(text, "Not specified, and why")
    flat = _flat(section).lower()
    assert "blocked" in flat or "no authorized" in flat, (
        "the open section must record that #3215 is blocked on an authorized source"
    )
    # Each open item names the artefact that would resolve it.
    rows = re.findall(r"^\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|$", section, re.MULTILINE)
    open_rows = [r for r in rows if len(r[0]) > 3 and not r[0].startswith("---")]
    assert len(open_rows) >= 3, (
        "the open section needs at least three named questions with their "
        f"resolving evidence, found {len(open_rows)}"
    )
    for question, why, evidence in open_rows:
        assert why.strip(), f"open question {question!r} has no reason it is open"
        assert evidence.strip(), (
            f"open question {question!r} does not say what evidence would settle it"
        )

    # And the most load-bearing one is timestamp semantics: ordering, dedupe and
    # correlation all rest on it, so it cannot be quietly omitted.
    assert "timestamp" in flat, (
        "timestamp semantics are the question the whole contract leans on and "
        "must appear in the open list"
    )


def test_a_negative_verdict_stays_acceptable_and_no_build_is_pre_committed():
    """The doc must not argue for a build, and must not pre-commit to one.

    #3215's disposition is explicitly conditional, so a contract that quietly
    reads as "therefore we should build this" has overstepped what was
    authorized -- and would be the strongest argument anyone has for building it
    on the strength of a document that was never meant to be one.
    """
    text = _doc().lower()
    assert "negative verdict" in text or "negative outcome" in text, (
        "the contract must record that not building it remains an acceptable outcome"
    )
    assert "recommend" in text, (
        "the contract must be explicit about its own recommendation (or the "
        "absence of one) rather than leaving it to be inferred from tone"
    )
    for verdict in ("we should build", "next step is to build", "will be built"):
        assert verdict not in text, (
            f"{verdict!r} pre-commits to a build #3215 does not authorize"
        )


def test_the_acceptance_criteria_are_offline_and_fixture_only():
    """Any future implementation is gated on inert fixtures and no access.

    The issue authorizes none of exploitation, credentials, appliance access or
    deployment, and says tracking the proposal does not authorize obtaining
    access. The criteria are therefore the last line of defence: they have to
    say the proof is synthetic, because a criteria list that merely says
    "offline" still reads as permission to point a connector at a real box.
    """
    text = _doc()
    section = _section(text, "Acceptance criteria for any future implementation")
    flat = _flat(section).lower()
    for required in ("offline", "fixture", "no appliance access"):
        assert required in flat, (
            f"the acceptance criteria must state {required!r} -- the issue "
            "authorizes no exploitation, credentials, appliance access or deployment"
        )
    for forbidden in ("exploitation", "credential", "deployment"):
        assert forbidden in flat, (
            f"the acceptance criteria must name {forbidden!r} as out of bounds"
        )


def test_the_example_records_use_the_fleets_own_fictional_identifiers():
    """Examples are `nexusai-*` / TEST-NET, never a real customer's.

    `docs/personas/README.md` already forbids real organizations, cloned sites
    and real customer data. An audit contract is exactly the shape of document
    that invites pasting in a real hostname while illustrating a field, and a
    realistic-looking example is the most likely place for one to land.
    """
    text = _doc()
    assert "nexusai" in text.lower(), (
        "the worked examples should use this fleet's own fictional organization"
    )
    for material in EXCLUDED_MATERIAL:
        # No PEM header, no key block, no bearer-looking literal.
        assert "BEGIN " not in text, "no PEM/banner material belongs in an example"
        assert material in text.lower(), (
            f"{material!r} is discussed as excluded; the examples must not "
            "quietly reintroduce it"
        )
    for real_shape in (r"\b(?:\d{1,3}\.){3}\d{1,3}\b",):
        for match in re.findall(real_shape, text):
            octets = [int(o) for o in match.split(".")]
            assert octets[0] == 203 and octets[1] == 0 and octets[2] == 113, (
                f"{match} is a literal address in the contract; use the RFC 5737 "
                "TEST-NET-3 placeholder or a persona name, never a real one"
            )
