#!/usr/bin/env python3
"""Regression test for #2532: five FLARE-VM mentions in
docs/sandbox/windows/IMPLEMENTATION_PLAN.md and docs/windows11-malware-lab-hardening.md
still advertised FLARE-VM as a live component of the golden image, even though
sandbox/windows/packer/win11-analysis.pkr.hcl removed it on 2026-08-02 (#2451/PR #2531
fixed a different, earlier batch of stale references in the same two files).

WHAT THIS TEST ASSERTS, AND WHY IT IS SHAPED THIS WAY

A blanket "no FLARE-VM string anywhere under docs/sandbox/windows/" check is wrong on
two counts:

  * IMPLEMENTATION_PLAN.md deliberately keeps two historical mentions (the
    "no multi-hour FLARE-VM install anymore" build-time note and the "FLARE-VM was
    part of this chain through 2026-08-02" removal note) -- those describe their own
    history honestly and #2532 explicitly leaves them alone.
  * docs/sandbox/windows/packer-golden-image-guide.md predates the 2026-08-02 removal
    and was never updated; its FLARE-VM mentions are real staleness but are a separate,
    much larger problem outside this issue's five call-outs.

So this test targets exactly the five spots #2532 named, plus a blanket check on
windows11-malware-lab-hardening.md (whose only three FLARE-VM mentions were all part
of the five, so it should end up with zero).
"""
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
IMPLEMENTATION_PLAN = REPO_ROOT / "docs" / "sandbox" / "windows" / "IMPLEMENTATION_PLAN.md"
HARDENING_DOC = REPO_ROOT / "docs" / "windows11-malware-lab-hardening.md"


def test_implementation_plan_mermaid_drops_flare_node():
    text = IMPLEMENTATION_PLAN.read_text(encoding="utf-8")
    assert 'Flare["FLARE-VM tools"]' not in text, (
        "IMPLEMENTATION_PLAN.md's guest-topology mermaid diagram still has a "
        "FLARE-VM node; the detonation guest does not contain that tooling (#2532)."
    )


def test_implementation_plan_tool_summary_drops_flare_row():
    text = IMPLEMENTATION_PLAN.read_text(encoding="utf-8")
    assert "FLARE-VM (mandiant)" not in text, (
        "IMPLEMENTATION_PLAN.md's Tool Summary table still lists FLARE-VM as a "
        "component; it was removed from the build on 2026-08-02 (#2532)."
    )


def test_implementation_plan_keeps_its_intentional_history_notes():
    """The two mentions #2532 explicitly leaves alone must still be present.

    A future overzealous cleanup could delete these along with the stale ones;
    they are honest history, not advertising, and removing them would just
    delete a reader's ability to find out where FLARE-VM went.
    """
    text = IMPLEMENTATION_PLAN.read_text(encoding="utf-8")
    assert "no multi-hour FLARE-VM install anymore" in text
    assert "FLARE-VM was part of this chain through 2026-08-02" in text


def test_hardening_doc_has_no_flare_vm_mentions():
    """All three FLARE-VM mentions in this file were stale; none are historical notes."""
    text = HARDENING_DOC.read_text(encoding="utf-8")
    assert "FLARE-VM" not in text, (
        "docs/windows11-malware-lab-hardening.md still mentions FLARE-VM. This file's "
        "only FLARE-VM references (the phase table row, the DNS/Dnscache pitfall, and "
        "the Mandiant reference link) all described a component the image no longer "
        "installs and were removed for #2532; if this fires, a new mention needs the "
        "same treatment rather than being reintroduced."
    )


def test_hardening_doc_phase_table_attributes_tools_to_04_tools_ps1():
    """The replacement row must point at the file that actually runs these phases.

    #2532's second defect: the old row said "same" (meaning 01-hardening.ps1) for
    phases 7-12, but phases 8-12 are in 04-tools.ps1. This pins the fix down to a
    real file reference instead of just checking FLARE-VM's absence.
    """
    text = HARDENING_DOC.read_text(encoding="utf-8")
    assert "`packer/scripts/04-tools.ps1` phases 8" in text, (
        "docs/windows11-malware-lab-hardening.md's phase table no longer attributes "
        "phases 8-12 to `04-tools.ps1`; per docs/sandbox/windows/IMPLEMENTATION_PLAN.md "
        "those phases (Sysmon, PS logging, FakeNet-NG, QEMU guest agent) live in "
        "04-tools.ps1, not 01-hardening.ps1 (#2532)."
    )


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
