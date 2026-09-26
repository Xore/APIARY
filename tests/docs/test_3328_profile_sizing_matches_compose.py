#!/usr/bin/env python3
"""Regression test for #3328: the per-role sizing table in
docs/deploy-profiles/README.md must keep matching the compose files it claims
to summarise, and the measured figures it cites must still be present in the
docs they were measured in.

Two different failure modes, two different checks:

1. A *declared* total (sum of `deploy.resources.limits`) is reproducible from
   the tree, so a hand-copied number in the doc is strictly worse than a
   generated one -- it goes stale silently the next time a stack's limit moves.
   tests/docs/test_2849_router_canary_reuse.py and
   test_arcane_git_sync_doc_issue_2552.py already hold other docs to recomputed
   numbers for the same reason. This test recomputes every row through
   scripts/deploy-profile-sizing.py and requires the doc's rows to match it
   exactly, in both directions: a missing row fails, and so does a leftover row
   the compose files no longer produce.

2. A *measured* figure cannot be recomputed -- the hosts are not here -- but it
   can be provenance-checked. Every one the doc quotes has to still exist,
   verbatim, in the doc it was measured in, so "measured 2026-09-05" cannot
   quietly become a claim about a box that has since been re-imaged. This is
   the doc-text regression style #2576 uses: it pins the claim to its source
   rather than pretending to re-measure anything.
"""
from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DOC_PATH = REPO_ROOT / "docs" / "deploy-profiles" / "README.md"
SIZING_SCRIPT = REPO_ROOT / "scripts" / "deploy-profile-sizing.py"

# Only rows that name their subject in backticks belong to the generated
# sizing table; the "## Profiles" table above links with [`full.txt`](...)
# instead, and the measured-host tables further up name paths and mounts
# (`` | `/var` | ... ``), so the comparison is scoped to the one section
# scripts/deploy-profile-sizing.py --format md actually generates.
ROW = re.compile(r"^\|\s*`[^`]+`.*\|\s*$", re.MULTILINE)


def _load_sizing_module():
    spec = importlib.util.spec_from_file_location("deploy_profile_sizing", SIZING_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sizing_section() -> str:
    text = DOC_PATH.read_text(encoding="utf-8")
    start = text.index("## Sizing, per host role")
    rest = text[start + 1 :]
    end = rest.find("\n## ")
    return rest[:end] if end != -1 else rest


def _generated_table_section() -> str:
    """The "### Declared ceilings, per profile" subsection -- the only part of
    the doc this script is expected to have written."""
    section = _sizing_section()
    start = section.index("### Declared ceilings, per profile")
    rest = section[start + 1 :]
    end = rest.find("\n### ")
    return rest[:end] if end != -1 else rest


def _doc_rows() -> set[str]:
    return {line.strip() for line in ROW.findall(_generated_table_section())}


def test_script_and_doc_exist():
    assert SIZING_SCRIPT.exists(), f"missing sizing script at {SIZING_SCRIPT}"
    assert DOC_PATH.exists(), f"missing doc at {DOC_PATH}"


def test_doc_rows_match_the_compose_files():
    """The generated rows and the doc's rows are the same set."""
    sizing = _load_sizing_module()
    profiles = [
        sizing.profile_totals(p) for p in sorted((REPO_ROOT / "deploy-profiles").glob("*.txt"))
    ]
    vps = {"totals": sizing.role_totals(sizing.service_limits(sizing.VPS_COMPOSE))}
    generated = {line.strip() for line in sizing.report_markdown(profiles, vps).splitlines()}

    documented = _doc_rows()
    assert documented, (
        f"no backticked table rows found in {DOC_PATH}'s sizing section -- "
        "has the table been restructured?"
    )
    assert generated == documented, (
        f"{DOC_PATH}'s sizing table does not match the compose files.\n"
        f"  computed but not documented: {sorted(generated - documented)}\n"
        f"  documented but not computed: {sorted(documented - generated)}\n"
        "Regenerate with: scripts/deploy-profile-sizing.py --format md"
    )


def test_every_profile_has_a_row():
    """A new deploy-profiles/*.txt must get its own row, or the table is
    quietly incomplete -- the previous test cannot see a profile that was never
    documented."""
    sizing = _load_sizing_module()
    documented = _doc_rows()
    for profile in sorted((REPO_ROOT / "deploy-profiles").glob("*.txt")):
        assert any(f"`{profile.name}`" in row for row in documented), (
            f"{profile.name} has no row in {DOC_PATH}'s sizing table"
        )


def test_vps_role_row_is_present_and_marks_its_unlimited_services():
    """The VPS row is the one most likely to be read as a complete answer: 30
    of its 50 services declare no limit at all. It must be there, and it must
    keep reporting that gap rather than quietly dropping it."""
    sizing = _load_sizing_module()
    totals = sizing.role_totals(sizing.service_limits(sizing.VPS_COMPOSE))
    row = [r for r in _doc_rows() if r.startswith("| `vps/`")]
    assert len(row) == 1, f"expected exactly one `vps/` row, found {row}"
    undeclared = str(len(totals["undeclared"]))
    assert row[0].rstrip("|").split("|")[-1].strip() == undeclared, (
        f"the VPS row reports {row[0].rstrip('|').split('|')[-1].strip()} services "
        f"without declared limits, but vps/docker-compose.yml has {undeclared}"
    )


def test_vps_ram_is_still_declared_unmeasured():
    """The VPS's RAM is the one figure nobody has recorded. It is tempting to
    fill the cell in from the declared 4.4 GiB sum, which is a floor over 50
    services of which 30 declare nothing -- not a measurement. If a real
    measurement is ever recorded this assertion is what has to be updated in
    the same commit."""
    section = _sizing_section()
    assert "not measured anywhere in this repo" in section, (
        f"{DOC_PATH}'s sizing section no longer says the VPS's RAM is "
        "unmeasured -- if it has now been measured, record the source and "
        "command here rather than deleting the caveat"
    )


MEASUREMENTS = [
    # (substring that must still exist in the source doc, source doc)
    ("Xeon **Gold 5220R**, 24c/48t", "docs/benchmarks/plans/2026-09-05-1947-resume-plan.md"),
    ("93 G, 6×16 GiB", "docs/benchmarks/plans/2026-09-05-1947-resume-plan.md"),
    ("load average on the homeserver was", "docs/benchmarks/plans/2026-09-05-1947-resume-plan.md"),
    ("8G swapfile", "docs/HOMESERVER-DISK-LAYOUT.md"),
    ("Samsung MZVLW256HEHP", "docs/HOMESERVER-DISK-LAYOUT.md"),
    ("96% full", "scripts/disk-usage-watch.py"),
    ("179GB of buildkit cache", "scripts/disk-usage-watch.py"),
    ("93% (131G free of 1.8T) as of 2026-08-31", "scripts/install-homeserver.sh"),
    ("245.8 GB in container", "docs/container-writable-layer-audit-2026-09-03.md"),
    ("20475 MiB", "docs/gpu-llm-analysis-worker.md"),
    ("The VPS has 2 cores", "vps/docker-compose.yml"),
    ("116 GB VPS", "vps/docker-compose.yml"),
    ("4.4 GB and climbing", "docs/vps/suricata/README.md"),
    ("OOM-kills Suricata against its current 768M", "vps/docker-compose.yml"),
    ("256M OOM-killed this container repeatedly", "arcane/home/honeypot-dashboard/compose.yml"),
    ("OOM-looped on every", "arcane/home/honeypot-payload-analysis/compose.yml"),
]


@pytest.mark.parametrize("needle,source", MEASUREMENTS, ids=[s for _, s in MEASUREMENTS])
def test_measured_claims_still_exist_in_their_source(needle: str, source: str):
    """Every measured number the sizing section quotes must still be findable
    in the doc it was measured in, so the citation cannot rot into folklore."""
    path = REPO_ROOT / source
    assert path.exists(), f"cited source {source} does not exist"
    assert needle in path.read_text(encoding="utf-8"), (
        f"{DOC_PATH}'s sizing section cites {source} for {needle!r}, but that "
        f"text is no longer there -- re-measure, or correct the doc and this "
        "test together"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
