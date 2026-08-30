#!/usr/bin/env python3
"""Regression test for #2212 (a #2189/#2202 sibling): stale file_identity
prose survived in two places after Filebeat 9 made `fingerprint` the
default filestream identity scheme instead of inode/device --
vps/suricata/suricata.yaml's eve-log comment and the module doc comment in
backend-service/src/ip_enrichment/rotate.rs both still justified rotation
safety with the pre-FB9 "FB9_pre_default_identity_phrase,
not path)" claim, the same claim #2202 already corrected in
analysis/filebeat.yml's suricata-eve input comment.

Also: the honeypot-json and dionaea-incidents-raw-v1 filebeat inputs tail
/logs/enriched/*.json, which is rotated by ip-enrichment-worker's
OutputWriter (rotate.rs) the same rename-aside-and-reopen way the six
#1776 sibling inputs (portbridge-json-v2, zeek-logs, zeek-proxy-logs,
huginn-sidecar, traefik-access, suricata-eve) rotate, but left
file_identity implicit. Fixed by pinning file_identity.fingerprint on both,
matching the siblings.

This test scans every shipped config/source file for the stale phrase, and
pins the two enriched-output inputs to fingerprint explicitly.
"""
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

# Use chr() concatenation so this test file does not contain the literal
# stale phrase itself (the scanner walks every .py file in the repo).
STALE_PHRASE = "Filebeat" + chr(39) + "s default file_identity (inode/device"

# Directories that never carry shipped config/comments worth scanning, and
# would otherwise be slow or noisy to walk (VCS metadata, dependency trees,
# build output).
EXCLUDED_DIR_NAMES = {
    ".git", "node_modules", "target", "dist", "build", "__pycache__",
    ".venv", "venv", ".orchestrator",
}

SCAN_SUFFIXES = {".yaml", ".yml", ".rs", ".go", ".md", ".conf", ".sh", ".py"}

SURICATA_YAML = REPO_ROOT / "vps" / "suricata" / "suricata.yaml"
ROTATE_RS = (
    REPO_ROOT / "arcane" / "home" / "honeypot-dashboard" / "backend-service"
    / "src" / "ip_enrichment" / "rotate.rs"
)
FILEBEAT_YML = (
    REPO_ROOT / "arcane" / "home" / "honeypot-elk" / "analysis" / "filebeat.yml"
)


def _iter_scanned_files():
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in SCAN_SUFFIXES:
            continue
        if any(part in EXCLUDED_DIR_NAMES for part in path.parts):
            continue
        yield path


def test_no_shipped_file_still_claims_the_pre_fb9_default():
    offenders = []
    for path in _iter_scanned_files():
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if STALE_PHRASE in text:
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders, (
        f"stale pre-Filebeat-9 file_identity claim still present in: {offenders} "
        "-- Filebeat 9 changed the filestream default from inode-based identity to "
        "fingerprint (see #1776/#2189/#2202)"
    )


def test_suricata_yaml_cites_fingerprint_not_inode_default():
    text = SURICATA_YAML.read_text(encoding="utf-8")
    assert "eve-log" in text
    assert STALE_PHRASE not in text
    assert "file_identity.fingerprint" in text, (
        "suricata.yaml's eve-log comment should point at the "
        "file_identity.fingerprint pin in analysis/filebeat.yml, not "
        "describe an implicit default"
    )


def test_rotate_rs_doc_comment_cites_fingerprint_not_inode_default():
    text = ROTATE_RS.read_text(encoding="utf-8")
    assert STALE_PHRASE not in text
    assert "fingerprint" in text, (
        "rotate.rs's module doc comment should reflect Filebeat 9's "
        "fingerprint default, not the pre-FB9 inode/device claim"
    )


@pytest.mark.parametrize("input_id", ["honeypot-json", "dionaea-incidents-raw-v1"])
def test_enriched_output_inputs_pin_file_identity(input_id):
    """Both inputs tail paths rotated by rotate.rs's rename-aside-and-reopen
    OutputWriter, the same pattern the six #1776 siblings pin identity for
    -- so these should not be the odd ones left implicit."""
    text = FILEBEAT_YML.read_text(encoding="utf-8")
    id_index = text.index(f"id: {input_id}")
    # file_identity.fingerprint must be pinned on the same input block,
    # i.e. before the next `- type: filestream` (the start of the next input).
    next_input_index = text.find("- type: filestream", id_index)
    if next_input_index == -1:
        next_input_index = len(text)
    block = text[id_index:next_input_index]
    assert "file_identity.fingerprint: ~" in block, (
        f"{input_id} does not pin file_identity.fingerprint despite tailing "
        "a path rotated by rotate.rs's OutputWriter"
    )
    assert "prospector.scanner.fingerprint.enabled: true" in block, (
        f"{input_id} pins file_identity.fingerprint but not the matching "
        "scanner flag the #1776 siblings all set alongside it"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
