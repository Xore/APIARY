#!/usr/bin/env python3
"""Regression test for #2708: the zeek-logs and zeek-proxy-logs filestream
inputs in analysis/filebeat.yml were pinned to fingerprint identity by
#1776/#2202, but fingerprint hashes a fixed byte window of each file, and for
high-column-count Zeek logs (modbus_detailed) that window landed entirely
inside the static header, which is byte-identical across every hourly
rotation. Filebeat treated every rotation after the first as "already known"
and silently skipped it -- 22,807 skip warnings/hour, none of those files
ever reaching Elasticsearch.

Fixed by switching both Zeek inputs to native (inode+device) identity, which
never hashes file content and so cannot collide this way. This test pins
that choice so a future edit does not quietly restore the fingerprint pin
(or drop identity pinning back to implicit) on these two inputs.
"""
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FILEBEAT_YML = (
    REPO_ROOT / "arcane" / "home" / "honeypot-elk" / "analysis" / "filebeat.yml"
)


def _input_block(text, input_id):
    id_index = text.index(f"id: {input_id}")
    next_input_index = text.find("- type: filestream", id_index)
    if next_input_index == -1:
        next_input_index = len(text)
    return text[id_index:next_input_index]


@pytest.mark.parametrize("input_id", ["zeek-logs", "zeek-proxy-logs"])
def test_zeek_inputs_pin_native_identity_not_fingerprint(input_id):
    text = FILEBEAT_YML.read_text(encoding="utf-8")
    block = _input_block(text, input_id)
    assert "file_identity.native: ~" in block, (
        f"{input_id} should pin file_identity.native -- fingerprint identity "
        "collides on Zeek logs whose header exceeds the fingerprint window "
        "and is identical across hourly rotations (#2708)"
    )
    assert "file_identity.fingerprint" not in block, (
        f"{input_id} still pins file_identity.fingerprint, which is exactly "
        "the scheme #2708 found silently dropping rotated Zeek logs"
    )
    assert "prospector.scanner.fingerprint.enabled" not in block, (
        f"{input_id} still enables the fingerprint scanner alongside native "
        "identity; that flag is only meaningful for fingerprint identity and "
        "its presence here would be stale"
    )


@pytest.mark.parametrize("input_id", ["zeek-logs", "zeek-proxy-logs"])
def test_zeek_inputs_still_pin_some_explicit_identity(input_id):
    """Guards against identity pinning being dropped back to implicit
    entirely, which is the #1776 regression these inputs were fixed for."""
    text = FILEBEAT_YML.read_text(encoding="utf-8")
    block = _input_block(text, input_id)
    assert "file_identity." in block, (
        f"{input_id} must pin an explicit file_identity scheme -- leaving it "
        "implicit is the #1776 class of bug (Filebeat's default can change "
        "underneath a rotating file between major versions)"
    )


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
