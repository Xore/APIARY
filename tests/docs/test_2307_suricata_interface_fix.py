#!/usr/bin/env python3
"""Regression test for #2307: suricata.yaml af-packet pinned interface: ens6.

The WireGuard-exclusion bpf-filter (`not udp port 51820`) lived under a
named `- interface: ens6` af-packet stanza. Suricata matches af-packet
config by literal interface name and falls back to the `- interface:
default` stanza for anything else. The real capture NIC is runtime-derived
(CAPTURE_INTERFACE, detect-capture-interface.service, #1929/#1932) and had
already been renamed once (ens6 -> eth0), so the named stanza went stale
and the fallback -- which carried no filter -- applied instead, silently
re-opening the tunnel-traffic feedback loop the filter exists to prevent.

The fix moves the filter onto the `default` stanza, which matches
whatever interface `-i` names by construction, and removes the named
stanza so there is no interface-specific pin left to drift.
"""
import pathlib
import re
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SURICATA_YAML = REPO_ROOT / "vps" / "suricata" / "suricata.yaml"
SCAN_RULES = REPO_ROOT / "vps" / "suricata" / "rules" / "honeypot-scan.rules"

WIREGUARD_BPF_FILTER = "not udp port 51820"


def _af_packet_block(text):
    """Return the af-packet: top-level key and all its indented lines."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line.rstrip() == "af-packet:"), None)
    assert start is not None, f"no top-level `af-packet:` key found in {SURICATA_YAML}"
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.strip() == "" or line.startswith((" ", "\t")):
            block.append(line)
            continue
        break  # dedent back to column 0 -- next top-level key
    return "\n".join(block)


def test_suricata_yaml_exists():
    assert SURICATA_YAML.exists(), f"suricata.yaml not found at {SURICATA_YAML}"


def test_af_packet_has_no_hardcoded_interface_name():
    block = _af_packet_block(SURICATA_YAML.read_text(encoding="utf-8"))
    interface_names = re.findall(r"^\s*-\s*interface:\s*(\S+)", block, re.MULTILINE)
    assert interface_names, "no `interface:` stanzas found under af-packet"
    non_default = [name for name in interface_names if name != "default"]
    assert not non_default, (
        f"af-packet still pins a specific interface name {non_default!r} -- "
        "the capture NIC is runtime-derived (CAPTURE_INTERFACE, #1929/#1932) "
        "and can be renamed under a reboot, so only the `default` stanza is "
        "safe to key config on (#2307)"
    )


def test_af_packet_default_stanza_carries_wireguard_bpf_filter():
    block = _af_packet_block(SURICATA_YAML.read_text(encoding="utf-8"))
    assert "interface: default" in block, (
        f"af-packet has no `- interface: default` stanza:\n{block}"
    )
    assert WIREGUARD_BPF_FILTER in block, (
        f"af-packet block is missing the WireGuard-exclusion bpf-filter "
        f"({WIREGUARD_BPF_FILTER!r}) -- without it, sshfs/tunnel traffic to "
        "the home server gets captured again and pcap-log fills with junk "
        "every few seconds (#2307)"
    )


def test_honeypot_scan_rules_does_not_hardcode_nic_name():
    text = SCAN_RULES.read_text(encoding="utf-8")
    assert "ens6" not in text, (
        f"{SCAN_RULES} still hardcodes the NIC name 'ens6' -- the capture "
        "interface is runtime-derived and has already been renamed once (#2307)"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
