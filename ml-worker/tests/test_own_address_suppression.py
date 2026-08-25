"""Addresses we own must not raise operator-facing alerts (issues #1959, #1794).

Measured before the fix: on the largest alert day on record, loopback was the
single biggest "source" -- 3,204 of 6,669 alerts. `ML_HOME_NET` carried only
the VPS WAN address, so the WireGuard tunnel, the home LAN and loopback all
read as remote parties.
"""

import ipaddress
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models import isolation_forest as iso  # noqa: E402


class TestDefaultLocalRanges:
    """These are defaults, not required configuration: they are properties of
    the deployment shape rather than of one install."""

    @pytest.mark.parametrize("ip", [
        "127.0.0.1",        # the actual 48% of the spike
        "127.1.2.3",
        "10.8.0.1",         # WireGuard, VPS end
        "10.8.0.2",         # WireGuard, homeserver end
        "192.168.99.99",    # home LAN (any RFC1918)
        "192.168.1.10",
        "172.17.0.5",       # docker bridge
        "10.0.0.7",
        "169.254.1.1",      # link-local
    ])
    def test_our_own_addresses_are_recognised(self, ip):
        assert iso.is_our_own_address(ip)

    @pytest.mark.parametrize("ip", [
        "203.0.113.9",      # TEST-NET-3, stands in for a real scanner
        "198.51.100.42",    # TEST-NET-2
        "192.0.2.1",        # TEST-NET-1
        "8.8.8.8",
    ])
    def test_remote_addresses_are_not_suppressed(self, ip):
        """The whole point is still to alert on these."""
        assert not iso.is_our_own_address(ip)

    def test_loopback_v6(self):
        assert iso.is_our_own_address("::1")

    @pytest.mark.parametrize("junk", ["", None, "not-an-ip", "999.999.999.999"])
    def test_unparseable_input_is_not_treated_as_ours(self, junk):
        """Failing open here would suppress alerts on malformed data, which is
        the opposite of the safe direction."""
        assert not iso.is_our_own_address(junk)


class TestConfiguration:
    def test_wan_address_from_ml_home_net_is_still_included(self, monkeypatch):
        """The widened defaults must not displace the deployment-specific
        public address the installer writes."""
        monkeypatch.setattr(iso, "HOME_NET",
                            iso._parse_home_net("203.0.113.7/32")
                            + iso._parse_home_net(iso.DEFAULT_LOCAL_NETS))
        assert iso.is_our_own_address("203.0.113.7")
        assert iso.is_our_own_address("127.0.0.1")
        assert not iso.is_our_own_address("203.0.113.8")

    def test_local_nets_are_overridable(self):
        """A deployment whose honeypots legitimately live inside RFC1918 must
        be able to score them."""
        nets = iso._parse_home_net("127.0.0.0/8")
        assert any(ipaddress.ip_address("127.0.0.1") in n for n in nets)
        assert not any(ipaddress.ip_address("192.168.1.1") in n for n in nets)

    def test_defaults_cover_every_range_the_incident_named(self):
        parsed = iso._parse_home_net(iso.DEFAULT_LOCAL_NETS)
        for ip in ("127.0.0.1", "10.8.0.2", "192.168.99.99", "172.17.0.1"):
            assert any(ipaddress.ip_address(ip) in n for n in parsed), ip

    def test_unparseable_entries_are_skipped_not_fatal(self):
        assert iso._parse_home_net("127.0.0.0/8,garbage,10.8.0.0/24")

    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_empty_env_falls_back_to_the_defaults(self, value, monkeypatch):
        """compose passes "${ML_LOCAL_NETS:-}", so the variable is *set to an
        empty string* when unconfigured. os.getenv returns "" rather than its
        default there, which would silently disable the entire exclusion --
        the exact shape of the bug this fix exists to remove."""
        import importlib
        monkeypatch.delenv("ML_LOCAL_NETS", raising=False)
        if value is not None:
            monkeypatch.setenv("ML_LOCAL_NETS", value)
        reloaded = importlib.reload(iso)
        try:
            assert reloaded.is_our_own_address("127.0.0.1")
            assert reloaded.is_our_own_address("10.8.0.2")
        finally:
            monkeypatch.delenv("ML_LOCAL_NETS", raising=False)
            importlib.reload(iso)

    def test_an_explicit_value_replaces_the_defaults(self, monkeypatch):
        import importlib
        monkeypatch.setenv("ML_LOCAL_NETS", "10.99.0.0/16")
        reloaded = importlib.reload(iso)
        try:
            assert reloaded.is_our_own_address("10.99.1.1")
            assert not reloaded.is_our_own_address("127.0.0.1")
        finally:
            monkeypatch.delenv("ML_LOCAL_NETS", raising=False)
            importlib.reload(iso)


class TestFlowSideResolutionStillWorks:
    """The same list decides which side of a flow is ours, so widening it must
    not break the #174 netflow swap."""

    def test_our_side_is_resolved_as_local(self):
        src = {"source": {"ip": "10.8.0.2"}, "destination": {"ip": "203.0.113.9"}}
        remote, local = iso._resolve_flow_sides(src)
        assert remote["ip"] == "203.0.113.9"
        assert local["ip"] == "10.8.0.2"

    def test_no_swap_when_source_is_genuinely_remote(self):
        src = {"source": {"ip": "203.0.113.9"}, "destination": {"ip": "10.8.0.2"}}
        remote, _ = iso._resolve_flow_sides(src)
        assert remote["ip"] == "203.0.113.9"

    def test_no_swap_when_both_sides_are_ours(self):
        """Both-ours is the loopback case; it must not swap, and the alert path
        suppresses it instead."""
        src = {"source": {"ip": "127.0.0.1"}, "destination": {"ip": "127.0.0.1"}}
        remote, _ = iso._resolve_flow_sides(src)
        assert remote["ip"] == "127.0.0.1"
        assert iso.is_our_own_address(remote["ip"])
