#!/usr/bin/env python3
"""Regression test for #2295: scripts/isolation-audit.sh asserted the
isolation invariants documented in docs/honeypot-network-isolation.md for
the Windows detonation lane only.

The "no <forward> element" section already looped over both libvirt
networks (sandbox and honeypot-sandbox), but the two sections that make
that absence actually mean something -- the iptables FORWARD-ACCEPT
complement and the host-route/address sweep -- hardcoded 'virbr-sandbox'
(the Windows bridge, 10.10.10.0/24) alone. The Linux detonation lane
(bridge virbr-hpsbx, network honeypot-sandbox, 198.18.0.0/24 per
sandbox/network.xml and sandbox/forensic-egress-network.sh) passed through
both sections completely unaudited, so planting an explicit ACCEPT for
virbr-hpsbx, or leaving a forensic-egress host address on it after a failed
teardown, read as "isolation-audit: all checks passed".

The fix enumerates every guarded bridge/network/subnet once in
GUARDED_BRIDGES and has both sections iterate it, so a third sandbox
network only needs a table entry instead of a second hand-written check
block (the #2295 acceptance criterion on shared enumeration). The route
probe also moved from an exact-prefix 'ip route show <subnet>' to
'ip route get <probe-ip>' compared against the host's own default route,
so a covering supernet route is caught the same way an exact one is. The
Linux bridge is address-less by design (sandbox/network.xml), so its host
route is only legitimate while
sandbox/honeypot-sandbox-egress-network.service (which runs
forensic-egress-network.sh start/stop) is active -- outside that window a
host route via virbr-hpsbx is flagged the same as any other regression.
"""
import os
import pathlib
import re
import stat
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "isolation-audit.sh"
EGRESS_SERVICE = REPO_ROOT / "sandbox" / "honeypot-sandbox-egress-network.service"

WINDOWS_BRIDGE = "virbr-sandbox"
LINUX_BRIDGE = "virbr-hpsbx"
LINUX_SUBNET_PROBE_IP = "198.18.0.1"


def _script_text():
    return SCRIPT.read_text(encoding="utf-8")


def _section(text, heading, next_heading_snippet=None):
    """Slice out one '== heading ==' section's body, up to the next
    '# ---' divider (every section in this script is preceded by one)."""
    start = text.index(heading)
    end = text.index("# ---------------------------------------------------------------------------", start + len(heading))
    return text[start:end]


def test_script_exists():
    assert SCRIPT.exists(), f"isolation-audit.sh not found at {SCRIPT}"


def test_guarded_bridges_table_covers_both_lanes():
    text = _script_text()
    m = re.search(r"GUARDED_BRIDGES=\((.*?)\n\)", text, re.DOTALL)
    assert m, "GUARDED_BRIDGES array not found -- has the shared table been renamed or removed?"
    table = m.group(1)
    assert WINDOWS_BRIDGE in table, f"{WINDOWS_BRIDGE} missing from GUARDED_BRIDGES"
    assert LINUX_BRIDGE in table, (
        f"{LINUX_BRIDGE} missing from GUARDED_BRIDGES -- the Linux detonation "
        "lane would be unaudited again (#2295)"
    )


def test_forward_accept_check_iterates_guarded_bridges():
    text = _script_text()
    section = _section(text, 'section "Phase 0 iptables barrier')
    assert "GUARDED_BRIDGES" in section, (
        "the iptables FORWARD-ACCEPT complement no longer iterates "
        "GUARDED_BRIDGES -- it may have regressed to checking a single "
        "hardcoded bridge again (#2295)"
    )
    # The old bug: this exact grep, hardcoded, with no loop around it.
    assert "grep -q 'virbr-sandbox.*ACCEPT'" not in section


def test_route_check_iterates_guarded_bridges():
    text = _script_text()
    section = _section(text, 'section "No host route')
    assert "GUARDED_BRIDGES" in section, (
        "the host-route sweep no longer iterates GUARDED_BRIDGES -- it may "
        "have regressed to checking only 10.10.10.0/24 again (#2295)"
    )
    assert "ip route show 10.10.10.0/24" not in section, (
        "route probe reverted to an exact-prefix lookup, which misses a "
        "covering supernet route (#2295 acceptance criterion)"
    )


def test_forensic_egress_service_referenced_matches_real_unit():
    assert EGRESS_SERVICE.exists(), f"expected systemd unit file missing: {EGRESS_SERVICE}"
    text = _script_text()
    assert EGRESS_SERVICE.name in text, (
        f"isolation-audit.sh does not reference {EGRESS_SERVICE.name} -- the "
        "authorized-forensic-window check must name the real unit that "
        "sandbox/forensic-egress-network.sh installs, not an invented marker"
    )


# ---------------------------------------------------------------------------
# Behavioral tests: run the real script against a fake PATH so it needs no
# root, no libvirt, and no docker daemon. Every external command the script
# calls is either a controllable stub (sudo, iptables, ip, systemctl) or is
# left to fail closed exactly as it would in an unprivileged CI container
# -- irrelevant to the assertions below, which only look at the specific
# FAIL/OK lines the fix is responsible for.

FAKE_SUDO = """#!/usr/bin/env bash
[ "$1" = "-n" ] && shift
exec "$@"
"""

FAKE_IPTABLES = """#!/usr/bin/env bash
if [ "$1" = "-S" ] && [ "$2" = "FORWARD" ]; then
  cat "$FAKE_RULES_FILE"
  exit 0
fi
exit 1
"""

# ip route show default -> $FAKE_IP_DEFAULT_DEV (unset = no default route).
# ip route get <ip>      -> device named by FAKE_IP_ROUTE_GET_<ip-with-underscores>.
FAKE_IP = """#!/usr/bin/env bash
if [ "$1" = "route" ] && [ "$2" = "show" ] && [ "$3" = "default" ]; then
  if [ -n "${FAKE_IP_DEFAULT_DEV:-}" ]; then
    echo "default via 192.0.2.1 dev $FAKE_IP_DEFAULT_DEV"
  fi
  exit 0
fi
if [ "$1" = "route" ] && [ "$2" = "get" ]; then
  key="FAKE_IP_ROUTE_GET_${3//./_}"
  dev="${!key:-}"
  if [ -n "$dev" ]; then
    echo "$3 dev $dev src 0.0.0.0 uid 0"
  fi
  exit 0
fi
exit 1
"""

# systemctl is-active --quiet honeypot-sandbox-egress-network.service
# exits 0 (active) when FAKE_EGRESS_ACTIVE=1, else 3 (inactive), matching
# real systemctl exit-code semantics closely enough for this script's use.
FAKE_SYSTEMCTL = """#!/usr/bin/env bash
if [ "$1" = "is-active" ]; then
  [ "${FAKE_EGRESS_ACTIVE:-0}" = "1" ] && exit 0 || exit 3
fi
exit 4
"""


@pytest.fixture()
def fake_bin(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for name, content in (
        ("sudo", FAKE_SUDO),
        ("iptables", FAKE_IPTABLES),
        ("ip", FAKE_IP),
        ("systemctl", FAKE_SYSTEMCTL),
    ):
        path = bindir / name
        path.write_text(content, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return bindir


def _run(fake_bin, rules_text, extra_env=None):
    tmp_dir = fake_bin.parent
    rules_file = tmp_dir / "forward-rules.txt"
    rules_file.write_text(rules_text, encoding="utf-8")
    env = dict(os.environ)
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["FAKE_RULES_FILE"] = str(rules_file)
    env.pop("FAKE_IP_DEFAULT_DEV", None)
    env.pop("FAKE_EGRESS_ACTIVE", None)
    for key in list(env):
        if key.startswith("FAKE_IP_ROUTE_GET_"):
            del env[key]
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


CLEAN_RULES = "-P FORWARD DROP\n"


@pytest.mark.skipif(sys.platform == "win32", reason="uses bash and Unix-style stubs")
def test_clean_ruleset_passes_both_bridges(fake_bin):
    result = _run(fake_bin, CLEAN_RULES)
    assert f"nothing explicitly ACCEPTs {WINDOWS_BRIDGE} traffic" in result.stdout
    assert f"nothing explicitly ACCEPTs {LINUX_BRIDGE} traffic" in result.stdout
    assert "ACCEPT rule references" not in result.stdout


@pytest.mark.skipif(sys.platform == "win32", reason="uses bash and Unix-style stubs")
def test_planted_accept_on_linux_bridge_fails_audit(fake_bin):
    """Acceptance criterion from #2295: planting
    '-A FORWARD -i virbr-hpsbx -o ethX -j ACCEPT' must make the audit exit
    nonzero with a named FAIL line -- before the fix this bridge was never
    checked, so this exact rule was invisible."""
    rules = CLEAN_RULES + f"-A FORWARD -i {LINUX_BRIDGE} -o eth0 -j ACCEPT\n"
    result = _run(fake_bin, rules)
    assert f"an explicit ACCEPT rule references {LINUX_BRIDGE} in the FORWARD chain" in result.stdout
    # The other (Windows) bridge must still read clean -- this is a
    # per-bridge check, not a blanket failure once anything looks wrong.
    assert f"nothing explicitly ACCEPTs {WINDOWS_BRIDGE} traffic" in result.stdout
    assert result.returncode != 0


@pytest.mark.skipif(sys.platform == "win32", reason="uses bash and Unix-style stubs")
def test_planted_accept_on_windows_bridge_still_fails_audit(fake_bin):
    """The pre-existing Windows-lane check must keep working after the
    refactor into a loop over GUARDED_BRIDGES."""
    rules = CLEAN_RULES + f"-A FORWARD -i {WINDOWS_BRIDGE} -o eth0 -j ACCEPT\n"
    result = _run(fake_bin, rules)
    assert f"an explicit ACCEPT rule references {WINDOWS_BRIDGE} in the FORWARD chain" in result.stdout
    assert result.returncode != 0


@pytest.mark.skipif(sys.platform == "win32", reason="uses bash and Unix-style stubs")
def test_lingering_hpsbx_route_outside_forensic_window_fails(fake_bin):
    """Acceptance criterion from #2295: a lingering 198.18.0.0/24 host
    route on virbr-hpsbx after a simulated failed teardown must FAIL, not
    pass silently -- unless the forensic-egress window is acknowledged
    active."""
    result = _run(
        fake_bin,
        CLEAN_RULES,
        extra_env={
            f"FAKE_IP_ROUTE_GET_{LINUX_SUBNET_PROBE_IP.replace('.', '_')}": LINUX_BRIDGE,
            "FAKE_EGRESS_ACTIVE": "0",
        },
    )
    assert "outside the forensic-egress window" in result.stdout
    assert result.returncode != 0


@pytest.mark.skipif(sys.platform == "win32", reason="uses bash and Unix-style stubs")
def test_hpsbx_route_during_authorized_forensic_window_passes(fake_bin):
    """The same lingering route must NOT fail while
    honeypot-sandbox-egress-network.service reports active -- that is the
    intentional, documented controlled-egress mode
    (sandbox/install-forensic-egress.sh), not a regression."""
    result = _run(
        fake_bin,
        CLEAN_RULES,
        extra_env={
            f"FAKE_IP_ROUTE_GET_{LINUX_SUBNET_PROBE_IP.replace('.', '_')}": LINUX_BRIDGE,
            "FAKE_EGRESS_ACTIVE": "1",
        },
    )
    assert "outside the forensic-egress window" not in result.stdout
    assert f"{LINUX_BRIDGE}" in result.stdout
    assert "only reachable via virbr-hpsbx" in result.stdout


@pytest.mark.skipif(sys.platform == "win32", reason="uses bash and Unix-style stubs")
def test_covering_supernet_route_is_caught(fake_bin):
    """Acceptance criterion from #2295: a covering-supernet route over a
    guarded subnet (resolves via neither the guarded bridge nor the host's
    own default route) must FAIL. 'ip route show <exact subnet>' (the old
    check) could not see this; 'ip route get <probe ip>' can."""
    result = _run(
        fake_bin,
        CLEAN_RULES,
        extra_env={
            "FAKE_IP_DEFAULT_DEV": "eth0",
            f"FAKE_IP_ROUTE_GET_{LINUX_SUBNET_PROBE_IP.replace('.', '_')}": "tun-aggregate",
        },
    )
    assert "neither virbr-hpsbx nor the host default route" in result.stdout
    assert "possibly a covering supernet" in result.stdout
    assert result.returncode != 0


@pytest.mark.skipif(sys.platform == "win32", reason="uses bash and Unix-style stubs")
def test_no_route_present_is_informational_not_a_failure(fake_bin):
    """Between detonations neither bridge is up -- that must stay a quiet
    '--' info line, not a FAIL, or the audit would be red at rest."""
    result = _run(fake_bin, CLEAN_RULES, extra_env={"FAKE_IP_DEFAULT_DEV": "eth0"})
    assert "no sandbox-specific route to 10.10.10.0/24" in result.stdout
    assert "no sandbox-specific route to 198.18.0.0/24" in result.stdout
    assert "FAIL" not in result.stdout.split("No host route into guarded sandbox subnets")[1].split(
        "Stack containers"
    )[0]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
