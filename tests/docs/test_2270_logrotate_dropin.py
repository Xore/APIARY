#!/usr/bin/env python3
"""Regression test for #2270: sandbox/install-forensic-egress.sh enables two
long-running, root-started services -- dnsmasq (log-queries=extra) and squid
(stdio access.log + cache.log) -- that log unbounded to
/var/log/honeypot-sandbox/{dns,proxy}/. Debian's packaged
/etc/logrotate.d/squid only covers /var/log/squid/*, and nothing in the repo
covered the honeypot-sandbox paths, so enabling controlled egress started
unbounded, root-owned disk growth that can wedge the host.

The fix ships sandbox/forensic-egress-logrotate.conf, a logrotate drop-in
installed to /etc/logrotate.d/honeypot-sandbox-egress, covering both trees.
Its postrotate script signals each daemon to reopen its log file in place:
SIGUSR2 to dnsmasq via the pid file its systemd unit actually writes, and
`squid -k rotate -f <conf>` for squid.

SIGUSR2, not SIGUSR1, is the part worth guarding: per dnsmasq(8)'s NOTES
section, SIGUSR1 only dumps cache statistics to the system log -- SIGUSR2 is
the signal documented to close and reopen a `log-facility` file. Sending
USR1 would look plausible, pass a casual read, and still leave dnsmasq
writing to the rotated-away (deleted) inode forever, silently defeating the
fix while `logrotate` reports success.
"""
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SANDBOX_DIR = REPO_ROOT / "sandbox"
INSTALLER = SANDBOX_DIR / "install-forensic-egress.sh"
DROPIN = SANDBOX_DIR / "forensic-egress-logrotate.conf"
DNSMASQ_SERVICE = SANDBOX_DIR / "honeypot-sandbox-egress-dns.service"
PROXY_SERVICE = SANDBOX_DIR / "honeypot-sandbox-egress-proxy.service"
SQUID_CONF = SANDBOX_DIR / "forensic-egress-squid.conf"
DNSMASQ_CONF = SANDBOX_DIR / "forensic-egress-dnsmasq.conf"

DNSMASQ_PID_FILE = "/run/honeypot-sandbox-dnsmasq.pid"
SQUID_CONF_PATH = "/etc/honeypot-sandbox/squid.conf"
DROPIN_DEST = "/etc/logrotate.d/honeypot-sandbox-egress"

LOGROTATE_BIN = shutil.which("logrotate") or (
    "/usr/sbin/logrotate" if pathlib.Path("/usr/sbin/logrotate").exists() else None
)


def _dropin_text():
    return DROPIN.read_text(encoding="utf-8")


def test_dropin_file_exists():
    assert DROPIN.exists(), f"{DROPIN} not found"


def test_dropin_covers_both_log_trees():
    text = _dropin_text()
    assert "/var/log/honeypot-sandbox/dns/*.log" in text, (
        "logrotate drop-in must glob the dnsmasq query-log tree"
    )
    assert "/var/log/honeypot-sandbox/proxy/*.log" in text, (
        "logrotate drop-in must glob the squid tree (access.log and "
        "cache.log both live there)"
    )


def test_dropin_has_bounded_rotation_settings():
    text = _dropin_text()
    for directive in ("daily", "rotate 14", "compress", "missingok", "notifempty", "sharedscripts"):
        assert directive in text, f"logrotate drop-in is missing `{directive}`"


def test_dropin_delaycompress_present_for_dnsmasq_tcp_hold():
    # dnsmasq(8) NOTES: TCP-query child processes can keep the just-rotated
    # logfile open for up to 150s after a SIGUSR2; compressing immediately
    # can race an active writer. Required to be used with delaycompress.
    assert "delaycompress" in _dropin_text()


def test_postrotate_signals_dnsmasq_with_usr2_not_usr1():
    text = _dropin_text()
    assert DNSMASQ_PID_FILE in text, (
        f"postrotate must reference dnsmasq's actual pid file {DNSMASQ_PID_FILE} "
        "(see --pid-file= in honeypot-sandbox-egress-dns.service)"
    )
    assert "USR2" in text, (
        "postrotate must send SIGUSR2 to dnsmasq -- per dnsmasq(8) NOTES, "
        "SIGUSR1 only dumps cache statistics to syslog; SIGUSR2 is what "
        "closes and reopens a log-facility file"
    )
    assert "USR1" not in text, (
        "SIGUSR1 does not reopen a dnsmasq log-facility file (it only dumps "
        "stats) -- sending it would leave dnsmasq writing to the deleted, "
        "rotated-away inode forever while logrotate reports success"
    )


def test_postrotate_rotates_squid_via_its_actual_conf_path():
    assert f"squid -k rotate -f {SQUID_CONF_PATH}" in _dropin_text(), (
        f"postrotate must run `squid -k rotate -f {SQUID_CONF_PATH}` against "
        "the actual installed config path"
    )


def test_pid_file_matches_dnsmasq_systemd_unit():
    text = DNSMASQ_SERVICE.read_text(encoding="utf-8")
    m = re.search(r"--pid-file=(\S+)", text)
    assert m, f"{DNSMASQ_SERVICE} ExecStart has no --pid-file= flag"
    assert m.group(1) == DNSMASQ_PID_FILE, (
        f"dnsmasq unit's pid file is {m.group(1)!r}, but the logrotate "
        f"drop-in hardcodes {DNSMASQ_PID_FILE!r} -- keep them in sync"
    )


def test_squid_conf_path_matches_proxy_systemd_unit():
    text = PROXY_SERVICE.read_text(encoding="utf-8")
    assert f"-f {SQUID_CONF_PATH}" in text, (
        f"{PROXY_SERVICE} does not launch squid against {SQUID_CONF_PATH}"
    )


def test_squid_conf_log_paths_match_dropin_glob():
    text = SQUID_CONF.read_text(encoding="utf-8")
    assert "/var/log/honeypot-sandbox/proxy/access.log" in text
    assert "/var/log/honeypot-sandbox/proxy/cache.log" in text


def test_dnsmasq_conf_log_path_matches_dropin_glob():
    text = DNSMASQ_CONF.read_text(encoding="utf-8")
    assert "/var/log/honeypot-sandbox/dns/queries.log" in text


def test_installer_deploys_the_dropin():
    text = INSTALLER.read_text(encoding="utf-8")
    assert f'"$script_dir/forensic-egress-logrotate.conf" {DROPIN_DEST}' in text, (
        "install-forensic-egress.sh must install forensic-egress-logrotate.conf "
        f"to {DROPIN_DEST}"
    )


def test_installer_validates_the_dropin_before_finishing():
    text = INSTALLER.read_text(encoding="utf-8")
    assert f"logrotate -d {DROPIN_DEST}" in text, (
        "installer should probe-parse the installed drop-in the same way it "
        "already validates dnsmasq.conf (--test) and squid.conf (-k parse)"
    )


def test_installer_installs_logrotate_package():
    text = INSTALLER.read_text(encoding="utf-8")
    apt_line = next(
        (line for line in text.splitlines() if line.strip().startswith("DEBIAN_FRONTEND=noninteractive apt-get install")),
        None,
    )
    assert apt_line, "no apt-get install line found in installer"
    assert "logrotate" in apt_line, (
        "installer must ensure the logrotate package is present, not assume "
        "it's already on the host"
    )


@pytest.mark.skipif(LOGROTATE_BIN is None, reason="logrotate not installed")
def test_dropin_parses_with_real_logrotate_debug_mode(tmp_path):
    """Debug mode ('don't do anything, just test and print debug messages')
    exercises the real parser against the file exactly as shipped, including
    its absolute /var/log and /run paths -- missingok means the target trees
    don't need to exist for this to succeed."""
    result = subprocess.run(
        [LOGROTATE_BIN, "-d", str(DROPIN), "-s", str(tmp_path / "status")],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"logrotate -d rejected the drop-in as shipped "
        f"(stdout/stderr follow):\n{result.stdout}\n{result.stderr}"
    )
    assert "error" not in result.stderr.lower(), result.stderr


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
