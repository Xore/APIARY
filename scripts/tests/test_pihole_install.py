#!/usr/bin/env python3
"""Smoke-test the tracked Pi-hole/DNSCrypt install topology from #1387."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "pihole" / "compose.yml"
DNSCRYPT_CONFIG = ROOT / "pihole" / "dnscrypt-proxy.toml"
INSTALLER = ROOT / "scripts" / "install-homeserver.sh"
TEST_LAN_IP = "127.0.0.42"


def rendered_compose() -> dict[str, object]:
    """Render the installer template and ask Compose to normalize it."""
    with tempfile.TemporaryDirectory() as temp_dir:
        work = Path(temp_dir)
        work.joinpath("compose.yml").write_text(
            COMPOSE.read_text().replace("__LAN_IP__", TEST_LAN_IP)
        )
        work.joinpath("dnscrypt-proxy").mkdir()
        work.joinpath("dnscrypt-proxy", "dnscrypt-proxy.toml").write_bytes(
            DNSCRYPT_CONFIG.read_bytes()
        )
        env = os.environ | {
            "PIHOLE_PASSWORD": "ci-placeholder-not-a-secret",
            "INSTALL_TIMEZONE": "Europe/Berlin",
        }
        result = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                str(work / "compose.yml"),
                "config",
                "--format",
                "json",
            ],
            check=True,
            capture_output=True,
            env=env,
            text=True,
        )
        return json.loads(result.stdout)


class PiholeInstallSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = rendered_compose()
        cls.services = cls.config["services"]

    def test_dnscrypt_is_private_and_healthcheck_resolves_externally(self) -> None:
        dnscrypt = self.services["dnscrypt"]
        self.assertNotIn("ports", dnscrypt)
        self.assertEqual(
            dnscrypt["healthcheck"]["test"],
            [
                "CMD",
                "dnscrypt-proxy",
                "-config",
                "/config/dnscrypt-proxy.toml",
                "-resolve",
                "example.com,127.0.0.1:5053",
            ],
        )

        with DNSCRYPT_CONFIG.open("rb") as config_file:
            dnscrypt_config = tomllib.load(config_file)
        self.assertEqual(dnscrypt_config["listen_addresses"], ["0.0.0.0:5053"])
        self.assertEqual(
            dnscrypt_config["sources"]["public-resolvers"]["cache_file"],
            "/config/public-resolvers.md",
        )

    def test_pihole_uses_ready_dnscrypt_service_and_real_healthcheck(self) -> None:
        pihole = self.services["pihole"]
        self.assertEqual(pihole["environment"]["FTLCONF_dns_upstreams"], "dnscrypt#5053")
        self.assertEqual(
            pihole["depends_on"]["dnscrypt"]["condition"], "service_healthy"
        )
        health_command = pihole["healthcheck"]["test"]
        self.assertEqual(health_command[0], "CMD-SHELL")
        self.assertIn("$(date +%s).healthcheck.example.com", health_command[1])
        self.assertIn("status: (NOERROR|NXDOMAIN)", health_command[1])

    def test_only_pihole_is_published_on_the_configured_lan_ip(self) -> None:
        ports = self.services["pihole"]["ports"]
        self.assertTrue(ports)
        self.assertEqual({port["host_ip"] for port in ports}, {TEST_LAN_IP})
        self.assertEqual(
            {(port["target"], port["published"], port["protocol"]) for port in ports},
            {(53, "53", "tcp"), (53, "53", "udp"), (80, "80", "tcp")},
        )

    def test_installer_copies_source_of_truth_and_probes_lan_dns(self) -> None:
        installer = INSTALLER.read_text()
        self.assertIn('"$REPO_DIR/pihole/compose.yml"', installer)
        self.assertIn('"$REPO_DIR/pihole/dnscrypt-proxy.toml"', installer)
        self.assertIn('"$dir/dnscrypt-proxy/dnscrypt-proxy.toml"', installer)
        self.assertIn('chown 65532:65532 "$dir/dnscrypt-proxy"', installer)
        self.assertIn('dig @"$PIHOLE_LAN_IP" example.com', installer)
        self.assertIn("run_step pihole-verify", installer)
        self.assertIn("curl dnsutils gnupg", installer)


if __name__ == "__main__":
    unittest.main(verbosity=2)
