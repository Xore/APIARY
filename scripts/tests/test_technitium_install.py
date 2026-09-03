#!/usr/bin/env python3
"""Smoke-test the tracked Technitium DNS install topology.

Replaces the Pi-hole/DNSCrypt smoke test from #1387 after the Pi-hole ->
Technitium swap (2026-09-03). Same pipeline principle: render the tracked
compose through Compose's own validator, assert the topology invariants the
installer depends on (LAN-bind-only ports, healthcheck, no dnscrypt sidecar).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "technitium" / "compose.yml"
INSTALLER = ROOT / "scripts" / "install-homeserver.sh"
TEST_LAN_IP = "127.0.0.42"


def rendered_compose() -> dict[str, Any]:
    """Render the tracked compose and ask Compose to normalize it."""
    with tempfile.TemporaryDirectory() as temp_dir:
        work = Path(temp_dir)
        work.joinpath("compose.yml").write_text(COMPOSE.read_text())
        env = os.environ | {
            "TECHNITIUM_PASSWORD": "ci-placeholder-not-a-secret",
            "INSTALL_TIMEZONE": "Europe/Berlin",
            # Same ${LAN_IP:-127.0.0.1} interpolation mechanism the old
            # pihole stack used since #1502.
            "LAN_IP": TEST_LAN_IP,
        }
        proc = subprocess.run(
            ["docker", "compose", "-f", "compose.yml", "config", "--format", "json"],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        import json

        return json.loads(proc.stdout)


class TechnitiumInstallSmokeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.compose = rendered_compose()

    def test_compose_file_tracked(self) -> None:
        self.assertTrue(COMPOSE.is_file(), f"{COMPOSE} missing")

    def test_installer_tracked(self) -> None:
        self.assertTrue(INSTALLER.is_file(), f"{INSTALLER} missing")

    def test_installer_references_technitium_steps(self) -> None:
        text = INSTALLER.read_text()
        for fn in (
            "step_technitium_provision()",
            "step_technitium_start()",
            "step_technitium_verify()",
        ):
            self.assertIn(fn, text)
        # The old pihole step functions must be gone.
        self.assertNotIn("step_pihole_provision()", text)

    def test_no_dnscrypt_sidecar(self) -> None:
        services = self.compose["services"]
        self.assertNotIn("dnscrypt", services, "dnscrypt sidecar should be gone")
        self.assertIn("technitium", services)

    def test_binds_lan_ip_not_wildcard(self) -> None:
        """53 must never bind 0.0.0.0 — collides with hp-dns-honeypot (#518)."""
        ports = self.compose["services"]["technitium"].get("ports", [])
        dns = [p for p in ports if int(p.get("target", 0)) == 53]
        self.assertTrue(dns, "no :53 port published")
        for p in dns:
            host_ip = p.get("host_ip", "")
            self.assertEqual(
                host_ip, TEST_LAN_IP,
                f":53 not bound to the LAN IP (got {host_ip!r})",
            )

    def test_admin_ui_port_published(self) -> None:
        ports = self.compose["services"]["technitium"].get("ports", [])
        ui = [p for p in ports if int(p.get("target", 0)) == 5380]
        self.assertTrue(ui, "admin UI :5380 not published")

    def test_healthcheck_present(self) -> None:
        svc = self.compose["services"]["technitium"]
        hc = svc.get("healthcheck")
        self.assertIsNotNone(hc, "healthcheck missing")
        self.assertIn("dig", " ".join(hc.get("test", [])))

    def test_image_pinned_by_digest(self) -> None:
        image = self.compose["services"]["technitium"]["image"]
        self.assertIn("@sha256:", image, f"image not digest-pinned: {image}")

    def test_manifest_references_technitium(self) -> None:
        import json

        manifest = json.loads(
            (ROOT / "arcane" / "manifests" / "home-production.json").read_text()
        )
        entries = manifest if isinstance(manifest, list) else manifest.get("syncs", [])
        names = [e.get("syncName") for e in entries if isinstance(e, dict)]
        self.assertIn("technitium", names)
        self.assertNotIn("pihole", names)


if __name__ == "__main__":
    unittest.main()
