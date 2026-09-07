#!/usr/bin/env python3
"""Exercise compose-drift-watch.py's arcane_image_drift() (#3048) with fixture
compose files -- no docker daemon, no live stacks root.

honeypot-arcane is excluded from every manifest-driven check in this script
by design (it's installer-/deploy.yml-managed, not an Arcane gitops-sync),
which is exactly why its image tag drifted silently across a rebuild
(v2.9.0 live vs v2.10.1 on main) with nothing to catch it. This pins the
narrow image-line comparison that closes that gap."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "compose-drift-watch.py"

_spec = importlib.util.spec_from_file_location("compose_drift_watch", SCRIPT)
cdw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cdw)


class ArcaneImageDriftTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.stacks_root = Path(self.tmp.name)
        (self.stacks_root / "honeypot-arcane").mkdir()

    def write_live(self, image: str) -> None:
        (self.stacks_root / "honeypot-arcane" / "compose.yml").write_text(
            f"services:\n  arcane:\n    image: {image}\n"
        )

    def test_matching_image_is_no_finding(self) -> None:
        repo_image = cdw.arcane_image(cdw.ARCANE_REPO_COMPOSE.read_text())
        self.write_live(repo_image)
        self.assertIsNone(cdw.arcane_image_drift(self.stacks_root))

    def test_stale_live_image_is_flagged(self) -> None:
        self.write_live("ghcr.io/getarcaneapp/manager:v2.9.0@sha256:" + "a" * 64)
        finding = cdw.arcane_image_drift(self.stacks_root)
        self.assertIsNotNone(finding)
        self.assertIn("honeypot-arcane", finding)
        self.assertIn("v2.9.0", finding)

    def test_missing_live_compose_is_not_checked(self) -> None:
        # setUp only creates the honeypot-arcane/ directory, not compose.yml
        self.assertIsNone(cdw.arcane_image_drift(self.stacks_root))


if __name__ == "__main__":
    unittest.main()
