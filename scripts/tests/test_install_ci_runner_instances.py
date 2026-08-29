#!/usr/bin/env python3
"""Pin #2572's runner-instance derivation in install-ci-runner.sh.

Before #2572, RUNNER_HOME/RUNNER_USER were fixed constants regardless of
--name, so there was no way to register a second honeypot-ci runner
instance on the box without colliding with the first one's _work dir,
.runner file, and system user -- the whole matrix serialized behind one
executor. This extracts the script's own argument-parsing + instance
derivation block (marked by BEGIN/END comments) and executes it for real
under bash, asserting the derived RUNNER_HOME/RUNNER_USER/name/labels for
several --instance values, instead of just grepping for text.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts" / "github-ci-runner" / "install-ci-runner.sh"


def _derivation_block() -> str:
    text = INSTALLER.read_text()
    match = re.search(
        r"# --- BEGIN instance derivation.*?\n(.*?)# --- END instance derivation ---",
        text,
        re.DOTALL,
    )
    assert match, "instance-derivation markers not found in install-ci-runner.sh"
    return match.group(1)


def derive(*cli_args: str) -> dict[str, str]:
    """Run the real derivation logic under bash with the given CLI args."""
    script = _derivation_block() + '\nprintf "%s\\n" "$RUNNER_HOME" "$RUNNER_USER" "$name" "$RUNNER_LABELS"\n'
    result = subprocess.run(
        ["bash", "-c", 'RUNNER_LABELS="self-hosted,linux,x64,honeypot-ci"\n' + script,
         "install-ci-runner.sh", *cli_args],
        check=True,
        capture_output=True,
        text=True,
    )
    home, user, name, labels = result.stdout.splitlines()
    return {"home": home, "user": user, "name": name, "labels": labels}


class InstallCiRunnerInstancesTest(unittest.TestCase):
    def test_default_instance_keeps_the_original_singleton_layout(self) -> None:
        derived = derive("--repo", "Xore/APIARY")
        self.assertEqual(derived["home"], "/opt/github-ci-runner")
        self.assertEqual(derived["user"], "github-ci-runner")
        self.assertTrue(derived["name"].endswith("-ci"))
        self.assertNotIn("-ci-", derived["name"])

    def test_second_instance_gets_isolated_home_and_user(self) -> None:
        derived = derive("--repo", "Xore/APIARY", "--instance", "2")
        self.assertEqual(derived["home"], "/opt/github-ci-runner-2")
        self.assertEqual(derived["user"], "github-ci-runner-2")
        self.assertTrue(derived["name"].endswith("-ci-2"))

    def test_third_instance_never_collides_with_second(self) -> None:
        second = derive("--repo", "Xore/APIARY", "--instance", "2")
        third = derive("--repo", "Xore/APIARY", "--instance", "3")
        self.assertNotEqual(second["home"], third["home"])
        self.assertNotEqual(second["user"], third["user"])
        self.assertNotEqual(second["name"], third["name"])

    def test_explicit_name_overrides_the_derived_default_but_not_home_or_user(self) -> None:
        derived = derive("--repo", "Xore/APIARY", "--instance", "2", "--name", "custom-ci")
        self.assertEqual(derived["name"], "custom-ci")
        self.assertEqual(derived["home"], "/opt/github-ci-runner-2")
        self.assertEqual(derived["user"], "github-ci-runner-2")

    def test_every_instance_shares_the_same_labels(self) -> None:
        # Same labels across instances is what lets GitHub actually
        # schedule a queued job onto whichever instance is idle -- a
        # per-instance label would just recreate one queue per box.
        primary = derive("--repo", "Xore/APIARY")
        second = derive("--repo", "Xore/APIARY", "--instance", "2")
        self.assertEqual(primary["labels"], second["labels"])
        self.assertIn("honeypot-ci", primary["labels"])

    def test_missing_repo_still_fails_loudly(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError):
            derive()


if __name__ == "__main__":
    unittest.main(verbosity=2)
