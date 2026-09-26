#!/usr/bin/env python3
"""Behaviour tests for scripts/node-runtime-major.sh (#3331).

The script is the anti-drift mechanism, so what is worth pinning is not
"it prints 22 today" -- the Dockerfile can move and the test should follow
it -- but the parse and the refusals. Each of these cases is a way the
parse could quietly go wrong and hand CI a version nobody ships:

- a semver tag (node:24.1-alpine) read as major "24.1", which setup-node
  would resolve to nothing;
- a variant-less node:20 rejected outright, or an image reference rebuilt
  from a re-parsed variant instead of reused verbatim;
- a `#FROM node:99-...` comment read as a stage, pinning CI to a node that
  does not exist;
- build and runtime stages on different majors silently resolved to
  whichever came first -- the artifact would be built by one node and
  served by another, and CI would be green about neither;
- a ref carrying shell metacharacters reaching the docker command line it
  is interpolated into.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "node-runtime-major.sh"
FRONTEND_DOCKERFILE = (
    Path(__file__).resolve().parents[2]
    / "arcane/home/honeypot-dashboard/frontend-next/Dockerfile"
)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def run(*args: str, github_output: str | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if github_output is None:
        env.pop("GITHUB_OUTPUT", None)
    else:
        env["GITHUB_OUTPUT"] = github_output
    return subprocess.run(
        ["bash", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=env,
    )


class DerivationTests(unittest.TestCase):
    def _derive(self, dockerfile: str) -> tuple[subprocess.CompletedProcess, dict[str, str]]:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Dockerfile"
            path.write_text(dockerfile)
            out = Path(tmp) / "gh-output"
            proc = run(str(path), github_output=str(out))
            outputs = {}
            if out.exists():
                for line in out.read_text().splitlines():
                    key, _, value = line.partition("=")
                    outputs[key] = value
            return proc, outputs

    def test_build_and_runtime_stage_on_one_major(self):
        proc, outputs = self._derive(
            f"FROM node:22-alpine@{DIGEST_A} AS build\nFROM node:22-alpine@{DIGEST_B}\n"
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(outputs, {"node-version": "22", "node-image": "node:22-alpine"})

    def test_semver_tag_yields_the_bare_major(self):
        """node:24.1-alpine is major 24 -- not "24.1", which resolves to nothing."""
        proc, outputs = self._derive(
            f"FROM node:24.1-alpine@{DIGEST_A} AS build\nFROM node:24.1-alpine@{DIGEST_B}\n"
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(outputs["node-version"], "24")
        # The image keeps the tag as written: a re-parsed variant would emit
        # node:24-1-alpine, an image that does not exist.
        self.assertEqual(outputs["node-image"], "node:24.1-alpine")

    def test_variantless_tag_is_accepted(self):
        proc, outputs = self._derive("FROM node:20\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(outputs, {"node-version": "20", "node-image": "node:20"})

    def test_indented_from_and_digest_are_tolerated(self):
        proc, outputs = self._derive(
            f"  FROM node:22-alpine@{DIGEST_A} AS build\n"
            f"FROM node:22-alpine@{DIGEST_A}\n"
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(outputs["node-version"], "22")

    def test_commented_from_line_is_not_a_stage(self):
        proc, outputs = self._derive(
            "# FROM node:99-alpine AS old\n"
            f"FROM node:22-alpine@{DIGEST_A} AS build\n"
            f"FROM node:22-alpine@{DIGEST_B}\n"
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(outputs["node-version"], "22")

    def test_first_stage_supplies_the_image(self):
        """`npm ci` must run in the image that builds, not the one that serves."""
        proc, outputs = self._derive(
            f"FROM node:22-alpine@{DIGEST_A} AS build\nFROM node:22-bookworm@{DIGEST_B}\n"
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(outputs["node-image"], "node:22-alpine")

    def test_disagreeing_majors_are_refused(self):
        proc, _ = self._derive(
            f"FROM node:24-alpine@{DIGEST_A} AS build\nFROM node:22-alpine@{DIGEST_B}\n"
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("disagree", proc.stderr)

    def test_dockerfile_without_a_node_stage_is_refused(self):
        proc, _ = self._derive("FROM golang:1.26 AS build\nFROM scratch\n")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("no 'FROM node:", proc.stderr)

    def test_unversioned_tag_is_refused(self):
        """node:latest would make every run a different node, silently."""
        proc, _ = self._derive("FROM node:latest\n")
        self.assertNotEqual(proc.returncode, 0)

    def test_shell_metacharacters_cannot_reach_the_output(self):
        """The image ref is interpolated into a `docker run` line downstream."""
        proc, _ = self._derive("FROM node:22-alpine; rm -rf /\n")
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("rm -rf", proc.stdout)

    def test_missing_dockerfile_is_refused(self):
        proc = run("/nonexistent/Dockerfile")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("no such Dockerfile", proc.stderr)

    def test_silent_without_github_output(self):
        """Local use must not append a literal 'node-version=22' to stdout."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "Dockerfile"
            path.write_text("FROM node:22-alpine\n")
            proc = run(str(path))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn("node-version=", proc.stdout)
            self.assertIn("node 22", proc.stdout)


class RealDockerfileTests(unittest.TestCase):
    def test_defaults_to_the_frontend_dockerfile(self):
        proc = run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("frontend-next/Dockerfile", proc.stdout)

    def test_frontend_dockerfile_resolves(self):
        proc = run(str(FRONTEND_DOCKERFILE))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertRegex(proc.stdout, r"^node \d+ \(node:")


if __name__ == "__main__":
    unittest.main()
