#!/usr/bin/env python3
"""Pin the #3318 coverage ratchet and test-discovery guard, without a coverage run.

The issue asks for two proofs -- that the ratchet fails a deliberate drop, and
that the discovery guard catches a canary. Both were demonstrated by hand
before this file existed; a demonstration in a PR description is a transcript,
and a transcript does not stop the next person from widening the tolerance,
loosening a comparison, or quietly deleting the CI step. So each proof is
pinned here as a case that fails if the property regresses.

Three groups, and why they need different fixtures:

* `BaselineContract` asserts things about the committed files with no
  execution at all -- the baseline's shape, the tolerance, the scope globs,
  and the fact that package.json still declares the commands. This is the
  anti-weakening half. It is the group that would notice a PR which raised
  tolerance.pctPoints to make its own run go green, and it needs neither node
  nor an install, so it cannot skip.

* `RatchetBites` drives the real `coverage-ratchet.mjs` with synthetic
  coverage summaries through its `--summary` flag, against the real committed
  baseline. No coverage run is needed, and every case is a decision the script
  has to get right: the arithmetic, the two independent gates, and the refusal
  to pass on a missing measurement or an unusable baseline. Needs node.

* `DiscoveryGuard` runs the real guard over the real package tree, twice: once
  as it stands, and once with a planted canary. Needs node AND an installed
  package, because the guard's whole design is to ask the real runners what
  they collect rather than reimplement their globs -- with no install there is
  nothing to ask, and the guard correctly exits 2 rather than guessing.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# arcane/home/honeypot-dashboard/ is Arcane's home directory, so `home` is a
# real path segment and not a typo to tidy away.
PACKAGE = ROOT / "arcane" / "home" / "honeypot-dashboard" / "frontend-next"
RATCHET = PACKAGE / "scripts" / "coverage-ratchet.mjs"
GUARD = PACKAGE / "scripts" / "test-discovery-guard.mjs"
BASELINE = PACKAGE / "coverage-baseline.json"
VITEST_CONFIG = PACKAGE / "vitest.config.ts"

# The canary is planted in the package tree on purpose -- the guard walks it,
# so a canary anywhere else would be testing nothing. .spec.ts rather than
# .test.ts for the reason the guard's own comment gives: vitest's include
# globs only name the .test infix, so this is the shape a test file can take
# and never be collected, and a guard that knew only .test would pass it.
CANARY_REL = "src/lib/__test_3318_discovery_canary.spec.ts"

# Same skip conditions as test_3315_image_revision.py, for the same reason: the
# scripts/tests lane has no guarantee of an npm install, and a test that fails
# on a missing toolchain is a test that reports the wrong problem.
HAVE_NODE = shutil.which("node") is not None
HAVE_INSTALL = (PACKAGE / "node_modules" / "vitest" / "vitest.mjs").is_file()


def run_ratchet(summary: dict | None, cwd: Path = PACKAGE, args: tuple[str, ...] = ()):
    """Run the real ratchet, optionally over a synthetic summary. Returns (rc, output)."""
    tmp = None
    argv = [str(RATCHET), *args]
    if summary is not None:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump(summary, tmp)
        tmp.close()
        argv += ["--summary", tmp.name]
    try:
        proc = subprocess.run(["node", *argv], cwd=cwd, capture_output=True, text=True, timeout=120)
        return proc.returncode, proc.stdout + proc.stderr
    finally:
        if tmp is not None:
            Path(tmp.name).unlink(missing_ok=True)


def summary_from(covered_delta: int = 0, total_delta: int = 0, files: int = 127) -> dict:
    """A coverage summary shaped like the real one, moved by the given deltas.

    Shaped rather than hand-written per case so the numbers in each test's
    name stay the only place the arithmetic is stated. `files` controls the
    per-file entry count, because the ratchet reports a scope change from it.
    """
    base = json.loads(BASELINE.read_text())
    totals = {}
    for metric, t in base["totals"].items():
        covered = t["covered"] + (covered_delta if metric in ("lines", "branches") else 0)
        total = t["total"] + (total_delta if metric in ("lines", "branches") else 0)
        totals[metric] = {
            "covered": covered,
            "total": total,
            "skipped": 0,
            "pct": round(100 * covered / total, 2) if total else 100,
        }
    doc = {"total": totals}
    for i in range(files):
        doc[f"../src/filler{i:03d}.ts"] = totals["lines"]
    return doc


class BaselineContract(unittest.TestCase):
    """What the committed files must keep saying. No execution, so no skip."""

    def setUp(self):
        self.baseline = json.loads(BASELINE.read_text())
        self.package = json.loads((PACKAGE / "package.json").read_text())

    def test_baseline_is_well_formed(self):
        for key in ("about", "recordedAt", "measuredWith", "scope", "tolerance", "files", "totals"):
            self.assertIn(key, self.baseline, f"coverage-baseline.json lost {key!r}")
        self.assertGreater(self.baseline["files"], 0, "a baseline measuring zero files is not a baseline")
        for metric in ("lines", "branches"):
            total = self.baseline["totals"][metric]
            self.assertGreater(total["total"], 0)
            self.assertLessEqual(total["covered"], total["total"])
            # pct is recorded for the human reading the diff; the ratchet
            # recomputes it from the counts, so the two must agree here or the
            # committed file is describing something the script will not do.
            self.assertAlmostEqual(total["pct"], 100 * total["covered"] / total["total"], places=3)

    def test_scope_is_src_only_and_says_so(self):
        # The issue's scope, in the file that records the measurement: src/
        # only, and explicitly not tests, not config, not generated.
        self.assertIn("src/", self.baseline["scope"])
        for excluded in (".test.", ".spec.", "routeTree.gen.ts"):
            self.assertIn(excluded, self.baseline["scope"], f"scope no longer excludes {excluded}")

    def test_tolerance_has_not_been_loosened(self):
        tolerance = self.baseline["tolerance"]
        # Zero, exactly. This is the gate that fires when a change removes
        # tested behaviour, and it is the one a "just this once" PR reaches for
        # first. Loosening it is legal only by changing this assertion in the
        # same commit, which is the point.
        self.assertEqual(
            tolerance["coveredCount"],
            0,
            "tolerance.coveredCount was raised. It is 0 so that no amount of "
            "denominator manipulation can absorb a lost covered line.",
        )
        # Bounded below as well as above: a token value like 0.05 would pass a
        # <= 1.0 assertion while letting any real regression through.
        self.assertGreaterEqual(
            tolerance["pctPoints"],
            0.5,
            "tolerance.pctPoints was shrunk to a value that cannot catch a regression",
        )
        self.assertLessEqual(
            tolerance["pctPoints"],
            1.0,
            "tolerance.pctPoints was widened beyond the value this issue set",
        )

    def test_commands_and_provider_are_still_declared(self):
        scripts = self.package["scripts"]
        for name in ("test:coverage", "test:discovery", "coverage:ratchet", "coverage:baseline"):
            self.assertIn(name, scripts, f"package.json lost the {name} script")
        self.assertIn("@vitest/coverage-v8", self.package["devDependencies"])
        # The rule this lane is held to: no coverage tool beyond v8.
        others = [d for d in self.package["devDependencies"] if "coverage" in d and d != "@vitest/coverage-v8"]
        self.assertEqual(others, [], f"a second coverage provider appeared: {others}")

    def test_coverage_config_excludes_tests_and_generated(self):
        # Asserted as text because that is where the scope actually lives, and
        # a config that quietly widened its include globs would move every
        # number in the baseline without failing anything else.
        config = VITEST_CONFIG.read_text()
        self.assertIn("coverage", config)
        for glob in ("**/*.test.ts", "**/*.test.tsx", "**/*.spec.ts", "**/*.spec.tsx", "src/routeTree.gen.ts"):
            self.assertIn(glob, config, f"vitest.config.ts coverage.exclude lost {glob!r}")
        self.assertIn("src/**/*.ts", config, "coverage.include no longer covers src/**/*.ts")


@unittest.skipUnless(HAVE_NODE, "node is not on PATH")
class RatchetBites(unittest.TestCase):
    """The ratchet's decisions, driven through the real script."""

    def test_measurement_equal_to_baseline_passes(self):
        rc, out = run_ratchet(summary_from())
        self.assertEqual(rc, 0, out)
        self.assertIn("no regression", out)

    def test_improvement_passes(self):
        # A ratchet that fails on a rise is a ratchet people turn off.
        rc, out = run_ratchet(summary_from(covered_delta=40, files=127))
        self.assertEqual(rc, 0, out)

    def test_one_covered_line_lost_fails_even_though_the_percentage_holds(self):
        # THE case. One covered line is ~0.0136pp, far inside the 1.0pp
        # tolerance, so the percentage gate alone would wave this through --
        # which is exactly why tolerance.coveredCount exists. If this ever
        # passes, the ratchet has stopped being a non-regression guard and
        # become a rounding check.
        rc, out = run_ratchet(summary_from(covered_delta=-1))
        self.assertEqual(rc, 1, out)
        self.assertIn("lost 1 covered line", out)
        self.assertIn("no tolerance allowed", out)

    def test_one_covered_branch_lost_fails(self):
        rc, out = run_ratchet(summary_from(covered_delta=-1))
        self.assertEqual(rc, 1, out)
        self.assertIn("lost 1 covered branch", out)

    def test_pct_drop_past_tolerance_fails_with_the_covered_count_intact(self):
        # The other direction: a change that ADDS untested source. No covered
        # line is lost, so the count gate cannot see it -- the percentage gate
        # exists for exactly this.
        #
        # The delta is derived rather than guessed, because how much new
        # uncovered code it takes to move this gate depends on where the
        # baseline sits, and at ~11% that is a lot: the denominator has to
        # grow past covered/(pct-tolerance) before the percentage moves by
        # tolerance at all. A gate that is coarse in one direction and exact in
        # the other is the honest shape of a low-coverage ratchet, and
        # tolerance.coveredCount is what makes the other direction exact.
        base = json.loads(BASELINE.read_text())["totals"]["lines"]
        pct = base["pct"] / 100
        tolerance = json.loads(BASELINE.read_text())["tolerance"]["pctPoints"] / 100
        needed = int(base["covered"] / (pct - tolerance)) - base["total"] + 1
        self.assertGreater(needed, 0, "a 1.0pp tolerance should need real new code to trip at this baseline")
        rc, out = run_ratchet(summary_from(total_delta=needed))
        self.assertEqual(rc, 1, out)
        self.assertIn("fell", out)
        self.assertIn("pp, past the", out)

    def test_new_untested_source_inside_tolerance_does_not_fail(self):
        # The same arithmetic, the other side: a new route's worth of uncovered
        # lines is not a regression and must not turn the gate red. Without
        # this, the honest fix for a red ratchet would be to stop running it.
        rc, out = run_ratchet(summary_from(total_delta=40))
        self.assertEqual(rc, 0, out)

    def test_small_denominator_change_alone_does_not_fail(self):
        # A file leaving src/ moves the denominator. If it was uncovered, the
        # percentage goes UP and nothing was lost -- so this passes, and the
        # script says the scope moved rather than letting a reader assume the
        # number held still for the reason they think.
        rc, out = run_ratchet(summary_from(total_delta=-100, files=126))
        self.assertEqual(rc, 0, out)
        self.assertIn("scope changed", out)

    def test_missing_summary_fails_loudly_rather_than_passing(self):
        rc, out = run_ratchet(None, args=("--summary", "/nonexistent/coverage-summary.json"))
        self.assertEqual(rc, 2, out)
        self.assertIn("cannot read the coverage summary", out)
        self.assertIn("test:coverage", out)

    def test_unusable_baseline_fails_loudly(self):
        # A baseline that is not a baseline -- truncated, hand-edited into
        # nonsense, or half-merged -- must not be silently replaced or
        # silently accepted. Copied into a scratch package root because the
        # script resolves the baseline next to itself.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            shutil.copy(RATCHET, root / "scripts" / RATCHET.name)
            (root / "coverage-baseline.json").write_text(json.dumps({"totals": {"lines": {"pct": 60}}}))
            summary = root / "summary.json"
            summary.write_text(json.dumps(summary_from()))
            proc = subprocess.run(
                ["node", str(root / "scripts" / RATCHET.name), "--summary", str(summary)],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("not a usable baseline", proc.stdout + proc.stderr)

    def test_update_writes_the_measurement_it_was_given(self):
        # --update must still validate the baseline it is about to replace, so
        # a regeneration over a broken one fails rather than healing it
        # silently. And it must write the measured numbers, not a target.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            shutil.copy(RATCHET, root / "scripts" / RATCHET.name)
            shutil.copy(BASELINE, root / "coverage-baseline.json")
            summary = root / "summary.json"
            summary.write_text(json.dumps(summary_from(covered_delta=7)))
            proc = subprocess.run(
                ["node", str(root / "scripts" / RATCHET.name), "--update", "--summary", str(summary)],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            written = json.loads((root / "coverage-baseline.json").read_text())
            self.assertEqual(written["totals"]["lines"]["covered"], json.loads(BASELINE.read_text())["totals"]["lines"]["covered"] + 7)
            # The tolerance is not a measurement: regenerating must not move it.
            self.assertEqual(written["tolerance"], json.loads(BASELINE.read_text())["tolerance"])


@unittest.skipUnless(HAVE_NODE and HAVE_INSTALL, "node or an npm install of frontend-next is missing")
class DiscoveryGuard(unittest.TestCase):
    """The guard over the real tree, and over the real tree plus a canary."""

    def test_real_tree_is_clean(self):
        proc = subprocess.run(["node", str(GUARD)], cwd=PACKAGE, capture_output=True, text=True, timeout=300)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("every test-shaped file is collected", proc.stdout)
        # Both runners must have been asked, or the guard is only half a guard.
        self.assertIn("vitest collects", proc.stdout)
        self.assertIn("playwright collects", proc.stdout)

    def test_canary_is_caught_and_then_removed(self):
        canary = PACKAGE / CANARY_REL
        self.assertFalse(canary.exists(), f"{CANARY_REL} already exists; refusing to overwrite it")
        canary.parent.mkdir(parents=True, exist_ok=True)
        canary.write_text("import { expect, it } from 'vitest'\nit('canary', () => expect(1).toBe(1))\n")
        self.addCleanup(lambda: canary.unlink(missing_ok=True))
        proc = subprocess.run(["node", str(GUARD)], cwd=PACKAGE, capture_output=True, text=True, timeout=300)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        # The diagnostic has to name the file, or a red run sends the reader
        # looking for it.
        self.assertIn(CANARY_REL, proc.stdout + proc.stderr)
        # And the tree is clean again afterwards -- a guard proof that leaves
        # evidence behind is a guard proof the next run trips over.
        canary.unlink()
        self.assertFalse(canary.exists())
        again = subprocess.run(["node", str(GUARD)], cwd=PACKAGE, capture_output=True, text=True, timeout=300)
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)


if __name__ == "__main__":
    unittest.main()
