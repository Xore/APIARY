#!/usr/bin/env python3
"""Tests for validate_manifest.py's coverage gaps (#2038).

Each check is exercised against a synthetic fixture tree (CORPUS_DIR
monkeypatched to a tempdir) so a real cross-compiler toolchain is never
needed -- matching this validator's own "ordinary CI, stdlib-only" contract.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "corpus"))

import validate_manifest as vm  # noqa: E402


def reset_failures():
    vm.failures = 0


class RequiredForbiddenOverlapTest(unittest.TestCase):
    def setUp(self):
        reset_failures()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.corpus_dir = Path(self.tmp.name)
        self.orig_corpus_dir = vm.CORPUS_DIR
        vm.CORPUS_DIR = self.corpus_dir
        self.addCleanup(lambda: setattr(vm, "CORPUS_DIR", self.orig_corpus_dir))

    def write_rubric(self, cases):
        (self.corpus_dir / "rev_cases_v2_rubric.json").write_text(json.dumps({"cases": cases}))

    def test_a_genuine_collision_fails_naming_both_terms(self):
        """An alternative with no negation protection, unlike safe_strcpy's
        'not vulnerable', is a real collision -- forbidden_hit fires on it
        exactly as it would on a model's answer."""
        self.write_rubric({
            "bad_case": {
                "required_groups": [["vulnerable"]],
                "forbidden": ["vulnerable"],
            }
        })
        vm.check_required_forbidden_overlap()
        self.assertEqual(vm.failures, 1)

    def test_negation_protected_alternative_does_not_false_positive(self):
        """#2517: 'not vulnerable' containing 'vulnerable' is not a real
        collision under the polarity-aware runtime scorer -- this check must
        not regress to the naive substring false positive #2517 fixed."""
        self.write_rubric({
            "safe_strcpy_shaped": {
                "required_groups": [["not vulnerable", "not exploitable", "safe"]],
                "forbidden": ["vulnerable", "exploitable"],
            }
        })
        vm.check_required_forbidden_overlap()
        self.assertEqual(vm.failures, 0)

    def test_identifier_glue_does_not_false_positive(self):
        """#2037/#2517: naming the twin case ('vulnerable_strcpy') inside a
        required alternative is not a collision either."""
        self.write_rubric({
            "twin_reference": {
                "required_groups": [["same shape as vulnerable_strcpy"]],
                "forbidden": ["vulnerable"],
            }
        })
        vm.check_required_forbidden_overlap()
        self.assertEqual(vm.failures, 0)

    def test_no_forbidden_list_is_never_flagged(self):
        self.write_rubric({
            "no_forbidden": {"required_groups": [["vulnerable"]], "forbidden": []}
        })
        vm.check_required_forbidden_overlap()
        self.assertEqual(vm.failures, 0)


class RubricWithoutBuildTest(unittest.TestCase):
    def setUp(self):
        reset_failures()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.corpus_dir = Path(self.tmp.name)
        self.orig_corpus_dir = vm.CORPUS_DIR
        vm.CORPUS_DIR = self.corpus_dir
        self.addCleanup(lambda: setattr(vm, "CORPUS_DIR", self.orig_corpus_dir))
        (self.corpus_dir / "harness").mkdir()
        (self.corpus_dir / "verify_semantics.py").write_text("")

    def test_rubric_entry_with_no_matching_build_fails(self):
        """#2038 gap 2: a rubric entry whose fixture was deleted or never
        built used to pass every check -- record_baseline.py iterates
        *builds*, so it would just silently never be scored."""
        manifest = {"builds": [{"case_source": "a.c"}]}
        (self.corpus_dir / "rev_cases_v2_rubric.json").write_text(json.dumps({
            "cases": {"a": {}, "orphaned_case": {}}
        }))
        vm.check_rubric_and_harness_coverage(manifest)
        self.assertGreaterEqual(vm.failures, 1)

    def test_full_coverage_both_directions_passes(self):
        manifest = {"builds": [{"case_source": "a.c"}]}
        (self.corpus_dir / "rev_cases_v2_rubric.json").write_text(json.dumps({
            "cases": {"a": {}}
        }))
        (self.corpus_dir / "verify_semantics.py").write_text("EXCLUDED: a -- no semantic harness")
        vm.check_rubric_and_harness_coverage(manifest)
        self.assertEqual(vm.failures, 0)


class ComboCompletenessTest(unittest.TestCase):
    def setUp(self):
        reset_failures()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.corpus_dir = Path(self.tmp.name)
        self.orig_corpus_dir = vm.CORPUS_DIR
        vm.CORPUS_DIR = self.corpus_dir
        self.addCleanup(lambda: setattr(vm, "CORPUS_DIR", self.orig_corpus_dir))
        (self.corpus_dir / "src").mkdir()
        (self.corpus_dir / "src" / "a.c").write_text("int main(){return 0;}")

    def full_build(self, toolchain, opt):
        return {
            "case_source": "a.c", "split": "train", "toolchain": toolchain, "arch": "x86_64",
            "compiler": "gcc", "compiler_version": "1", "target_triple": "x86_64-linux-gnu",
            "opt_level": opt, "compile_command": "gcc",
            "unstripped": {"path": "a", "sha256": "0" * 64, "size": 1, "disassembly": "mov"},
            "stripped": {"path": "a.s", "sha256": "1" * 64, "size": 1, "disassembly": "mov"},
        }

    def full_grid_builds(self):
        return [self.full_build(tc, opt)
                for tc in vm.EXPECTED_TOOLCHAINS for opt in vm.EXPECTED_OPT_LEVELS]

    def test_a_missing_combo_fails(self):
        """#2038 gap 3: a partially regenerated manifest -- a toolchain
        dropped mid-run -- must not pass just because every source has >=1
        build."""
        builds = self.full_grid_builds()[:-1]  # drop exactly one combo
        (self.corpus_dir / "manifest.json").write_text(json.dumps({"builds": builds}))
        vm.check_manifest()
        self.assertGreaterEqual(vm.failures, 1)

    def test_the_complete_grid_passes(self):
        builds = self.full_grid_builds()
        (self.corpus_dir / "manifest.json").write_text(json.dumps({"builds": builds}))
        vm.check_manifest()
        self.assertEqual(vm.failures, 0)


class RealCorpusPassesCleanlyTest(unittest.TestCase):
    """#2038 acceptance criterion 4: all three checks fire in ordinary CI
    (stdlib-only) against the real, committed corpus -- not just synthetic
    fixtures."""

    def test_main_returns_zero_against_the_committed_corpus(self):
        reset_failures()
        vm.CORPUS_DIR = vm.CORPUS_DIR  # already the real path at import time
        rc = vm.main()
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
