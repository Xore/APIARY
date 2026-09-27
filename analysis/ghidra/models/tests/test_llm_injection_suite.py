#!/usr/bin/env python3
"""#3334: the host-side wiring that actually runs the injection corpus.

The suite itself (llm-worker/injection_suite.py) landed with its own unit
tests, but nothing ran it: no workflow, no timer, no unit. That is the exact
failure this repository has been bitten by repeatedly -- test_injection_gate.py
sat unwired and red for days, and two other test files were never run by CI at
all -- so these tests cover the *wiring*, not the model.

The runner is exercised for real against a stub `docker` on PATH. Everything it
touches is a temp directory and a fake compose invocation, so this runs in CI
on a runner with no GPU, no Ollama and no model.
"""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent          # analysis/ghidra/models
ROOT = HERE.parents[2]                                  # repository root
RUNNER = HERE / "run-llm-injection-suite.sh"
DIGEST = "bdbd181c33f2ed1b31c972991882db3cf4d192569092138a7d29e973cd9debe8"
UNITS = (
    "honeypot-llm-injection-suite.service",
    "honeypot-llm-injection-suite.timer",
    "honeypot-llm-injection-suite.path",
)


def report(passed=8, total=8, failed=()):
    return json.dumps(
        {
            "mode": "injection-suite",
            "model_digest": DIGEST,
            "passed": passed,
            "total": total,
            "cases": [
                {"name": name, "passed": False, "failures": ["severity=low"]}
                for name in failed
            ]
            + [{"name": f"case-{i}", "passed": True, "failures": []} for i in range(passed)],
        }
    )


class RunnerHarness(unittest.TestCase):
    """A checkout-shaped tree, a stub docker, and a record directory."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.repo = self.tmp / "repo"
        (self.repo / "llm-worker").mkdir(parents=True)
        (self.repo / "analysis" / "ghidra" / "models").mkdir(parents=True)
        for name in ("contracts.py", "injection_suite.py", "worker.py"):
            (self.repo / "llm-worker" / name).write_text(f"# {name}\n", encoding="utf-8")
        (self.repo / "llm-worker" / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        self.write_overlay(DIGEST)
        (self.repo / "analysis" / "ghidra" / "models" / "approved-models.json").write_text(
            json.dumps({"slots": {"sessions": {"artifact": {"digest": DIGEST}}}}), encoding="utf-8"
        )

        self.records = self.tmp / "records"
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        # The stub stands in for `docker compose ... run`: same stdout contract
        # (one JSON object on stdout) and same exit status, so the runner's own
        # parse-and-propagate logic is what is under test. The exit code is
        # read at run time, not baked in here, so one stub serves every case.
        self.docker_stub = self.bin / "docker"
        self.docker_stub.write_text(
            "#!/usr/bin/env bash\n"
            f"cat {self.tmp / 'stdout'}\n"
            'exit "${STUB_DOCKER_EXIT:-0}"\n',
            encoding="utf-8",
        )
        self.docker_stub.chmod(0o755)
        (self.tmp / "stdout").write_text(report(), encoding="utf-8")

    def write_overlay(self, digest):
        (self.repo / "llm-worker" / "docker-compose.synthetic-canary.yml").write_text(
            f"services:\n  llm-worker:\n    environment:\n"
            f"      LLM_EXPECTED_MODEL_DIGEST: '{digest}'\n",
            encoding="utf-8",
        )

    def run_runner(self, *args, digest=DIGEST, exit_code=0):
        env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "APIARY_REPO_DIR": str(self.repo),
            "LLM_INJECTION_SUITE_RECORD_DIR": str(self.records),
            "STUB_DOCKER_EXIT": str(exit_code),
        }
        return subprocess.run(
            [str(RUNNER), *args], capture_output=True, text=True, env=env, timeout=120
        )

    def fingerprint(self):
        path = self.records / ".fingerprint"
        return path.read_text(encoding="utf-8").strip() if path.is_file() else None

    def latest(self):
        path = self.records / "latest.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else None


class ConfigurationTests(RunnerHarness):
    def test_rejects_an_unknown_mode(self):
        result = self.run_runner("sometimes")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unknown mode", result.stderr)

    def test_rejects_a_missing_checkout_rather_than_reporting_a_pass(self):
        result = subprocess.run(
            [str(RUNNER), "weekly"],
            capture_output=True,
            text=True,
            env={**os.environ, "APIARY_REPO_DIR": str(self.tmp / "nowhere"),
                 "LLM_INJECTION_SUITE_RECORD_DIR": str(self.records)},
            timeout=120,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("APIARY_REPO_DIR", result.stderr)
        # The dangerous outcome is a green run that measured nothing.
        self.assertIsNone(self.latest())

    def test_refuses_a_pin_the_manifest_does_not_approve(self):
        # The overlay asserting a digest the manifest does not approve means the
        # suite would measure a model the governance record does not describe.
        self.write_overlay("0" * 64)
        result = self.run_runner("weekly")
        self.assertEqual(result.returncode, 2)
        self.assertIn("pin moved without a requalification", result.stderr)
        self.assertIsNone(self.latest())


class RunTests(RunnerHarness):
    def test_passing_run_records_the_report_and_the_fingerprint(self):
        result = self.run_runner("weekly")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("8/8 passed", result.stdout)
        self.assertEqual(self.latest()["model_digest"], DIGEST)
        self.assertIsNotNone(self.fingerprint())
        # Owner-only, like every other record this stack keeps.
        record = next(self.records.glob("injection-suite-*.json"))
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)

    def test_a_failed_case_fails_the_run_and_records_no_fingerprint(self):
        # The whole point of the corpus: a flipped verdict must be a non-zero
        # exit, and must not leave behind a "verified" claim.
        (self.tmp / "stdout").write_text(report(passed=7, total=8, failed=("benign-relabel",)), encoding="utf-8")
        result = self.run_runner("weekly")
        self.assertEqual(result.returncode, 1)
        self.assertIn("benign-relabel", result.stdout)
        self.assertIsNone(self.fingerprint())

    def test_worker_failure_propagates_even_with_a_clean_report(self):
        result = self.run_runner("weekly", exit_code=1)
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(self.fingerprint())

    def test_unparseable_output_is_kept_as_a_log_not_a_report(self):
        (self.tmp / "stdout").write_text("injection suite failed to run: model unreachable\n", encoding="utf-8")
        result = self.run_runner("weekly")
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(self.latest())
        log = next(self.records.glob("injection-suite-*.log"))
        self.assertIn("model unreachable", log.read_text(encoding="utf-8"))


class TriggerTests(RunnerHarness):
    def test_onchange_skips_when_nothing_changed(self):
        self.assertEqual(self.run_runner("weekly").returncode, 0)
        # install-analysis-host.sh rewrites the manifest byte-identically on
        # every routine re-sync, and that must not load the model again.
        result = self.run_runner("onchange")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unchanged since the last passing run", result.stdout)
        self.assertEqual(len(list(self.records.glob("injection-suite-*.json"))), 1)

    def test_onchange_reruns_after_the_pin_moves(self):
        self.assertEqual(self.run_runner("weekly").returncode, 0)
        new_digest = "1" * 64
        manifest = self.repo / "analysis" / "ghidra" / "models" / "approved-models.json"
        manifest.write_text(
            json.dumps({"slots": {"sessions": {"artifact": {"digest": new_digest}}}}), encoding="utf-8"
        )
        self.write_overlay(new_digest)
        result = self.run_runner("onchange")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(list(self.records.glob("injection-suite-*.json"))), 2)

    def test_onchange_reruns_after_the_suite_source_changes(self):
        # A moved digest is not the only reason to re-measure: an edited
        # SYSTEM_PROMPT or judge() invalidates the last verdict even though the
        # pin never moved.
        self.assertEqual(self.run_runner("weekly").returncode, 0)
        (self.repo / "llm-worker" / "injection_suite.py").write_text("# edited\n", encoding="utf-8")
        result = self.run_runner("onchange")
        self.assertNotIn("unchanged since the last passing run", result.stdout)
        self.assertEqual(len(list(self.records.glob("injection-suite-*.json"))), 2)

    def test_weekly_always_measures_even_when_nothing_changed(self):
        # The weekly leg exists to expose decay on a host nobody touched, so it
        # must not inherit the onchange skip.
        self.assertEqual(self.run_runner("weekly").returncode, 0)
        self.assertEqual(self.run_runner("weekly").returncode, 0)
        self.assertEqual(len(list(self.records.glob("injection-suite-*.json"))), 2)

    def test_a_failure_re_opens_the_onchange_leg(self):
        self.assertEqual(self.run_runner("weekly").returncode, 0)
        (self.tmp / "stdout").write_text(report(passed=7, total=8, failed=("benign-relabel",)), encoding="utf-8")
        self.assertEqual(self.run_runner("weekly").returncode, 1)
        result = self.run_runner("onchange")
        self.assertNotIn("unchanged since the last passing run", result.stdout)


class WiringTests(unittest.TestCase):
    """The units, the installer, and the docs that have to agree with them."""

    def test_units_exist(self):
        for name in UNITS:
            self.assertTrue((HERE / name).is_file(), f"missing unit {name}")

    def test_both_triggers_exist_and_agree_on_the_template_unit(self):
        timer = (HERE / "honeypot-llm-injection-suite.timer").read_text(encoding="utf-8")
        path = (HERE / "honeypot-llm-injection-suite.path").read_text(encoding="utf-8")
        self.assertIn("Unit=honeypot-llm-injection-suite@weekly.service", timer)
        self.assertIn("Unit=honeypot-llm-injection-suite@onchange.service", path)
        # The two instances are the template's only argument, so the template
        # must pass %i through or both legs silently run the same mode.
        service = (HERE / "honeypot-llm-injection-suite.service").read_text(encoding="utf-8")
        self.assertIn("run-llm-injection-suite.sh %i", service)

    def test_path_watches_files_the_installer_actually_deploys(self):
        installer = (ROOT / "analysis" / "ghidra" / "install-analysis-host.sh").read_text(encoding="utf-8")
        # The installer writes these under $target, which is /opt/honeypot-ghidra.
        self.assertIn('target=/opt/honeypot-ghidra', installer)
        for deployed in (
            '"$target/models/approved-models.json"',
            '"$target/models/llm-worker-synthetic-canary.yml"',
        ):
            self.assertIn(deployed, installer, f"{deployed} is watched but never installed")
        path = (HERE / "honeypot-llm-injection-suite.path").read_text(encoding="utf-8")
        self.assertIn("PathChanged=/opt/honeypot-ghidra/models/approved-models.json", path)
        self.assertIn("PathChanged=/opt/honeypot-ghidra/models/llm-worker-synthetic-canary.yml", path)

    def test_installer_enables_both_triggers_and_the_record_dir(self):
        installer = (ROOT / "analysis" / "ghidra" / "install-analysis-host.sh").read_text(encoding="utf-8")
        for expected in (
            "honeypot-llm-injection-suite@.service",
            "systemctl enable --now honeypot-llm-injection-suite.timer",
            "systemctl enable --now honeypot-llm-injection-suite.path",
            "install -d -m 0700 -o root -g root /var/lib/honeypot-ghidra/injection-suite",
        ):
            self.assertIn(expected, installer)
        # The unit grants exactly one writable path; a record directory it does
        # not grant would fail the run under ProtectSystem=strict.
        service = (HERE / "honeypot-llm-injection-suite.service").read_text(encoding="utf-8")
        self.assertIn("ReadWritePaths=/var/lib/honeypot-ghidra/injection-suite", service)
        self.assertIn("ProtectSystem=strict", service)

    def test_env_example_documents_the_knobs_the_unit_reads(self):
        example = (ROOT / "analysis" / "ghidra" / "worker" / "honeypot-ghidra.default.example").read_text(
            encoding="utf-8"
        )
        for knob in ("APIARY_REPO_DIR", "LLM_INJECTION_SUITE_RECORD_DIR", "LLM_INJECTION_SUITE_RETENTION_DAYS"):
            self.assertIn(f"{knob}=", example)

    def test_record_doc_is_linked_from_the_documentation_map(self):
        # check-docs-reachable.py fails a doc nothing links to.
        docs_map = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
        self.assertIn("llm-injection-suite-record.md", docs_map)


if __name__ == "__main__":
    unittest.main()
