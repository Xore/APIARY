#!/usr/bin/env python3
"""Synthetic-only tests for local-model governance; no Ollama or GPU required."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent.parent
# #670 moved approval-record.md into docs/ alongside every other README/plan
# doc, but left this drift-detection test reading it from the code
# directory it used to live in -- confirmed live via CI (#720): every PR's
# "Scripts and Compose" check now fails with FileNotFoundError regardless
# of what it actually touches, since this test runs unconditionally.
# install-analysis-host.sh already deploys from the new docs/ path, so this
# test was the one file the reorg missed, not the other way around.
DOCS_DIR = HERE.parents[2] / "docs" / "analysis" / "ghidra" / "models"
SPEC = importlib.util.spec_from_file_location("model_governance", HERE / "model-governance.py")
governance = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(governance)


class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.manifest = governance.read_json(HERE / "approved-models.json")

    def snapshot(self):
        # One entry per unique tag, not per slot: this mirrors real `ollama
        # list` output, which has exactly one row for a given installed
        # model regardless of how many manifest slots point at it. Slots
        # can share a tag (e.g. issue #568's promotion put qwen3:14b in all
        # three slots) -- building one fabricated "installed copy" per slot
        # here would silently diverge from what a live snapshot ever looks
        # like, and masked real drift-detection bugs behind an
        # unrealistic 1:1 slot:model assumption when that test was written.
        by_tag: dict[str, dict] = {}
        for slot in self.manifest["slots"].values():
            artifact = slot["artifact"]
            by_tag[artifact["tag"]] = {
                "name": artifact["tag"],
                "digest": artifact["digest"],
                "size": artifact["size_bytes"],
                "details": {
                    "family": artifact["family"],
                    "parameter_size": artifact["parameter_size"],
                    "quantization_level": artifact["quantization"],
                },
            }
        return {
            "models": list(by_tag.values()),
            "runtime": {
                "ollama_version": self.manifest["runtime"]["ollama_version"],
                "image_reference": self.manifest["runtime"]["ollama_image"],
                "image_id": self.manifest["runtime"]["ollama_image_id"],
                "repo_digests": [self.manifest["runtime"]["ollama_repo_digest"]],
                "environment": [
                    f"{key}={value}" for key, value in self.manifest["runtime"]["environment"].items()
                ],
            },
            "host": {
                key: self.manifest["approved_host"][key]
                for key in ("gpu_uuid", "gpu", "gpu_memory_mib", "driver", "compute_capability")
            },
        }

    def report(self):
        result = {"benchmark": self.manifest["benchmark_version"], "slots": {}}
        for name, slot in self.manifest["slots"].items():
            cases = {
                case_name: {
                    "score": gate["minimum_score"],
                    "schema_ok": True,
                    "injection_ok": True,
                    "critical_ok": True,
                }
                for case_name, gate in slot["gates"]["cases"].items()
            }
            result["slots"][name] = {
                "model": slot["artifact"]["tag"],
                "artifact": {"digest": slot["artifact"]["digest"]},
                "qualification_request": json.loads(json.dumps(slot["qualification_request"])),
                "contract": json.loads(json.dumps(slot["contract"])),
                "score": {"percent": slot["gates"]["minimum_percent"]},
                "context_probe": {"passed": True},
                "cases": cases,
            }
        return result

    def test_approved_snapshot_has_no_drift(self):
        status = governance.evaluate_drift(self.manifest, self.snapshot())
        self.assertEqual(status["overall"], "approved")
        self.assertTrue(status["advisory_only"])
        self.assertEqual(
            governance.approval_record(self.manifest),
            (DOCS_DIR / "approval-record.md").read_text(encoding="utf-8"),
        )

    def test_digest_and_host_drift_are_independently_visible(self):
        ghidra_tag = self.manifest["slots"]["ghidra"]["artifact"]["tag"]
        # Every slot sharing this tag is really the same installed artifact
        # (see snapshot()'s comment) -- corrupting it must show drift on
        # every one of those slots, not just "ghidra".
        affected_slots = [
            name for name, slot in self.manifest["slots"].items()
            if slot["artifact"]["tag"] == ghidra_tag
        ]
        snapshot = self.snapshot()
        entry = next(m for m in snapshot["models"] if m["name"] == ghidra_tag)
        entry["digest"] = "0" * 64
        snapshot["host"]["driver"] = "changed"
        status = governance.evaluate_drift(self.manifest, snapshot)
        self.assertEqual(status["overall"], "drift")
        for slot_name in affected_slots:
            self.assertIn("model_digest_changed", status["slots"][slot_name]["codes"])
        self.assertIn("host_driver_changed", status["host"]["codes"])

    # --- #2394: the GPU is verified by identity, never by position ----------

    def test_removed_pinned_card_is_approved_gpu_absent(self):
        # The collected shape when nvidia-smi --id=<approved> reports no such
        # device (driver 595.84: exit 6, "No devices were found"). Distinct
        # from gpu_telemetry_unavailable, and no fallback comparison against
        # whichever other card is present.
        snapshot = self.snapshot()
        snapshot["host"] = {
            "approved_gpu_absent": True,
            "expected_gpu_uuid": self.manifest["approved_host"]["gpu_uuid"],
        }
        status = governance.evaluate_drift(self.manifest, snapshot)
        self.assertEqual(status["overall"], "drift")
        self.assertEqual(status["host"], {"status": "drift", "codes": ["approved_gpu_absent"]})

    def test_wrong_card_identity_drifts_even_when_name_and_driver_match(self):
        # Index-order sampling's failure mode: every field the old schema
        # compared looks right, but a different physical card produced them.
        snapshot = self.snapshot()
        snapshot["host"]["gpu_uuid"] = "GPU-deadbeef-0000-0000-0000-000000000000"
        status = governance.evaluate_drift(self.manifest, snapshot)
        self.assertEqual(status["overall"], "drift")
        self.assertEqual(status["host"]["codes"], ["host_gpu_uuid_changed"])

    def test_legacy_snapshot_without_recorded_uuid_cannot_pass_as_approved(self):
        # Pre-#2394 snapshots carry name/memory/driver only; they must drift
        # until re-collected under the new schema rather than silently
        # continue index-order sampling.
        snapshot = self.snapshot()
        del snapshot["host"]["gpu_uuid"]
        status = governance.evaluate_drift(self.manifest, snapshot)
        self.assertEqual(status["overall"], "drift")
        self.assertEqual(status["host"]["codes"], ["host_gpu_uuid_changed"])

    def test_unverified_identity_snapshot_is_drift(self):
        snapshot = self.snapshot()
        snapshot["host"] = {"gpu_identity_unverified": True}
        status = governance.evaluate_drift(self.manifest, snapshot)
        self.assertEqual(status["overall"], "drift")
        self.assertEqual(status["host"]["codes"], ["approved_gpu_uuid_missing"])

    def test_container_reservation_mismatch_is_independently_visible(self):
        uuid = self.manifest["approved_host"]["gpu_uuid"]
        snapshot = self.snapshot()
        # The compose overlay not applying at all.
        snapshot["runtime"]["container_gpu_device_ids"] = []
        drifted = governance.evaluate_drift(self.manifest, snapshot)
        self.assertEqual(drifted["overall"], "drift")
        self.assertEqual(drifted["runtime"]["codes"], ["ollama_container_gpu_reservation_changed"])
        # A different card reserved than the one approved.
        snapshot["runtime"]["container_gpu_device_ids"] = ["GPU-deadbeef-0000-0000-0000-000000000000"]
        still_drifted = governance.evaluate_drift(self.manifest, snapshot)
        self.assertIn(
            "ollama_container_gpu_reservation_changed", still_drifted["runtime"]["codes"]
        )
        # The pin holding as deployed.
        snapshot["runtime"]["container_gpu_device_ids"] = [uuid]
        healthy = governance.evaluate_drift(self.manifest, snapshot)
        self.assertEqual(healthy["overall"], "approved")

    def _collect_with_stubs(self, smi_result, inspect, expected_gpu_uuid=None):
        """Drive collect_snapshot with docker/nvidia-smi stood in for; the
        real ones need a GPU and an Ollama socket this test host lacks."""
        captured: list[list[str]] = []

        def fake_run_json(command, timeout=15):
            if command[:2] == ["docker", "inspect"]:
                return [
                    {
                        "Config": {"Image": "ollama/ollama:test", "Env": []},
                        "Image": "sha256:" + "a" * 64,
                        "HostConfig": {"DeviceRequests": inspect},
                    }
                ]
            return [{"RepoDigests": ["ollama/ollama@sha256:" + "c" * 64]}]

        def fake_smi(command, **kwargs):
            captured.append(command)
            return smi_result

        with mock.patch.object(governance, "request_json", side_effect=lambda url, timeout=10: {}), \
                mock.patch.object(governance, "run_json", side_effect=fake_run_json), \
                mock.patch.object(governance.subprocess, "run", side_effect=fake_smi):
            result = governance.collect_snapshot(
                "http://127.0.0.1:1", "ghidra-ollama-1", expected_gpu_uuid
            )
        return result, captured

    def test_collect_queries_by_uuid_and_records_the_observed_identity(self):
        uuid = self.manifest["approved_host"]["gpu_uuid"]
        completed = subprocess.CompletedProcess([], 0)
        completed.stdout = f"{uuid}, NVIDIA RTX 4000 Ada Generation, 20475, 595.84, 8.9\n"
        completed.stderr = ""
        snapshot, calls = self._collect_with_stubs(
            completed,
            [{"Driver": "nvidia", "DeviceIDs": [uuid], "Capabilities": [["gpu"]]}],
            expected_gpu_uuid=uuid,
        )
        self.assertEqual(calls[0][1], f"--id={uuid}")
        self.assertEqual(
            snapshot["host"],
            {
                "gpu_uuid": uuid,
                "gpu": "NVIDIA RTX 4000 Ada Generation",
                "gpu_memory_mib": 20475,
                "driver": "595.84",
                "compute_capability": "8.9",
            },
        )
        self.assertEqual(snapshot["runtime"]["container_gpu_device_ids"], [uuid])

    def test_collect_reports_absence_instead_of_sampling_any_other_card(self):
        expected = "GPU-deadbeef-0000-0000-0000-000000000000"
        completed = subprocess.CompletedProcess([], 6)
        # Live driver 595.84 behavior: rc=6 and the message lands on stdout.
        completed.stdout = "No devices were found\n"
        completed.stderr = ""
        snapshot, calls = self._collect_with_stubs(completed, [], expected_gpu_uuid=expected)
        self.assertEqual(calls[0][1], f"--id={expected}")
        self.assertEqual(snapshot["host"]["approved_gpu_absent"], True)
        self.assertNotIn("gpu", snapshot["host"])
        self.assertEqual(snapshot["runtime"]["container_gpu_device_ids"], [])

    def test_collect_without_a_pin_refuses_to_sample_index_zero(self):
        completed = subprocess.CompletedProcess([], 0)
        completed.stdout = "GPU-x, Some Other Card, 5120, 595.84, 6.1\n"
        completed.stderr = ""
        snapshot, calls = self._collect_with_stubs(completed, [])
        self.assertEqual(calls, [], "no positional query may run without an identity pin")
        self.assertEqual(snapshot["host"], {"gpu_identity_unverified": True})

    def test_missing_model_is_drift_not_an_install_action(self):
        ghidra_tag = self.manifest["slots"]["ghidra"]["artifact"]["tag"]
        affected_slots = [
            name for name, slot in self.manifest["slots"].items()
            if slot["artifact"]["tag"] == ghidra_tag
        ]
        snapshot = self.snapshot()
        snapshot["models"] = [m for m in snapshot["models"] if m["name"] != ghidra_tag]
        status = governance.evaluate_drift(self.manifest, snapshot)
        self.assertEqual(status["overall"], "drift")
        for slot_name in affected_slots:
            self.assertEqual(status["slots"][slot_name]["codes"], ["model_missing"])
        self.assertTrue(status["advisory_only"])

    @unittest.skipIf(os.name == "nt", "Windows does not implement POSIX chmod bits")
    def test_status_file_is_not_world_readable(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "status.json"
            governance.write_status(path, {"overall": "approved"})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_case_gate_cannot_be_hidden_by_aggregate(self):
        report = self.report()
        report["slots"]["sessions"]["score"]["percent"] = 100
        report["slots"]["sessions"]["cases"]["agentic-encoded-exfiltration"]["critical_ok"] = False
        failures = governance.verify_report(self.manifest, report)
        self.assertIn("sessions:agentic-encoded-exfiltration:critical_ok_failed", failures)

    def test_contract_and_exact_digest_are_promotion_gates(self):
        report = self.report()
        report["slots"]["ghidra"]["contract"]["prompt_contract_version"] = "changed"
        report["slots"]["revdeck"]["artifact"]["digest"] = "f" * 64
        failures = governance.verify_report(self.manifest, report)
        self.assertIn("ghidra:contract_changed", failures)
        self.assertIn("revdeck:digest_changed", failures)

    def test_benchmark_session_fixture_safety_fields_are_typed(self):
        benchmark_path = HERE.parent / "benchmarks" / "evaluate-models.py"
        spec = importlib.util.spec_from_file_location("qualification_benchmark", benchmark_path)
        benchmark = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        import sys
        sys.modules["qualification_benchmark"] = benchmark
        spec.loader.exec_module(benchmark)
        self.assertEqual(
            benchmark._sha256_json(benchmark.session_schema()),
            self.manifest["slots"]["sessions"]["contract"]["effective_schema_sha256"],
        )
        for case in benchmark.SESSION_CASES:
            self.assertIsInstance(case.required_mitre, tuple, case.name)
            self.assertIsInstance(case.forbidden_summary, tuple, case.name)
            self.assertIsInstance(case.forbidden_mitre, tuple, case.name)
            self.assertIsInstance(case.injection_attempt, bool, case.name)
            self.assertIsInstance(case.critical, bool, case.name)

    def test_promotion_is_explicit_atomic_and_rollback_is_named(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_path = root / "approved-models.json"
            record_path = root / "approval-record.md"
            candidate = root / "candidate.json"
            report_path = root / "report.json"
            backups = root / "backups"
            manifest_path.write_bytes(governance.canonical_bytes(self.manifest))
            record_path.write_text("previous record\n", encoding="utf-8")
            candidate.write_bytes(governance.canonical_bytes(self.manifest))
            report_path.write_bytes(governance.canonical_bytes(self.report()))

            rejected = argparse.Namespace(
                approve="no",
                candidate_manifest=candidate,
                report=report_path,
                manifest=manifest_path,
                record=record_path,
                backup_dir=backups,
                approval_date="2026-08-01",
                decision_record="#158",
            )
            with self.assertRaises(ValueError):
                governance.command_promote(rejected)

            rejected.approve = "PROMOTE"
            self.assertEqual(governance.command_promote(rejected), 0)
            promoted = json.loads(manifest_path.read_text())
            self.assertEqual(
                promoted["slots"]["ghidra"]["approval"]["report_sha256"],
                governance.sha256_bytes(report_path.read_bytes()),
            )
            backup_id = next(backups.iterdir()).name
            rollback = argparse.Namespace(
                approve="ROLLBACK",
                manifest=manifest_path,
                record=record_path,
                backup_dir=backups,
                backup_id=backup_id,
            )
            self.assertEqual(governance.command_rollback(rollback), 0)
            self.assertEqual(record_path.read_text(), "previous record\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
