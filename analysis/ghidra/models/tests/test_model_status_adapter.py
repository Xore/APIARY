#!/usr/bin/env python3
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("model_status_adapter", HERE / "model-status-adapter.py")
adapter = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(adapter)

# #2065: the real producer, loaded too -- the adapter's validator and the
# drift checker's failure path were never exercised against each other,
# which is exactly how CamelCase exception codes sailed through every test
# while making the dashboard's unavailable state unservable in production.
GOV_SPEC = importlib.util.spec_from_file_location("model_governance", HERE / "model-governance.py")
governance = importlib.util.module_from_spec(GOV_SPEC)
assert GOV_SPEC.loader
GOV_SPEC.loader.exec_module(governance)


class ModelStatusAdapterTests(unittest.TestCase):
    def status_file(self, value):
        root = Path(tempfile.mkdtemp())
        path = root / "status.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        os.chmod(path, 0o600)
        return path

    def test_sanitizes_fixed_schema(self):
        path = self.status_file({"schema_version": 1, "checked_at": "2026-08-01T00:00:00Z", "overall": "drift", "slots": {"ghidra": {"status": "drift", "codes": ["model_digest_changed"]}}, "runtime": {"status": "approved", "codes": []}, "host": {"status": "approved", "codes": []}, "advisory_only": True, "secret": "must not pass"})
        result = adapter.sanitize_status(path)
        self.assertEqual(result["overall"], "drift")
        self.assertNotIn("secret", result)

    def test_rejects_world_readable_source(self):
        if os.name != "posix":
            self.skipTest("POSIX permission bits are not available")
        path = self.status_file({"schema_version": 1, "overall": "approved", "slots": {}, "advisory_only": True})
        real_stat = path.stat()
        unsafe_stat = SimpleNamespace(st_mode=real_stat.st_mode | 0o044, st_size=real_stat.st_size, st_uid=real_stat.st_uid)
        with mock.patch.object(Path, "stat", return_value=unsafe_stat), self.assertRaises(ValueError):
            adapter.sanitize_status(path)

    def test_rejects_unknown_slots_and_codes(self):
        for value in [
            {"schema_version": 1, "overall": "approved", "slots": {"arbitrary": {"status": "approved", "codes": []}}, "advisory_only": True},
            {"schema_version": 1, "overall": "drift", "slots": {}, "codes": ["../../secret"], "advisory_only": True},
        ]:
            with self.assertRaises(ValueError):
                adapter.sanitize_status(self.status_file(value))


def _manifest():
    def slot(tag, digest):
        return {
            "artifact": {"tag": tag, "digest": digest, "size_bytes": 10,
                         "family": "qwen3", "parameter_size": "14B",
                         "quantization": "Q4_K_M"},
            "runtime_request": {}, "qualification_request": {},
            "contract": {}, "gates": {},
            "approval": {"report_sha256": "b" * 64},
        }

    return {
        "manifest_version": 1,
        "runtime": {"ollama_version": "0.5.4", "ollama_image": "ollama/ollama:t",
                    "ollama_image_id": "sha256:" + "a" * 64,
                    "ollama_repo_digest": "sha256:" + "c" * 64,
                    "environment": {}},
        "approved_host": {"gpu": "RTX 4000 Ada", "gpu_memory_mib": 20480,
                          "driver": "570", "compute_capability": "8.9"},
        "slots": {name: slot(f"model-{name}", "d" * 64)
                  for name in ("ghidra", "sessions", "revdeck")},
    }


def _snapshot_for(manifest):
    models = []
    for name, slot in manifest["slots"].items():
        artifact = slot["artifact"]
        models.append({"model": artifact["tag"], "digest": artifact["digest"],
                       "size": artifact["size_bytes"],
                       "details": {"family": artifact["family"],
                                   "parameter_size": artifact["parameter_size"],
                                   "quantization_level": artifact["quantization"]}})
    runtime = manifest["runtime"]
    host = manifest["approved_host"]
    return {
        "models": models,
        "runtime": {"ollama_version": runtime["ollama_version"],
                    "image_reference": runtime["ollama_image"],
                    "image_id": runtime["ollama_image_id"],
                    "repo_digests": [runtime["ollama_repo_digest"]],
                    "environment": [f"{k}={v}" for k, v in runtime["environment"].items()]},
        "host": dict(host),
    }


class CrossModuleContractTests(unittest.TestCase):
    """The producer's own output shapes run through the real sanitizer
    (#2065) -- governance's evaluate_drift success shape and command_check's
    exception-path shapes, not synthetic lowercase stand-ins."""

    def test_approved_shape_round_trips(self):
        status = governance.evaluate_drift(_manifest(), _snapshot_for(_manifest()))
        self.assertEqual(status["overall"], "approved")
        result = adapter.sanitize_status(CrossModuleContractTests.write_status(status))
        self.assertEqual(result["overall"], "approved")

    def check_run(self, args):
        rc = governance.command_check(args)
        self.assertEqual(rc, 3)  # unavailable -> the documented nonzero path
        return adapter.sanitize_status(args.status_file)

    def test_failing_run_codes_are_servable_and_distinct(self):
        root = Path(tempfile.mkdtemp())
        manifest_path = root / "m.json"
        manifest_path.write_text(json.dumps(_manifest()), encoding="utf-8")
        # ollama unreachable: collect_snapshot's request_json raises URLError.
        ollama_down = self.check_run(SimpleNamespace(
            manifest=manifest_path, snapshot=None,
            base_url="http://127.0.0.1:9", container="c",
            status_file=root / "s1.json", warn_only=False))
        code_ollama = ollama_down["codes"][0]
        self.assertTrue(code_ollama.startswith("inspection_failed:urlerror"),
                        f"unexpected code: {code_ollama}")
        self.assertEqual(ollama_down["overall"], "unavailable")

        # docker inspect failed: tags/version answer, then docker exits 1.
        with mock.patch.object(governance, "request_json", return_value={}), \
                mock.patch.object(governance, "run_json",
                                  side_effect=subprocess.CalledProcessError(1, ["docker", "inspect", "c"])):
            docker_broken = self.check_run(SimpleNamespace(
                manifest=root / "m.json", snapshot=None,
                base_url="http://127.0.0.1:9", container="c",
                status_file=root / "s2.json", warn_only=False))
        code_docker = docker_broken["codes"][0]
        self.assertTrue(code_docker.startswith("inspection_failed:calledprocesserror"),
                        f"unexpected code: {code_docker}")

        # manifest unreadable: read_json raises FileNotFoundError inside the
        # try now (#2065), instead of crashing without updating the artifact.
        missing_manifest = self.check_run(SimpleNamespace(
            manifest=root / "does-not-exist.json", snapshot=None,
            base_url="http://127.0.0.1:9", container="c",
            status_file=root / "s3.json", warn_only=False))
        code_manifest = missing_manifest["codes"][0]
        self.assertTrue(code_manifest.startswith("inspection_failed:filenotfounderror"),
                        f"unexpected code: {code_manifest}")

        # AC: three distinct failure causes stay distinct end-to-end.
        codes = [code_ollama, code_docker, code_manifest]
        for code in codes:
            self.assertIsNotNone(adapter.CODE.fullmatch(code),
                                 f"{code} must satisfy the adapter's own regex")
        self.assertEqual(len(set(codes)), 3)

    def test_long_exception_messages_stay_within_the_code_budget(self):
        noisy = ValueError("x" * 300)
        (code,) = governance._inspection_codes(noisy)
        self.assertLessEqual(len(code), 96)
        self.assertIsNotNone(adapter.CODE.fullmatch(code))

    @staticmethod
    def write_status(value):
        root = Path(tempfile.mkdtemp())
        path = root / "status.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        os.chmod(path, 0o600)
        return path


if __name__ == "__main__":
    unittest.main()
