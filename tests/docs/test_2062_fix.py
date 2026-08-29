#!/usr/bin/env python3
"""Regression test for #2062: approved-models.json's ollama runtime entry
was stale against the actually-deployed engine.

#1407's "safe-batch image bump" moved docker-compose.ghidra.yml's ollama
pin from 0.32.0 to 0.32.13 but never touched
analysis/ghidra/models/approved-models.json's `runtime` block, and nobody
re-ran the qualification benchmark (benchmarks/evaluate-models.py) against
the new engine. model-governance.py's check-runtime drift check compares a
live host's Ollama version/image/image-id/repo-digest against exactly that
block, so from the moment the compose bump shipped, every host running the
current compose reported runtime drift against an engine version that was
never actually deployed -- and production triage answers were coming from
an engine that was never qualified against the approved gates.

The fix updates approved-models.json's runtime block to the 0.32.13 image
docker-compose.ghidra.yml pins (version, image reference, image id, and
repo digest all follow the same single-digest convention the 0.32.0 entry
already used), and documents -- in a `runtime.bump_policy` field, since
JSON has no comment syntax, and in a comment on the compose `image:` line
itself -- that any future engine bump must be paired with re-running
evaluate-models.py and promoting the result via `model-governance.py
promote` before or alongside the compose edit.

These tests check the fix from both directions: the manifest's ollama
runtime entry actually matches the compose pin today, the drift checker
(exercised as it actually runs in production, via the check-runtime CLI
against a snapshot file) reports clean for a host running that pin, and a
planted mismatch (manifest reverted to 0.32.0, compose left at 0.32.13)
reproduces the original bug and is caught as drift.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import tempfile

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
GHIDRA_DIR = REPO_ROOT / "analysis" / "ghidra"
MODELS_DIR = GHIDRA_DIR / "models"
MANIFEST_PATH = MODELS_DIR / "approved-models.json"
GOVERNANCE_SCRIPT = MODELS_DIR / "model-governance.py"
COMPOSE_PATH = GHIDRA_DIR / "docker-compose.ghidra.yml"

_SPEC = importlib.util.spec_from_file_location("model_governance_2062", GOVERNANCE_SCRIPT)
governance = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(governance)

STALE_0_32_0_DIGEST = "57f573b47f1f71ebb445789f279fe3e596a8beab182f7cf486db9205bad87c5a"


def _ollama_service_block(text: str) -> str:
    """Return the top-level `  ollama:` compose service stanza and all of
    its indented lines, mirroring how other tests/docs regression tests
    (e.g. test_2307_suricata_interface_fix.py) scope a YAML edit to the
    exact block it belongs to instead of matching anywhere in the file."""
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line == "  ollama:"), None)
    assert start is not None, f"no top-level `  ollama:` service found in {COMPOSE_PATH}"
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.strip() == "" or line.startswith("    ") or line.startswith("\t"):
            block.append(line)
            continue
        break  # dedent back to column 2 -- next top-level service
    return "\n".join(block)


def _compose_ollama_image_ref() -> str:
    block = _ollama_service_block(COMPOSE_PATH.read_text(encoding="utf-8"))
    match = re.search(r"^\s*image:\s*(\S+)", block, re.MULTILINE)
    assert match, f"no `image:` line found in the ollama service block:\n{block}"
    return match.group(1)


def _manifest() -> dict:
    return governance.read_json(MANIFEST_PATH)


def _split_image_ref(image_ref: str) -> tuple[str, str]:
    tag_part, digest = image_ref.split("@")
    return tag_part.split(":")[-1], digest


def _snapshot_for(manifest: dict, image_ref: str) -> dict:
    """A synthetic live-runtime snapshot for a host that pulled exactly the
    digest-pinned image docker-compose.ghidra.yml specifies -- the same
    shape collect_snapshot() builds from `docker inspect` + Ollama's
    /api/version, but constructed here so the test needs neither Docker
    nor a GPU."""
    version, digest = _split_image_ref(image_ref)
    by_tag = {}
    for slot in manifest["slots"].values():
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
            "ollama_version": version,
            "image_reference": image_ref,
            "image_id": digest,
            "repo_digests": [f"ollama/ollama@{digest}"],
            "environment": [
                f"{key}={value}" for key, value in manifest["runtime"]["environment"].items()
            ],
            "container_gpu_device_ids": [manifest["approved_host"]["gpu_uuid"]],
        },
        "host": {
            key: manifest["approved_host"][key]
            for key in ("gpu_uuid", "gpu", "gpu_memory_mib", "driver", "compute_capability")
        },
    }


def _run_check_runtime_cli(tmp_path, manifest: dict, snapshot: dict) -> tuple[int, dict]:
    """Invoke the real check-runtime subcommand as a subprocess, exactly as
    honeypot-model-drift.service does (minus --warn-only, so the exit code
    itself reflects approved vs. drift), against a manifest and snapshot
    written to disk. --snapshot is check-runtime's own file-based path for
    running without a live Ollama/Docker socket."""
    manifest_path = tmp_path / "manifest.json"
    snapshot_path = tmp_path / "snapshot.json"
    status_path = tmp_path / "status.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    snapshot_path.write_text(json.dumps(snapshot), encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable, str(GOVERNANCE_SCRIPT), "check-runtime",
            "--manifest", str(manifest_path),
            "--snapshot", str(snapshot_path),
            "--status-file", str(status_path),
        ],
        capture_output=True, text=True, timeout=30,
    )
    status = json.loads(status_path.read_text(encoding="utf-8"))
    return completed.returncode, status


def test_manifest_and_compose_files_exist():
    assert MANIFEST_PATH.exists(), f"missing {MANIFEST_PATH}"
    assert COMPOSE_PATH.exists(), f"missing {COMPOSE_PATH}"


def test_manifest_still_validates():
    governance.validate_manifest(_manifest())


def test_approved_models_ollama_entry_matches_compose_pin():
    manifest = _manifest()
    image_ref = _compose_ollama_image_ref()
    version, digest = _split_image_ref(image_ref)

    runtime = manifest["runtime"]
    assert runtime["ollama_version"] == version, (
        f"approved-models.json records ollama_version={runtime['ollama_version']!r} "
        f"but docker-compose.ghidra.yml pins {image_ref!r} (version {version!r}) -- "
        "the manifest was not re-qualified after the compose image bump (#2062)"
    )
    assert runtime["ollama_image"] == image_ref, (
        f"approved-models.json's ollama_image {runtime['ollama_image']!r} does not "
        f"match docker-compose.ghidra.yml's pinned image {image_ref!r}"
    )
    assert runtime["ollama_image_id"] == digest
    assert runtime["ollama_repo_digest"] == f"ollama/ollama@{digest}"


def test_check_runtime_cli_is_clean_for_a_host_on_the_pinned_compose_image(tmp_path):
    manifest = _manifest()
    image_ref = _compose_ollama_image_ref()
    snapshot = _snapshot_for(manifest, image_ref)

    returncode, status = _run_check_runtime_cli(tmp_path, manifest, snapshot)

    assert status["runtime"]["status"] == "approved", (
        "model-governance.py reports runtime drift against a host running "
        f"exactly the image docker-compose.ghidra.yml pins: "
        f"{status['runtime'].get('codes')} -- approved-models.json's runtime "
        "block is stale (#2062)"
    )
    assert status["overall"] == "approved", status
    assert returncode == 0, f"check-runtime exited {returncode}, expected 0 (approved): {status}"


def test_check_runtime_cli_flags_drift_when_manifest_is_stale():
    """Reproduce the original bug directly: revert the manifest's runtime
    block to the pre-#1407 0.32.0 pin while the live host (simulated here)
    stays on the current 0.32.13 compose image. This is exactly the
    situation #2062 reported, and proves the checker does correctly flag
    it once the two genuinely diverge -- the checker itself was never
    broken, only its input data was stale."""
    manifest = _manifest()
    image_ref = _compose_ollama_image_ref()
    snapshot = _snapshot_for(manifest, image_ref)

    stale = copy.deepcopy(manifest)
    stale["runtime"]["ollama_version"] = "0.32.0"
    stale["runtime"]["ollama_image"] = f"ollama/ollama:0.32.0@sha256:{STALE_0_32_0_DIGEST}"
    stale["runtime"]["ollama_image_id"] = f"sha256:{STALE_0_32_0_DIGEST}"
    stale["runtime"]["ollama_repo_digest"] = f"ollama/ollama@sha256:{STALE_0_32_0_DIGEST}"

    with tempfile.TemporaryDirectory() as tmp:
        returncode, status = _run_check_runtime_cli(pathlib.Path(tmp), stale, snapshot)

    assert status["overall"] == "drift", status
    assert status["runtime"]["status"] == "drift"
    for code in (
        "ollama_version_changed",
        "ollama_image_reference_changed",
        "ollama_image_id_changed",
        "ollama_repo_digest_unknown",
    ):
        assert code in status["runtime"]["codes"], (
            f"expected {code!r} when the manifest is stuck at 0.32.0 but the "
            f"live host runs {image_ref!r}; got {status['runtime']['codes']}"
        )
    assert returncode == 2, f"check-runtime exited {returncode}, expected 2 (drift): {status}"


def test_manifest_documents_the_bump_policy():
    policy = _manifest()["runtime"].get("bump_policy", "")
    assert policy, "runtime.bump_policy is missing -- JSON has no comment syntax, so this is where a future editor learns a bump needs re-qualification (#2062)"
    lowered = policy.lower()
    assert "evaluate-models.py" in policy, policy
    assert "promote" in lowered, policy
    assert "drift" in lowered, policy


def test_compose_documents_the_bump_policy_next_to_the_pin():
    block = _ollama_service_block(COMPOSE_PATH.read_text(encoding="utf-8"))
    assert "2062" in block, (
        "the ollama service block has no #2062 note next to the image pin -- "
        "the next version bump should see this comment before it can repeat "
        "the same silent-drift mistake"
    )
    assert "approved-models.json" in block


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
