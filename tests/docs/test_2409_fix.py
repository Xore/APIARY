#!/usr/bin/env python3
"""Regression test for #2409: the homeserver's deployed Ollama runtime pin
drifted from approved-models.json.

#2062/#2623 already re-pinned approved-models.json's `runtime` block to the
0.32.13 image docker-compose.ghidra.yml deploys (see test_2062_fix.py). This
file pins the two follow-on requirements #2409 raised on top of that fix:

1. The manifest and the compose pin must still agree -- re-asserted here
   directly against `model-governance.py check-runtime`, run the same way
   `honeypot-model-drift.service` runs it, against a synthetic snapshot
   shaped exactly like the compose-pinned image so a future edit to either
   file that breaks the agreement fails CI instead of only being caught by
   the live timer on the homeserver.
2. `install-analysis-host.sh` must deploy the manifest (carrying
   `approved_host.gpu_uuid`) to `/opt/honeypot-ghidra/models/` on every run,
   so the `approved_gpu_uuid_missing` advisory leg the issue calls out is a
   transient state that clears on redeploy, not a permanent gap -- and the
   README documents both new advisory-only codes for operators instead of
   surprising them.

Live verification against the homeserver's actually-running container is
out of scope here (no network path to the lab from this checkout); this
file only pins the file-level contract that check-runtime and the installer
both depend on.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
GHIDRA_DIR = REPO_ROOT / "analysis" / "ghidra"
MODELS_DIR = GHIDRA_DIR / "models"
MANIFEST_PATH = MODELS_DIR / "approved-models.json"
GOVERNANCE_SCRIPT = MODELS_DIR / "model-governance.py"
COMPOSE_PATH = GHIDRA_DIR / "docker-compose.ghidra.yml"
INSTALL_SCRIPT = GHIDRA_DIR / "install-analysis-host.sh"
README_PATH = REPO_ROOT / "docs" / "analysis" / "ghidra" / "models" / "README.md"

_SPEC = importlib.util.spec_from_file_location("model_governance_2409", GOVERNANCE_SCRIPT)
governance = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(governance)


def _manifest() -> dict:
    return governance.read_json(MANIFEST_PATH)


def _ollama_service_block(text: str) -> str:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line == "  ollama:"), None)
    assert start is not None, f"no top-level `  ollama:` service found in {COMPOSE_PATH}"
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.strip() == "" or line.startswith("    ") or line.startswith("\t"):
            block.append(line)
            continue
        break
    return "\n".join(block)


def _compose_ollama_image_ref() -> str:
    block = _ollama_service_block(COMPOSE_PATH.read_text(encoding="utf-8"))
    match = re.search(r"^\s*image:\s*(\S+)", block, re.MULTILINE)
    assert match, f"no `image:` line found in the ollama service block:\n{block}"
    return match.group(1)


def _split_image_ref(image_ref: str) -> tuple[str, str]:
    tag_part, digest = image_ref.split("@")
    return tag_part.split(":")[-1], digest


def _synthetic_deployed_snapshot(manifest: dict, image_ref: str) -> dict:
    """A live-shaped snapshot for a host actually running the compose pin --
    what `docker inspect` + Ollama's own API would report if the homeserver
    were currently deployed to exactly the image docker-compose.ghidra.yml
    specifies."""
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


def test_approved_models_runtime_pin_matches_the_currently_served_model(tmp_path):
    """The manifest's runtime pin must equal what a host on the currently
    deployed compose image actually serves -- the exact agreement #2409
    reports as drifted (ollama_image_reference_changed / ollama_image_id_changed
    / ollama_repo_digest_unknown / ollama_version_changed)."""
    manifest = _manifest()
    image_ref = _compose_ollama_image_ref()
    snapshot = _synthetic_deployed_snapshot(manifest, image_ref)

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

    assert status["runtime"]["status"] == "approved", (
        "approved-models.json's runtime pin does not match the model a host "
        f"on the current compose image actually serves: {status['runtime'].get('codes')} "
        "-- re-pin the manifest (if the deployed image is the new approved one) "
        "or requalify-by-redeploy (if the manifest is authoritative) per #2409"
    )
    assert status["overall"] == "approved", status
    assert completed.returncode == 0, (completed.returncode, status)


def test_approved_host_gpu_uuid_is_pinned_in_the_manifest():
    """#2409: the manifest must carry approved_host.gpu_uuid so the next
    install-analysis-host.sh run ships it to the prod copy and clears the
    approved_gpu_uuid_missing advisory leg."""
    gpu_uuid = _manifest()["approved_host"].get("gpu_uuid")
    assert isinstance(gpu_uuid, str) and gpu_uuid.startswith("GPU-"), (
        f"approved_host.gpu_uuid missing or malformed: {gpu_uuid!r}"
    )


def test_install_script_deploys_the_manifest_to_the_prod_path():
    """#2409: the prod manifest copy only picks up approved_host.gpu_uuid on
    the next install-analysis-host.sh run -- assert that run actually
    installs approved-models.json (not just the governance scripts) so that
    expectation holds."""
    text = INSTALL_SCRIPT.read_text(encoding="utf-8")
    # The install line is backslash-continued; the regex allows optional
    # whitespace and a literal newline between the install args and the
    # source/dest pair.
    assert re.search(
        r'install\s+[\s\S]*"\$here/models/approved-models\.json"\s+"\$target/models/approved-models\.json"',
        text,
    ), "install-analysis-host.sh no longer deploys approved-models.json to the prod path"


def test_readme_documents_the_post_2394_advisory_codes():
    """#2409: operators must not read approved_gpu_uuid_missing or a
    host_gpu_uuid_changed replay of an old snapshot as a regression -- both
    are expected, honest states during the #2394 rollout."""
    text = README_PATH.read_text(encoding="utf-8")
    assert "approved_gpu_uuid_missing" in text, (
        "README does not document approved_gpu_uuid_missing -- an operator "
        "seeing it before the prod manifest is redeployed will misread it as a regression"
    )
    assert "host_gpu_uuid_changed" in text, (
        "README does not document host_gpu_uuid_changed for pre-#2394 --snapshot replays"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
