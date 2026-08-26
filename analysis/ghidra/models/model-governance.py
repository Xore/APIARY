#!/usr/bin/env python3
"""Local-model drift, report verification, promotion, and rollback controls.

All runtime inspection is read-only.  Requalification is deliberately a
separate operator action performed by evaluate-models.py; this tool never
pulls, deletes, or replaces a model and never manages containers or VMs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("manifest_version") != 1:
        raise ValueError("unsupported manifest_version")
    runtime = manifest.get("runtime")
    host = manifest.get("approved_host")
    slots = manifest.get("slots")
    if not isinstance(runtime, dict) or not isinstance(host, dict):
        raise ValueError("runtime and approved_host records are required")
    if not isinstance(slots, dict) or set(slots) != {"ghidra", "sessions", "revdeck"}:
        raise ValueError("manifest must define exactly ghidra, sessions, and revdeck slots")
    for name, slot in slots.items():
        if not isinstance(slot, dict):
            raise ValueError(f"slot {name} must be an object")
        artifact = slot.get("artifact", {})
        digest = artifact.get("digest") if isinstance(artifact, dict) else None
        if not isinstance(digest, str) or len(digest) != 64:
            raise ValueError(f"slot {name} requires an exact 64-character digest")
        int(digest, 16)
        for key in ("runtime_request", "qualification_request", "contract", "gates", "approval"):
            if not isinstance(slot.get(key), dict):
                raise ValueError(f"slot {name} requires {key}")
        report_hash = slot["approval"].get("report_sha256")
        if not isinstance(report_hash, str) or len(report_hash) != 64:
            raise ValueError(f"slot {name} requires an archived report SHA-256")
        int(report_hash, 16)


def request_json(url: str, timeout: int = 10) -> dict[str, Any]:
    request = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        value = json.loads(response.read())
    if not isinstance(value, dict):
        raise ValueError("endpoint did not return an object")
    return value


def run_json(command: list[str], timeout: int = 15) -> Any:
    completed = subprocess.run(
        command, check=True, capture_output=True, text=True, timeout=timeout
    )
    return json.loads(completed.stdout)


def collect_snapshot(base_url: str, container: str) -> dict[str, Any]:
    """Collect only local, read-only runtime identity and capacity metadata."""
    snapshot: dict[str, Any] = {"models": [], "runtime": {}, "host": {}}
    tags = request_json(f"{base_url.rstrip('/')}/api/tags")
    snapshot["models"] = tags.get("models", [])
    snapshot["runtime"]["ollama_version"] = request_json(
        f"{base_url.rstrip('/')}/api/version"
    ).get("version")

    inspected = run_json(["docker", "inspect", container])
    if not isinstance(inspected, list) or not inspected:
        raise ValueError("docker inspect returned no container")
    item = inspected[0]
    snapshot["runtime"].update(
        {
            "image_reference": item.get("Config", {}).get("Image"),
            "image_id": item.get("Image"),
            "environment": sorted(item.get("Config", {}).get("Env", [])),
        }
    )
    try:
        image = run_json(["docker", "image", "inspect", item.get("Image", "")])
        if isinstance(image, list) and image:
            snapshot["runtime"]["repo_digests"] = image[0].get("RepoDigests", [])
    except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
        snapshot["runtime"]["repo_digests"] = []

    try:
        completed = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=name,memory.total,driver_version,compute_cap",
                "--format=csv,noheader,nounits",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        parts = [part.strip() for part in completed.stdout.splitlines()[0].split(",")]
        snapshot["host"] = {
            "gpu": parts[0],
            "gpu_memory_mib": int(parts[1]),
            "driver": parts[2],
            "compute_capability": parts[3],
        }
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        snapshot["host"] = {"unavailable": True}
    return snapshot


def _model_index(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in snapshot.get("models", []):
        if not isinstance(item, dict):
            continue
        for key in (item.get("name"), item.get("model")):
            if isinstance(key, str):
                result[key] = item
    return result


def evaluate_drift(manifest: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    validate_manifest(manifest)
    models = _model_index(snapshot)
    slot_status: dict[str, Any] = {}
    for name, slot in manifest["slots"].items():
        artifact = slot["artifact"]
        found = models.get(artifact["tag"])
        codes: list[str] = []
        if found is None:
            codes.append("model_missing")
        else:
            details = found.get("details", {}) if isinstance(found.get("details"), dict) else {}
            comparisons = {
                "digest": (found.get("digest"), artifact["digest"]),
                "size": (found.get("size"), artifact["size_bytes"]),
                "family": (details.get("family"), artifact["family"]),
                "parameter_size": (details.get("parameter_size"), artifact["parameter_size"]),
                "quantization": (details.get("quantization_level"), artifact["quantization"]),
            }
            codes.extend(
                f"model_{field}_changed"
                for field, (actual, expected) in comparisons.items()
                if actual != expected
            )
        slot_status[name] = {"status": "approved" if not codes else "drift", "codes": codes}

    runtime = snapshot.get("runtime", {})
    expected_runtime = manifest["runtime"]
    runtime_codes: list[str] = []
    if runtime.get("ollama_version") != expected_runtime["ollama_version"]:
        runtime_codes.append("ollama_version_changed")
    if runtime.get("image_reference") != expected_runtime["ollama_image"]:
        runtime_codes.append("ollama_image_reference_changed")
    if runtime.get("image_id") != expected_runtime["ollama_image_id"]:
        runtime_codes.append("ollama_image_id_changed")
    repo_digests = runtime.get("repo_digests", [])
    if expected_runtime["ollama_repo_digest"] not in repo_digests:
        runtime_codes.append("ollama_repo_digest_unknown")
    actual_env = set(runtime.get("environment", []))
    for key, value in expected_runtime["environment"].items():
        if f"{key}={value}" not in actual_env:
            runtime_codes.append(f"runtime_env_{key.lower()}_changed")

    actual_host = snapshot.get("host", {})
    host_codes: list[str] = []
    if actual_host.get("unavailable"):
        host_codes.append("gpu_telemetry_unavailable")
    else:
        for key in ("gpu", "gpu_memory_mib", "driver", "compute_capability"):
            if actual_host.get(key) != manifest["approved_host"].get(key):
                host_codes.append(f"host_{key}_changed")

    statuses = [item["status"] for item in slot_status.values()]
    overall = "approved"
    if runtime_codes or host_codes or "drift" in statuses:
        overall = "drift"
    return {
        "schema_version": 1,
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "overall": overall,
        "slots": slot_status,
        "runtime": {"status": "approved" if not runtime_codes else "drift", "codes": runtime_codes},
        "host": {"status": "approved" if not host_codes else "drift", "codes": host_codes},
        "advisory_only": True,
    }


def verify_report(manifest: dict[str, Any], report: dict[str, Any]) -> list[str]:
    """Return gate failures; every named case is independent of aggregate score."""
    validate_manifest(manifest)
    failures: list[str] = []
    if report.get("benchmark") != manifest.get("benchmark_version"):
        failures.append("benchmark_version_changed")
    report_slots = report.get("slots", {})
    if not isinstance(report_slots, dict):
        return failures + ["slots_missing"]
    for name, slot in manifest["slots"].items():
        result = report_slots.get(name)
        if not isinstance(result, dict):
            failures.append(f"{name}:result_missing")
            continue
        if result.get("model") != slot["artifact"]["tag"]:
            failures.append(f"{name}:model_changed")
        artifact = result.get("artifact", {})
        if not isinstance(artifact, dict):
            artifact = {}
        if artifact.get("digest") != slot["artifact"]["digest"]:
            failures.append(f"{name}:digest_changed")
        if result.get("qualification_request") != slot["qualification_request"]:
            failures.append(f"{name}:request_settings_changed")
        if result.get("contract") != slot["contract"]:
            failures.append(f"{name}:contract_changed")
        gates = slot["gates"]
        score = result.get("score", {})
        percent = score.get("percent") if isinstance(score, dict) else None
        if not isinstance(percent, (int, float)) or percent < gates["minimum_percent"]:
            failures.append(f"{name}:aggregate_below_minimum")
        cases = result.get("cases", {})
        if not isinstance(cases, dict):
            failures.append(f"{name}:cases_missing")
            continue
        for case_name, case_gate in gates["cases"].items():
            case = cases.get(case_name)
            if not isinstance(case, dict):
                failures.append(f"{name}:{case_name}:missing")
                continue
            case_score = case.get("score")
            if not isinstance(case_score, (int, float)) or case_score < case_gate["minimum_score"]:
                failures.append(f"{name}:{case_name}:score_regression")
            for boolean_gate in ("schema_ok", "injection_ok", "critical_ok"):
                if case_gate.get(f"require_{boolean_gate}") and case.get(boolean_gate) is not True:
                    failures.append(f"{name}:{case_name}:{boolean_gate}_failed")
        probe = result.get("context_probe", {})
        if gates.get("require_context_probe") and (
            not isinstance(probe, dict) or probe.get("passed") is not True
        ):
            failures.append(f"{name}:context_probe_failed")
    return failures


def _write_atomic_pair(first: Path, first_data: bytes, second: Path, second_data: bytes) -> None:
    originals = {
        first: first.read_bytes() if first.exists() else None,
        second: second.read_bytes() if second.exists() else None,
    }
    temporary: list[Path] = []
    try:
        for destination, data in ((first, first_data), (second, second_data)):
            destination.parent.mkdir(parents=True, exist_ok=True)
            handle, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
            os.close(handle)
            temp = Path(name)
            temporary.append(temp)
            temp.write_bytes(data)
        os.replace(temporary[0], first)
        temporary.pop(0)
        try:
            os.replace(temporary[0], second)
            temporary.pop(0)
        except Exception:
            original = originals[first]
            if original is None:
                first.unlink(missing_ok=True)
            else:
                first.write_bytes(original)
            raise
    finally:
        for path in temporary:
            path.unlink(missing_ok=True)


def approval_record(manifest: dict[str, Any]) -> str:
    lines = [
        "# Approved local-model qualification record",
        "",
        "This file is generated with the reviewed manifest. Model promotion is explicit; runtime drift never edits it.",
        "",
        "| Slot | Exact model | Approval date | Archived report SHA-256 | Decision record |",
        "|---|---|---|---|---|",
    ]
    for name, slot in manifest["slots"].items():
        approval = slot["approval"]
        artifact = slot["artifact"]
        lines.append(
            f"| {name} | `{artifact['tag']}@sha256:{artifact['digest']}` | "
            f"{approval['date']} | `{approval['report_sha256']}` | {approval['decision_record']} |"
        )
    lines.extend(["", "Rollback restores a specifically named backup; no latest/automatic selection is allowed.", ""])
    return "\n".join(lines)


def backup_pair(manifest_path: Path, record_path: Path, backup_root: Path) -> str:
    backup_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = backup_root / backup_id
    suffix = 0
    while destination.exists():
        suffix += 1
        destination = backup_root / f"{backup_id}-{suffix}"
    destination.mkdir(parents=True)
    if manifest_path.exists():
        shutil.copy2(manifest_path, destination / "approved-models.json")
    if record_path.exists():
        shutil.copy2(record_path, destination / "approval-record.md")
    return destination.name


def write_status(path: Path | None, status: dict[str, Any]) -> None:
    data = canonical_bytes(status)
    if path is None:
        print(data.decode(), end="")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(handle)
    temporary = Path(name)
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def _inspection_codes(exc: BaseException) -> list[str]:
    """Reason code for an inspection that could not run at all (#2065).

    The model-status adapter only serves codes matching [a-z0-9_:-]{1,96},
    so the exception class is lowercased and the message slugged into that
    same alphabet. The first version wrote CamelCase class names
    (inspection_failed:URLError, :JSONDecodeError, ...) that sanitize_status
    rejected wholesale -- meaning overall=unavailable, the one state whose
    entire job is explaining WHY inspection failed, was the one state the
    dashboard could never see (it got a generic adapter 503 instead). The
    message slug is what distinguishes "permission denied" reading the
    docker socket from connection-refused to Ollama; the file is root-owned
    0600 on a private host path, so carrying it costs nothing in exposure.
    """
    name = type(exc).__name__.lower()
    slug = re.sub(r"[^a-z0-9]+", "_", str(exc).lower()).strip("_")
    return [f"inspection_failed:{name}:{slug}"[:96]]


def command_check(args: argparse.Namespace) -> int:
    try:
        # The manifest read belongs inside the try like everything else:
        # an unreadable manifest is exactly the same class of "cannot know,
        # say why" as a dead Ollama, and crashing here left the previous
        # artifact -- or nothing at all -- for the dashboard to serve.
        manifest = read_json(args.manifest)
        snapshot = read_json(args.snapshot) if args.snapshot else collect_snapshot(args.base_url, args.container)
        status = evaluate_drift(manifest, snapshot)
    except Exception as exc:
        status = {
            "schema_version": 1,
            "checked_at": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
            "overall": "unavailable",
            "codes": _inspection_codes(exc),
            "advisory_only": True,
        }
    write_status(args.status_file, status)
    if args.status_file:
        print(json.dumps({"overall": status["overall"], "status_file_updated": True}))
    if args.warn_only or status["overall"] == "approved":
        return 0
    return 2 if status["overall"] == "drift" else 3


def command_verify(args: argparse.Namespace) -> int:
    manifest = read_json(args.manifest)
    report = read_json(args.report)
    failures = verify_report(manifest, report)
    print(json.dumps({"eligible": not failures, "failures": failures}, indent=2))
    return 0 if not failures else 2


def command_promote(args: argparse.Namespace) -> int:
    if args.approve != "PROMOTE":
        raise ValueError("promotion requires the exact --approve PROMOTE acknowledgement")
    candidate = read_json(args.candidate_manifest)
    report_bytes = args.report.read_bytes()
    report = json.loads(report_bytes)
    report_hash = sha256_bytes(report_bytes)
    for slot in candidate.get("slots", {}).values():
        slot["approval"] = {
            "date": args.approval_date,
            "report_sha256": report_hash,
            "decision_record": args.decision_record,
        }
    validate_manifest(candidate)
    failures = verify_report(candidate, report)
    if failures:
        print(json.dumps({"promoted": False, "failures": failures}, indent=2))
        return 2
    backup_id = backup_pair(args.manifest, args.record, args.backup_dir)
    _write_atomic_pair(
        args.manifest,
        canonical_bytes(candidate),
        args.record,
        approval_record(candidate).encode(),
    )
    print(json.dumps({"promoted": True, "backup_id": backup_id, "report_sha256": report_hash}))
    return 0


def command_rollback(args: argparse.Namespace) -> int:
    if args.approve != "ROLLBACK":
        raise ValueError("rollback requires the exact --approve ROLLBACK acknowledgement")
    source = args.backup_dir / args.backup_id
    previous_manifest = source / "approved-models.json"
    previous_record = source / "approval-record.md"
    manifest = read_json(previous_manifest)
    validate_manifest(manifest)
    if not previous_record.is_file():
        raise ValueError("named backup does not contain the approval record")
    backup_id = backup_pair(args.manifest, args.record, args.backup_dir)
    _write_atomic_pair(
        args.manifest,
        previous_manifest.read_bytes(),
        args.record,
        previous_record.read_bytes(),
    )
    print(json.dumps({"rolled_back": True, "restorable_backup_id": backup_id}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check-runtime")
    check.add_argument("--manifest", type=Path, required=True)
    check.add_argument("--base-url", default="http://127.0.0.1:11434")
    check.add_argument("--container", default="ghidra-ollama-1")
    check.add_argument("--snapshot", type=Path)
    check.add_argument("--status-file", type=Path)
    check.add_argument("--warn-only", action="store_true")
    check.set_defaults(func=command_check)

    verify = subparsers.add_parser("verify-report")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--report", type=Path, required=True)
    verify.set_defaults(func=command_verify)

    promote = subparsers.add_parser("promote")
    promote.add_argument("--candidate-manifest", type=Path, required=True)
    promote.add_argument("--report", type=Path, required=True)
    promote.add_argument("--manifest", type=Path, required=True)
    promote.add_argument("--record", type=Path, required=True)
    promote.add_argument("--backup-dir", type=Path, required=True)
    promote.add_argument("--approval-date", required=True)
    promote.add_argument("--decision-record", required=True)
    promote.add_argument("--approve", required=True)
    promote.set_defaults(func=command_promote)

    rollback = subparsers.add_parser("rollback")
    rollback.add_argument("--manifest", type=Path, required=True)
    rollback.add_argument("--record", type=Path, required=True)
    rollback.add_argument("--backup-dir", type=Path, required=True)
    rollback.add_argument("--backup-id", required=True)
    rollback.add_argument("--approve", required=True)
    rollback.set_defaults(func=command_rollback)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError, subprocess.SubprocessError) as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}))
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
