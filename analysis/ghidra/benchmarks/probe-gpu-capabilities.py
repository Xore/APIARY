#!/usr/bin/env python3
"""Reusable GPU/model capability probe -- not a task-accuracy benchmark.

`evaluate-models.py` answers "is this model accurate enough for this task."
This script answers a different, recurring question: "did the *hardware or
runtime* change in a way that makes a re-evaluation worth running at all."
Run it whenever the GPU, driver, Ollama version, or model roster changes --
e.g. after a card swap, a driver upgrade, or before deciding whether to
open a new re-evaluation issue like #568/#569.

It never picks a model, never writes to approved-models.json, and never
compares task accuracy. Two independent checks:

1. capability-drift: live nvidia-smi/driver/Ollama version vs. the
   `approved_host` block already recorded in a manifest -- flags when
   headroom changed enough that a stale VRAM assumption could be baked
   into a docs decision (exactly what happened before #518).
2. context-sweep: for one already-installed model, run the existing
   16k-sentinel context probe (borrowed from evaluate-models.py, not
   reimplemented) at a list of context sizes, recording whether the probe
   still passes and what it costs in VRAM/tokens-per-second at each size.
   This is what actually answers "how much bigger can we make
   OLLAMA_CONTEXT_LENGTH / MAX_CONTENT_CHARS now" -- not the model's
   accuracy, just whether a bigger window is safe and what it costs.

Both checks are read-only against the live Ollama server: no model is
pulled, no container is touched, and each probed model is unloaded
afterward via the same `unload()` used by evaluate-models.py.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def _load_evaluate_models():
    # evaluate-models.py has a hyphen, so it can't be `import`ed by name;
    # load it by path instead of duplicating its Ollama/GPU helper functions.
    path = Path(__file__).resolve().parent / "evaluate-models.py"
    spec = importlib.util.spec_from_file_location("evaluate_models", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["evaluate_models"] = module  # dataclass() needs this pre-registered
    spec.loader.exec_module(module)
    return module


_eval = _load_evaluate_models()
context_probe = _eval.context_probe
nvidia_memory = _eval.nvidia_memory
ollama_ps = _eval.ollama_ps
unload = _eval.unload


def nvidia_smi_field(query: str) -> str | None:
    try:
        completed = subprocess.run(
            ["nvidia-smi", f"--query-gpu={query}", "--format=csv,noheader"],
            check=True, capture_output=True, text=True, timeout=10,
        )
        return completed.stdout.splitlines()[0].strip()
    except (OSError, subprocess.SubprocessError, IndexError):
        return None


def live_host_facts() -> dict[str, Any]:
    return {
        "gpu": nvidia_smi_field("name"),
        "gpu_memory_mib": (lambda v: int(v.split()[0]) if v else None)(
            nvidia_smi_field("memory.total")
        ),
        "driver": nvidia_smi_field("driver_version"),
        "compute_capability": nvidia_smi_field("compute_cap"),
    }


def capability_drift(manifest_path: str) -> dict[str, Any]:
    with open(manifest_path, encoding="utf-8") as source:
        manifest = json.load(source)
    recorded = manifest.get("approved_host", {})
    live = live_host_facts()
    fields = ("gpu", "gpu_memory_mib", "driver", "compute_capability")
    drift = {
        field: {"recorded": recorded.get(field), "live": live.get(field)}
        for field in fields
        if str(recorded.get(field)) != str(live.get(field))
    }
    return {
        "recorded_host": recorded,
        "live_host": live,
        "drift": drift,
        "reevaluation_suggested": bool(drift),
    }


def context_sweep(base_url: str, model: str, sizes: list[int]) -> list[dict[str, Any]]:
    results = []
    for size in sizes:
        started = time.time()
        probe = context_probe(base_url, model, size)
        loaded = ollama_ps(base_url, model)
        results.append({
            "context_tokens": size,
            "passed": probe["passed"],
            "loaded_model": loaded,
            "nvidia_memory_used_mib": nvidia_memory(),
            "elapsed_seconds": round(time.time() - started, 2),
        })
        unload(base_url, model)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:11434")
    parser.add_argument("--manifest", help="approved-models.json to diff live host facts against")
    parser.add_argument("--context-sweep-model", help="installed model tag to context-sweep")
    parser.add_argument(
        "--context-sizes", default="4096,8192,16384,32768,65536",
        help="comma-separated context_tokens values to probe",
    )
    args = parser.parse_args()

    report: dict[str, Any] = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    if args.manifest:
        report["capability_drift"] = capability_drift(args.manifest)
        drift = report["capability_drift"]["drift"]
        if drift:
            print(f"HOST DRIFT DETECTED vs {args.manifest}:", file=sys.stderr)
            for field, values in drift.items():
                print(f"  {field}: recorded={values['recorded']!r} live={values['live']!r}", file=sys.stderr)
        else:
            print("no host drift vs manifest's approved_host", file=sys.stderr)

    if args.context_sweep_model:
        sizes = [int(item) for item in args.context_sizes.split(",")]
        print(f"context-sweeping {args.context_sweep_model} at {sizes}...", file=sys.stderr)
        sweep = context_sweep(args.base_url, args.context_sweep_model, sizes)
        report["context_sweep"] = {"model": args.context_sweep_model, "results": sweep}
        for item in sweep:
            loaded = item["loaded_model"]
            vram = loaded.get("size_vram")
            print(
                f"  ctx={item['context_tokens']:>6} passed={item['passed']!s:<5} "
                f"vram={vram if vram else 'n/a'} nvidia_used_mib={item['nvidia_memory_used_mib']}",
                file=sys.stderr,
            )

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
