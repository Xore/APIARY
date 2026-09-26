"""Invariants the rex86-eval stack must hold for the model-quant-benchmark
drivers to work at all (#847).

These are not style checks. Every one of them encodes a hardcoded path or
filename that at least one rex86_*.sh driver or one of the repo-side
helpers uses literally. Change one and the drivers fail at runtime on a
box that looks healthy.

Run: python3 analysis/ghidra/benchmarks/tests/test_rex86_stack.py
"""

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]  # tests/ -> benchmarks/ -> ghidra/ -> analysis/ -> repo
STACK = ROOT / "arcane" / "home" / "rex86-eval"
BENCH = ROOT / "analysis" / "ghidra" / "benchmarks"

# The path every driver hardcodes. setup.sh must deploy here, not to
# wherever the repo happens to be checked out.
HARDCODE_STACK = "/var/dockge/stacks/rex86-eval"
CONTAINER = "rex86-eval"

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def main():
    compose = (STACK / "compose.yml").read_text()
    setup = (STACK / "setup.sh").read_text()

    # 1. The container name is the drivers' entry point.
    check(f"container_name: {CONTAINER}" in compose,
          f"compose.yml must set container_name: {CONTAINER}")
    check(CONTAINER in setup, f"setup.sh must reference the {CONTAINER} container")

    # 2. setup.sh deploys to the hardcoded stack path.
    check(HARDCODE_STACK in setup,
          f"setup.sh must deploy to the hardcoded {HARDCODE_STACK}")

    # 3. The three files the drivers invoke by absolute path inside /work.
    for name, rel in (
        ("corpus_eval.py", "engine-benchmark/corpus_eval.py"),
        ("manifest.json", "corpus/manifest.json"),
        ("rev_cases_v2_rubric.json", "corpus/rev_cases_v2_rubric.json"),
    ):
        check(f"/work/{name}" in setup, f"setup.sh must link {name} into /work")
        check((BENCH / rel).is_file(), f"missing source file {rel}")

    # 4. llama-server must exist at the path the drivers call.
    check("/work/llama.cpp/build/bin/llama-server" in setup,
          "setup.sh must build llama-server at /work/llama.cpp/build/bin")

    # 5. GPU is required (llama-server serves the adapter merges) and the
    #    CUDA base is pinned -- a floating tag would let a merge result
    #    change without anyone touching the repo.
    m = re.search(r"image:\s*(\S+)", compose)
    check(m is not None, "compose.yml must declare an image")
    if m:
        check(":" in m.group(1).split("/")[-1],
              f"image must be pinned to an explicit tag, got {m.group(1)}")
    check("capabilities: [gpu]" in compose or "capabilities:\n              - gpu" in compose,
          "compose.yml must reserve the GPU")

    # 6. Single GPU, single driver: every driver serialises through
    #    rex86_wait_for_gpu_drivers, which only helps if the pattern it
    #    uses actually matches the drivers on disk. The pattern is a
    #    generic regex on purpose, so the check is "does re match this
    #    filename", not "is this filename a literal substring" -- a
    #    substring test would fail the exact construction the comment in
    #    rex86_common.sh claims is the point.
    common = (BENCH / "model-quant-benchmark" / "rex86_common.sh").read_text()
    m = re.search(r"REX86_DRIVER_PATTERN='([^']+)'", common)
    check(m is not None, "rex86_common.sh must define REX86_DRIVER_PATTERN")
    pattern = m.group(1) if m else "$^"
    drivers = sorted(p.name for p in (BENCH / "model-quant-benchmark").glob("*.sh")
                     if re.match(r"(rex86_[A-Za-z0-9_]+|real_bench_run)\.sh$", p.name))
    for d in drivers:
        check(re.search(pattern, d) is not None,
              f"{d} is a GPU driver but rex86_common.sh's wait pattern "
              f"({pattern}) does not match it -- it would run concurrently and OOM")

    # 7. The manifest is valid JSON the harness can actually open.
    json.loads((BENCH / "corpus" / "manifest.json").read_text())

    if failures:
        print("FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"ok - stack invariants hold ({len(drivers)} GPU drivers serialise)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
