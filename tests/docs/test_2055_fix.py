#!/usr/bin/env python3
"""Regression test for #2055: operational-hardening for the rex86_*
driver scripts in model-quant-benchmark/.

The 5-item batch from a line-by-line review:

1. Previous results deleted before the replacement exists. The fix
   moves the `rm` to AFTER the new run's output file is created
   (or to a `.tmp` file that's only promoted on success), so a
   failed launch leaves the previous run's result file intact as
   the safety net.
2. Failed evals leave result files. The fix deletes the .out file
   on non-zero exit so the next run sees a missing result and
   re-runs the work.
3. Inconsistent single-GPU guards. The fix moves the guard to a
   shared helper `rex86_wait_for_gpu_drivers` in `rex86_common.sh`
   that matches every driver by name pattern, not an enumerated
   list that has to be kept in sync by hand.
4. Unpinned HF snapshots. (See the rex86_prefetch_base_models.sh
   change for the commit hash pin.)
5. (Issue-specific operational hardening — see the script diffs.)

This test pins the contract:
- every driver script sources `rex86_common.sh` (so they share
  the GPU guard and the result-file helpers)
- the shared `rex86_wait_for_gpu_drivers` function exists and uses
  the shared `REX86_DRIVER_PATTERN` regex (not an enumerated list)
- no driver script contains the old `rm -f "$result"` before the
  launch; the .out removal is after the launch produces output
  (or, equivalently, a .tmp file is used that's only promoted on
  success)
- the `rex86_prefetch_base_models.sh` script pins the HF snapshot
  to a specific commit hash, not `latest`
"""
import pathlib
import re

import pytest

BENCH_DIR = pathlib.Path(
    __file__
).resolve()
REPO_ROOT = BENCH_DIR.parents[2]
Rex86_DIR = REPO_ROOT / "analysis/ghidra/benchmarks/model-quant-benchmark"
COMMON = Rex86_DIR / "rex86_common.sh"

# Every driver in this directory must source rex86_common.sh so the
# shared GPU guard and the result-file helpers are available.
# Includes real_bench_run.sh (the rex86_*-pattern match also covers
# it via the shared pattern), the backfill_*, the run_*, the
# retry_*, the prefetch_*, and rex86_bench.sh (the legacy direct
# driver the issue called out as missing a guard entirely).
DRIVER_SCRIPTS = sorted(
    p.name
    for p in Rex86_DIR.glob("*.sh")
    if p.name not in ("rex86_common.sh",)
)


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def test_common_helper_exists():
    """The shared helper script must exist and define the
    GPU-driver-wait function used by every driver."""
    assert COMMON.exists(), (
        f"{COMMON} must exist as the shared helper for the rex86_*.sh "
        f"drivers. Before #2055, every driver had its own copy of the "
        f"single-GPU guard (or none at all); #2055 consolidates them "
        f"into this one file."
    )
    text = _read(COMMON)
    assert "rex86_wait_for_gpu_drivers()" in text, (
        f"{COMMON} must define rex86_wait_for_gpu_drivers()"
    )
    # The pattern must be a SHARED regex variable, not a per-call
    # inline pattern. The whole point of #2055's item 3 is one
    # pattern that matches every driver by construction.
    assert "REX86_DRIVER_PATTERN" in text, (
        f"{COMMON} must define a top-level REX86_DRIVER_PATTERN regex "
        f"that includes the rex86_/real_bench_run naming convention. "
        f"Per-call inline patterns or enumerated lists regress item 3."
    )
    # The shared pattern must actually match the rex86_ naming
    # convention, not be a hardcoded enumerated list of script
    # names (which would regress item 3 by having to be kept in sync).
    assert "rex86_" in text.split("REX86_DRIVER_PATTERN", 1)[1].split("\n", 1)[0], (
        f"{COMMON} must use a regex pattern (e.g. `rex86_*.sh`) not "
        f"an enumerated list of script names -- item 3 is about "
        f"making the guard resilient to new drivers by construction."
    )


def test_every_driver_sources_the_common_helper():
    """Every driver in this directory must source rex86_common.sh
    so the shared GPU guard and the result-file helpers are
    available. A driver that doesn\'t source the helper either
    (a) keeps the old per-driver GPU guard (item 3 regression)
    or (b) launches without a GPU guard at all (item 3 worse
    regression)."""
    for driver in DRIVER_SCRIPTS:
        path = Rex86_DIR / driver
        if not path.exists():
            continue  # file may have been renamed in this batch
        text = _read(path)
        assert "source " in text and "rex86_common.sh" in text, (
            f"{driver} must source rex86_common.sh to get the shared "
            f"GPU guard (item 3) and the result-file helpers (item 1 "
            f"and 2). Add `source \"$WORK/rex86_common.sh\"` (or the "
            f"equivalent path) to the top of the driver, after `set -e...`."
        )


def test_no_driver_does_bare_rm_f_before_launch():
    """Item 1: the old pattern was
        rm -f "$result"
        docker exec ... llama-server ...
    which destroys the previous run's result on a failed launch.
    The fix is to either move the rm after the run produces output
    (on success), or use a .tmp file that's only promoted on
    success. This test asserts the bare pre-launch rm is gone."""
    # Pattern: a line `rm -f "$result"` (or `rm -f <name>.corpus_eval.out`)
    # appears immediately before the docker exec llama-server launch.
    for driver in DRIVER_SCRIPTS:
        path = Rex86_DIR / driver
        if not path.exists():
            continue
        text = _read(path)
        # Find every "rm -f" that targets a *.corpus_eval.out file
        # and verify the next non-comment, non-blank line is NOT a
        # docker exec ... llama-server launch.
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if not re.search(
                r"\brm\s+-f\b.*\.corpus_eval\.out",
                line,
            ):
                continue
            # Look at the next ~5 non-blank, non-comment lines
            j = i + 1
            saw_launch = False
            while j < len(lines) and j < i + 8:
                nxt = lines[j].strip()
                if not nxt or nxt.startswith("#"):
                    j += 1
                    continue
                if "llama-server" in nxt or "ollama serve" in nxt or "vllm" in nxt:
                    saw_launch = True
                break
                # The rm was followed by a non-launch line; check the
                # next non-blank line
                j += 1
            if saw_launch and "tmp" not in line:
                pytest.fail(
                    f"{driver}: line {i+1} does `rm -f` on a .corpus_eval.out "
                    f"file and the next non-blank line launches a model "
                    f"server. A failed launch will destroy the previous "
                    f"run's result. #2055 item 1: move the rm to AFTER the "
                    f"launch produces output (or use a .tmp file that's "
                    f"only promoted on success)."
                )


def test_prefetch_pins_hf_snapshot():
    """Item 4: rex86_prefetch_base_models.sh must pin the HF snapshot
    to a specific commit hash, not `latest` or a moving tag. A new
    snapshot can break a run mid-batch; pinning to a commit hash
    guarantees reproducibility.

    The script may either hardcode the hash in the script source
    (preferred for fully reproducible runs) OR resolve "main" to a
    concrete commit SHA at fetch time via the HfApi() helper and
    pin the download to that. Both forms are acceptable; the test
    is the negation: a bare `revision="main"` or no --revision
    at all (defaults to main) is a regression."""
    path = Rex86_DIR / "rex86_prefetch_base_models.sh"
    if not path.exists():
        pytest.skip("rex86_prefetch_base_models.sh not found")
    text = _read(path)
    # Form 1: hardcoded commit hash in source
    has_pinned_hash = bool(
        re.search(r"--revision[=\s]+[0-9a-f]{8,40}", text)
        or re.search(
            r"huggingface\.co/[^/]+/[^/]+/resolve/[0-9a-f]{8,40}",
            text,
        )
    )
    # Form 2: resolves "main" to a concrete commit at fetch time
    # via the HfApi() helper, then pins the download to that.
    # Pattern: HfApi().model_info(...).sha (or .id, or .commit_sha)
    # followed by a snapshot_download using that resolved value.
    has_runtime_resolved_pin = bool(
        re.search(
            r"HfApi\(\)\.model_info\([^)]+\)\.(sha|id|commit_sha)",
            text,
        )
        and re.search(
            r"snapshot_download\([^)]*revision\s*=",
            text,
        )
    )
    assert has_pinned_hash or has_runtime_resolved_pin, (
        f"{path} must pin the HuggingFace snapshot to a specific "
        f"commit hash, either as a hardcoded `--revision <hash>` in "
        f"the script source OR by resolving the moving branch to a "
        f"concrete commit via `HfApi().model_info(...).sha` and "
        f"pinning `snapshot_download(..., revision=...)` to that. A "
        f"bare `revision=\"main\"` or no --revision at all (defaults "
        f"to main) is a regression. #2055 item 4: a new snapshot can "
        f"break a run mid-batch; pin to a commit hash for "
        f"reproducibility."
    )


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
