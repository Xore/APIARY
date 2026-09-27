#!/usr/bin/env python3
"""#3318: frontend-next's coverage ratchet, plus the test-discovery guard.

Two checks, one command, one CI step, because they are the same question asked
twice: does what CI runs still exercise what it used to?

  1. RATCHET. Read the *measured* coverage summary the frontend's own
     `npm run test:coverage` just wrote (coverage/coverage-summary.json,
     vitest's json-summary reporter) and compare it against the committed
     baseline in frontend-next/coverage-baseline.json. Two conditions, on the
     same measurement:

       a. the percentage must not be more than `tolerancePoints` below the
          baseline -- the issue's own ask ("fails when coverage drops by more
          than a small tolerance");
       b. the number of *covered* lines and branches must not be below the
          baseline at all.

     (b) is the sharper of the two and is why the gate is worth having. A
     percentage over 7,359 lines cannot see a seven-line regression -- the
     denominator is big enough to absorb it -- while the covered count drops
     by exactly seven and says so. (b) is the property the issue names
     ("no way to tell when a change deletes tested behavior"): a test file
     deleted, or a covered branch deleted out of a module, moves it. Both
     conditions read the same measured file, and (b) only ever makes the gate
     stricter, so it cannot weaken what (a) enforces.

     The measured number is read from a file the run produced; nothing here
     knows what coverage "should" be except the committed baseline, and that
     baseline only moves when someone edits it in a commit -- there is no
     --update flag, no auto-accept, and no environment variable that widens
     either tolerance, so the only way to lower the gate is a visible diff.

  2. DISCOVERY GUARD. Read the `include:` globs out of vitest.config.ts and
     fail if any *.test.ts / *.test.tsx file in the frontend tree is one those
     globs would not collect. A test file vitest never runs is a file, not a
     check: it sits in the tree looking like coverage, and the ratchet above
     would happily read the number produced without it.

Both failures are reported, not just the first, so one red run says everything
that is wrong with it. Exit status is the only thing CI reads.

Stdlib only, and the two inputs it needs (the measured summary, the globs) are
files this repository already produces. Nothing is fetched, no service is
contacted, and the walk stays inside the frontend directory.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

# frontend-next/ relative to the repository root, which is this script's
# grandparent. Anchored on __file__ so the check works from any working
# directory -- CI runs it from the workspace root, a developer runs it from
# the frontend directory, and a check that only works from one of those is a
# check people stop running.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FRONTEND_REL = "arcane/home/honeypot-dashboard/frontend-next"

# Directories that hold no source of ours. node_modules and the build outputs
# are the obvious pair; the rest are the run artifacts .gitignore already keeps
# out of the tree, listed so the walk does not have to learn about each one
# separately.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".nitro",
        ".output",
        ".stryker-tmp",
        ".tanstack",
        "coverage",
        "dist",
        "node_modules",
        "playwright-report",
        "reports",
        "test-results",
    }
)

# The suffix set that means "a unit test file". e2e/*.spec.ts is deliberately
# NOT here: those are Playwright's, run by a different job with a different
# config, and flagging them would be a false positive on a correct tree.
TEST_SUFFIXES = (".test.ts", ".test.tsx")

# `include: ['a', 'b']` in vitest.config.ts. Non-greedy so it stops at the
# first ']' rather than running to the last one in the file.
_INCLUDE_BLOCK = re.compile(r"\binclude\s*:\s*\[(.*?)\]", re.S)
_QUOTED = re.compile(r"""['"]([^'"]+)['"]""")

METRICS = ("lines", "branches")


class GateError(Exception):
    """A problem with the gate's own inputs, as opposed to a failing gate."""


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Compile a vitest/tinyglobby-style glob, where ** spans path segments.

    `fnmatch` is not usable here: its `*` crosses '/', so the pattern
    `src/**/*.test.ts` would not match `src/foo.test.ts` under it, while
    vitest matches that (a `**` segment matches zero directories). Getting this
    wrong in the permissive direction would make the discovery guard pass
    vacuously, which is the one failure mode it must not have.
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def read_include_globs(vitest_config: pathlib.Path) -> list[str]:
    """The `include:` globs, read from the config rather than restated here.

    Deriving instead of re-declaring is the whole #3331 argument applied to a
    second file: a copy of the globs in this script is a second thing to
    forget, and forgetting it is precisely how a guard starts passing against
    a config it no longer describes.

    An unreadable or empty glob list is an error, never an empty match set --
    a guard with no patterns would flag every test file in the tree, and a
    guard that could not tell the difference is not a guard.
    """
    try:
        text = vitest_config.read_text(encoding="utf-8")
    except OSError as exc:
        raise GateError(f"cannot read {vitest_config}: {exc}") from exc
    block = _INCLUDE_BLOCK.search(text)
    if block is None:
        raise GateError(f"no `include: [...]` found in {vitest_config}")
    globs = _QUOTED.findall(block.group(1))
    if not globs:
        raise GateError(f"`include:` in {vitest_config} lists no globs")
    return globs


def iter_test_files(frontend: pathlib.Path):
    """Every *.test.ts / *.test.tsx under the frontend tree, walking down only."""
    for path in sorted(frontend.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(frontend).parts[:-1]):
            continue
        if path.name.endswith(TEST_SUFFIXES):
            yield path


def undiscovered_tests(frontend: pathlib.Path, globs: list[str]) -> list[str]:
    """Test files no include glob would collect, relative to `frontend`."""
    patterns = [glob_to_regex(g) for g in globs]
    missed = []
    for path in iter_test_files(frontend):
        rel = path.relative_to(frontend).as_posix()
        if not any(p.match(rel) for p in patterns):
            missed.append(rel)
    return missed


def _metric(summary: dict, metric: str, field: str, label: str) -> float:
    try:
        return float(summary[metric][field])
    except (KeyError, TypeError, ValueError) as exc:
        raise GateError(
            f"{label} has no {metric}.{field} -- a coverage-summary.json the "
            f"gate cannot read is a coverage claim nobody can check"
        ) from exc


def _pct(summary: dict, metric: str, label: str) -> float:
    return _metric(summary, metric, "pct", label)


def check_ratchet(
    baseline: dict, measured: dict, tolerance_points: float, tolerance_counts: float
) -> list[str]:
    """Errors for every metric that fell past either allowance.

    Compared per metric rather than on some average, so a change that trades
    branch coverage for line coverage cannot hide inside a combined number.
    """
    errors = []
    for metric in METRICS:
        base_pct = _pct(baseline, metric, "coverage-baseline.json")
        got_pct = _pct(measured, metric, "the measured coverage summary")
        if got_pct < base_pct - tolerance_points:
            errors.append(
                f"coverage {metric} dropped: baseline {base_pct:.2f}%, measured "
                f"{got_pct:.2f}% (tolerance {tolerance_points:.2f} points). Raise "
                f"it back with a test, or -- if the drop is intended -- record "
                f"the new measurement in coverage-baseline.json in the same commit."
            )
        base_cov = _metric(baseline, metric, "covered", "coverage-baseline.json")
        got_cov = _metric(measured, metric, "covered", "the measured coverage summary")
        if got_cov < base_cov - tolerance_counts:
            errors.append(
                f"covered {metric} regressed: baseline {base_cov:g}, measured "
                f"{got_cov:g} (allowance {tolerance_counts:g}). Fewer lines or "
                f"branches under test than the baseline records is exactly the "
                f"non-regression this gate exists for -- a deleted or narrowed "
                f"test, not a rounding difference."
            )
    return errors


def load_json(path: pathlib.Path, label: str) -> dict:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise GateError(f"cannot read {label} at {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise GateError(f"{label} at {path} is not valid JSON: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--frontend", type=pathlib.Path, default=REPO_ROOT / FRONTEND_REL)
    parser.add_argument("--baseline", type=pathlib.Path, default=None)
    parser.add_argument("--measured", type=pathlib.Path, default=None)
    parser.add_argument("--vitest-config", type=pathlib.Path, default=None)
    args = parser.parse_args(argv)

    frontend = args.frontend.resolve()
    baseline_path = args.baseline or frontend / "coverage-baseline.json"
    measured_path = args.measured or frontend / "coverage" / "coverage-summary.json"
    config_path = args.vitest_config or frontend / "vitest.config.ts"

    try:
        baseline = load_json(baseline_path, "the committed baseline")
        measured = load_json(measured_path, "the measured coverage summary")
        globs = read_include_globs(config_path)
        # The tolerances live in the committed baseline, not on the command
        # line: a flag would let a workflow edit widen the gate without the
        # diff that widening the baseline demands.
        tolerance_points = float(baseline["tolerancePoints"])
        tolerance_counts = float(baseline["toleranceCounts"])
    except GateError as exc:
        print(f"::error::{exc}")
        return 2
    except (KeyError, TypeError, ValueError) as exc:
        print(
            f"::error::{baseline_path} does not carry numeric tolerancePoints and "
            f"toleranceCounts: {exc}"
        )
        return 2

    errors: list[str] = []
    try:
        if not isinstance(measured.get("total"), dict):
            raise GateError(
                "the measured summary has no `total` block -- vitest's "
                "json-summary reporter writes one, so this is a different file"
            )
        errors = check_ratchet(
            baseline["total"], measured["total"], tolerance_points, tolerance_counts
        )
    except GateError as exc:
        print(f"::error::{exc}")
        return 2

    missed = undiscovered_tests(frontend, globs)
    for rel in missed:
        errors.append(
            f"{rel} is a test file no `include:` glob in "
            f"{config_path.name} would collect -- it never runs, and it is not "
            f"in the coverage number either. Widen the include globs, or move "
            f"the file into a directory they cover."
        )

    print(f"include globs: {', '.join(globs)}")
    for metric in METRICS:
        print(
            f"{metric}: baseline {_pct(baseline['total'], metric, 'baseline'):.2f}% "
            f"({_metric(baseline['total'], metric, 'covered', 'baseline'):g} covered)  "
            f"measured {_pct(measured['total'], metric, 'measured'):.2f}% "
            f"({_metric(measured['total'], metric, 'covered', 'measured'):g} covered)  "
            f"tolerance {tolerance_points:.2f} points / {tolerance_counts:g} items"
        )
    print(f"test files checked for discovery: {sum(1 for _ in iter_test_files(frontend))}")

    for error in errors:
        print(f"::error::{error}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
