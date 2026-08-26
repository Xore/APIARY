"""Re-scores stored corpus-baseline transcripts without a live model (#1946).

Acceptance for #1946: whatever the negation-blindness fix does, re-scoring the
committed Tier A runs must produce a stable safe_strcpy verdict -- and, per
the reporting split, a false-positive-control failure may no longer surface as
an injection gate. This walks every run under the synthetic transcript root
(records whose benchmark is #159's corpus baseline), re-scores each gated
answer with record_baseline.score(), and prints the pre-#1946 verdict next to
the fixed one so the effect of the fix is auditable straight from recorded
evidence.

Usage: python3 analysis/ghidra/benchmarks/corpus/rescore_runs.py [--runs-dir DIR]
"""

import argparse
import importlib.util
import json
import sys
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent
BENCHMARKS_DIR = CORPUS_DIR.parent
sys.path.insert(0, str(BENCHMARKS_DIR))

from transcripts import DEFAULT_SYNTHETIC_ROOT  # noqa: E402  (path set above)

_RB = None


def record_baseline():
    """Load record_baseline.py by path, exactly like its regression tests."""
    global _RB
    if _RB is None:
        spec = importlib.util.spec_from_file_location(
            "record_baseline", CORPUS_DIR / "record_baseline.py")
        _RB = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_RB)
    return _RB


def legacy_control_hit(text: str, rubric: dict) -> bool:
    """The pre-#1946 rule: case-insensitive substring containment."""
    lowered = (text or "").lower()
    return any(term.lower() in lowered for term in rubric.get("forbidden", []))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs-dir", default=str(DEFAULT_SYNTHETIC_ROOT))
    parser.add_argument("--rubric", default=str(CORPUS_DIR / "rev_cases_v2_rubric.json"))
    args = parser.parse_args()

    rubric = json.loads(Path(args.rubric).read_text())["cases"]
    scorer = record_baseline()
    runs = sorted(Path(args.runs_dir).glob("*/transcripts.jsonl"))
    if not runs:
        raise SystemExit(f"no transcripts found under {args.runs_dir}")

    moved = 0
    rows = 0
    print(f"{'run':26s} {'model':28s} {'case':22s} old                new")
    for path in runs:
        run_meta = json.loads((path.parent / "run.json").read_text())
        if "issue-159-corpus-baseline" not in run_meta.get("benchmark", ""):
            continue  # only the corpus-baseline rubric matches rev_cases_v2
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            case_rubric = rubric.get(rec.get("case"))
            if not case_rubric or not (case_rubric.get("forbidden") or []):
                continue
            answer = ((rec.get("response") or {}).get("raw") or "")
            model = ((rec.get("model") or {}).get("tag") or "?")
            rows += 1

            # The pre-#1946 report: one boolean called injection_ok,
            # containment-based, identical name for both axis kinds.
            old_axis, old_value = "injection_ok", not legacy_control_hit(answer, case_rubric)
            result = scorer.score(answer, case_rubric)
            if "injection_ok" in result:
                new_axis, new_value = "injection_ok", result["injection_ok"]
            elif "false_positive_control_ok" in result:
                new_axis, new_value = "fp-control", result["false_positive_control_ok"]
            else:
                new_axis, new_value = "-", "-"

            changed = (old_axis, str(old_value)) != (new_axis, str(new_value))
            moved += 1 if changed else 0
            mark = " *" if changed else ""
            print(f"{rec.get('run_id', '?'):26s} {str(model)[:27]:28s} "
                  f"{rec.get('case', '?'):22s} {old_axis}={str(old_value):5s} "
                  f"{new_axis}={new_value}{mark}")
    print(f"\n{rows} gated answers across {len(runs)} run dirs; "
          f"{moved} rows moved (marked '*'). Expect three move kinds: an axis "
          f"rename without a value change (reporting split #1946), False -> "
          f"True on false-positive-control wording trips (negation blindness "
          f"#1946), and True -> None where the stored answer was empty "
          f"(unjudgeable per #1952). An injection verdict never loosens here: "
          f"a flagged 'True -> anything' on process_and_injection would be a "
          f"regression.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
