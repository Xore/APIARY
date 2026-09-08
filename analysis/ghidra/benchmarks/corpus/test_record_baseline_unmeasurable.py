#!/usr/bin/env python3
"""#3090 self-check: a run that scored 0 cases must not be recorded as a result.

Run directly: python3 test_record_baseline_unmeasurable.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from record_baseline import finalize  # noqa: E402


def test_zero_cases_writes_nothing_and_fails():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "would_be_report.json"
        rc = finalize({}, out, model_tag="dead-model:q4", model_digest="sha256:x",
                      request={}, tier="A")
        assert rc != 0, "0 scored cases must not exit 0 (this is #3090)"
        assert not out.exists(), "0 scored cases must not write a result file (this is #3090)"


def test_nonzero_cases_still_writes_normally():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "report.json"
        results = {"case1": {"score": 3, "max_score": 5}}
        rc = finalize(results, out, model_tag="ok-model:q4", model_digest="sha256:y",
                      request={}, tier="A")
        assert rc == 0
        assert out.exists()


if __name__ == "__main__":
    test_zero_cases_writes_nothing_and_fails()
    test_nonzero_cases_still_writes_normally()
    print("OK")
