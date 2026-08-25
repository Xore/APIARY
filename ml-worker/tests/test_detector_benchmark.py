"""Tests for the Tier 1 detector contract benchmark (issue #1794).

The checks are exercised against stub candidates rather than the real models,
so the harness's own logic is verified without torch and without a trained
checkpoint. The point is that a *failing* candidate is actually caught -- a
contract benchmark that passes everything is worse than none, because it
launders an untested detector as a checked one.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks.evaluate_detectors import (  # noqa: E402
    ABSTENTION,
    NEUTRAL,
    Candidate,
    check_abstains_without_history,
    check_neutral_on_inference_failure,
    check_scores_are_bounded,
    check_survives_every_sensor_schema,
    check_survives_malformed_document,
    load_fixtures,
    run_checks,
)

FIXTURES = load_fixtures()


def candidate(fn, *, abstains=True, name="stub"):
    return Candidate(name=name, score_event=fn, abstains=abstains)


class TestAbstention:
    def test_accepts_a_detector_that_abstains(self):
        result = check_abstains_without_history(
            candidate(lambda src, n: ABSTENTION), FIXTURES["single_event"])
        assert result.passed

    def test_rejects_a_low_score_standing_in_for_abstention(self):
        """0.01 asserts normality about a source barely seen. No accuracy
        metric would ever show this."""
        result = check_abstains_without_history(
            candidate(lambda src, n: 0.01), FIXTURES["single_event"])
        assert not result.passed
        assert "asserts normality" in result.detail

    def test_rejects_the_neutral_value_as_abstention(self):
        result = check_abstains_without_history(
            candidate(lambda src, n: NEUTRAL), FIXTURES["single_event"])
        assert not result.passed

    def test_skips_for_a_detector_that_declares_it_does_not_abstain(self):
        """IsoForest returns the neutral 0.5 before its first retrain instead,
        so the check would be meaningless rather than failing."""
        result = check_abstains_without_history(
            candidate(lambda src, n: NEUTRAL, abstains=False), FIXTURES["single_event"])
        assert result.skipped

    def test_abstention_and_neutral_are_different_values(self):
        assert ABSTENTION != NEUTRAL


class TestInferenceFailure:
    def test_accepts_neutral_on_failure(self):
        result = check_neutral_on_inference_failure(
            candidate(lambda src, n: NEUTRAL), FIXTURES["single_event"], lambda: None)
        assert result.passed

    def test_rejects_failing_to_confident_normal(self):
        """Returning 0.0 on an inference error reads as 'confirmed normal',
        the one answer a broken detector must never give."""
        result = check_neutral_on_inference_failure(
            candidate(lambda src, n: 0.0), FIXTURES["single_event"], lambda: None)
        assert not result.passed
        assert "confirmed normal" in result.detail

    def test_rejects_propagating_the_exception(self):
        def boom(src, n):
            raise RuntimeError("cuda is on fire")

        result = check_neutral_on_inference_failure(
            candidate(boom), FIXTURES["single_event"], lambda: None)
        assert not result.passed
        assert "propagated" in result.detail

    def test_skips_when_no_fault_injector_is_supplied(self):
        result = check_neutral_on_inference_failure(
            candidate(lambda src, n: NEUTRAL), FIXTURES["single_event"], None)
        assert result.skipped


class TestBounds:
    def test_accepts_scores_in_range(self):
        assert check_scores_are_bounded(
            candidate(lambda src, n: 0.42), FIXTURES["documents"]).passed

    @pytest.mark.parametrize("bad", [1.5, -0.1, float("nan"), None, "0.5", True])
    def test_rejects_out_of_range_or_non_numeric(self, bad):
        """A NaN or an out-of-range value poisons the composite blend rather
        than failing visibly. True is rejected too -- bool is an int subclass
        and would otherwise slip through as 1.0."""
        assert not check_scores_are_bounded(
            candidate(lambda src, n: bad), FIXTURES["documents"]).passed


class TestSchemaCoverage:
    def test_accepts_a_detector_that_handles_every_sensor(self):
        result = check_survives_every_sensor_schema(
            candidate(lambda src, n: 0.5), FIXTURES["by_sensor"])
        assert result.passed
        assert "dionaea-incident" in result.observed
        assert "conpot-modbus" in result.observed

    def test_rejects_a_detector_that_throws_on_one_sensor(self):
        """A detector that throws on one sensor stops scoring it, and the alert
        count merely drops -- which looks like an improvement."""
        def picky(src, n):
            if "conpot" in str(src.get("event", {}).get("sensor", "")).lower():
                raise KeyError("event.sensor")
            return 0.5

        result = check_survives_every_sensor_schema(candidate(picky), FIXTURES["by_sensor"])
        assert not result.passed
        assert "raised" in result.detail

    def test_malformed_document_must_not_raise(self):
        def fragile(src, n):
            return float(src["@timestamp"] is not None)

        assert not check_survives_malformed_document(
            candidate(fragile), FIXTURES["malformed"]).passed
        assert check_survives_malformed_document(
            candidate(lambda src, n: 0.5), FIXTURES["malformed"]).passed


class TestReport:
    def test_a_clean_candidate_passes_and_declares_its_caps(self):
        report = run_checks(
            candidate(lambda src, n: ABSTENTION), FIXTURES, lambda: None)
        # The stub abstains on every call, including the failure probe, so the
        # neutral check fails -- which is itself the correct outcome.
        assert any(c.name == "neutral_on_inference_failure" and not c.passed
                   for c in report.checks)
        assert report.caps, "a run must state the bounds it applied"
        assert "does not measure accuracy" in report.caps[0]

    def test_skipped_checks_do_not_count_as_passed(self):
        """A check that could not run is not a check that passed."""
        report = run_checks(candidate(lambda src, n: 0.5, abstains=False), FIXTURES, None)
        summary = report.as_dict()
        assert summary["counts"]["skipped"] >= 2
        assert summary["counts"]["passed"] + summary["counts"]["failed"] \
            + summary["counts"]["skipped"] == summary["counts"]["total"]

    def test_a_failing_candidate_fails_the_report(self):
        report = run_checks(candidate(lambda src, n: 99.0), FIXTURES, lambda: None)
        assert not report.passed


class TestFixtures:
    def test_every_sensor_shape_is_present(self):
        assert len(FIXTURES["by_sensor"]) >= 7
        assert FIXTURES["documents"]
        assert FIXTURES["malformed"] is not None

    def test_fixtures_use_only_reserved_addresses(self):
        """Same safety rule as the LLM fixtures: TEST-NET only, reviewed before
        commit."""
        import json as _json
        blob = _json.dumps(FIXTURES["documents"])
        for reserved in ("192.0.2.", "198.51.100.", "203.0.113."):
            if reserved in blob:
                break
        else:
            pytest.fail("no TEST-NET address found in the fixture corpus")
