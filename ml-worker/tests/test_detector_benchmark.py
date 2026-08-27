"""Tests for the Tier 1 detector contract benchmark (issue #1794), under the
#1969 contract: an opinion is a float in [0, 1]; absence is None -- never a
low score, never a placeholder constant.

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
    ABSENT,
    BENCHMARK_VERSION,
    Candidate,
    check_abstains_on_inference_failure,
    check_abstains_without_history,
    check_composite_renormalises_over_present_detectors,
    check_scores_are_bounded,
    check_survives_every_sensor_schema,
    check_survives_malformed_document,
    load_fixtures,
    run_checks,
)

FIXTURES = load_fixtures()


def candidate(fn, *, abstains=True, trained=False, name="stub"):
    return Candidate(name=name, score_event=fn, abstains=abstains, trained=trained)


class TestAbstention:
    def test_accepts_a_detector_that_abstains(self):
        result = check_abstains_without_history(
            candidate(lambda src, n: ABSENT), FIXTURES["single_event"])
        assert result.passed

    def test_rejects_a_low_score_standing_in_for_abstention(self):
        """0.01 asserts normality about a source barely seen. No accuracy
        metric would ever show this."""
        result = check_abstains_without_history(
            candidate(lambda src, n: 0.01), FIXTURES["single_event"])
        assert not result.passed
        assert "asserts normality" in result.detail

    def test_rejects_a_placeholder_constant_as_absence(self):
        """v1 allowed a neutral 0.5 here; #1969 removed the placeholder
        entirely -- a constant IS a vote, just one cast from nothing."""
        result = check_abstains_without_history(
            candidate(lambda src, n: 0.5), FIXTURES["single_event"])
        assert not result.passed

    def test_skips_for_a_detector_that_declares_it_does_not_abstain(self):
        result = check_abstains_without_history(
            candidate(lambda src, n: 0.5, abstains=False), FIXTURES["single_event"])
        assert result.skipped

    def test_benchmark_version_is_v2(self):
        """Guards against an accidental revert of the #1969 contract while
        keeping v1's sentinel vocabulary."""
        assert BENCHMARK_VERSION.endswith("-v2")


class TestInferenceFailure:
    def test_accepts_absence_on_failure(self):
        result = check_abstains_on_inference_failure(
            candidate(lambda src, n: ABSENT, trained=True),
            FIXTURES["single_event"], lambda: None)
        assert result.passed

    def test_skips_an_untrained_candidate_rather_than_passing_vacuously(self):
        """On an untrained model pre-fault and post-fault are both None, so
        nothing was exercised -- a check that cannot run is not a passing one."""
        result = check_abstains_on_inference_failure(
            candidate(lambda src, n: ABSENT, trained=False),
            FIXTURES["single_event"], lambda: None)
        assert result.skipped
        assert "untrained" in result.detail

    def test_rejects_scoring_confidently_through_the_fault(self):
        """Returning ANY number through a broken forward pass claims knowledge
        it does not have; low scores additionally read as 'confirmed normal'."""
        result = check_abstains_on_inference_failure(
            candidate(lambda src, n: 0.0, trained=True),
            FIXTURES["single_event"], lambda: None)
        assert not result.passed

    def test_rejects_propagating_the_exception(self):
        def boom(src, n):
            raise RuntimeError("cuda is on fire")

        result = check_abstains_on_inference_failure(
            candidate(boom, trained=True), FIXTURES["single_event"], lambda: None)
        assert not result.passed
        assert "propagated" in result.detail

    def test_skips_when_no_fault_injector_is_supplied(self):
        result = check_abstains_on_inference_failure(
            candidate(lambda src, n: ABSENT), FIXTURES["single_event"], None)
        assert result.skipped


class TestBounds:
    def test_accepts_scores_in_range(self):
        assert check_scores_are_bounded(
            candidate(lambda src, n: 0.42), FIXTURES["documents"]).passed

    def test_accepts_absence_and_reports_its_share(self):
        result = check_scores_are_bounded(
            candidate(lambda src, n: ABSENT), FIXTURES["documents"])
        assert result.passed
        assert "abstained as None" in result.detail

    @pytest.mark.parametrize("bad", [1.5, -0.1, float("nan"), "0.5", True])
    def test_rejects_out_of_range_or_non_numeric(self, bad):
        """A NaN or an out-of-range value poisons the composite blend rather
        than failing visibly. True is rejected too -- bool is an int subclass
        and would otherwise slip through as 1.0."""
        assert not check_scores_are_bounded(
            candidate(lambda src, n: bad), FIXTURES["documents"]).passed


class TestCompositeRenormalisation:
    """The ensemble check runs production compute_composite() against
    detector-absent cases (#1969)."""

    def test_production_semantics_pass(self):
        assert check_composite_renormalises_over_present_detectors().passed

    def test_the_check_catches_v1_style_placeholder_arithmetic(self, monkeypatch):
        """A revert to treating None-as-some-vote must fail loudly here --
        the check exercises production code, so break the production code in
        the same way a regression would arrive."""
        import worker

        monkeypatch.setattr(worker, "compute_composite",
                            lambda scores: sum((0.4, 0.4, 0.2)[i] * (scores.get(k) or 0.5)
                                               for i, k in enumerate(["isolation_forest", "lstm_ae", "hbos"])))
        result = check_composite_renormalises_over_present_detectors()
        assert not result.passed


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
        assert check_survives_malformed_document(
            candidate(lambda src, n: ABSENT), FIXTURES["malformed"]).passed


class TestReport:
    def test_an_untrained_abstaining_candidate_passes_with_the_fault_check_skipped(self):
        report = run_checks(
            candidate(lambda src, n: ABSENT), FIXTURES, lambda: None)
        # Nothing exercised the fault path (the candidate is untrained), so
        # that check reports a skip -- visibly, not as a quiet pass.
        assert any(c.name == "abstains_on_inference_failure" and c.skipped
                   for c in report.checks)
        assert report.passed
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
