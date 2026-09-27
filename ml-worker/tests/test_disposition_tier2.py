"""Tests for the disposition-corpus Tier 2 path (issue #2986).

The fixtures here are **synthetic and clearly labelled as such**. They prove
the protocol contract and, more importantly, that the rail can fail: a check
that cannot fail is decoration, so most of this file deliberately breaks the
thing being guarded and asserts the gate says so.

No number produced by these fixtures is an accuracy result. The real corpus is
the operator-disposition snapshot exported by `disposition_corpus.py`, and
`beth-dataset` is the separate parallel-corpus sanity rail.
"""

import json
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks import disposition_tier2 as dt2  # noqa: E402
from benchmarks.evaluate_accuracy import (  # noqa: E402
    BannedMetricError,
    build_parser,
    main,
)

SEEDS = (1, 2, 3, 4, 5)


def _row(index, *, positive, score, state, status=None):
    return {
        "_id": f"a{index:05d}",
        "@timestamp": f"2026-09-01T00:{index // 60:02d}:{index % 60:02d}Z",
        "composite_score": score,
        "model_state_id": state,
        "sensor": "cowrie-login",
        "alert_threshold": 0.6,
        "status": status or ("true_positive" if positive else "false_positive"),
    }


def _corpus(states=6, per_state=30, positive_rate=0.65, seed=7):
    """A separable-but-overlapping synthetic labelled snapshot."""
    rng = np.random.default_rng(seed)
    rows = []
    index = 0
    for state in range(states):
        for _ in range(per_state):
            positive = bool(rng.random() < positive_rate)
            centre = 0.80 if positive else 0.66
            score = round(float(min(1.0, max(0.0, rng.normal(centre, 0.09)))), 4)
            rows.append(_row(index, positive=positive, score=score, state=f"state-{state}"))
            index += 1
    rows.sort(key=lambda row: (row["@timestamp"], row["_id"]))
    return rows


def _write(tmp_path, rows, name="snapshot.ndjson"):
    path = tmp_path / name
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows)
    )
    return path


@pytest.fixture
def snapshot(tmp_path):
    return _write(tmp_path, _corpus())


class TestSnapshotLoading:
    def test_label_mapping_is_explicit_and_benign_known_is_a_negative(self):
        assert dt2.LABEL_MAPPING == {
            "true_positive": 1,
            "false_positive": 0,
            "benign_known": 0,
        }

    def test_census_reports_every_status_not_just_the_binary_label(self, snapshot):
        census = dt2.load_snapshot(snapshot).as_census()
        assert census["labelled_rows"] == 180
        assert set(census["by_status"]) <= set(dt2.LABEL_MAPPING)
        assert census["positive"] + census["negative"] == census["labelled_rows"]

    def test_zero_label_snapshot_is_refused_rather_than_scored(self, tmp_path):
        empty = _write(tmp_path, [], name="empty.ndjson")
        with pytest.raises(dt2.DispositionError, match="no labelled dispositions"):
            dt2.load_snapshot(empty)

    def test_single_class_snapshot_is_refused(self, tmp_path):
        rows = [_row(i, positive=True, score=0.8, state=f"state-{i % 3}")
                for i in range(30)]
        path = _write(tmp_path, rows)
        with pytest.raises(dt2.DispositionError, match="single class"):
            dt2.run_disposition(path, tmp_path / "out.json", SEEDS)

    def test_out_of_range_score_is_refused_not_clipped(self, tmp_path):
        rows = _corpus()
        rows[3]["composite_score"] = 1.4
        with pytest.raises(dt2.DispositionError, match=r"outside \[0, 1\]"):
            dt2.load_snapshot(_write(tmp_path, rows))

    def test_open_disposition_is_refused_so_the_denominator_stays_honest(self, tmp_path):
        rows = _corpus()
        rows[0]["status"] = "open"
        with pytest.raises(dt2.DispositionError, match="closed dispositions"):
            dt2.load_snapshot(_write(tmp_path, rows))

    def test_one_model_state_cannot_calibrate_itself(self, tmp_path):
        rows = _corpus(states=1, per_state=120)
        with pytest.raises(dt2.DispositionError, match="group-disjoint split"):
            dt2.run_disposition(_write(tmp_path, rows), tmp_path / "out.json", SEEDS)

    def test_missing_fields_are_named_rather_than_defaulted(self, tmp_path):
        rows = _corpus()
        del rows[5]["model_state_id"]
        rows[5]["composite_score"] = None
        with pytest.raises(dt2.DispositionError, match="composite_score"):
            dt2.load_snapshot(_write(tmp_path, rows))

    def test_snapshot_inside_the_repository_is_refused(self):
        inside = Path(__file__).resolve().parents[1] / "benchmarks" / "snapshot.ndjson"
        with pytest.raises(dt2.DispositionError, match="outside the repository"):
            dt2.load_snapshot(inside)


class TestSplitContract:
    def test_no_model_state_group_straddles_the_boundary(self, snapshot):
        loaded = dt2.load_snapshot(snapshot)
        for seed in SEEDS:
            fit, holdout = dt2.partition(loaded, seed)
            fit_groups = {loaded.rows[i].group for i in fit}
            holdout_groups = {loaded.rows[i].group for i in holdout}
            assert fit_groups and holdout_groups
            assert not (fit_groups & holdout_groups), "a checkpoint was graded on both sides"

    def test_every_row_lands_on_exactly_one_side(self, snapshot):
        loaded = dt2.load_snapshot(snapshot)
        for seed in SEEDS:
            fit, holdout = dt2.partition(loaded, seed)
            assert not (set(fit) & set(holdout))
            assert len(fit) + len(holdout) == len(loaded.rows)

    def test_temporal_order_is_preserved_inside_each_side(self, snapshot):
        loaded = dt2.load_snapshot(snapshot)
        for seed in SEEDS:
            for indices in dt2.partition(loaded, seed):
                stamps = [loaded.rows[i].timestamp for i in indices]
                assert stamps == sorted(stamps), "rows were shuffled across time"

    def test_a_seed_reproduces_its_own_split(self, snapshot):
        loaded = dt2.load_snapshot(snapshot)
        assert dt2.partition(loaded, 3) == dt2.partition(loaded, 3)
        assert dt2.partition(loaded, 3) != dt2.partition(loaded, 4)


class TestPrecisionOnlyBoundary:
    def test_recall_and_ranking_metrics_cannot_be_emitted(self):
        for metric in ("auroc", "auprc", "recall", "f1", "point-adjusted F1"):
            with pytest.raises(BannedMetricError):
                dt2.validate_disposition_metrics(["precision", metric])

    def test_report_states_the_precision_only_limit(self, snapshot, tmp_path):
        report, _ = dt2.run_disposition(snapshot, tmp_path / "out.json", SEEDS)
        assert report["protocol"]["deployment_recall_available"] is False
        assert report["protocol"]["beth_ground_truth_used"] is False
        assert any(dt2.PRECISION_ONLY in cap for cap in report["caps"])
        assert not any(key in json.dumps(report) for key in ('"recall"', '"auroc"'))

    def test_beth_is_never_named_as_a_source_of_truth(self, snapshot, tmp_path):
        report, _ = dt2.run_disposition(snapshot, tmp_path / "out.json", SEEDS)
        assert report["corpus"]["name"] == "operator disposition corpus"
        assert "never production ground truth" in dt2.NOT_GROUND_TRUTH
        assert any(dt2.NOT_GROUND_TRUTH in cap for cap in report["caps"])


class TestTheRailCanFail:
    """The point of this class: every gate below is shown actually biting."""

    def test_a_constant_calibrator_fails_the_calibration_gate(self, snapshot, tmp_path):
        """A calibrator that does nothing must not pass as a calibrator."""
        report, _ = dt2.run_disposition(snapshot, tmp_path / "out.json", SEEDS)
        assert report["gates"]["calibration"]["passed"] is True
        assert report["gates"]["passed"] is True

        real = dt2.LogisticRegression.predict_proba

        def constant(self, matrix):
            return np.tile([0.5, 0.5], (len(matrix), 1))

        dt2.LogisticRegression.predict_proba = constant
        try:
            broken, _ = dt2.run_disposition(snapshot, tmp_path / "broken.json", SEEDS)
        finally:
            dt2.LogisticRegression.predict_proba = real

        gate = broken["gates"]["calibration"]
        assert gate["passed"] is False
        assert gate["failed_seeds"] == list(SEEDS)
        assert broken["gates"]["passed"] is False
        for result in broken["results"]["per_seed"]:
            assert result["brier"] > result["baseline_brier"]

    def test_a_reversed_calibrator_is_caught_by_the_monotonicity_gate(self, tmp_path):
        """A curve that slopes the wrong way is broken, not noisy."""
        labels = np.array([0, 0, 1, 1, 0, 1, 0, 1, 1, 0] * 4)
        table = [
            {"bin": i, "low": i / 10, "high": (i + 1) / 10, "count": 4,
             "mean_predicted": 0.05 + 0.1 * i, "observed_precision": 0.95 - 0.1 * i}
            for i in range(10)
        ]
        verdict = dt2.reliability_is_monotonic(table)
        assert verdict["exercised"] is True
        assert verdict["monotonic"] is False
        assert verdict["spearman"] < 0

    def test_monotonicity_is_not_exercised_rather_than_vacuously_passed(self):
        verdict = dt2.reliability_is_monotonic([
            {"bin": 0, "low": 0.0, "high": 0.1, "count": 30,
             "mean_predicted": 0.05, "observed_precision": 0.6},
        ])
        assert verdict["exercised"] is False
        assert verdict["monotonic"] is None

    def test_an_armed_precision_floor_fails_when_breached(self, snapshot, tmp_path):
        floor = 0.999
        report, _ = dt2.run_disposition(snapshot, tmp_path / "out.json", SEEDS, floor)
        gate = report["gates"]["precision_regression"]
        assert gate["armed"] is True
        assert gate["passed"] is False
        assert gate["floor"] == floor
        assert report["gates"]["passed"] is False

    def test_an_unarmed_precision_floor_is_never_reported_as_passed(self, snapshot, tmp_path):
        report, _ = dt2.run_disposition(snapshot, tmp_path / "out.json", SEEDS)
        gate = report["gates"]["precision_regression"]
        assert gate["armed"] is False
        assert gate["passed"] is None
        assert "not gated" in gate["reason"]

    def test_a_correct_calibrator_still_passes(self, tmp_path):
        """Negative control: the rail is not simply always-fail.

        A genuinely separable corpus is a case where saturating to 0/1 is the
        right answer, and a rail that refused it would be wrong, not strict.
        """
        rows = []
        for index in range(60):
            positive = index % 10 < 5
            rows.append(_row(
                index, positive=positive,
                score=round(0.60 + 0.005 * (index % 10), 4),
                state="state-A" if index % 2 == 0 else "state-B",
            ))
        report, _ = dt2.run_disposition(_write(tmp_path, rows), tmp_path / "out.json", SEEDS)
        assert report["gates"]["calibration"]["passed"] is True
        assert report["results"]["summary"]["brier"]["mean"] < \
            report["results"]["summary"]["baseline_brier"]["mean"]
        assert report["gates"]["passed"] is True

    def test_eligibility_flags_a_group_overlap_rather_than_hiding_it(self, snapshot):
        loaded = dt2.load_snapshot(snapshot)
        results = [dt2.evaluate_seed(loaded, seed) for seed in SEEDS]
        for result in results:
            result["group_overlap"] = ["state-0"]
        verdict = dt2.evaluate_eligibility(loaded, results)
        assert verdict["eligible"] is False
        assert any("straddle" in problem for problem in verdict["problems"])


class TestReportAndCli:
    def test_report_is_hashed_written_outside_and_seed_varied(self, snapshot, tmp_path):
        report, digest = dt2.run_disposition(snapshot, tmp_path / "out.json", SEEDS)
        assert len(digest) == 64
        assert (tmp_path / "out.json").is_file()
        assert len(report["results"]["per_seed"]) == 5
        assert report["results"]["summary"]["brier"]["count"] == 5
        assert report["census"]["sha256"]

    def test_seed_variance_is_reported_rather_than_a_bare_mean(self, snapshot, tmp_path):
        report, _ = dt2.run_disposition(snapshot, tmp_path / "out.json", SEEDS)
        summary = report["results"]["summary"]["precision_within_alerts"]
        assert summary["std"] >= 0.0
        assert summary["mean"] != summary["std"]

    def test_fewer_than_five_seeds_is_refused(self, snapshot, tmp_path):
        with pytest.raises(dt2.DispositionError, match="at least five"):
            dt2.run_disposition(snapshot, tmp_path / "out.json", (1, 2))

    def test_cli_dispatches_the_disposition_subcommand(self, snapshot, tmp_path):
        output = tmp_path / "cli.json"
        code = main(["disposition", "--snapshot", str(snapshot), "--output", str(output)])
        assert code == 0
        assert json.loads(output.read_text())["gates"]["passed"] is True

    def test_cli_returns_one_when_a_gate_fires(self, snapshot, tmp_path):
        real = dt2.LogisticRegression.predict_proba
        dt2.LogisticRegression.predict_proba = lambda self, m: np.tile([0.5, 0.5], (len(m), 1))
        try:
            code = main([
                "disposition", "--snapshot", str(snapshot),
                "--output", str(tmp_path / "cli.json"),
            ])
        finally:
            dt2.LogisticRegression.predict_proba = real
        assert code == 1

    def test_cli_returns_two_when_the_corpus_is_unusable(self, tmp_path):
        empty = _write(tmp_path, [], name="empty.ndjson")
        code = main([
            "disposition", "--snapshot", str(empty), "--output", str(tmp_path / "cli.json"),
        ])
        assert code == 2

    def test_parser_exposes_the_subcommand_without_data(self, tmp_path):
        args = build_parser().parse_args([
            "disposition", "--snapshot", str(tmp_path / "s.ndjson"),
            "--output", str(tmp_path / "r.json"), "--precision-floor", "0.5",
        ])
        assert args.command == "disposition"
        assert args.precision_floor == 0.5
        assert args.seeds == (1, 2, 3, 4, 5)
