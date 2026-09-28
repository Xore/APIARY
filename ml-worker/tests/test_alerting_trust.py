"""Tests for the #3451 alerting-trust measurement.

The claims under test are mostly negative ones -- that the harness *refuses* to
produce a number it cannot earn. Those are the claims that matter, so they are
asserted directly rather than inferred from a passing run.
"""

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks import alerting_trust as trust  # noqa: E402
from benchmarks.evaluate_accuracy import build_parser, main  # noqa: E402


def snapshot_lines(counts, *, model_state=lambda i: f"iso:1|hbos:1|lstm:{i % 3}"):
    """Build a labelled NDJSON snapshot with the given per-status counts."""
    statuses = []
    for status, count in counts.items():
        statuses.extend([status] * count)
    lines = []
    for index, status in enumerate(statuses):
        lines.append(json.dumps({
            "_id": f"alert-{index}",
            "@timestamp": f"2026-09-25T{index % 24:02d}:00:00Z",
            "composite_score": 0.5 + (index % 50) / 100,
            "model_state_id": model_state(index),
            "sensor": "cowrie-login",
            "alert_threshold": 0.85,
            "status": status,
        }, sort_keys=True))
    return "\n".join(lines) + "\n"


def write_snapshot(tmp_path, counts, name="snapshot.ndjson", **kwargs):
    path = tmp_path / name
    path.write_text(snapshot_lines(counts, **kwargs), encoding="utf-8")
    return path


# --- the reporting rule -------------------------------------------------


def test_unmeasured_leg_never_carries_a_value():
    leg = trust.unmeasured("precision", "no labels")
    record = trust.as_record(leg)
    assert record["status"] == "UNMEASURED"
    assert record["value"] is None
    assert record["reason"] == "no labels"


def test_a_zero_on_a_skipped_leg_is_rejected():
    """The reporting rule, enforced: 0.0 on an unrun leg must not serialise."""
    forged = trust.Leg(metric="precision", status="UNMEASURED", value=0.0, reason="OOM")
    with pytest.raises(trust.AlertingTrustError, match="claim about a result"):
        trust.as_record(forged)


def test_a_measured_leg_without_a_value_is_rejected():
    with pytest.raises(trust.AlertingTrustError, match="marked measured with no value"):
        trust.measured("precision", None)


def test_an_unexplained_absence_is_rejected():
    with pytest.raises(trust.AlertingTrustError, match="must carry a reason"):
        trust.unmeasured("precision", "   ")


def test_zero_labelled_rows_is_unmeasured_not_zero_precision():
    """A run that produced nothing must not report precision 0.0."""
    leg = trust.precision_leg([])
    assert leg.status == "UNMEASURED"
    assert leg.value is None
    assert "zero labelled" in leg.reason
    assert trust.as_record(leg)["value"] is None


def test_an_empty_snapshot_is_refused_rather_than_scored(tmp_path):
    """`load_snapshot` itself rejects a zero-label file; the leg above is the
    defence in depth for a Snapshot that arrives empty by some other route."""
    snapshot = write_snapshot(tmp_path, {})
    with pytest.raises(Exception, match="no labelled dispositions"):
        trust.load_snapshot(snapshot)


# --- recall is structurally unavailable ---------------------------------


def test_recall_is_unmeasured_and_explains_why(tmp_path):
    leg = trust.recall_leg()
    record = trust.as_record(leg)
    assert record["status"] == "UNMEASURED"
    assert record["value"] is None
    assert record["reason"] == trust.RECALL_REASON
    assert "PRECISION-ONLY" in record["reason"]
    assert trust.RECALL_DENOMINATOR_AVAILABLE is False


def test_recall_stays_unmeasured_against_a_large_perfect_corpus(tmp_path):
    """The point that matters: recall is unmeasured by construction, not by
    lack of data. A 900-alert all-true-positive corpus still yields UNMEASURED,
    because the missing denominator is the below-threshold population and no
    amount of labelling above threshold creates it."""
    snapshot = write_snapshot(tmp_path, {"true_positive": 900})
    rows = trust.load_snapshot(snapshot).rows
    assert trust.precision_leg(rows).measured
    assert trust.recall_leg().status == "UNMEASURED"


def test_requesting_recall_is_refused():
    with pytest.raises(trust.AlertingTrustError, match="no denominator"):
        trust.assert_recall_not_requested(["recall"])
    # The alias must not be a way around it either.
    with pytest.raises(trust.AlertingTrustError, match="no denominator"):
        trust.assert_recall_not_requested(["sensitivity"])


def test_precision_is_permitted_by_the_guard():
    trust.assert_recall_not_requested(["precision"])


def test_no_recall_number_anywhere_in_a_full_report(tmp_path):
    """A whole report walked for a numeric recall. Belt and braces."""
    snapshot = write_snapshot(tmp_path, {
        "true_positive": 7, "false_positive": 3, "benign_known": 2,
    })
    report, _ = trust.run_alerting_trust(snapshot, None, tmp_path / "report.json")
    assert report["legs"]["recall"]["value"] is None
    assert report["recall_denominator_available"] is False
    blob = json.dumps(report)
    # The literal 0.0 must never appear as a recall value.
    assert '"recall"' in blob
    assert trust.as_record(trust.recall_leg())["value"] is None
    for leg in report["legs"].values():
        if leg["status"] == "UNMEASURED":
            assert leg["value"] is None


# --- benign_known is decided, documented, and kept in the denominator -----


def test_benign_known_is_a_negative_and_stays_in_the_denominator(tmp_path):
    snapshot = write_snapshot(tmp_path, {
        "true_positive": 4, "false_positive": 3, "benign_known": 3,
    })
    rows = trust.load_snapshot(snapshot).rows
    leg = trust.precision_leg(rows)
    assert leg.value == pytest.approx(4 / 10)
    assert leg.detail["benign_known"] == 3
    assert leg.detail["negatives"] == 6
    assert leg.detail["denominator"] == 10


def test_excluding_benign_known_would_inflate_precision(tmp_path):
    """The counterfactual is reported, and it really is higher."""
    snapshot = write_snapshot(tmp_path, {
        "true_positive": 4, "false_positive": 3, "benign_known": 3,
    })
    rows = trust.load_snapshot(snapshot).rows
    leg = trust.precision_leg(rows)
    detail = leg.detail
    excluded = detail["precision_if_benign_known_excluded"]
    assert leg.value == pytest.approx(0.4)
    assert excluded == pytest.approx(4 / 7)
    assert excluded > leg.value, "excluding negatives from the denominator must inflate"
    assert "inflates" in detail["exclusion_note"]


def test_no_counterfactual_when_benign_known_is_absent(tmp_path):
    snapshot = write_snapshot(tmp_path, {"true_positive": 5, "false_positive": 5})
    detail = trust.precision_leg(trust.load_snapshot(snapshot).rows).detail
    assert "precision_if_benign_known_excluded" not in detail


def test_benign_known_treatment_is_published_in_the_report(tmp_path):
    snapshot = write_snapshot(tmp_path, {"true_positive": 2, "benign_known": 1})
    report, _ = trust.run_alerting_trust(snapshot, None, tmp_path / "r.json")
    treatment = report["benign_known"]
    assert treatment["scored_as"] == "negative"
    assert treatment["in_denominator"] is True
    assert len(treatment["rationale"]) > 80


def test_label_mapping_is_shared_with_the_calibration_rail():
    """Two consumers of one snapshot must not disagree about a disposition."""
    from benchmarks.disposition_tier2 import LABEL_MAPPING, NEGATIVE_STATUSES
    assert trust.LABEL_MAPPING == LABEL_MAPPING
    assert "benign_known" in NEGATIVE_STATUSES


# --- open alerts are not negatives and are not counted as zero -----------


def test_unlabelled_alerts_are_unmeasured_without_a_census(tmp_path):
    """The snapshot is closed-only: counting `open` there yields 0 every run."""
    snapshot = write_snapshot(tmp_path, {"true_positive": 5, "false_positive": 5})
    leg = trust.open_alerts_leg(None)
    assert leg.status == "UNMEASURED"
    assert leg.value is None
    assert "closed dispositions only" in leg.reason


def test_unlabelled_alerts_run_when_a_real_census_exists(tmp_path):
    census = {"census": {"alerts": {
        "total": 12, "labelled_count": 10,
        "by_disposition_status": {
            "open": 1, "true_positive": 5, "false_positive": 4,
            "benign_known": 1, "<missing>": 1,
        },
    }}}
    leg = trust.open_alerts_leg(census)
    assert leg.measured
    assert leg.value == 2  # open 1 + one document with no status field
    assert leg.detail["open_alerts"] == 1
    assert leg.detail["missing_status"] == 1


def test_a_malformed_census_is_unmeasured_not_an_exception(tmp_path):
    for bad in ({}, {"census": {}}, {"census": {"alerts": {"total": 3}}}):
        leg = trust.open_alerts_leg(bad)
        assert leg.status == "UNMEASURED"
        assert leg.value is None


# --- precision arithmetic and honesty -----------------------------------


def test_precision_reports_sample_size_and_uncertainty(tmp_path):
    snapshot = write_snapshot(tmp_path, {"true_positive": 30, "false_positive": 70})
    leg = trust.precision_leg(trust.load_snapshot(snapshot).rows)
    assert leg.value == pytest.approx(0.3)
    assert leg.detail["labelled_alerts"] == 100
    low, high = leg.detail["wilson_95"]
    assert low < 0.3 < high


def test_a_tiny_corpus_does_not_look_certain(tmp_path):
    """3/3 = 1.000 must not read as a deployment claim."""
    snapshot = write_snapshot(tmp_path, {"true_positive": 3})
    leg = trust.precision_leg(trust.load_snapshot(snapshot).rows)
    low, _ = leg.detail["wilson_95"]
    assert leg.value == 1.0
    assert low < 0.5, "a 3-row perfect sample must not carry a tight interval"
    assert "No negative" in leg.detail["caveat"]


def test_a_corpus_with_no_true_positives_is_flagged(tmp_path):
    snapshot = write_snapshot(tmp_path, {"false_positive": 4, "benign_known": 1})
    leg = trust.precision_leg(trust.load_snapshot(snapshot).rows)
    assert leg.value == 0.0
    assert leg.measured, "a measured zero is a real result; only a *skipped* leg is UNMEASURED"
    assert "No true positives" in leg.detail["caveat"]


def test_precision_needs_no_split_or_calibrator(tmp_path):
    """One model_state_id would make disposition_tier2 refuse to score. It does
    not affect a count over the labelled population, so precision still runs."""
    snapshot = write_snapshot(
        tmp_path,
        {"true_positive": 3, "false_positive": 2},
        name="single-state.ndjson",
        model_state=lambda i: "iso:1|hbos:1|lstm:1",
    )
    rows = trust.load_snapshot(snapshot).rows
    assert len({row.group for row in rows}) == 1
    leg = trust.precision_leg(rows)
    assert leg.measured
    assert leg.value == pytest.approx(0.6)


def test_wilson_interval_is_bounded():
    assert trust.wilson_interval(0, 0) is None
    low, high = trust.wilson_interval(0, 10)
    assert low == pytest.approx(0.0) and 0.0 < high < 1.0
    low, high = trust.wilson_interval(10, 10)
    assert high == pytest.approx(1.0) and 0.0 < low < 1.0


# --- the command ---------------------------------------------------------


def test_command_writes_a_hashed_report(tmp_path):
    snapshot = write_snapshot(tmp_path, {"true_positive": 8, "false_positive": 2})
    output = tmp_path / "trust.json"
    code = main(["alerting-trust", "--snapshot", str(snapshot), "--output", str(output)])
    assert code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["issue"] == 3451
    assert report["legs"]["precision"]["value"] == pytest.approx(0.8)
    assert report["legs"]["recall"]["status"] == "UNMEASURED"


def test_command_uses_the_census_when_supplied(tmp_path):
    snapshot = write_snapshot(tmp_path, {"true_positive": 4, "false_positive": 1})
    census = tmp_path / "census.json"
    census.write_text(json.dumps({"census": {"alerts": {
        "total": 9, "labelled_count": 5,
        "by_disposition_status": {"open": 4, "true_positive": 4, "false_positive": 1},
    }}}), encoding="utf-8")
    output = tmp_path / "trust.json"
    code = main(["alerting-trust", "--snapshot", str(snapshot),
                 "--census", str(census), "--output", str(output)])
    assert code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["legs"]["unlabelled_alerts"]["value"] == 4


def test_command_refuses_to_invent_a_number_without_a_snapshot(tmp_path, capsys):
    output = tmp_path / "trust.json"
    code = main(["alerting-trust", "--output", str(output)])
    assert code == 2
    assert not output.exists()
    err = capsys.readouterr().err
    assert "no disposition snapshot supplied" in err
    assert "UNMEASURED" in err


def test_command_rejects_a_report_inside_the_repository(tmp_path):
    snapshot = write_snapshot(tmp_path, {"true_positive": 1})
    inside = Path(__file__).resolve().parents[1] / "benchmarks" / "trust-should-not-exist.json"
    try:
        code = main(["alerting-trust", "--snapshot", str(snapshot),
                     "--census", str(inside), "--output", str(tmp_path / "t.json")])
    finally:
        inside.unlink(missing_ok=True)
    assert code == 2


def test_parser_registers_the_subcommand():
    args = build_parser().parse_args([
        "alerting-trust", "--output", "/tmp/x.json",
    ])
    assert args.command == "alerting-trust"
    assert args.snapshot is None and args.census is None


def test_printed_report_shows_unmeasured_recall_literally(tmp_path, capsys):
    snapshot = write_snapshot(tmp_path, {"true_positive": 3, "false_positive": 1})
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        main(["alerting-trust", "--snapshot", str(snapshot),
              "--output", str(tmp_path / "t.json")])
    out = buffer.getvalue()
    assert "recall: UNMEASURED" in out
    assert "PRECISION-ONLY" in out
    assert "0.7500" in out


def test_print_report_works_on_an_all_unmeasured_record(tmp_path):
    """A record where every leg failed must still print, not crash."""
    report = {
        "issue": 3451,
        "question": "q",
        "corpus": {"kind": "snapshot", "sha256": "0" * 64},
        "census": {"by_status": {}, "labelled_rows": 0},
        "benign_known": trust.BENIGN_KNOWN_TREATMENT,
        "reporting_rule": trust.UNMEASURED,
        "legs": {
            "precision": trust.as_record(trust.unmeasured("precision", "no rows")),
            "recall": trust.as_record(trust.recall_leg()),
            "unlabelled_alerts": trust.as_record(trust.unmeasured("u", "no census")),
        },
    }
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        trust.print_report(report)
    assert buffer.getvalue().count("UNMEASURED") >= 3
