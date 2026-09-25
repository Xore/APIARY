"""Tests for the read-only operator-disposition export and census."""

import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks import disposition_corpus as corpus  # noqa: E402


def hit(identifier, status, *, sensor="cowrie-login", model="isolation_forest",
        model_state="iso:1|hbos:1|lstm:1", threshold=0.85, reason="private note",
        timestamp="2026-09-25T10:00:00Z"):
    source = {
        "@timestamp": timestamp,
        "composite_score": 0.91,
        "model_scores": {model: 0.91, "lstm_ae": 0.9, "hbos": 0.8},
        "contributing_detectors": [model, "lstm_ae", "hbos"],
        "alert_threshold": threshold,
        "model_state_id": model_state,
        "sensor": sensor,
        "status": status,
        "disposition_reason": reason,
        "disposition_by": "operator@example.test",
        "disposed_at": timestamp,
    }
    if status is None:
        source.pop("status")
    return {"_id": identifier, "_source": source}


def run_local(tmp_path, hits):
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps(hits), encoding="utf-8")
    _, report = corpus.run_fixture(
        str(fixture), str(tmp_path / "labels.ndjson"), str(tmp_path / "report.json"))
    return report, (tmp_path / "labels.ndjson").read_text(encoding="utf-8")


def test_census_denominators_and_balanced_labels(tmp_path):
    hits = [
        hit("tp-1", "true_positive", model_state="iso:1|hbos:1|lstm:1"),
        hit("fp-1", "false_positive", sensor="dionaea-connection", model_state="iso:1|hbos:1|lstm:2"),
        hit("bk-1", "benign_known", sensor="conpot-modbus", model="lstm_ae",
            model_state="iso:1|hbos:1|lstm:3"),
        hit("open-1", "open", timestamp="2026-09-24T10:00:00Z"),
        hit("legacy-1", None, timestamp="2026-09-23T10:00:00Z"),
    ]
    report, exported = run_local(tmp_path, hits)
    alerts = report["census"]["alerts"]
    assert alerts["total"] == 5
    assert alerts["labelled_count"] == 3
    assert alerts["labelled_denominator"] == 5
    assert alerts["labelled_fraction"] == pytest.approx(0.6)
    assert alerts["by_disposition_status"]["open"] == 1
    assert alerts["by_disposition_status"]["<missing>"] == 1
    assert report["calibration_gate"]["status"] == "eligible_for_tier_2_calibration"
    assert report["census"]["groupings"]["labelled"]["by_sensor"] == {
        "conpot-modbus": 1, "cowrie-login": 1, "dionaea-connection": 1,
    }
    assert report["census"]["time_range"]["all_alerts"] == {
        "min": "2026-09-23T10:00:00Z", "max": "2026-09-25T10:00:00Z",
    }
    assert len(exported.splitlines()) == 3
    assert "open-1" not in exported and "legacy-1" not in exported


def test_zero_labels_is_prominent_and_precision_only(tmp_path):
    report, exported = run_local(tmp_path, [hit("open-1", "open")])
    assert report["census"]["alerts"]["labelled_count"] == 0
    assert report["calibration_gate"]["status"] == "non_calibratable"
    assert report["calibration_gate"]["deployment_recall_available"] is False
    output = io.StringIO()
    with redirect_stdout(output):
        corpus.print_report(report)
    text = output.getvalue()
    assert "PRECISION-ONLY" in text
    assert "HEADLINE: zero labelled dispositions" in text
    assert exported == ""


@pytest.mark.parametrize("status", corpus.CLOSED_STATUSES)
def test_single_class_is_non_calibratable(tmp_path, status):
    report, _ = run_local(tmp_path, [hit("one", status)])
    assert report["calibration_gate"]["status"] == "non_calibratable"
    assert report["calibration_gate"]["reason"] == "single labelled class"


def test_reasons_are_redacted_by_default_but_can_be_audited(tmp_path):
    source = hit("tp-1", "true_positive", reason="do not publish this note")
    redacted = corpus.census_from_hits([source]).rows[0]
    audited = corpus.census_from_hits([source], redact_reason=False).rows[0]
    assert redacted["disposition_reason"] == corpus.REASON_REDACTION
    assert audited["disposition_reason"] == "do not publish this note"


def test_open_and_legacy_rows_are_never_exported():
    result = corpus.census_from_hits([
        hit("tp-1", "true_positive"),
        hit("open-1", "open"),
        hit("legacy-1", None),
    ])
    assert result.labelled_count == 1
    assert [row["_id"] for row in result.rows] == ["tp-1"]


def test_missing_field_and_model_state_counts():
    row = hit("tp-1", "true_positive")
    row["_source"].pop("sensor")
    row["_source"].pop("model_state_id")
    result = corpus.census_from_hits([row])
    groups = corpus._groups(result.rows)
    assert groups["missing_fields"]["sensor"] == 1
    assert groups["missing_fields"]["model_state_id"] == 1
    assert groups["distinct_model_state_ids"] == 0


def test_report_hash_matches_export(tmp_path):
    report, _ = run_local(tmp_path, [hit("tp-1", "true_positive")])
    export = tmp_path / "labels.ndjson"
    assert corpus.hashlib.sha256(export.read_bytes()).hexdigest() == report["export"]["sha256"]
    report_file = tmp_path / "report.json"
    assert corpus.hashlib.sha256(report_file.read_bytes()).hexdigest() == report["report_sha256"]


def test_endpoint_is_explicit_and_unreachable_is_actionable(monkeypatch):
    with pytest.raises(corpus.CorpusError, match="explicit"):
        corpus.validate_endpoint(None)
    with pytest.raises(corpus.CorpusError, match="http"):
        corpus.validate_endpoint("elasticsearch:9200")

    def unreachable(*args, **kwargs):
        raise corpus.urllib.error.URLError("connection refused")

    monkeypatch.setattr(corpus.urllib.request, "urlopen", unreachable)
    with pytest.raises(corpus.ElasticsearchUnavailable, match="could not reach"):
        corpus.run_elasticsearch(
            endpoint="http://127.0.0.1:1", output="/tmp/no-snapshot", report_output="/tmp/no-report",
            api_key=None, username=None, password=None, page_size=10, timeout=0.1,
        )


def test_elasticsearch_client_only_sends_read_methods(monkeypatch):
    calls = []

    def fake_request(client, method, path, body=None):
        calls.append((method, path, body))
        if method == "POST" and path == "/_search" and body.get("aggs"):
            return {
                "hits": {"total": {"value": 3, "relation": "eq"}, "hits": []},
                "aggregations": {
                    "statuses": {"buckets": [{"key": "open", "doc_count": 3}]},
                    "alert_time": {"stats": {"min": None, "max": None}},
                },
            }
        if "/_pit" in path and method == "POST":
            return {"id": "pit-1"}
        if path == "/_search":
            return {"hits": {"hits": []}, "pit_id": "pit-1"}
        if method == "DELETE":
            return {"succeeded": True}
        raise AssertionError((method, path))

    monkeypatch.setattr(corpus, "_request", fake_request)
    census, rows = corpus.fetch_elasticsearch_census(
        {"endpoint": "http://es.invalid", "headers": {}, "timeout": 1}, page_size=2)
    assert census.total == 3 and census.labelled_count == 0 and rows == []
    assert {method for method, _, _ in calls} <= {"POST", "DELETE"}
    assert all(method in {"POST", "DELETE"} for method, _, _ in calls)
    assert any("/_pit" in path for _, path, _ in calls)
