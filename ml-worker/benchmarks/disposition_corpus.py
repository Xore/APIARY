"""Read-only export and census for operator-disposition alerts."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit


BENCHMARK_VERSION = "apiary-ml-worker-disposition-corpus-v1"
INDEX = "ml-anomalies"
STATUSES = ("open", "true_positive", "false_positive", "benign_known")
CLOSED_STATUSES = ("true_positive", "false_positive", "benign_known")
REASON_REDACTION = "[REDACTED]"
EXPORT_FIELDS = (
    "@timestamp", "composite_score", "model_scores", "contributing_detectors",
    "alert_threshold", "model_state_id", "sensor", "status",
    "disposition_reason", "disposition_by", "disposed_at",
)
PRECISION_ONLY = (
    "PRECISION-ONLY: only above-threshold alerts are persisted; deployment recall and "
    "ordinary below-threshold calibration are unavailable from this corpus."
)


class CorpusError(RuntimeError):
    """An actionable export/census failure."""


class ElasticsearchUnavailable(CorpusError):
    """The configured Elasticsearch endpoint is unreachable."""


@dataclass
class Census:
    total: int
    status_counts: dict[str, int]
    labelled_count: int
    rows: list[dict[str, Any]] = field(default_factory=list)
    time_range: dict[str, str | None] | None = None


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def present(value: Any) -> bool:
    return value is not None and value not in ("", [], {})


def model_name(value: Any) -> str | None:
    if isinstance(value, dict):
        for name, score in value.items():
            if score is not None:
                return str(name)
    return None


def source_value(source: dict[str, Any], field: str) -> Any:
    if field == "sensor":
        return source.get("sensor") or (source.get("event") or {}).get("sensor")
    return source.get(field)


def normalise_row(hit: dict[str, Any], redact_reason: bool = True) -> dict[str, Any]:
    if not isinstance(hit, dict) or not isinstance(hit.get("_id"), str):
        raise CorpusError("each corpus hit must have a string _id")
    source = hit.get("_source")
    if not isinstance(source, dict):
        raise CorpusError(f"corpus hit {hit['_id']} has no object _source")
    if source.get("status") not in CLOSED_STATUSES:
        raise CorpusError(f"corpus hit {hit['_id']} is not a closed disposition")
    row = {"_id": hit["_id"]}
    for field in EXPORT_FIELDS:
        value = source_value(source, field)
        if value is not None:
            row[field] = deepcopy(value)
    if redact_reason and "disposition_reason" in row:
        row["disposition_reason"] = REASON_REDACTION
    return row


def normalise_hits(value: Any) -> list[dict[str, Any]]:
    while isinstance(value, dict) and "hits" in value:
        value = value["hits"]
    if not isinstance(value, list):
        raise CorpusError("fixture must be a JSON list of Elasticsearch hits")
    return value


def census_from_hits(hits: Any, redact_reason: bool = True) -> Census:
    """Census a complete corpus, excluding open rows from the export."""
    hits = normalise_hits(hits)
    counts: Counter[str] = Counter()
    timestamps: list[str] = []
    for hit in hits:
        if not isinstance(hit, dict) or not isinstance(hit.get("_source"), dict):
            raise CorpusError("each corpus hit must have an object _source")
        source = hit["_source"]
        status = source.get("status")
        counts[str(status) if status else "<missing>"] += 1
        timestamp = source.get("@timestamp")
        if present(timestamp):
            timestamps.append(str(timestamp))
    closed_rows = [
        normalise_row(hit, redact_reason=redact_reason)
        for hit in hits if (hit.get("_source") or {}).get("status") in CLOSED_STATUSES
    ]
    status_counts = {status: counts.get(status, 0) for status in STATUSES}
    for status, count in counts.items():
        if status not in status_counts:
            status_counts[status] = count
    labelled_count = sum(status_counts[status] for status in CLOSED_STATUSES)
    if labelled_count != len(closed_rows):
        raise CorpusError("closed status counts and exported rows disagree")
    return Census(
        total=len(hits),
        status_counts=status_counts,
        labelled_count=labelled_count,
        rows=closed_rows,
        time_range={"min": min(timestamps), "max": max(timestamps)} if timestamps else None,
    )


def _range(rows: list[dict[str, Any]]) -> dict[str, str | None] | None:
    for field in ("@timestamp", "disposed_at"):
        values = [str(row[field]) for row in rows if present(row.get(field))]
        if values:
            return {"min": min(values), "max": max(values)}
    return None


def _missing(rows: list[dict[str, Any]]) -> dict[str, int]:
    missing = {
        field: sum(not present(source_value(row, field)) for row in rows)
        for field in EXPORT_FIELDS
    }
    missing["model_scores"] = sum(model_name(row.get("model_scores")) is None for row in rows)
    return missing


def _counter(values: list[Any]) -> dict[str, int]:
    return dict(sorted(Counter(str(value) for value in values if present(value)).items()))


def _groups(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "by_sensor": _counter([row.get("sensor") for row in rows]),
        "by_model": _counter([model_name(row.get("model_scores")) for row in rows]),
        "by_threshold": _counter([row.get("alert_threshold") for row in rows]),
        "distinct_model_state_ids": len({
            str(row["model_state_id"]) for row in rows if present(row.get("model_state_id"))
        }),
        "missing_fields": _missing(rows),
    }


def build_report(census: Census, *, source: dict[str, Any], export: dict[str, Any]) -> dict[str, Any]:
    if sum(census.status_counts.values()) != census.total:
        raise CorpusError("status counts do not sum to the total alert count")
    if census.labelled_count != len(census.rows):
        raise CorpusError("labelled count does not match exported rows")
    labelled = census.rows
    class_counts = {status: census.status_counts.get(status, 0) for status in CLOSED_STATUSES}
    classes_present = sum(count > 0 for count in class_counts.values())
    if census.labelled_count == 0:
        gate = "non_calibratable"
        reason = "zero labelled dispositions"
    elif classes_present < 2:
        gate = "non_calibratable"
        reason = "single labelled class"
    else:
        gate = "eligible_for_tier_2_calibration"
        reason = "at least two labelled classes"
    by_status = {status: _groups([
        row for row in labelled if row.get("status") == status
    ]) for status in CLOSED_STATUSES}
    return {
        "generated_at": now_utc(),
        "protocol": {
            "version": BENCHMARK_VERSION,
            "read_only": True,
            "index": INDEX,
            "closed_statuses": list(CLOSED_STATUSES),
            "export_fields": list(EXPORT_FIELDS),
            "reasons_redacted": export.get("reasons_redacted", True),
        },
        "source": source,
        "census": {
            "alerts": {
                "total": census.total,
                "by_disposition_status": census.status_counts,
                "labelled_count": census.labelled_count,
                "labelled_denominator": census.total,
                "labelled_fraction": census.labelled_count / census.total if census.total else None,
                "class_balance": {
                    "counts": class_counts,
                    "denominator": census.labelled_count,
                    "fractions": {
                        status: count / census.labelled_count if census.labelled_count else None
                        for status, count in class_counts.items()
                    },
                },
            },
            "time_range": {
                "all_alerts": census.time_range,
                "labelled": _range(labelled),
                "by_labelled_status": {
                    status: _range([row for row in labelled if row.get("status") == status])
                    for status in CLOSED_STATUSES
                },
            },
            "groupings": {
                "labelled": _groups(labelled),
                "by_labelled_status": by_status,
            },
        },
        "calibration_gate": {
            "status": gate,
            "reason": reason,
            "classes_present": classes_present,
            "precision_only": True,
            "precision_only_message": PRECISION_ONLY,
            "deployment_recall_available": False,
        },
        "export": export,
        "caps": [
            PRECISION_ONLY,
            "Unlabelled and below-threshold events are not negative examples.",
            "This tool reports eligibility; it does not fit or score a calibrator.",
        ],
    }


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def report_digest(report: dict[str, Any]) -> str:
    """Hash the report content without its digest field to avoid self-reference."""
    content = {key: value for key, value in report.items() if key != "report_sha256"}
    return hashlib.sha256(_json_bytes(content)).hexdigest()


def write_report(path: str | os.PathLike[str], report: dict[str, Any]) -> str:
    report["report_sha256"] = report_digest(report)
    return write_atomic(path, _json_bytes(report))


def write_atomic(path: str | os.PathLike[str], payload: bytes) -> str:
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".dispositions-", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return hashlib.sha256(payload).hexdigest()


def export_rows(census: Census, output: str | os.PathLike[str], *,
                reasons_redacted: bool = True) -> dict[str, Any]:
    lines = [json.dumps(row, sort_keys=True, separators=(",", ":")) for row in census.rows]
    payload = ("\n".join(lines) + ("\n" if lines else "")).encode()
    digest = write_atomic(output, payload)
    return {
        "path": str(Path(output).expanduser().resolve()),
        "format": "ndjson",
        "rows": len(census.rows),
        "bytes": len(payload),
        "sha256": digest,
        "reasons_redacted": reasons_redacted,
    }


def print_report(report: dict[str, Any]) -> None:
    alerts = report["census"]["alerts"]
    print("=" * 78)
    print(PRECISION_ONLY)
    print("=" * 78)
    if alerts["labelled_count"] == 0:
        print("HEADLINE: zero labelled dispositions; calibration is blocked.")
    else:
        print("HEADLINE: labelled dispositions found; calibration is not run by this tool.")
    print(f"Total alerts: {alerts['total']}")
    print(f"Labelled subset: {alerts['labelled_count']} / {alerts['labelled_denominator']}")
    for status, count in alerts["by_disposition_status"].items():
        print(f"  {status}: {count}")
    time_range = report["census"]["time_range"]
    print(f"Alert time range: {time_range['all_alerts'] or 'unavailable'}")
    print(f"Labelled time range: {time_range['labelled'] or 'unavailable'}")
    print(f"Calibration gate: {report['calibration_gate']['status']}")
    print(f"Export: {report['export']['rows']} rows -> {report['export']['path']}")
    print(f"Snapshot SHA-256: {report['export']['sha256']}")
    if report.get("report_sha256"):
        print(f"Report SHA-256 (canonical content): {report['report_sha256']}")


def load_fixture(path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    fixture = Path(path).expanduser()
    try:
        with fixture.open(encoding="utf-8") as source:
            value = json.load(source)
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusError(f"could not read fixture {fixture}: {exc}") from exc
    return normalise_hits(value)


def _hits_total(body: dict[str, Any]) -> int:
    total = body.get("hits", {}).get("total")
    value = total.get("value") if isinstance(total, dict) else total
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CorpusError("Elasticsearch response has no valid hits.total")
    return value


def _buckets(body: dict[str, Any], name: str) -> list[dict[str, Any]]:
    value = body.get("aggregations", {}).get(name, {}).get("buckets")
    if not isinstance(value, list):
        raise CorpusError(f"Elasticsearch response has no {name} buckets")
    return value


def _request(client: dict[str, Any], method: str, path: str,
             body: Any = None) -> dict[str, Any]:
    endpoint = str(client.get("endpoint") or "").rstrip("/")
    if not endpoint:
        raise CorpusError("an explicit Elasticsearch endpoint is required")
    headers = {"Accept": "application/json", "Content-Type": "application/json",
               **client.get("headers", {})}
    request = urllib.request.Request(
        endpoint + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=client["timeout"]) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:300]
        raise CorpusError(f"Elasticsearch {method} {path} failed ({exc.code}): {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise ElasticsearchUnavailable(f"could not reach Elasticsearch at {endpoint}: {exc}") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CorpusError(f"Elasticsearch returned invalid JSON for {path}") from exc
    if not isinstance(value, dict):
        raise CorpusError(f"Elasticsearch returned a non-object for {path}")
    return value


def validate_endpoint(value: str | None) -> str:
    if not value:
        raise CorpusError(
            "an explicit Elasticsearch endpoint is required; pass --es-host or set ES_HOST")
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise CorpusError("Elasticsearch endpoint must be an explicit http(s) URL")
    if parsed.username or parsed.password:
        raise CorpusError("do not put credentials in --es-host; use --api-key or environment variables")
    return value.rstrip("/")


def _client(endpoint: str, api_key: str | None, username: str | None,
            password: str | None, timeout: float) -> dict[str, Any]:
    import base64
    headers = {}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    elif username or password:
        token = base64.b64encode(f"{username or ''}:{password or ''}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    return {"endpoint": endpoint, "headers": headers, "timeout": timeout}


def _census_query() -> dict[str, Any]:
    return {
        "size": 0,
        "track_total_hits": True,
        "query": {"match_all": {}},
        "aggs": {
            "statuses": {"terms": {"field": "status", "missing": "<missing>", "size": 100}},
            "alert_time": {"stats": {"field": "@timestamp"}},
        },
    }


def _stats_range(aggregations: dict[str, Any]) -> dict[str, str | None] | None:
    alert_time = aggregations.get("alert_time")
    if not isinstance(alert_time, dict):
        raise CorpusError("Elasticsearch response has no alert-time stats")
    stats = alert_time.get("stats", alert_time)
    if not isinstance(stats, dict):
        raise CorpusError("Elasticsearch response has invalid alert-time stats")
    minimum = stats.get("min_as_string", stats.get("min"))
    maximum = stats.get("max_as_string", stats.get("max"))
    if minimum is None and maximum is None:
        return None
    return {"min": _text(minimum), "max": _text(maximum)}


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


def _census_from_elasticsearch(client: dict[str, Any], pit_id: str) -> Census:
    query = _census_query()
    query["pit"] = {"id": pit_id, "keep_alive": "1m"}
    body = _request(client, "POST", "/_search", query)
    counts: Counter[str] = Counter()
    for bucket in _buckets(body, "statuses"):
        key = bucket.get("key")
        value = bucket.get("doc_count")
        if not isinstance(key, str) or isinstance(value, bool) or not isinstance(value, int):
            raise CorpusError("Elasticsearch returned an invalid status bucket")
        counts[key] += value
    total = _hits_total(body)
    if sum(counts.values()) != total:
        raise CorpusError("status aggregation does not cover every alert")
    status_counts = {status: counts.get(status, 0) for status in STATUSES}
    for status, count in counts.items():
        status_counts.setdefault(status, count)
    labelled = sum(status_counts[status] for status in CLOSED_STATUSES)
    status_counts = {status: status_counts.get(status, 0) for status in STATUSES}
    for status, count in counts.items():
        status_counts.setdefault(status, count)
    return Census(total, status_counts, labelled, [], _stats_range(body.get("aggregations", {})))


def _open_pit(client: dict[str, Any]) -> str:
    body = _request(client, "POST", f"/{INDEX}/_pit?{urlencode({'keep_alive': '1m'})}")
    pit_id = body.get("id")
    if not isinstance(pit_id, str) or not pit_id:
        raise CorpusError("Elasticsearch did not return a PIT id")
    return pit_id


def _close_pit(client: dict[str, Any], pit_id: str) -> None:
    try:
        _request(client, "DELETE", "/_pit", {"id": pit_id})
    except CorpusError:
        pass


def _fetch_rows(client: dict[str, Any], page_size: int,
                redact_reason: bool, pit_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    search_after: list[Any] | None = None
    try:
        while True:
            body: dict[str, Any] = {
                "size": page_size,
                "pit": {"id": pit_id, "keep_alive": "1m"},
                "query": {"terms": {"status": list(CLOSED_STATUSES)}},
                "sort": [{"_shard_doc": "asc"}],
                "_source": list(EXPORT_FIELDS),
                "track_total_hits": True,
            }
            if search_after is not None:
                body["search_after"] = search_after
            response = _request(client, "POST", "/_search", body)
            pit_id = response.get("pit_id", pit_id)
            hits = response.get("hits", {}).get("hits")
            if not isinstance(hits, list):
                raise CorpusError("Elasticsearch search response has no hits list")
            rows.extend(normalise_row(hit, redact_reason) for hit in hits)
            if len(hits) < page_size:
                break
            if not hits or "sort" not in hits[-1]:
                raise CorpusError("Elasticsearch page is missing search_after sort values")
            search_after = hits[-1]["sort"]
    finally:
        _close_pit(client, pit_id)
    return rows


def fetch_elasticsearch_census(client: dict[str, Any], *, page_size: int = 1000,
                               redact_reason: bool = True) -> tuple[Census, list[dict[str, Any]]]:
    """Open one PIT, then use it for census and immutable labelled export."""
    pit_id = _open_pit(client)
    try:
        census = _census_from_elasticsearch(client, pit_id)
        rows = _fetch_rows(client, page_size, redact_reason, pit_id)
    except Exception:
        _close_pit(client, pit_id)
        raise
    return census, rows


def run_elasticsearch(*, endpoint: str, output: str, report_output: str,
                      api_key: str | None, username: str | None,
                      password: str | None, page_size: int, timeout: float,
                      include_reason: bool = False) -> tuple[Census, dict[str, Any]]:
    client = _client(validate_endpoint(endpoint), api_key, username, password, timeout)
    census, rows = fetch_elasticsearch_census(client, page_size=page_size,
                                               redact_reason=not include_reason)
    status_counts: Counter[str] = Counter()
    for row in rows:
        status = row.get("status")
        if status not in CLOSED_STATUSES:
            raise CorpusError("exported row is not a closed disposition")
        status_counts[status] += 1
    if any(status_counts.get(status, 0) != census.status_counts.get(status, 0)
           for status in CLOSED_STATUSES):
        raise CorpusError("exported status counts differ from the census")
    census.rows = rows
    if len(census.rows) != census.labelled_count:
        raise CorpusError("exported labelled rows do not match the census labelled count")
    export = export_rows(census, output, reasons_redacted=not include_reason)
    source = {"kind": "elasticsearch", "index": INDEX, "endpoint": endpoint}
    report = build_report(census, source=source, export=export)
    write_report(report_output, report)
    return census, report


def run_fixture(path: str, output: str, report_output: str,
                include_reason: bool = False) -> tuple[Census, dict[str, Any]]:
    census = census_from_hits(load_fixture(path), redact_reason=not include_reason)
    export = export_rows(census, output, reasons_redacted=not include_reason)
    source = {"kind": "fixture", "path": str(Path(path).resolve())}
    report = build_report(census, source=source, export=export)
    write_report(report_output, report)
    return census, report


def parse_args(argv: list[str] | None = None) -> Any:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--es-host", help="explicit Elasticsearch URL; env ES_HOST/ELASTICSEARCH_URL also works")
    source.add_argument("--fixture", help="local JSON ES-hit fixture for offline verification")
    parser.add_argument("--output", required=True, help="labelled NDJSON snapshot path")
    parser.add_argument("--report", required=True, help="hashed JSON census report path")
    parser.add_argument("--api-key", default=os.getenv("ES_API_KEY") or os.getenv("ELASTICSEARCH_API_KEY"))
    parser.add_argument("--username", default=os.getenv("ES_USERNAME") or os.getenv("ELASTICSEARCH_USERNAME"))
    parser.add_argument("--password", default=os.getenv("ES_PASSWORD") or os.getenv("ELASTICSEARCH_PASSWORD"))
    parser.add_argument("--page-size", type=int, default=1000)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--include-reason", action="store_true", help="include free-text reasons (not default)")
    args = parser.parse_args(argv)
    if args.page_size < 1 or args.page_size > 10000:
        parser.error("--page-size must be between 1 and 10000")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.fixture:
            _, report = run_fixture(args.fixture, args.output, args.report, args.include_reason)
        else:
            endpoint = args.es_host or os.getenv("ES_HOST") or os.getenv("ELASTICSEARCH_URL")
            _, report = run_elasticsearch(
                endpoint=validate_endpoint(endpoint), output=args.output,
                report_output=args.report, api_key=args.api_key,
                username=args.username, password=args.password,
                page_size=args.page_size, timeout=args.timeout,
                include_reason=args.include_reason,
            )
    except CorpusError as exc:
        print(f"disposition corpus: {exc}", file=sys.stderr)
        return 2
    print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
