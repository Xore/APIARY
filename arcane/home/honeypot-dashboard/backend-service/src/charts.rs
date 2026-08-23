//! Overview chart-data endpoints, ported from the Go tier's dedicated
//! chart files (ml_backlog.go #1283, netflow_volume.go #1278,
//! anomaly_trend.go #1279, dionaea_cve_chart.go #1276,
//! os_distribution.go #1277, scanner_fingerprints.go #1275,
//! endlessh_stats.go #1294). JSON shapes match the legacy /api/*
//! endpoints exactly so the ported chart builders consume them
//! unchanged: line/scatter = [{name, points:[{time,value}]}],
//! bar/barh = {categories, values}, pie = [{name, value}].
//!
//! Two snapshot-backed legacy endpoints are re-derived live here (the
//! Rust tier keeps no in-memory event cache by design):
//! - os-distribution counts unique source IPs per p0f OS guess from
//!   portbridge-v2-* (the Go snapshot counted fingerprint occurrences;
//!   unique attackers is the more honest distribution and is stable
//!   across replicas).
//! - endlessh-held-histogram used to bucket held_ms client-side from the
//!   raw disconnect events (honeypot.* is flattened — stats/range
//!   aggregations are unsupported, the same limitation aggregate.go
//!   documents); #1611 workstream F promoted it to a real typed field, so
//!   this is now a genuine ES range aggregation.

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::{json, Value};

use crate::AppState;

const WEEK: &str = "now-7d";
const OVERVIEW_WINDOW: &str = "now-48h";

#[derive(Serialize)]
pub struct Point {
    pub time: String,
    pub value: f64,
}

#[derive(Serialize)]
pub struct Series {
    pub name: String,
    pub points: Vec<Point>,
}

#[derive(Serialize)]
pub struct Bar {
    pub categories: Vec<String>,
    pub values: Vec<u64>,
}

#[derive(Serialize)]
pub struct PiePoint {
    pub name: String,
    pub value: u64,
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

/// /api/v1/charts/ml-backlog — hourly average queue depth per source
/// index from ml-worker-metrics' backlog gauge documents.
pub async fn ml_backlog(State(state): State<AppState>) -> Result<Json<Vec<Series>>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "query": {"bool": {"filter": [
            {"term": {"kind": "backlog"}},
            {"range": {"@timestamp": {"gte": WEEK}}}
        ]}},
        "aggs": {"sources": {
            "terms": {"field": "source_index", "size": 10},
            "aggs": {"hourly": {
                "date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0},
                "aggs": {"avg_backlog": {"avg": {"field": "backlog_count"}}}
            }}
        }}
    });
    let result = state
        .es
        .search_index(&["ml-worker-metrics"], body)
        .await
        .map_err(bad_gateway)?;
    let series = result["aggregations"]["sources"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|source| Series {
            name: source["key"].as_str().unwrap_or("").to_string(),
            points: source["hourly"]["buckets"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|bucket| {
                    // avg is null for empty buckets — skip, same as Go.
                    Some(Point {
                        time: bucket["key_as_string"].as_str()?.to_string(),
                        value: bucket["avg_backlog"]["value"].as_f64()?,
                    })
                })
                .collect(),
        })
        .collect();
    Ok(Json(series))
}

/// Hourly traffic volume, summed over whichever sensor is producing it.
///
/// #1741: Suricata's `netflow` records are being retired -- they and `flow`
/// are 80.1% of its document volume and carry packets and bytes where Zeek's
/// `conn.log` carries the same plus duration, conn_state, history, service and
/// six fingerprints. This chart was the reason that removal was blocked.
///
/// Reads Zeek first and falls back to Suricata when Zeek has produced nothing
/// for the window, rather than switching over in one step. Both orderings are
/// then safe: before Zeek is deployed the chart keeps working from Suricata,
/// after Suricata's netflow is switched off it keeps working from Zeek, and
/// neither deploy has to happen first. Preferring one over the other rather
/// than summing both matters -- during any overlap the two sensors are
/// watching the same packets, so adding them would double every figure.
async fn traffic_sum(
    state: &AppState,
    zeek_fields: &[&str],
    suricata_field: &str,
    name: &str,
) -> anyhow::Result<Vec<Series>> {
    // Zeek splits volume by direction, so a bucket total is the sum of its
    // originator and responder fields.
    let zeek_aggs: serde_json::Map<String, Value> = zeek_fields
        .iter()
        .enumerate()
        .map(|(i, field)| (format!("part{i}"), json!({"sum": {"field": field}})))
        .collect();
    let zeek_body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": WEEK}}},
        "aggs": {"hourly": {
            "date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0},
            "aggs": zeek_aggs
        }}
    });
    let zeek = state.es.search_index(&["zeek-v1-conn-*"], zeek_body).await?;
    let zeek_points: Vec<Point> = zeek["aggregations"]["hourly"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|bucket| {
            let value = (0..zeek_fields.len())
                .map(|i| bucket[format!("part{i}")]["value"].as_f64().unwrap_or(0.0))
                .sum();
            Some(Point { time: bucket["key_as_string"].as_str()?.to_string(), value })
        })
        .collect();

    if zeek_points.iter().any(|point| point.value > 0.0) {
        return Ok(vec![Series { name: name.to_string(), points: zeek_points }]);
    }

    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": WEEK}}},
        "aggs": {"hourly": {
            "date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0},
            "aggs": {"total": {"sum": {"field": suricata_field}}}
        }}
    });
    let result = state.es.search_index(&["suricata-v2-netflow-*"], body).await?;
    let points = result["aggregations"]["hourly"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|bucket| {
            Some(Point {
                time: bucket["key_as_string"].as_str()?.to_string(),
                value: bucket["total"]["value"].as_f64().unwrap_or(0.0),
            })
        })
        .collect();
    Ok(vec![Series { name: name.to_string(), points }])
}

pub async fn netflow_bytes(State(state): State<AppState>) -> Result<Json<Vec<Series>>, (StatusCode, String)> {
    traffic_sum(
        &state,
        &["zeek.orig_ip_bytes", "zeek.resp_ip_bytes"],
        "suricata.eve.netflow.bytes",
        "bytes",
    )
    .await
    .map(Json)
    .map_err(bad_gateway)
}

pub async fn netflow_packets(State(state): State<AppState>) -> Result<Json<Vec<Series>>, (StatusCode, String)> {
    traffic_sum(
        &state,
        &["zeek.orig_pkts", "zeek.resp_pkts"],
        "suricata.eve.netflow.pkts",
        "packets",
    )
    .await
    .map(Json)
    .map_err(bad_gateway)
}

/// /api/v1/charts/anomaly-trend — protocol-conformance violations per
/// claimed app protocol, hourly. Live aggregation over
/// suricata-v2-anomaly-* (the Go tier derived this from its in-memory
/// cache; same 48h window).
pub async fn anomaly_trend(State(state): State<AppState>) -> Result<Json<Vec<Series>>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": OVERVIEW_WINDOW}}},
        "aggs": {"protos": {
            "terms": {"field": "suricata.eve.app_proto", "size": 20, "missing": "(none)"},
            "aggs": {"hourly": {
                "date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0}
            }}
        }}
    });
    let result = state
        .es
        .search_index(&["suricata-v2-anomaly-*"], body)
        .await
        .map_err(bad_gateway)?;
    let mut series: Vec<Series> = result["aggregations"]["protos"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|proto| Series {
            name: proto["key"].as_str().unwrap_or("").to_string(),
            points: proto["hourly"]["buckets"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|bucket| {
                    Some(Point {
                        time: bucket["key_as_string"].as_str()?.to_string(),
                        value: bucket["doc_count"].as_f64().unwrap_or(0.0),
                    })
                })
                .collect(),
        })
        .collect();
    // Sorted by name, not bucket (count) order — same determinism fix as
    // the Go tier's #40.
    series.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Json(series))
}

/// /api/v1/charts/dionaea-cves — top exploited CVEs / named incidents.
/// data.* is flattened: terms on a flattened leaf works, no .keyword.
///
/// #1611 workstream E.3: dionaea-incidents-v1-* is a raw duplicate of the
/// same incidents that already flow into honeypot-v2-* (audited against
/// the live cluster) — Workstream A's dionaea detail branch (event_detail.rs)
/// already renders them richly there. This dedicated family stays scoped
/// to this one chart; no separate incidents endpoint is needed.
pub async fn dionaea_cves(State(state): State<AppState>) -> Result<Json<Bar>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "query": {"range": {"timestamp": {"gte": WEEK}}},
        "aggs": {"names": {
            "terms": {"field": "data.name", "size": 15},
            "aggs": {"cve": {"terms": {"field": "data.cve", "size": 1}}}
        }}
    });
    let result = state
        .es
        .search_index(&["dionaea-incidents-v1-*"], body)
        .await
        .map_err(bad_gateway)?;
    let mut bar = Bar { categories: Vec::new(), values: Vec::new() };
    for bucket in result["aggregations"]["names"]["buckets"].as_array().into_iter().flatten() {
        let mut label = bucket["key"].as_str().unwrap_or("").to_string();
        if let Some(cve) = bucket["cve"]["buckets"]
            .as_array()
            .and_then(|cves| cves.first())
            .and_then(|cve| cve["key"].as_str())
        {
            label = format!("{label} ({cve})");
        }
        bar.categories.push(label);
        bar.values.push(bucket["doc_count"].as_u64().unwrap_or(0));
    }
    Ok(Json(bar))
}

/// /api/v1/charts/os-distribution — unique attacker IPs per p0f OS guess
/// (portbridge-v2-*, #241/#1277).
pub async fn os_distribution(State(state): State<AppState>) -> Result<Json<Vec<PiePoint>>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": OVERVIEW_WINDOW}}},
        "aggs": {"os": {
            "terms": {"field": "portbridge.os", "size": 20},
            "aggs": {"ips": {"cardinality": {"field": "portbridge.src_ip"}}}
        }}
    });
    let result = state
        .es
        .search_index(&["portbridge-v2-*"], body)
        .await
        .map_err(bad_gateway)?;
    let points = result["aggregations"]["os"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|bucket| {
            let os = bucket["key"].as_str().unwrap_or("");
            !os.is_empty() && os != "???"
        })
        .map(|bucket| PiePoint {
            name: bucket["key"].as_str().unwrap_or("").to_string(),
            value: bucket["ips"]["value"].as_u64().unwrap_or(0),
        })
        .collect();
    Ok(Json(points))
}

async fn fingerprint_bar(state: &AppState, indices: &[&str], body: Value, agg: &str) -> anyhow::Result<Bar> {
    let result = state.es.search_index(indices, body).await?;
    let mut bar = Bar { categories: Vec::new(), values: Vec::new() };
    for bucket in result["aggregations"][agg]["buckets"].as_array().into_iter().flatten() {
        bar.categories.push(bucket["key"].as_str().unwrap_or("").to_string());
        bar.values.push(bucket["doc_count"].as_u64().unwrap_or(0));
    }
    Ok(bar)
}

/// /api/v1/charts/tls-fingerprints — JA4 counts, excluding dest_port 443
/// (the deployment's own operator HTTPS; see scanner_fingerprints.go).
pub async fn tls_fingerprints(State(state): State<AppState>) -> Result<Json<Bar>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": WEEK}}}],
            "must_not": [{"term": {"suricata.eve.dest_port": 443}}]
        }},
        "aggs": {"ja4": {"terms": {"field": "suricata.eve.tls.ja4.keyword", "size": 15}}}
    });
    fingerprint_bar(&state, &["suricata-v2-tls-*"], body, "ja4").await.map(Json).map_err(bad_gateway)
}

/// /api/v1/charts/ssh-fingerprints — SSH client software counts.
pub async fn ssh_fingerprints(State(state): State<AppState>) -> Result<Json<Bar>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": WEEK}}},
        "aggs": {"software": {"terms": {"field": "suricata.eve.ssh.client.software_version.keyword", "size": 15}}}
    });
    fingerprint_bar(&state, &["suricata-v2-ssh-*"], body, "software").await.map(Json).map_err(bad_gateway)
}

/// /api/v1/charts/ml-anomaly-scores — one scatter series per detector
/// model plus the composite (#1284), reshaped from ml-anomalies docs.
pub async fn ml_anomaly_scores(State(state): State<AppState>) -> Result<Json<Vec<Series>>, (StatusCode, String)> {
    let body = json!({
        "size": 500,
        "sort": [{"timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "_source": ["@timestamp", "composite_score", "model_scores"],
        "query": {"match_all": {}}
    });
    let result = state
        .es
        .search_index(&["ml-anomalies"], body)
        .await
        .map_err(bad_gateway)?;
    let hits = result["hits"]["hits"].as_array().cloned().unwrap_or_default();

    // Model names come from the data itself, so a new detector shows up
    // with no dashboard change (same posture as the Go tier).
    let mut names: Vec<String> = hits
        .iter()
        .flat_map(|hit| {
            hit["_source"]["model_scores"]
                .as_object()
                .map(|scores| scores.keys().cloned().collect::<Vec<_>>())
                .unwrap_or_default()
        })
        .collect();
    names.sort();
    names.dedup();
    names.push("composite".to_string());

    let series = names
        .into_iter()
        .map(|name| Series {
            points: hits
                .iter()
                .filter_map(|hit| {
                    let source = &hit["_source"];
                    let time = source["@timestamp"].as_str()?.to_string();
                    let value = if name == "composite" {
                        source["composite_score"].as_f64()?
                    } else {
                        source["model_scores"][&name].as_f64()?
                    };
                    Some(Point { time, value })
                })
                .collect(),
            name,
        })
        .collect();
    Ok(Json(series))
}

const HELD_BUCKETS: &[(&str, u64)] = &[
    ("<1s", 1_000),
    ("1-5s", 5_000),
    ("5-15s", 15_000),
    ("15-60s", 60_000),
    ("1-5min", 300_000),
    ("5min+", u64::MAX),
];

/// /api/v1/charts/endlessh-held-histogram — how long the tarpit held
/// connections. #1611 workstream F: held_ms used to only ride the
/// flattened honeypot.* namespace (no range aggregation possible), so
/// this bucketed up to 10k raw disconnect events client-side. The
/// geoip-honeypot ingest pipeline now also copies it to a real top-level
/// `held_ms` (long) field (elasticsearch-setup.sh) on new documents, so
/// this is a genuine ES `range` aggregation — no per-request document cap.
/// Historical documents indexed before that pipeline change won't carry
/// the typed field and are simply absent from the histogram (same
/// no-backfill precedent as workstream D's technique promotion).
fn held_ranges() -> Vec<Value> {
    HELD_BUCKETS
        .iter()
        .scan(0u64, |from, (label, to)| {
            let range = if *to == u64::MAX {
                json!({"key": label, "from": *from})
            } else {
                json!({"key": label, "from": *from, "to": *to})
            };
            *from = *to;
            Some(range)
        })
        .collect()
}

pub async fn endlessh_histogram(State(state): State<AppState>) -> Result<Json<Bar>, (StatusCode, String)> {
    let ranges = held_ranges();
    let body = json!({
        "size": 0,
        "query": {"bool": {"filter": [
            {"term": {"event.sensor": "endlessh"}},
            {"term": {"honeypot.event": "disconnect"}},
            {"range": {"@timestamp": {"gte": OVERVIEW_WINDOW}}}
        ]}},
        "aggs": {"held": {"range": {"field": "held_ms", "keyed": true, "ranges": ranges}}}
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    let buckets = &result["aggregations"]["held"]["buckets"];
    let counts = HELD_BUCKETS.iter().map(|(label, _)| buckets[label]["doc_count"].as_u64().unwrap_or(0)).collect();
    Ok(Json(Bar {
        categories: HELD_BUCKETS.iter().map(|(label, _)| label.to_string()).collect(),
        values: counts,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_ranges_cover_every_bucket_contiguously_with_no_gaps_or_overlap() {
        let ranges = held_ranges();
        assert_eq!(ranges.len(), HELD_BUCKETS.len());
        assert_eq!(ranges[0]["key"], "<1s");
        assert_eq!(ranges[0]["from"], 0);
        assert_eq!(ranges[0]["to"], 1_000);
        // Each range's "from" must equal the previous range's "to" — no
        // duration falls between buckets or gets double-counted.
        for pair in ranges.windows(2) {
            assert_eq!(pair[0]["to"], pair[1]["from"]);
        }
        let last = ranges.last().unwrap();
        assert_eq!(last["key"], "5min+");
        assert_eq!(last["from"], 300_000);
        assert!(last.get("to").is_none(), "the open-ended top bucket must not set \"to\"");
    }
}
