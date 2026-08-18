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
//! - endlessh-held-histogram buckets held_ms client-side from the raw
//!   disconnect events (honeypot.* is flattened — stats/range
//!   aggregations are unsupported, the same limitation aggregate.go
//!   documents).

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

async fn netflow_sum(state: &AppState, field: &str, name: &str) -> anyhow::Result<Vec<Series>> {
    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": WEEK}}},
        "aggs": {"hourly": {
            "date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0},
            "aggs": {"total": {"sum": {"field": field}}}
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
    netflow_sum(&state, "suricata.eve.netflow.bytes", "bytes").await.map(Json).map_err(bad_gateway)
}

pub async fn netflow_packets(State(state): State<AppState>) -> Result<Json<Vec<Series>>, (StatusCode, String)> {
    netflow_sum(&state, "suricata.eve.netflow.pkts", "packets").await.map(Json).map_err(bad_gateway)
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

const HELD_BUCKETS: &[(&str, u64)] = &[
    ("<1s", 1_000),
    ("1-5s", 5_000),
    ("5-15s", 15_000),
    ("15-60s", 60_000),
    ("1-5min", 300_000),
    ("5min+", u64::MAX),
];

/// /api/v1/charts/endlessh-held-histogram — how long the tarpit held
/// connections. held_ms rides the flattened honeypot.* namespace (no
/// range aggregation possible), so the raw disconnect events are fetched
/// and bucketed here — bounded: endlessh disconnects are low-volume.
pub async fn endlessh_histogram(State(state): State<AppState>) -> Result<Json<Bar>, (StatusCode, String)> {
    let body = json!({
        "size": 10_000,
        "_source": ["honeypot.held_ms"],
        "query": {"bool": {"filter": [
            {"term": {"event.sensor": "endlessh"}},
            {"term": {"honeypot.event": "disconnect"}},
            {"range": {"@timestamp": {"gte": OVERVIEW_WINDOW}}}
        ]}}
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    let mut counts = vec![0u64; HELD_BUCKETS.len()];
    for hit in result["hits"]["hits"].as_array().into_iter().flatten() {
        let ms = hit["_source"]["honeypot"]["held_ms"].as_f64().unwrap_or(0.0).max(0.0) as u64;
        let index = HELD_BUCKETS.iter().position(|(_, upper)| ms < *upper).unwrap_or(HELD_BUCKETS.len() - 1);
        counts[index] += 1;
    }
    Ok(Json(Bar {
        categories: HELD_BUCKETS.iter().map(|(label, _)| label.to_string()).collect(),
        values: counts,
    }))
}
