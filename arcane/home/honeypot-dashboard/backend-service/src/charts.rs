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

/// /api/v1/charts/tcp-stack-clusters — unique attacker IPs per JA4T TCP-stack
/// fingerprint (`zeek-v1-conn-*`).
///
/// #1727 §7's replacement for the p0f OS-distribution chart above. Measured on
/// 14 days of this deployment's own traffic, p0f resolves 76.2% of connections
/// to a Linux kernel at or below 3.10 -- a version line that went EOL in 2017 --
/// produces zero Windows 10 labels in 2.69 M labelled connections, and finds
/// two Android hosts. It is a three-way Linux/Windows/other classifier wearing
/// version numbers, and the chart renders those numbers as if they meant
/// something.
///
/// JA4T does not name the OS, which is the point: it is a hash of the observed
/// TCP handshake parameters, so it clusters hosts that share a stack without
/// asserting what that stack is. Coverage is comparable (88.7% of connections
/// carry one, against p0f's 95.1% label rate) and it does not decay as the
/// signature database ages, because there is no database.
///
/// Both charts coexist while p0f still runs. Retiring p0f is what removes the
/// other one.
pub async fn tcp_stack_clusters(
    State(state): State<AppState>,
) -> Result<Json<Vec<PiePoint>>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": OVERVIEW_WINDOW}}},
        "aggs": {"stacks": {
            "terms": {"field": "zeek.ja4t", "size": 20},
            "aggs": {"ips": {"cardinality": {"field": "source.ip"}}}
        }}
    });
    let result = state
        .es
        .search_index(&["zeek-v1-conn-*"], body)
        .await
        .map_err(bad_gateway)?;
    let points = result["aggregations"]["stacks"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        // Zeek writes an empty ja4t for connections it never saw a SYN for --
        // a mid-stream capture start, or a scan that only ever sent a RST.
        .filter(|bucket| !bucket["key"].as_str().unwrap_or("").is_empty())
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

/// /api/v1/charts/ics-functions — what attackers actually asked the fake PLCs
/// to do, by ICS function code (`zeek-v1-*`, #1736).
///
/// Each ICSNPP parser names its function field differently, so this runs one
/// terms aggregation per field rather than pretending a single field spans
/// them, and labels each bar with the protocol it came from. Only the three
/// fields observed on real captured traffic are queried — modbus_detailed's
/// `func`, s7comm's `function_name` and dnp3's `fc_request`. BACnet, ENIP and
/// OPC-UA are parsed and indexed but have not yet produced a record here, so
/// guessing their field names would add rows that can only ever read zero.
///
/// Worth knowing when reading this chart: the interesting ICS events are rare
/// and the noise around them is not. One sample held 3 600 connections to
/// port 20000 and exactly two DNP3 records — which is the argument for the
/// chart, since an alert-only view loses those two entirely.
pub async fn ics_functions(State(state): State<AppState>) -> Result<Json<Bar>, (StatusCode, String)> {
    const SOURCES: &[(&str, &str, &str)] = &[
        ("modbus", "zeek-v1-modbus_detailed-*", "zeek.func"),
        ("s7comm", "zeek-v1-s7comm-*", "zeek.function_name"),
        ("dnp3", "zeek-v1-dnp3-*", "zeek.fc_request"),
    ];

    let mut bar = Bar { categories: Vec::new(), values: Vec::new() };
    for (proto, index, field) in SOURCES {
        let body = json!({
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": WEEK}}},
            "aggs": {"fn": {"terms": {"field": *field, "size": 8}}}
        });
        // One dead index must not blank the whole chart: a protocol nobody has
        // probed this week is a normal state, not an error.
        let Ok(result) = state.es.search_index(&[*index], body).await else {
            continue;
        };
        for bucket in result["aggregations"]["fn"]["buckets"].as_array().into_iter().flatten() {
            let name = bucket["key"].as_str().unwrap_or("");
            if name.is_empty() {
                continue;
            }
            bar.categories.push(format!("{proto}: {name}"));
            bar.values.push(bucket["doc_count"].as_u64().unwrap_or(0));
        }
    }
    Ok(Json(bar))
}

/// /api/v1/charts/decoy-requests — what was requested from the TLS-terminated
/// decoys (`traefik-v1-*`, #1739).
///
/// These requests exist nowhere else. Traefik terminates TLS for the
/// Host-routed decoys, so a wire sensor sees the ClientHello and then
/// ciphertext; this index is the only record that the request happened at all.
pub async fn decoy_requests(State(state): State<AppState>) -> Result<Json<Bar>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": WEEK}}},
        "aggs": {"paths": {"terms": {"field": "url.path", "size": 15}}}
    });
    fingerprint_bar(&state, &["traefik-v1-*"], body, "paths").await.map(Json).map_err(bad_gateway)
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
