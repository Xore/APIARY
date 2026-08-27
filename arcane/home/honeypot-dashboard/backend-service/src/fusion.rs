//! /api/v1/charts/attacker-fusion?id= — why attacker-identity-worker
//! merged these IPs (#1280): per signal category, how many distinct
//! values 2+ of the entity's member IPs share. Ported from
//! attacker_fusion.go; the per-category counting runs over terms
//! aggregations with a source-IP cardinality sub-agg instead of the Go
//! tier's in-memory event scan.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::AppState;

const WINDOW: &str = "now-48h";

#[derive(Deserialize)]
pub struct FusionQuery {
    pub id: String,
}

#[derive(Serialize)]
pub struct Fusion {
    pub categories: Vec<&'static str>,
    pub values: Vec<u64>,
    pub ips: Vec<String>,
}

/// (category label, index family, value field, ip field)
/// #1742/S5: the Zeek and huginn rows are additive. Signals that produce
/// nothing simply contribute a zero column, so this table is safe to extend
/// before those sensors are deployed -- and safe to keep extended if one is
/// later removed.
///
/// The `zeek.*` and `huginn.*` fields need no `.keyword` suffix: both objects
/// are mapped `flattened`, which indexes every leaf as a keyword already.
///
/// JA4T is listed alongside "p0f OS" rather than replacing it. p0f still runs,
/// and until it is actually retired (#1727 §0) dropping its row would lose a
/// signal the entity merges were built on. The two answer different questions
/// anyway: p0f guesses an OS name from a database whose newest Linux entry is
/// 3.x, while JA4T is a stack hash that clusters without claiming to know what
/// the stack is.
const SIGNALS: &[(&str, &[&str], &str, &str)] = &[
    ("JA3", &["suricata-v2-*"], "suricata.eve.tls.ja3.hash.keyword", "source.ip"),
    ("JA4", &["suricata-v2-*"], "suricata.eve.tls.ja4.keyword", "source.ip"),
    ("p0f OS", &["portbridge-v2-*"], "portbridge.os", "portbridge.src_ip"),
    ("SSH client", &["honeypot-v2-*"], "honeypot.version", "source.ip"),
    ("Payload hash", &["honeypot-v2-*"], "honeypot.shasum", "source.ip"),
    // Wire-level TCP stack hash. Measured 88.7% coverage of connections in
    // dev/sensing-lab, against p0f's 95.1% label coverage -- comparable reach,
    // but a precise hash instead of a label that resolves to a pre-2013 Linux
    // kernel three quarters of the time.
    ("JA4T", &["zeek-v1-conn-*"], "zeek.ja4t", "source.ip"),
    // SSH handshake algorithm lists. 98.6% coverage of SSH sessions, and
    // unlike the "SSH client" banner above it is not attacker-assertable.
    ("HASSH", &["zeek-v1-ssh-*"], "zeek.hassh", "source.ip"),
    ("JA4SSH", &["zeek-v1-ja4ssh-*"], "zeek.ja4ssh", "source.ip"),
    // Server-side TLS fingerprint -- our own sensors as an attacker sees them,
    // which nothing else in this table covers.
    ("JA4S", &["zeek-v1-ssl-*"], "zeek.ja4s", "source.ip"),
    // huginn-net's raw TCP signature. Present even when the OS match is
    // NotMatched, which is most of the time for SYN+ACK, so it clusters where
    // the label cannot.
    ("TCP signature", &["huginn-v1-*"], "huginn.observation.sig", "source.ip"),
];

pub async fn fusion(
    State(state): State<AppState>,
    Query(query): Query<FusionQuery>,
) -> Result<Json<Fusion>, (StatusCode, String)> {
    // Resolve the entity's member IPs from attackers-v1.
    let entity = state
        .es
        .search_index(
            &["attackers-v1"],
            json!({"size": 1, "query": {"term": {"id": query.id}}}),
        )
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let ips: Vec<String> = entity["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .and_then(|hit| hit["_source"]["ips"].as_array())
        .map(|values| values.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    if ips.is_empty() {
        return Err((StatusCode::NOT_FOUND, "no such attacker entity".into()));
    }

    let mut values = Vec::with_capacity(SIGNALS.len());
    for (_, indices, value_field, ip_field) in SIGNALS {
        let body = json!({
            "size": 0,
            "query": {"bool": {"filter": [
                {"range": {"@timestamp": {"gte": WINDOW}}},
                {"terms": {*ip_field: ips}}
            // #2145: probes carry no source.ip so the member-IP terms alone
            // already exclude them; the term keeps that guarantee explicit
            // (and no-op for the non-honeypot signals).
            ], "must_not": [crate::es::internal_probe_exclusion()]}},
            "aggs": {"values": {
                "terms": {"field": *value_field, "size": 100},
                "aggs": {"ips": {"cardinality": {"field": *ip_field}}}
            }}
        });
        let result = state
            .es
            .search_index(indices, body)
            .await
            .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
        let shared = result["aggregations"]["values"]["buckets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|bucket| bucket["ips"]["value"].as_u64().unwrap_or(0) >= 2)
            .count() as u64;
        values.push(shared);
    }

    Ok(Json(Fusion {
        categories: SIGNALS.iter().map(|(label, ..)| *label).collect(),
        values,
        ips,
    }))
}
