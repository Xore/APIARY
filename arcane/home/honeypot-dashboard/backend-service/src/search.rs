//! /api/v1/search?q= — the grouped investigate search, ported from
//! search.go. The Go tier substring-scanned its in-memory event cache;
//! this tier runs one aggregation pass with per-group prefix filters
//! (prefix queries are supported on flattened fields — verified live,
//! unlike wildcard) plus keyword wildcards where the mapping allows.
//! `redirect` is the exact-single-entity check the caller uses to jump
//! straight to a detail page (quick-search's "Enter" row).
//!
//! #1611 workstream F: "HTTP paths" used to be prefix-only, like every
//! other flattened-field group below (`honeypot.path` can't do substring
//! matching). It now queries `url.path` instead — a real `wildcard`-typed
//! field the geoip-honeypot ingest pipeline already copies `honeypot.path`
//! into (elasticsearch-setup.sh) — so this group alone gets genuine
//! substring/infix hunting, the same trick "Suricata signatures" already
//! used against a keyword field.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;

use crate::AppState;

const WINDOW: &str = "now-48h";
const GROUP_LIMIT: usize = 8;

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
}

#[derive(Serialize)]
pub struct Hit {
    pub label: String,
    pub count: u64,
    pub url: String,
}

#[derive(Serialize)]
pub struct Group {
    pub title: String,
    pub hits: Vec<Hit>,
    /// How many further matches the GROUP_LIMIT-capped terms agg left out
    /// (sum_other_doc_count) — feeds the "N more →" overflow link the Go
    /// results page carried (search.html:51, #1653).
    pub more: u64,
    /// Where the overflow link goes: the raw ES history console scoped to
    /// this query, the one surface guaranteed to show everything.
    pub more_url: String,
}

#[derive(Serialize)]
pub struct SearchResult {
    pub query: String,
    /// Set when the query unambiguously names one entity.
    pub redirect: Option<String>,
    pub groups: Vec<Group>,
    pub total: usize,
}

struct GroupSpec {
    title: &'static str,
    agg: &'static str,
    field: &'static str,
    url: fn(&str) -> String,
}

const GROUPS: &[GroupSpec] = &[
    GroupSpec { title: "Sessions", agg: "sessions", field: "honeypot.session", url: |v| format!("/sessions/{v}") },
    // Per-hit pivots target the events explorer's pivot filters
    // (events.rs, #1653) — a search hit lands on the exact filtered
    // scope, not a generic list page (the Go tier's own hit-URL shape).
    GroupSpec { title: "Payloads", agg: "payloads", field: "honeypot.shasum", url: |v| format!("/payload-analysis/{v}") },
    GroupSpec { title: "Commands", agg: "commands", field: "honeypot.canonical_command", url: |v| format!("/events?cmd={}", crate::services_control::urlencode(v)) },
    // "HTTP paths" (url.path, wildcard) is queried separately below.
    GroupSpec { title: "Credentials (usernames)", agg: "users", field: "honeypot.username", url: |_| "/events?kind=login".to_string() },
    GroupSpec { title: "Fingerprints", agg: "fingerprints", field: "honeypot.canonical_fingerprint", url: |v| format!("/events?fingerprint={}", crate::services_control::urlencode(v)) },
    GroupSpec { title: "Personas", agg: "personas", field: "honeypot.persona_id", url: |v| format!("/events?persona={}", crate::services_control::urlencode(v)) },
];

pub async fn search(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> Result<Json<SearchResult>, (StatusCode, String)> {
    let needle = query.q.trim().to_string();
    if needle.is_empty() || needle.len() > 256 {
        return Ok(Json(SearchResult { query: needle, redirect: None, groups: Vec::new(), total: 0 }));
    }

    let mut aggs = serde_json::Map::new();
    for spec in GROUPS {
        aggs.insert(
            spec.agg.to_string(),
            // The prefix filter narrows to docs whose value matches; these
            // fields are single-valued per doc, so the terms sub-agg then
            // only surfaces prefix-matching values (no include-regex — not
            // supported on flattened leaves).
            json!({
                "filter": {"prefix": {spec.field: needle.clone()}},
                "aggs": {"values": {"terms": {"field": spec.field, "size": GROUP_LIMIT}}}
            }),
        );
    }
    // Suricata signatures: keyword mapping, real substring wildcard.
    aggs.insert(
        "signatures".to_string(),
        json!({
            "filter": {"wildcard": {"suricata.eve.alert.signature.keyword": {"value": format!("*{needle}*"), "case_insensitive": true}}},
            "aggs": {"values": {"terms": {"field": "suricata.eve.alert.signature.keyword", "size": GROUP_LIMIT}}}
        }),
    );
    // HTTP paths: wildcard mapping (workstream F), real substring wildcard
    // — same trick as signatures above, on the ingest-pipeline-promoted
    // url.path field instead of the flattened honeypot.path.
    aggs.insert(
        "paths".to_string(),
        json!({
            "filter": {"wildcard": {"url.path": {"value": format!("*{needle}*"), "case_insensitive": true}}},
            "aggs": {"values": {"terms": {"field": "url.path", "size": GROUP_LIMIT}}}
        }),
    );
    // Exact IP (or CIDR) → source group with count.
    let ip_query: Option<Value> = if needle.parse::<IpAddr>().is_ok() || needle.contains('/') {
        Some(json!({"term": {"source.ip": needle.clone()}}))
    } else {
        None
    };
    if let Some(ip_term) = &ip_query {
        aggs.insert("ips".to_string(), json!({"filter": ip_term}));
    }

    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": WINDOW}}},
        "aggs": aggs
    });
    let result = state
        .es
        .search(body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let result_aggs = &result["aggregations"];

    let mut groups: Vec<Group> = Vec::new();
    let mut total = 0usize;
    let more_url = format!("/history?q={}", crate::services_control::urlencode(&needle));
    let overflow = |agg: &Value| agg["values"]["sum_other_doc_count"].as_u64().unwrap_or(0);

    if ip_query.is_some() {
        let count = result_aggs["ips"]["doc_count"].as_u64().unwrap_or(0);
        if count > 0 {
            total += 1;
            groups.push(Group {
                title: "Attack sources".to_string(),
                more: 0,
                more_url: more_url.clone(),
                hits: vec![Hit {
                    label: needle.clone(),
                    count,
                    url: format!("/investigate/ip/{needle}"),
                }],
            });
        }
    }

    for spec in GROUPS {
        let hits: Vec<Hit> = result_aggs[spec.agg]["values"]["buckets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|bucket| {
                let label = bucket["key"].as_str()?.to_string();
                Some(Hit { url: (spec.url)(&label), count: bucket["doc_count"].as_u64().unwrap_or(0), label })
            })
            .collect();
        if !hits.is_empty() {
            total += hits.len();
            let more = overflow(&result_aggs[spec.agg]);
            groups.push(Group { title: spec.title.to_string(), hits, more, more_url: more_url.clone() });
        }
    }

    let signature_hits: Vec<Hit> = result_aggs["signatures"]["values"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|bucket| {
            let label = bucket["key"].as_str()?.to_string();
            Some(Hit { url: "/events".to_string(), count: bucket["doc_count"].as_u64().unwrap_or(0), label })
        })
        .collect();
    if !signature_hits.is_empty() {
        total += signature_hits.len();
        let more = overflow(&result_aggs["signatures"]);
        groups.push(Group { title: "Suricata signatures".to_string(), hits: signature_hits, more, more_url: more_url.clone() });
    }

    let path_hits: Vec<Hit> = result_aggs["paths"]["values"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|bucket| {
            let label = bucket["key"].as_str()?.to_string();
            Some(Hit { url: "/sensors".to_string(), count: bucket["doc_count"].as_u64().unwrap_or(0), label })
        })
        .collect();
    if !path_hits.is_empty() {
        total += path_hits.len();
        let more = overflow(&result_aggs["paths"]);
        groups.push(Group { title: "HTTP paths".to_string(), hits: path_hits, more, more_url: more_url.clone() });
    }

    // Exact-entity redirect: a session id or payload hash that matched a
    // whole value, or a literal IP.
    let redirect = groups.iter().find_map(|group| {
        let hit = group.hits.first()?;
        let exact = hit.label.eq_ignore_ascii_case(&needle);
        match group.title.as_str() {
            "Sessions" if exact => Some(format!("/sessions/{}", hit.label)),
            "Attack sources" => Some(format!("/investigate/ip/{}", hit.label)),
            _ => None,
        }
    });

    Ok(Json(SearchResult { query: needle, redirect, groups, total }))
}
