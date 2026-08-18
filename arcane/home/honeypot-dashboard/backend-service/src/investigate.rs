//! /api/v1/investigate/ip/{ip} — one source address's profile: activity
//! summary, sensors/ports/countries touched, credentials and commands
//! tried, sessions, techniques, and the newest events. The Go tier's
//! /investigate/ip page over its in-memory cache, re-derived as one
//! aggregation pass + one bounded event fetch.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use serde_json::json;
use std::net::IpAddr;

use crate::{events::EventRow, AppState};

const WINDOW: &str = "now-10d";

#[derive(Serialize)]
pub struct Kv {
    pub key: String,
    pub count: u64,
}

#[derive(Serialize)]
pub struct IpProfile {
    pub ip: String,
    pub total: u64,
    pub first: String,
    pub last: String,
    pub country: String,
    pub asn: String,
    pub sensors: Vec<Kv>,
    pub ports: Vec<Kv>,
    pub protos: Vec<Kv>,
    pub credentials: Vec<Kv>,
    pub commands: Vec<Kv>,
    pub sessions: Vec<Kv>,
    pub techniques: Vec<Kv>,
    pub events: Vec<EventRow>,
}

fn kv(result: &serde_json::Value, agg: &str) -> Vec<Kv> {
    result["aggregations"][agg]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|bucket| {
            let key = bucket["key"]
                .as_str()
                .map(String::from)
                .or_else(|| bucket["key"].as_i64().map(|n| n.to_string()))
                .or_else(|| {
                    bucket["key"].as_array().map(|parts| {
                        parts
                            .iter()
                            .map(|part| part.as_str().unwrap_or(""))
                            .collect::<Vec<_>>()
                            .join(" / ")
                    })
                })?;
            Some(Kv { key, count: bucket["doc_count"].as_u64().unwrap_or(0) })
        })
        .collect()
}

pub async fn ip(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Result<Json<IpProfile>, (StatusCode, String)> {
    if ip.parse::<IpAddr>().is_err() {
        return Err((StatusCode::BAD_REQUEST, "invalid ip".into()));
    }
    let filter = json!({"bool": {"filter": [
        {"term": {"source.ip": ip}},
        {"range": {"@timestamp": {"gte": WINDOW}}}
    ]}});
    let agg_body = json!({
        "size": 0,
        "track_total_hits": true,
        "query": filter,
        "aggs": {
            "first": {"min": {"field": "@timestamp"}},
            "last": {"max": {"field": "@timestamp"}},
            "country": {"terms": {"field": "source.geo.country_iso_code", "size": 1}},
            "asn": {"terms": {"field": "source.as.organization_name", "size": 1}},
            "sensors": {"terms": {"field": "event.sensor", "size": 30}},
            "ports": {"terms": {"field": "destination.port", "size": 20}},
            "protos": {"terms": {"field": "network.protocol", "size": 20}},
            "creds": {"multi_terms": {"terms": [
                {"field": "honeypot.username"}, {"field": "honeypot.password"}], "size": 20}},
            "commands": {"terms": {"field": "honeypot.canonical_command", "size": 20}},
            "sessions": {"terms": {"field": "honeypot.session", "size": 20}},
            "techniques": {"terms": {"field": "honeypot.canonical_attck_techniques", "size": 20}}
        }
    });
    let events_body = json!({
        "size": 50,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": filter
    });
    let (aggs, events) = tokio::try_join!(state.es.search(agg_body), state.es.search(events_body))
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

    let total = aggs["hits"]["total"]["value"].as_u64().unwrap_or(0);
    if total == 0 {
        return Err((StatusCode::NOT_FOUND, "no events for this ip".into()));
    }
    let text = |value: &serde_json::Value| value.as_str().unwrap_or("").to_string();
    let rows: Vec<EventRow> = events["hits"]["hits"]
        .as_array()
        .map(|hits| hits.iter().map(|hit| crate::events::row_from_source(&hit["_source"])).collect())
        .unwrap_or_default();

    Ok(Json(IpProfile {
        ip,
        total,
        first: text(&aggs["aggregations"]["first"]["value_as_string"]),
        last: text(&aggs["aggregations"]["last"]["value_as_string"]),
        country: kv(&aggs, "country").first().map(|row| row.key.clone()).unwrap_or_default(),
        asn: kv(&aggs, "asn").first().map(|row| row.key.clone()).unwrap_or_default(),
        sensors: kv(&aggs, "sensors"),
        ports: kv(&aggs, "ports"),
        protos: kv(&aggs, "protos"),
        credentials: kv(&aggs, "creds")
            .into_iter()
            .map(|mut row| {
                // Same telnet-NUL cleanup the overview cred table applies.
                row.key = row.key.replace("\\x00", "").chars().filter(|c| !c.is_control()).collect();
                row
            })
            .collect(),
        commands: kv(&aggs, "commands"),
        sessions: kv(&aggs, "sessions"),
        techniques: kv(&aggs, "techniques"),
        events: rows,
    }))
}
