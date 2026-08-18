//! Aggregation-backed list endpoints for the Investigate family. Query
//! shapes mirror the Go dashboard's es_aggregate.go semantics (same index
//! families, same field names); each returns page-shaped JSON the BFF
//! passes through to the routes.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::AppState;

fn text(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_size")]
    pub size: u64,
}

fn default_size() -> u64 {
    25
}

// ── Attack sources (/ips): top source IPs with activity window ───────────

#[derive(Serialize)]
pub struct SourceRow {
    pub ip: String,
    pub country: String,
    pub events: u64,
    pub logins: u64,
    pub sessions: u64,
    pub sensors: Vec<String>,
    pub first: String,
    pub last: String,
}

#[derive(Serialize)]
pub struct SourcesPage {
    pub total_unique: u64,
    pub rows: Vec<SourceRow>,
}

pub async fn sources(
    State(state): State<AppState>,
    Query(q): Query<PageQuery>,
) -> Result<Json<SourcesPage>, (StatusCode, String)> {
    let size = (q.offset + q.size).min(1000);
    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-10d"}}},
        "aggs": {
            "unique": {"cardinality": {"field": "source.ip"}},
            "ips": {
                "terms": {"field": "source.ip", "size": size, "order": {"_count": "desc"}},
                "aggs": {
                    "country": {"terms": {"field": "source.geo.country_iso_code", "size": 1}},
                    "sensors": {"terms": {"field": "event.sensor", "size": 30}},
                    "logins": {"filter": {"terms": {"honeypot.event": ["login.failed", "login.success", "auth_attempt"]}}},
                    "sessions": {"cardinality": {"field": "honeypot.session"}},
                    "first": {"min": {"field": "@timestamp"}},
                    "last": {"max": {"field": "@timestamp"}}
                }
            }
        }
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    let total_unique = result["aggregations"]["unique"]["value"].as_u64().unwrap_or(0);
    let rows = result["aggregations"]["ips"]["buckets"]
        .as_array()
        .map(|buckets| {
            buckets
                .iter()
                .skip(q.offset as usize)
                .map(|bucket| SourceRow {
                    ip: text(&bucket["key"]),
                    country: bucket["country"]["buckets"]
                        .as_array()
                        .and_then(|c| c.first())
                        .map(|c| text(&c["key"]))
                        .unwrap_or_default(),
                    events: bucket["doc_count"].as_u64().unwrap_or(0),
                    logins: bucket["logins"]["doc_count"].as_u64().unwrap_or(0),
                    sessions: bucket["sessions"]["value"].as_u64().unwrap_or(0),
                    sensors: bucket["sensors"]["buckets"]
                        .as_array()
                        .map(|s| s.iter().map(|b| text(&b["key"])).collect())
                        .unwrap_or_default(),
                    first: text(&bucket["first"]["value_as_string"]),
                    last: text(&bucket["last"]["value_as_string"]),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(SourcesPage { total_unique, rows }))
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}
