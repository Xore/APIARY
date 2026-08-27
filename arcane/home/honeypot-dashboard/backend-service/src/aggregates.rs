//! Aggregation-backed list endpoints for the Investigate family. Query
//! shapes mirror the Go dashboard's es_aggregate.go semantics (same index
//! families, same field names); each returns page-shaped JSON the BFF
//! passes through to the routes.

// (filter_values below also lives here — small shared aggregation helpers.)
use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{es::logins_filter, AppState};

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
    /// True when the terms aggregation hit its 1000-bucket request
    /// ceiling and `total_unique` counts IPs that no row shows (#2044).
    pub truncated: bool,
    pub rows: Vec<SourceRow>,
}

pub async fn sources(
    State(state): State<AppState>,
    Query(q): Query<PageQuery>,
) -> Result<Json<SourcesPage>, (StatusCode, String)> {
    let size = (q.offset + q.size).min(1000);
    let body = json!({
        "size": 0,
        // #2145: the /ips top-attacker list; probes mostly drop out via the
        // source.ip aggs, but the exclusion makes that incidental protection
        // explicit (and keeps the total-unique count probe-free).
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": "now-10d"}}}],
            "must_not": [crate::es::internal_probe_exclusion()]
        }},
        "aggs": {
            "unique": {"cardinality": {"field": "source.ip"}},
            "ips": {
                "terms": {"field": "source.ip", "size": size, "order": {"_count": "desc"}},
                "aggs": {
                    "country": {"terms": {"field": "source.geo.country_iso_code", "size": 1}},
                    "sensors": {"terms": {"field": "event.sensor", "size": 30}},
                    "logins": {"filter": logins_filter()},
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
    // The cardinality agg counts the whole window while the terms agg
    // silently stops at its size ceiling; when they disagree, IPs exist
    // that no row shows (#2044).
    let listed = result["aggregations"]["ips"]["buckets"]
        .as_array()
        .map(|buckets| buckets.len())
        .unwrap_or(0);
    Ok(Json(SourcesPage {
        total_unique,
        truncated: total_unique > listed as u64,
        rows,
    }))
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

#[derive(serde::Serialize)]
pub struct FilterValues {
    pub sensors: Vec<String>,
    pub countries: Vec<String>,
    /// City names over the event window (#2045) — the drill-in target the
    /// overview map pins now filter events by.
    pub cities: Vec<String>,
    pub protos: Vec<String>,
    pub ports: Vec<String>,
    pub kinds: Vec<String>,
}

/// /api/v1/filter-values — the filter bar's autocomplete vocabularies,
/// mirroring the Go tier's /api/filter-values (live terms over the event
/// window).
pub async fn filter_values(State(state): State<AppState>) -> Result<Json<FilterValues>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        // #2145: probe docs DO carry sensors/kinds/ports/protos values, so
        // without this clause the fleet's healthchecks leak into the
        // filter-bar vocabulary the operator browses.
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": "now-48h"}}}],
            "must_not": [crate::es::internal_probe_exclusion()]
        }},
        "aggs": {
            "sensors": {"terms": {"field": "event.sensor", "size": 60}},
            "countries": {"terms": {"field": "source.geo.country_iso_code", "size": 200}},
            // Same field the map's multi_terms buckets on; a city term is
            // only useful alongside its country, so the size follows the
            // map pin cap (dashboard.rs, 500) rather than a bar-length one.
            "cities": {"terms": {"field": "source.geo.city_name", "size": 500}},
            "protos": {"terms": {"field": "network.protocol", "size": 60}},
            "ports": {"terms": {"field": "destination.port", "size": 60}},
            "kinds": {"terms": {"field": "honeypot.event", "size": 40}}
        }
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    let keys = |agg: &str| -> Vec<String> {
        result["aggregations"][agg]["buckets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|bucket| {
                let key = &bucket["key"];
                key.as_str().map(String::from).or_else(|| key.as_i64().map(|n| n.to_string()))
            })
            .collect()
    };
    let mut values = FilterValues {
        sensors: keys("sensors"),
        countries: keys("countries"),
        cities: keys("cities"),
        protos: keys("protos"),
        ports: keys("ports"),
        kinds: keys("kinds"),
    };
    values.countries.sort();
    values.cities.sort();
    Ok(Json(values))
}
