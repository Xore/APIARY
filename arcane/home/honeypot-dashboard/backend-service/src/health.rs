//! /api/v1/source-health — per-sensor ingestion freshness + ES cluster
//! state, the port's version of the Go source-health page's ES half. (The
//! filebeat/log-tail half joins with the worker port #1610, which owns
//! host-local observability.)

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::json;

use crate::AppState;

#[derive(Serialize)]
pub struct SensorHealth {
    pub sensor: String,
    pub documents: u64,
    pub last_seen: String,
    /// ACTIVE (<5m), QUIET (<1h), STALE otherwise — same thresholds the Go
    /// page communicates.
    pub state: String,
}

#[derive(Serialize)]
pub struct SourceHealth {
    pub cluster_status: String,
    pub total_documents: u64,
    pub sensors: Vec<SensorHealth>,
}

pub async fn source_health(State(state): State<AppState>) -> Result<Json<SourceHealth>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "track_total_hits": true,
        "aggs": {
            "sensors": {
                "terms": {"field": "event.sensor", "size": 60, "order": {"last": "desc"}},
                "aggs": {"last": {"max": {"field": "@timestamp"}}}
            },
            "newest": {"max": {"field": "@timestamp"}}
        }
    });
    let result = state
        .es
        .search(body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

    let cluster_status = state.es.cluster_status().await;
    let total_documents = result["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let sensors = result["aggregations"]["sensors"]["buckets"]
        .as_array()
        .map(|buckets| {
            buckets
                .iter()
                .map(|bucket| {
                    let last_ms = bucket["last"]["value"].as_f64().unwrap_or(0.0) as i64;
                    let age_s = ((now_ms - last_ms) / 1000).max(0);
                    SensorHealth {
                        sensor: bucket["key"].as_str().unwrap_or("").to_string(),
                        documents: bucket["doc_count"].as_u64().unwrap_or(0),
                        last_seen: bucket["last"]["value_as_string"].as_str().unwrap_or("").to_string(),
                        state: if age_s < 300 {
                            "ACTIVE"
                        } else if age_s < 3600 {
                            "QUIET"
                        } else {
                            "STALE"
                        }
                        .to_string(),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Json(SourceHealth { cluster_status, total_documents, sensors }))
}
