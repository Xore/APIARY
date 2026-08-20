//! /api/v1/ml-health — per-model retrain history (#1611 workstream E.5).
//! ml-worker-metrics today only feeds the backlog chart (charts.rs); its
//! `kind: retrain` documents (accepted/rejected retrain decisions, with
//! before/after anomaly rates) go entirely unsurfaced, so a drifting or
//! silently-rejected model is invisible. One doc per model: its most
//! recent retrain outcome.

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::json;

use crate::AppState;

const INDEX: &str = "ml-worker-metrics";

#[derive(Serialize)]
pub struct ModelHealth {
    pub model: String,
    pub timestamp: String,
    pub accepted: bool,
    pub reason: String,
    pub anomaly_rate_new: f64,
    pub anomaly_rate_previous: f64,
    pub train_samples: u64,
}

pub async fn list(State(state): State<AppState>) -> Result<Json<Vec<ModelHealth>>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "query": {"term": {"kind": "retrain"}},
        "aggs": {
            "models": {
                "terms": {"field": "model", "size": 20},
                "aggs": {"latest": {"top_hits": {"size": 1, "sort": [{"@timestamp": {"order": "desc"}}]}}}
            }
        }
    });
    let result = state
        .es
        .search_index(&[INDEX], body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let text = |value: &serde_json::Value| value.as_str().unwrap_or("").to_string();
    let models = result["aggregations"]["models"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|bucket| {
            let hit = bucket["latest"]["hits"]["hits"].as_array().and_then(|hits| hits.first())?;
            let source = &hit["_source"];
            Some(ModelHealth {
                model: bucket["key"].as_str().unwrap_or("").to_string(),
                timestamp: text(&source["@timestamp"]),
                accepted: source["accepted"].as_bool().unwrap_or(false),
                reason: text(&source["reason"]),
                anomaly_rate_new: source["anomaly_rate_new"].as_f64().unwrap_or(0.0),
                anomaly_rate_previous: source["anomaly_rate_previous"].as_f64().unwrap_or(0.0),
                train_samples: source["train_samples"].as_u64().unwrap_or(0),
            })
        })
        .collect();
    Ok(Json(models))
}
