//! Reporter stats passthrough (#666), ported from
//! settings_reporter_stats_api.go: the operations pane's brief "reports
//! sent" glance. Elasticsearch is the only path here — es-results-importer
//! mirrors the reporter worker's own metrics.json into reporter-metrics-v1;
//! this never mounts the reporter's data volume directly.
//!
//! #1611 workstream E.7: this already satisfies the workstream's ask (a
//! raw `reporter_metrics` passthrough necessarily carries
//! attempted/suppressed_cooldown/dry_run/sent/failed/updated_at — whatever
//! the reporter worker itself writes to metrics.json) — no separate
//! health.rs field needed.

use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

use crate::AppState;

const INDEX: &str = "reporter-metrics-v1";

pub async fn stats(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let result = match state.es.search_index(&[INDEX], json!({"size": 1, "sort": [{"updated_at": {"order": "desc", "unmapped_type": "date"}}]})).await {
        Ok(result) => result,
        Err(error) => {
            return (StatusCode::BAD_GATEWAY, Json(json!({"available": false, "reason": error.to_string()})));
        }
    };
    let Some(hit) = result["hits"]["hits"].as_array().and_then(|hits| hits.first()) else {
        return (StatusCode::OK, Json(json!({"available": false, "reason": "no reporter metrics indexed yet"})));
    };
    let metrics = hit["_source"]["reporter_metrics"].clone();
    if metrics.is_null() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"available": false, "reason": "reporter-metrics-v1 document is missing reporter_metrics"})),
        );
    }
    (StatusCode::OK, Json(json!({"available": true, "stats": metrics})))
}
