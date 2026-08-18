//! Store-backed endpoints reading the authoritative worker/dashboard index
//! families directly (campaigns-v1, attacker-clusters-v1, attackers-v1,
//! cowrie-ttylog-v1, dashboard-alert-state-v1,
//! dashboard-payload-inventory-v1). These carry the correlators' full
//! output — scores, explanations, acknowledge state — so the port shows
//! exactly what the Go tier shows, not an approximation.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::AppState;

#[derive(Deserialize)]
pub struct StoreQuery {
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_size")]
    pub size: u64,
}

fn default_size() -> u64 {
    25
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

/// Generic hits page: {"total": N, "rows": [ _source... ]}. The BFF/routes
/// know each store's shape; this tier guarantees ordering + paging.
async fn store_page(
    state: &AppState,
    indices: &[&str],
    sort_field: &str,
    q: &StoreQuery,
    extra_filter: Option<Value>,
) -> anyhow::Result<Value> {
    store_page_excluding(state, indices, sort_field, q, extra_filter, &[]).await
}

async fn store_page_excluding(
    state: &AppState,
    indices: &[&str],
    sort_field: &str,
    q: &StoreQuery,
    extra_filter: Option<Value>,
    excludes: &[&str],
) -> anyhow::Result<Value> {
    let size = q.size.min(100);
    let query = extra_filter.unwrap_or_else(|| json!({"match_all": {}}));
    let mut body = json!({
        "from": q.offset,
        "size": size,
        "track_total_hits": true,
        "sort": [{sort_field: {"order": "desc", "unmapped_type": "date"}}],
        "query": query
    });
    if !excludes.is_empty() {
        body["_source"] = json!({"excludes": excludes});
    }
    let result = state.es.search_index(indices, body).await?;
    let total = result["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let rows: Vec<Value> = result["hits"]["hits"]
        .as_array()
        .map(|hits| hits.iter().map(|hit| hit["_source"].clone()).collect())
        .unwrap_or_default();
    Ok(json!({"total": total, "rows": rows}))
}

pub async fn campaigns(
    State(state): State<AppState>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    store_page(&state, &["campaigns-v1"], "score", &q, None)
        .await
        .map(Json)
        .map_err(bad_gateway)
}

pub async fn clusters(
    State(state): State<AppState>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    store_page(&state, &["attacker-clusters-v1"], "events", &q, None)
        .await
        .map(Json)
        .map_err(bad_gateway)
}

pub async fn attackers(
    State(state): State<AppState>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    store_page(&state, &["attackers-v1"], "events", &q, None)
        .await
        .map(Json)
        .map_err(bad_gateway)
}

pub async fn recordings(
    State(state): State<AppState>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    // ttylog_base64 excluded from the list (multi-KB per row); the replay
    // endpoint fetches a single doc by shasum when the pane opens.
    let size = q.size.min(100);
    let body = json!({
        "from": q.offset,
        "size": size,
        "track_total_hits": true,
        "sort": [{"imported_at": {"order": "desc", "unmapped_type": "date"}}],
        "_source": {"excludes": ["ttylog_base64"]},
        "query": {"match_all": {}}
    });
    let result = state
        .es
        .search_index(&["cowrie-ttylog-v1"], body)
        .await
        .map_err(bad_gateway)?;
    let total = result["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let rows: Vec<Value> = result["hits"]["hits"]
        .as_array()
        .map(|hits| hits.iter().map(|hit| hit["_source"].clone()).collect())
        .unwrap_or_default();
    Ok(Json(json!({"total": total, "rows": rows})))
}

pub async fn alerts(
    State(state): State<AppState>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    store_page(&state, &["dashboard-alert-state-v1"], "LastSeen", &q, None)
        .await
        .map(Json)
        .map_err(bad_gateway)
}

pub async fn payloads(
    State(state): State<AppState>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    store_page(&state, &["dashboard-payload-inventory-v1"], "MtimeUTC", &q, None)
        .await
        .map(Json)
        .map_err(bad_gateway)
}

/// Generic allowlisted store passthrough: /api/v1/store/{name}. Every
/// remaining store-shaped page reads through here instead of growing its
/// own handler; the allowlist keeps arbitrary index reads impossible.
pub async fn generic(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Query(q): Query<StoreQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    // (index, sort field, heavy fields excluded from list responses).
    let (index, sort, excludes): (&str, &str, &[&str]) = match name.as_str() {
        "auth-events" => ("auth-failure-events", "last_seen", &[]),
        // llm-worker output; index may not exist yet (ignore_unavailable).
        "llm-analysis" => ("llm-analysis", "@timestamp", &[]),
        "ml-anomalies" => ("ml-anomalies", "timestamp", &[]),
        "agent-campaigns" => ("agent-intrusion-campaigns", "last_seen", &[]),
        "canarytokens" => ("dashboard-canarytokens-v1", "created_at", &[]),
        "problem-reports" => ("dashboard-problem-reports-v1", "submitted_at", &["dom_snapshot"]),
        "dead-letters" => ("dead-letter-honeypot", "@timestamp", &[]),
        "yara" => ("yara-analysis-v1", "@timestamp", &[]),
        "sandbox-runs" => ("sandbox-analysis-v1", "@timestamp", &[]),
        "ghidra-runs" => ("ghidra-analysis-v1", "@timestamp", &[]),
        "static-analysis" => ("dashboard-static-analysis-v1", "Analysis.GeneratedUTC", &[]),
        "workbench-runs" => ("dashboard-workbench-runs-v1", "created_at", &[]),
        "generated-reports" => ("dashboard-generated-reports-v1", "created_at", &["pdf_base64"]),
        "report-definitions" => ("dashboard-reports-definitions-v1", "updated", &[]),
        "intelligence" => ("dashboard-intelligence-archive-v1", "generated", &[]),
        _ => return Err((StatusCode::NOT_FOUND, format!("unknown store {name}"))),
    };
    store_page_excluding(&state, &[index], sort, &q, None, excludes)
        .await
        .map(Json)
        .map_err(bad_gateway)
}
