//! Store-backed endpoints reading the authoritative worker/dashboard index
//! families directly (campaigns-v1, attacker-clusters-v1, attackers-v1,
//! cowrie-ttylog-v1, dashboard-alert-state-v1,
//! dashboard-payload-inventory-v1). These carry the correlators' full
//! output — scores, explanations, acknowledge state — so the port shows
//! exactly what the Go tier shows, not an approximation.
//!
//! #1611 workstream E.10: `auth-events-worker-state`, `ml-worker-state`,
//! and the other `dashboard-*-state`/`*-worker-state` indices are each a
//! single worker's own resume cursor (last-processed offset/timestamp) —
//! operational bookkeeping with no per-event or per-operator meaning, the
//! same category as a Kafka consumer group's committed offset. They're
//! deliberately absent from the `generic` allowlist below and from every
//! other endpoint in this crate; this comment is that decision on record
//! so the census question doesn't reopen.

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
    /// Free-text Lucene query string (dead-letters' search box, elastic.go's
    /// deadLetters `q` param). Only dead-letters.tsx sends this today, but
    /// every generic-backed store list can use it — additive, ignored by
    /// callers that never set it.
    #[serde(default)]
    pub q: Option<String>,
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
    let query = match extra_filter {
        Some(filter) => filter,
        None => match q.q.as_deref().map(str::trim).filter(|text| !text.is_empty()) {
            Some(text) => json!({"query_string": {"query": text, "default_operator": "AND"}}),
            None => json!({"match_all": {}}),
        },
    };
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
        .map(|hits| {
            hits.iter()
                .map(|hit| {
                    // _doc_id rides along for row-level actions (e.g. the
                    // ML anomaly ack keys on the anomalies page).
                    let mut row = hit["_source"].clone();
                    row["_doc_id"] = hit["_id"].clone();
                    row
                })
                .collect()
        })
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

#[derive(Deserialize)]
pub struct AckBody {
    pub ack: bool,
}

/// POST /api/v1/alerts/{key}/ack — flip one alert's Acknowledged flag
/// (dashboard-alert-state-v1 doc id == alert key), the ported
/// alertManager.acknowledge.
pub async fn acknowledge(
    State(state): State<AppState>,
    axum::extract::Path(key): axum::extract::Path<String>,
    Json(body): Json<AckBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    state
        .es
        .update_doc("dashboard-alert-state-v1", &key, json!({"Acknowledged": body.ack}))
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    Ok(Json(json!({"ok": true, "key": key, "ack": body.ack})))
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
        // #1611 workstream E.9: `error`, `details.username`, and
        // `details.redirect_uri` are already present here (no excludes) —
        // the workstream's ask is first-class *columns* for them on the
        // auth-events.tsx table, a frontend-only change; this passthrough
        // already carries every field they'd need.
        "auth-events" => ("auth-failure-events", "last_seen", &[]),
        // llm-worker output; index may not exist yet (ignore_unavailable).
        "llm-analysis" => ("llm-analysis", "@timestamp", &[]),
        "ml-anomalies" => ("ml-anomalies", "timestamp", &[]),
        // Matches dashboard/agent_campaigns.go's own refreshAgentCampaigns
        // sort (`sort=@timestamp:asc`) — the campaign-verdict documents
        // this index holds have no last_seen field at all (see the
        // agent-intrusion-worker port's build_campaign_verdict, #1610).
        "agent-campaigns" => ("agent-intrusion-campaigns", "@timestamp", &[]),
        "canarytokens" => ("dashboard-canarytokens-v1", "created_at", &[]),
        "problem-reports" => ("dashboard-problem-reports-v1", "submitted_at", &["dom_snapshot"]),
        "dead-letters" => ("dead-letter-honeypot", "@timestamp", &[]),
        "yara" => ("yara-analysis-v1", "@timestamp", &[]),
        "sandbox-runs" => ("sandbox-analysis-v1", "@timestamp", &[]),
        "ghidra-runs" => ("ghidra-analysis-v1", "@timestamp", &[]),
        "static-analysis" => ("dashboard-static-analysis-v1", "Analysis.GeneratedUTC", &[]),
        // Result families that may not exist yet on a given deployment
        // (ignore_unavailable keeps them safe): revdeck, CAPE, GitHub.
        "revdeck" => ("revdeck-analysis-v1", "@timestamp", &[]),
        "cape" => ("cape-analysis-v1", "@timestamp", &[]),
        "github-analysis" => ("github-analysis-v1", "@timestamp", &[]),
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

#[derive(Deserialize)]
pub struct PurgeQuery {
    #[serde(default)]
    pub q: Option<String>,
}

/// DELETE /api/v1/store/{name} — allowlisted like `generic`'s GET side,
/// but only dead-letters has a delete today (ported from elastic.go's
/// purgeDeadLetters). Sharing the route with `generic` rather than
/// registering a second literal path at `/api/v1/store/dead-letters`
/// avoids relying on axum/matchit's literal-over-param route precedence
/// for what would otherwise be an overlapping registration.
///
/// Admin-gated at the BFF (not here), same posture as every other admin
/// action in this tier. Purges exactly the same `q` Lucene query-string
/// scope the GET side searches with — an absent/empty q purges every
/// retained dead letter, matching Go's documented "the operator purges
/// exactly the scope they were just looking at" contract.
pub async fn generic_delete(
    axum::extract::Path(name): axum::extract::Path<String>,
    State(state): State<AppState>,
    Query(q): Query<PurgeQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if name != "dead-letters" {
        return Err((StatusCode::METHOD_NOT_ALLOWED, format!("store {name} has no delete route")));
    }
    let query = match q.q.as_deref().map(str::trim).filter(|text| !text.is_empty()) {
        Some(text) => json!({"query_string": {"query": text, "default_operator": "AND"}}),
        None => json!({"match_all": {}}),
    };
    let deleted = state.es.delete_by_query("dead-letter-honeypot", query).await.map_err(bad_gateway)?;
    Ok(Json(json!({"deleted": deleted})))
}
