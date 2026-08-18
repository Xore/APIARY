//! Dashboard config + users stores (settings subsystem, ported from
//! settings_store_es.go's ES-backed halves):
//! - GET /api/v1/config — the dashboard-config-v1 payload (presentation
//!   + behavior), driving branding text across the frontend.
//! - PUT /api/v1/config/presentation — replace the presentation block
//!   (revision+1); the BFF enforces the admin role before calling.
//! - GET /api/v1/users — the known-operators roster (subjects, roles,
//!   seen timestamps; per-user preference blobs stay out of the list).

use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};

use crate::AppState;

const CONFIG_INDEX: &str = "dashboard-config-v1";
const CONFIG_ID: &str = "config";
const USERS_INDEX: &str = "dashboard-users-v1";

async fn load_config(state: &AppState) -> anyhow::Result<Option<Value>> {
    if let Some(doc) = state.es.get_doc(CONFIG_INDEX, CONFIG_ID).await? {
        return Ok(Some(doc));
    }
    // The store may use a different doc id — fall back to the newest doc.
    let result = state
        .es
        .search_index(
            &[CONFIG_INDEX],
            json!({"size": 1, "sort": [{"revision": {"order": "desc", "unmapped_type": "long"}}]}),
        )
        .await?;
    Ok(result["hits"]["hits"].as_array().and_then(|hits| hits.first()).map(|hit| hit["_source"].clone()))
}

pub async fn get_config(State(state): State<AppState>) -> Result<Json<Value>, (StatusCode, String)> {
    let doc = load_config(&state)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?
        .unwrap_or_else(|| json!({"payload": {}}));
    Ok(Json(doc))
}

pub async fn put_presentation(
    State(state): State<AppState>,
    Json(presentation): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if !presentation.is_object() {
        return Err((StatusCode::BAD_REQUEST, "presentation object required".into()));
    }
    let mut doc = load_config(&state)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?
        .unwrap_or_else(|| json!({"schema_version": 4, "revision": 0, "payload": {}}));
    doc["payload"]["presentation"] = presentation;
    doc["revision"] = json!(doc["revision"].as_u64().unwrap_or(0) + 1);
    doc["updated"] = json!(chrono::Utc::now().to_rfc3339());
    state
        .es
        .index_doc(CONFIG_INDEX, CONFIG_ID, doc.clone())
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    Ok(Json(doc))
}

pub async fn users(State(state): State<AppState>) -> Result<Json<Value>, (StatusCode, String)> {
    let result = state
        .es
        .search_index(
            &[USERS_INDEX],
            json!({"size": 1, "sort": [{"revision": {"order": "desc", "unmapped_type": "long"}}]}),
        )
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let rows: Vec<Value> = result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .and_then(|hit| hit["_source"]["payload"]["users"].as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .map(|user| {
            json!({
                "subject": user["subject"],
                "username": user["last_username"],
                "role": user["role_snapshot"],
                "first_seen_at": user["first_seen_at"],
                "last_seen_at": user["last_seen_at"],
            })
        })
        .collect();
    Ok(Json(json!({"users": rows})))
}
