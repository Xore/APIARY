//! Dashboard config + users stores (settings subsystem, ported from
//! settings_store_es.go's ES-backed halves):
//! - GET /api/v1/config — the dashboard-config-v1 payload (presentation
//!   + behavior), driving branding text across the frontend.
//! - PUT /api/v1/config/presentation — replace the presentation block
//!   (revision+1); the BFF enforces the admin role before calling.
//! - PUT /api/v1/config/{section} for section in {honeypot, behavior,
//!   report-presets} — same shape as put_presentation, one level deeper:
//!   each replaces its own `payload.*` block (honeypot / behavior /
//!   report_presets respectively). Still deliberately JSON `Value`-level,
//!   not settings_admin_api.go's typed behaviorPatch/honeypotPatch +
//!   pinned-field + impact-classification machinery — see put_config_section.
//! - GET /api/v1/config/history, POST /api/v1/config/rollback (#1612) —
//!   revision history and restore, working at the JSON `Value` level like
//!   everything else here rather than porting settings_admin_api.go's full
//!   typed behavior/honeypot patch + pinned-field + impact-classification
//!   machinery, which nothing in this Rust tier writes yet.
//! - GET /api/v1/users — the known-operators roster (subjects, roles,
//!   seen timestamps; per-user preference blobs stay out of the list).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::audit::AuditEvent;
use crate::config_history::HistoryEntry;
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

#[derive(Deserialize)]
pub struct ActorQuery {
    #[serde(default)]
    actor_subject: String,
    #[serde(default)]
    actor_username: String,
}

pub async fn put_presentation(
    State(state): State<AppState>,
    Query(actor): Query<ActorQuery>,
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
    let revision = doc["revision"].as_i64().unwrap_or(0);
    let fields = vec!["presentation".to_string()];
    state.config_history.append(HistoryEntry {
        revision,
        time: String::new(),
        actor_subject: actor.actor_subject.clone(),
        actor_username: actor.actor_username.clone(),
        action: "update".into(),
        fields: fields.clone(),
        payload: doc["payload"].clone(),
    });
    state.audit.log(AuditEvent {
        actor_subject: actor.actor_subject,
        actor_username: actor.actor_username,
        action: "config.update".into(),
        fields,
        revision,
        result: "success".into(),
        ..Default::default()
    });
    Ok(Json(doc))
}

/// URL section name -> `payload.*` key. Only these three are exposed here;
/// `presentation` keeps its own dedicated route/handler above.
fn config_section_key(section: &str) -> Option<&'static str> {
    match section {
        "honeypot" => Some("honeypot"),
        "behavior" => Some("behavior"),
        "report-presets" => Some("report_presets"),
        _ => None,
    }
}

/// PUT /api/v1/config/{section} — identical in shape to put_presentation,
/// just parameterized over which `payload.*` block it replaces. Backs the
/// three settings.tsx admin panes that were previously entirely missing
/// server-side storage: Honeypot operations (staged thresholds, applied on
/// the consuming services' next restart — this endpoint only stores the
/// values), Dashboard behavior (live global defaults + feature toggles),
/// and Report Studio presets (per-preset name/description override map,
/// keyed by template id — an arbitrary object, same as everywhere else in
/// this file that just round-trips whatever JSON `Value` it's given).
pub async fn put_config_section(
    State(state): State<AppState>,
    Path(section): Path<String>,
    Query(actor): Query<ActorQuery>,
    Json(value): Json<Value>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let Some(payload_key) = config_section_key(&section) else {
        return Err((StatusCode::NOT_FOUND, "unknown config section".into()));
    };
    if !value.is_object() {
        return Err((StatusCode::BAD_REQUEST, format!("{payload_key} object required")));
    }
    let mut doc = load_config(&state)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?
        .unwrap_or_else(|| json!({"schema_version": 4, "revision": 0, "payload": {}}));
    doc["payload"][payload_key] = value;
    doc["revision"] = json!(doc["revision"].as_u64().unwrap_or(0) + 1);
    doc["updated"] = json!(chrono::Utc::now().to_rfc3339());
    state
        .es
        .index_doc(CONFIG_INDEX, CONFIG_ID, doc.clone())
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let revision = doc["revision"].as_i64().unwrap_or(0);
    let fields = vec![payload_key.to_string()];
    state.config_history.append(HistoryEntry {
        revision,
        time: String::new(),
        actor_subject: actor.actor_subject.clone(),
        actor_username: actor.actor_username.clone(),
        action: "update".into(),
        fields: fields.clone(),
        payload: doc["payload"].clone(),
    });
    state.audit.log(AuditEvent {
        actor_subject: actor.actor_subject,
        actor_username: actor.actor_username,
        action: "config.update".into(),
        fields,
        revision,
        result: "success".into(),
        ..Default::default()
    });
    Ok(Json(doc))
}

/// configHistoryView-equivalent: everything needed for review and rollback
/// selection, without the retained payload snapshot itself.
pub async fn history(State(state): State<AppState>) -> Json<Value> {
    let entries: Vec<Value> = state
        .config_history
        .read(crate::config_history::HISTORY_READ_LIMIT)
        .into_iter()
        .map(|entry| {
            json!({
                "revision": entry["revision"],
                "time": entry["time"],
                "actor_subject": entry["actor_subject"],
                "actor_username": entry["actor_username"],
                "action": entry["action"],
                "fields": entry["fields"],
            })
        })
        .collect();
    Json(json!({"entries": entries}))
}

#[derive(Deserialize)]
pub struct RollbackBody {
    revision: i64,
    #[serde(default)]
    actor_subject: String,
    #[serde(default)]
    actor_username: String,
}

/// Restores one retained revision's full payload as a NEW revision —
/// history is append-only, rollback never rewrites the past.
pub async fn rollback(
    State(state): State<AppState>,
    Json(body): Json<RollbackBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if body.revision < 0 {
        return Err((StatusCode::BAD_REQUEST, "a non-negative revision is required".into()));
    }
    let Some(entry) = state.config_history.find(body.revision) else {
        return Err((StatusCode::NOT_FOUND, "revision is no longer retained".into()));
    };
    let restored_payload = entry["payload"].clone();
    let mut doc = load_config(&state)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?
        .unwrap_or_else(|| json!({"schema_version": 4, "revision": 0, "payload": {}}));
    doc["payload"] = restored_payload.clone();
    doc["revision"] = json!(doc["revision"].as_u64().unwrap_or(0) + 1);
    doc["updated"] = json!(chrono::Utc::now().to_rfc3339());
    state
        .es
        .index_doc(CONFIG_INDEX, CONFIG_ID, doc.clone())
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let revision = doc["revision"].as_i64().unwrap_or(0);
    let fields = vec!["*".to_string()];
    state.config_history.append(HistoryEntry {
        revision,
        time: String::new(),
        actor_subject: body.actor_subject.clone(),
        actor_username: body.actor_username.clone(),
        action: "rollback".into(),
        fields: fields.clone(),
        payload: restored_payload,
    });
    state.audit.log(AuditEvent {
        actor_subject: body.actor_subject,
        actor_username: body.actor_username,
        action: "config.rollback".into(),
        fields,
        revision,
        result: "success".into(),
        ..Default::default()
    });
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
