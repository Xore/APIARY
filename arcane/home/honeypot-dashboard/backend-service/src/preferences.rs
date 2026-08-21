//! Per-user preference sync (#1612), ported from settings_users.go /
//! settings_api.go: one subject's preferences live nested in the shared
//! dashboard-users-v1/users document, alongside the read-only operator
//! roster config.rs's `users` handler already serves. Identity travels as
//! plain request params supplied by the BFF (subject/username/role) —
//! the same trust model ip_block.rs's `actor` body field already uses —
//! rather than a new header-based scheme; the BFF is the only caller of
//! this service (gated on the shared service token) so it is exactly as
//! trustworthy as every other BFF-supplied field here.
//!
//! Deliberately simpler than the Go tier: no per-subject ETag/If-Match
//! compare-and-swap (nothing else in this crate has that yet either) and
//! GET never refreshes an already-projected subject's last_seen_at/role —
//! only first contact writes, so a preference *read* never costs an ES
//! write. Follow-up if that's needed: throttled last_seen refresh like
//! userStore.Upsert's 5-minute window.

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::audit::AuditEvent;
use crate::AppState;

const USERS_INDEX: &str = "dashboard-users-v1";
const USERS_ID: &str = "users";
const SCHEMA_VERSION: u64 = 4;

async fn load_users_doc(state: &AppState) -> anyhow::Result<Value> {
    if let Some(doc) = state.es.get_doc(USERS_INDEX, USERS_ID).await? {
        return Ok(doc);
    }
    let result = state
        .es
        .search_index(
            &[USERS_INDEX],
            json!({"size": 1, "sort": [{"revision": {"order": "desc", "unmapped_type": "long"}}]}),
        )
        .await?;
    Ok(result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .map(|hit| hit["_source"].clone())
        .unwrap_or_else(|| json!({"schema_version": SCHEMA_VERSION, "revision": 0, "payload": {"users": []}})))
}

async fn save_users_doc(state: &AppState, mut doc: Value) -> anyhow::Result<Value> {
    doc["revision"] = json!(doc["revision"].as_u64().unwrap_or(0) + 1);
    doc["updated"] = json!(chrono::Utc::now().to_rfc3339());
    if doc["schema_version"].is_null() {
        doc["schema_version"] = json!(SCHEMA_VERSION);
    }
    state.es.index_doc(USERS_INDEX, USERS_ID, doc.clone()).await?;
    Ok(doc)
}

fn users_array(doc: &mut Value) -> &mut Vec<Value> {
    if !doc["payload"]["users"].is_array() {
        doc["payload"]["users"] = json!([]);
    }
    doc["payload"]["users"].as_array_mut().unwrap()
}

fn find_user<'a>(doc: &'a mut Value, subject: &str) -> Option<&'a mut Value> {
    users_array(doc).iter_mut().find(|u| u["subject"].as_str() == Some(subject))
}

fn default_preferences(timezone: &str) -> Value {
    let tz = if timezone.trim().is_empty() { "browser" } else { timezone.trim() };
    json!({
        "theme": "system",
        "palette": "claude",
        "density": "comfortable",
        "reduced_motion": "system",
        "collapsed_sidebar": false,
        "landing_page": "/",
        "remember_filters": false,
        "rows_per_page": 50,
        "wrap_long_values": false,
        "timezone": tz,
        "clock": "h24",
        "timestamps": "relative",
        "auto_refresh": true,
        "refresh_interval_seconds": 30,
        "live_toasts": true,
        "map_basemap": "osm",
        "map_clustering": true,
        "map_animation": true,
        "high_contrast": false,
        "large_evidence_text": false,
        "notify_severity": "high",
        "notify_sound": false,
        "notify_desktop": false,
        "default_event_window": "24h",
        "preserve_filters": false,
        "open_details_new_tab": false,
    })
}

fn new_projection(subject: &str, username: &str, role: &str, timezone: &str) -> Value {
    let now = chrono::Utc::now().to_rfc3339();
    json!({
        "subject": subject,
        "last_username": username,
        "role_snapshot": role,
        "first_seen_at": now,
        "last_seen_at": now,
        "preferences_version": SCHEMA_VERSION,
        "preferences_revision": 0,
        "preferences": default_preferences(timezone),
    })
}

#[derive(Deserialize)]
pub struct PreferencesQuery {
    #[serde(default)]
    subject: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    timezone: String,
}

pub async fn get(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<PreferencesQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if query.subject.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "subject is required".into()));
    }
    let mut doc = load_users_doc(&state).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    if let Some(user) = find_user(&mut doc, &query.subject) {
        let preferences = user["preferences"].clone();
        let revision = user["preferences_revision"].as_i64().unwrap_or(0);
        return Ok(Json(json!({"preferences": preferences, "revision": revision})));
    }
    let projection = new_projection(&query.subject, &query.username, &query.role, &query.timezone);
    let preferences = projection["preferences"].clone();
    users_array(&mut doc).push(projection);
    save_users_doc(&state, doc).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(json!({"preferences": preferences, "revision": 0})))
}

/// The fields settings_api.go's preferencesPatch allows. `palette` rides
/// along since Go commit 31286e1 (#1621) added it there — before that,
/// every appearance save carrying it 400'd on the strict decoder.
#[derive(Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
struct PreferencesPatch {
    theme: Option<String>,
    palette: Option<String>,
    density: Option<String>,
    reduced_motion: Option<String>,
    collapsed_sidebar: Option<bool>,
    landing_page: Option<String>,
    remember_filters: Option<bool>,
    rows_per_page: Option<i64>,
    wrap_long_values: Option<bool>,
    timezone: Option<String>,
    clock: Option<String>,
    timestamps: Option<String>,
    auto_refresh: Option<bool>,
    refresh_interval_seconds: Option<i64>,
    live_toasts: Option<bool>,
    map_basemap: Option<String>,
    map_clustering: Option<bool>,
    map_animation: Option<bool>,
    high_contrast: Option<bool>,
    large_evidence_text: Option<bool>,
    notify_severity: Option<String>,
    notify_sound: Option<bool>,
    notify_desktop: Option<bool>,
    default_event_window: Option<String>,
    preserve_filters: Option<bool>,
    open_details_new_tab: Option<bool>,
}

impl PreferencesPatch {
    fn empty(&self) -> bool {
        *self == PreferencesPatch::default()
    }

    /// Applies every present field onto `prefs`, returning the dotted
    /// (flat, here) field names that changed for the audit record.
    fn apply(self, prefs: &mut Value) -> Vec<String> {
        let mut fields = Vec::new();
        macro_rules! set {
            ($name:literal, $field:expr) => {
                if let Some(value) = $field {
                    prefs[$name] = json!(value);
                    fields.push($name.to_string());
                }
            };
        }
        set!("theme", self.theme);
        set!("palette", self.palette);
        set!("density", self.density);
        set!("reduced_motion", self.reduced_motion);
        set!("collapsed_sidebar", self.collapsed_sidebar);
        set!("landing_page", self.landing_page);
        set!("remember_filters", self.remember_filters);
        set!("rows_per_page", self.rows_per_page);
        set!("wrap_long_values", self.wrap_long_values);
        set!("timezone", self.timezone);
        set!("clock", self.clock);
        set!("timestamps", self.timestamps);
        set!("auto_refresh", self.auto_refresh);
        set!("refresh_interval_seconds", self.refresh_interval_seconds);
        set!("live_toasts", self.live_toasts);
        set!("map_basemap", self.map_basemap);
        set!("map_clustering", self.map_clustering);
        set!("map_animation", self.map_animation);
        set!("high_contrast", self.high_contrast);
        set!("large_evidence_text", self.large_evidence_text);
        set!("notify_severity", self.notify_severity);
        set!("notify_sound", self.notify_sound);
        set!("notify_desktop", self.notify_desktop);
        set!("default_event_window", self.default_event_window);
        set!("preserve_filters", self.preserve_filters);
        set!("open_details_new_tab", self.open_details_new_tab);
        fields
    }
}

#[derive(Deserialize)]
pub struct PreferencesWriteBody {
    #[serde(default)]
    subject: String,
    #[serde(default)]
    username: String,
    // Accepted for symmetry with the GET/reset params but unused here:
    // PUT never touches role_snapshot, matching UpdatePreferences.
    #[serde(default, rename = "role")]
    _role: String,
    #[serde(default)]
    patch: PreferencesPatch,
}

pub async fn put(
    State(state): State<AppState>,
    Json(body): Json<PreferencesWriteBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if body.subject.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "subject is required".into()));
    }
    if body.patch.empty() {
        return Err((StatusCode::BAD_REQUEST, "patch must set at least one preference field".into()));
    }
    let mut doc = load_users_doc(&state).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let Some(user) = find_user(&mut doc, &body.subject) else {
        return Err((StatusCode::NOT_FOUND, "no settings record yet; GET /api/v1/preferences first".into()));
    };
    let fields = body.patch.apply(&mut user["preferences"]);
    let revision = user["preferences_revision"].as_i64().unwrap_or(0) + 1;
    user["preferences_revision"] = json!(revision);
    let preferences = user["preferences"].clone();
    save_users_doc(&state, doc).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    state.audit.log(AuditEvent {
        actor_subject: body.subject,
        actor_username: body.username,
        action: "preferences.update".into(),
        fields,
        revision,
        result: "success".into(),
        ..Default::default()
    });
    Ok(Json(json!({"preferences": preferences, "revision": revision})))
}

#[derive(Deserialize)]
pub struct PreferencesResetBody {
    #[serde(default)]
    subject: String,
    #[serde(default)]
    username: String,
    #[serde(default, rename = "role")]
    _role: String,
    #[serde(default)]
    timezone: String,
}

pub async fn reset(
    State(state): State<AppState>,
    Json(body): Json<PreferencesResetBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if body.subject.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "subject is required".into()));
    }
    let mut doc = load_users_doc(&state).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let Some(user) = find_user(&mut doc, &body.subject) else {
        return Err((StatusCode::NOT_FOUND, "no settings record yet; GET /api/v1/preferences first".into()));
    };
    user["preferences"] = default_preferences(&body.timezone);
    let revision = user["preferences_revision"].as_i64().unwrap_or(0) + 1;
    user["preferences_revision"] = json!(revision);
    let preferences = user["preferences"].clone();
    save_users_doc(&state, doc).await.map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    state.audit.log(AuditEvent {
        actor_subject: body.subject,
        actor_username: body.username,
        action: "preferences.update".into(),
        fields: vec!["*".into()],
        revision,
        result: "success".into(),
        ..Default::default()
    });
    Ok(Json(json!({"preferences": preferences, "revision": revision})))
}
