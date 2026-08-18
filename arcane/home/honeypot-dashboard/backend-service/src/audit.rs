//! Append-only audit log for settings mutations, ported from
//! settings_audit.go: actor, action, dotted field names, revision, and
//! result; values are never written to the log. JSONL with a single
//! rotated generation (older events are not retained past one rotation —
//! matches the Go tier exactly).

use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::AppState;

const AUDIT_MAX_BYTES: u64 = 8 << 20;

#[derive(Serialize, Default, Clone, Debug)]
pub struct AuditEvent {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub time: String,
    pub actor_subject: String,
    pub actor_username: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub request_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_ip: String,
    pub action: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    pub revision: i64,
    /// success | conflict | invalid | error
    pub result: String,
}

pub struct AuditLogger {
    path: PathBuf,
    lock: Mutex<()>,
}

impl AuditLogger {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), lock: Mutex::new(()) }
    }

    /// Append one event. Audit failures never block the mutation that
    /// produced the event — best-effort, like the Go tier's logger.
    pub fn log(&self, mut event: AuditEvent) {
        let _guard = self.lock.lock().unwrap_or_else(|poison| poison.into_inner());
        if event.time.is_empty() {
            event.time = chrono::Utc::now().to_rfc3339();
        }
        if let Some(parent) = self.path.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return;
            }
        }
        rotate_if_oversized(&self.path, AUDIT_MAX_BYTES);
        let Ok(line) = serde_json::to_string(&event) else { return };
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(file, "{line}");
        }
    }

    /// Newest events first, bounded to limit. Only the live generation is
    /// read (matches settings_audit.go's read, which never consults the
    /// rotated .1 file).
    pub fn read(&self, limit: usize) -> Vec<Value> {
        if limit == 0 {
            return Vec::new();
        }
        let _guard = self.lock.lock().unwrap_or_else(|poison| poison.into_inner());
        let Ok(raw) = std::fs::read_to_string(&self.path) else { return Vec::new() };
        let mut events = Vec::with_capacity(limit.min(256));
        for line in raw.lines().rev() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<Value>(line) {
                events.push(value);
                if events.len() >= limit {
                    break;
                }
            }
        }
        events
    }
}

pub fn rotate_if_oversized(path: &Path, max_bytes: u64) {
    let Ok(meta) = std::fs::metadata(path) else { return };
    if meta.len() <= max_bytes {
        return;
    }
    let rotated = rotated_path(path);
    let _ = std::fs::remove_file(&rotated);
    let _ = std::fs::rename(path, &rotated);
}

pub fn rotated_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

#[derive(Deserialize)]
pub struct AuditQuery {
    limit: Option<usize>,
    action: Option<String>,
}

/// GET /api/v1/audit?limit=&action= — newest first, optional action
/// filter, limit clamped to [1, 500] (default 100), ported from
/// serveSettingsAudit.
pub async fn list(State(state): State<AppState>, Query(query): Query<AuditQuery>) -> Json<Value> {
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    let events = state.audit.read(500);
    let filtered: Vec<Value> = events
        .into_iter()
        .filter(|event| match query.action.as_deref() {
            Some(action) => event["action"].as_str() == Some(action),
            None => true,
        })
        .take(limit)
        .collect();
    Json(json!({"events": filtered}))
}
