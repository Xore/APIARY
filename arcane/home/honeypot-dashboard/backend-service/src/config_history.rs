//! Revision history for the dashboard-config-v1 store (#1612), ported from
//! settings_history.go: every successful mutation appends one JSON line
//! holding the full payload snapshot, so a rollback can restore any
//! retained revision exactly. Bounded and rotated the same way — a single
//! .1 generation — with reads spanning both generations, oldest-first
//! internally but returned newest-first.

use serde::Serialize;
use serde_json::Value;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const HISTORY_MAX_BYTES: u64 = 2 << 20;
pub const HISTORY_READ_LIMIT: usize = 200;

#[derive(Serialize, Clone, Debug)]
pub struct HistoryEntry {
    pub revision: i64,
    pub time: String,
    pub actor_subject: String,
    pub actor_username: String,
    /// update | rollback
    pub action: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,
    pub payload: Value,
}

pub struct ConfigHistory {
    path: PathBuf,
    lock: Mutex<()>,
}

impl ConfigHistory {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), lock: Mutex::new(()) }
    }

    pub fn append(&self, mut entry: HistoryEntry) {
        let _guard = self.lock.lock().unwrap_or_else(|poison| poison.into_inner());
        if entry.time.is_empty() {
            entry.time = chrono::Utc::now().to_rfc3339();
        }
        if let Some(parent) = self.path.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return;
            }
        }
        crate::audit::rotate_if_oversized(&self.path, HISTORY_MAX_BYTES);
        let Ok(line) = serde_json::to_string(&entry) else { return };
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(file, "{line}");
        }
    }

    /// Newest entries first across both generations: the rotated .1
    /// generation is read first, then the live file, so the live file's
    /// lines end up at the tail of the buffer — the backward walk below
    /// reaches them first, exactly matching settings_history.go's read.
    pub fn read(&self, limit: usize) -> Vec<Value> {
        if limit == 0 {
            return Vec::new();
        }
        let _guard = self.lock.lock().unwrap_or_else(|poison| poison.into_inner());
        let mut raw = String::new();
        for path in [rotated_path(&self.path), self.path.clone()] {
            if let Ok(data) = std::fs::read_to_string(&path) {
                raw.push_str(&data);
            }
        }
        let mut entries = Vec::with_capacity(limit.min(256));
        for line in raw.lines().rev() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<Value>(line) {
                if value["action"].as_str().is_some_and(|a| !a.is_empty()) {
                    entries.push(value);
                    if entries.len() >= limit {
                        break;
                    }
                }
            }
        }
        entries
    }

    pub fn find(&self, revision: i64) -> Option<Value> {
        self.read(HISTORY_READ_LIMIT).into_iter().find(|entry| entry["revision"].as_i64() == Some(revision))
    }
}

fn rotated_path(path: &Path) -> PathBuf {
    crate::audit::rotated_path(path)
}
