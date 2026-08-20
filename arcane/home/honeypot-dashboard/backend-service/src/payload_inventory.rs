//! payload-inventory-worker port (#1610): the write half of the payload
//! inventory, moved off a per-dashboard-instance disk walk into one
//! periodic worker loop — every dashboard/BFF instance reads the same
//! Elasticsearch documents this writes. Reuses payload_kind::classify_payload
//! (already ported for submission/workbench use) and payload_paths::payload_dirs
//! (already ported PAYLOAD_DIRS/SCRIPT_PAYLOAD_DIR resolution) rather than
//! re-deriving either.
//!
//! Ported from payload-inventory-worker/{scan.go,es.go,main.go}. Writes two
//! document families per unique hash: dashboard-payload-inventory-v1 (the
//! listing metadata) and dashboard-payload-bytes-v1 (the raw-bytes mirror —
//! same index payload_bytes.rs's on-demand self-heal path also writes; this
//! loop is that mirror's proactive, bulk-at-scan-time counterpart).

use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::payload_kind::classify_payload;
use crate::payload_paths::{is_valid_hash, payload_dirs};
use crate::AppState;

const INVENTORY_INDEX: &str = "dashboard-payload-inventory-v1";
const BYTES_INDEX: &str = "dashboard-payload-bytes-v1";
/// Matches payloadBytesRawCap/payloadBytesMaxBytes exactly (payload_bytes_es.go) —
/// same store, same caps, so a document mirrored by this loop looks
/// identical to one mirrored by the on-demand self-heal path.
const BYTES_RAW_CAP: u64 = 32 << 20;
const BYTES_MAX_SERIALIZED: usize = 48 << 20;
const PREVIEW_CAP: usize = 512;
const HEAD_BYTES: usize = 64 << 10;

#[derive(Serialize, Clone)]
struct CapturedFile {
    #[serde(rename = "Hash")]
    hash: String,
    #[serde(rename = "Size")]
    size: u64,
    #[serde(rename = "SizeH")]
    size_h: String,
    #[serde(rename = "Mtime")]
    mtime: String,
    #[serde(rename = "MtimeUTC")]
    mtime_utc: String,
    #[serde(rename = "MIME")]
    mime: String,
    #[serde(rename = "Kind")]
    kind: String,
    #[serde(rename = "KindCode")]
    kind_code: String,
    #[serde(rename = "Platform")]
    platform: String,
    #[serde(rename = "AnalysisPath")]
    analysis_path: String,
    #[serde(rename = "Dynamic")]
    dynamic: bool,
    #[serde(rename = "Sources")]
    sources: Vec<String>,
    #[serde(rename = "Copies")]
    copies: u32,
    #[serde(rename = "Preview")]
    preview: String,
    #[serde(rename = "PreviewTruncated")]
    preview_truncated: bool,
}

/// dionaea/cowrie/script → a fixed label; otherwise the directory's own
/// basename, falling back to "payloads" for a root/empty basename.
/// Ported verbatim from scan.go's payloadSourceName.
fn payload_source_name(dir: &str) -> String {
    let lower = dir.to_lowercase();
    if lower.contains("dionaea") {
        return "dionaea".to_string();
    }
    if lower.contains("cowrie") {
        return "cowrie".to_string();
    }
    if lower.contains("script") {
        return "scripts".to_string();
    }
    let name = Path::new(dir).file_name().and_then(|n| n.to_str()).unwrap_or("").trim();
    if name.is_empty() || name == "." {
        "payloads".to_string()
    } else {
        name.to_string()
    }
}

/// 1024-based K/M/G/T/P/E suffixes, one decimal place — ported verbatim
/// from scan.go's humanBytes.
fn human_bytes(n: u64) -> String {
    const UNIT: u64 = 1024;
    if n < UNIT {
        return format!("{n} B");
    }
    let mut div = UNIT;
    let mut exp = 0usize;
    let mut x = n / UNIT;
    while x >= UNIT {
        x /= UNIT;
        div *= UNIT;
        exp += 1;
    }
    let suffixes = b"KMGTPE";
    format!("{:.1} {}B", n as f64 / div as f64, suffixes[exp] as char)
}

/// Canonical `hex.Dump`-shaped hexdump: 16 bytes/row, offset prefix, two
/// 8-byte hex groups (blank-padded on a short final row so every row's `|`
/// sidebar lines up in the same column), ASCII sidebar with non-printable
/// bytes as '.'.
fn hex_dump(data: &[u8]) -> String {
    let mut out = String::new();
    for (row, chunk) in data.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", row * 16));
        for i in 0..16 {
            match chunk.get(i) {
                Some(byte) => out.push_str(&format!("{byte:02x} ")),
                None => out.push_str("   "),
            }
            if i == 7 {
                out.push(' ');
            }
        }
        out.push('|');
        for byte in chunk {
            let ch = *byte as char;
            out.push(if byte.is_ascii_graphic() || *byte == b' ' { ch } else { '.' });
        }
        out.push_str("|\n");
    }
    out
}

fn utc_or_empty(mtime: std::io::Result<std::time::SystemTime>) -> String {
    match mtime {
        Ok(t) => chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339(),
        Err(_) => String::new(),
    }
}

fn mtime_local_minutes(mtime: std::io::Result<std::time::SystemTime>) -> String {
    match mtime {
        Ok(t) => chrono::DateTime::<chrono::Utc>::from(t).format("%Y-%m-%d %H:%M").to_string(),
        Err(_) => String::new(),
    }
}

/// Recursive directory walk, mirroring filepath.WalkDir's traversal (best
/// effort — an unreadable subtree is skipped, never aborts the whole walk).
fn walk_dir(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else { continue };
        if file_type.is_dir() {
            walk_dir(&path, out);
        } else if file_type.is_file() {
            out.push(path);
        }
    }
}

/// Two-pass walk-then-merge across every configured directory: classify each
/// hash-named file once (first source wins the read), then union every
/// source label/copy-count/newest-mtime across directories sharing a hash.
/// Ported from scan.go's scanDirs. Blocking (real filesystem I/O) — call
/// through spawn_blocking.
fn scan_dirs(dirs: &[String]) -> (Vec<CapturedFile>, HashMap<String, (PathBuf, u64)>) {
    let mut files: HashMap<String, CapturedFile> = HashMap::new();
    let mut paths: HashMap<String, (PathBuf, u64)> = HashMap::new();
    let mut source_sets: HashMap<String, HashSet<String>> = HashMap::new();

    for dir in dirs {
        let source = payload_source_name(dir);
        let mut entries = Vec::new();
        walk_dir(Path::new(dir), &mut entries);
        for path in entries {
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            if !is_valid_hash(name) {
                continue;
            }
            let hash = name.to_lowercase();
            source_sets.entry(hash.clone()).or_default().insert(source.clone());

            if let Some(existing) = files.get_mut(&hash) {
                existing.copies += 1;
                if let Ok(meta) = path.metadata() {
                    let modified = mtime_local_minutes(meta.modified());
                    if modified > existing.mtime {
                        existing.mtime_utc = utc_or_empty(meta.modified());
                        existing.mtime = modified;
                    }
                }
                continue;
            }

            let Ok(meta) = path.metadata() else { continue };
            let size = meta.len();
            let mut mime = "application/octet-stream".to_string();
            let (mut kind, mut kind_code, mut platform, mut analysis_path, mut dynamic) =
                ("".to_string(), "".to_string(), "".to_string(), "".to_string(), false);
            let mut preview = String::new();

            if let Ok(mut file) = std::fs::File::open(&path) {
                use std::io::Read;
                let mut head = vec![0u8; HEAD_BYTES];
                if let Ok(n) = file.read(&mut head) {
                    head.truncate(n);
                    let classification = classify_payload(&head);
                    mime = mime_for(&classification.category, &head);
                    kind = classification.label;
                    kind_code = classification.code;
                    platform = classification.platform;
                    analysis_path = classification.analysis_path;
                    dynamic = classification.dynamic;
                    let preview_bytes = &head[..head.len().min(PREVIEW_CAP)];
                    preview = hex_dump(preview_bytes);
                }
            }

            files.insert(
                hash.clone(),
                CapturedFile {
                    hash: hash.clone(),
                    size,
                    size_h: human_bytes(size),
                    mtime: mtime_local_minutes(meta.modified()),
                    mtime_utc: utc_or_empty(meta.modified()),
                    mime,
                    kind,
                    kind_code,
                    platform,
                    analysis_path,
                    dynamic,
                    sources: Vec::new(),
                    copies: 1,
                    preview,
                    preview_truncated: size > PREVIEW_CAP as u64,
                },
            );
            paths.insert(hash, (path, size));
        }
    }

    let mut out = Vec::with_capacity(files.len());
    for (hash, mut file) in files {
        let mut sources: Vec<String> = source_sets.get(&hash).into_iter().flatten().cloned().collect();
        sources.sort();
        file.sources = sources;
        out.push(file);
    }
    out.sort_by(|a, b| b.mtime.cmp(&a.mtime));
    (out, paths)
}

/// Coarse MIME approximation from classify_payload's own category — not a
/// byte-for-byte port of Go's http.DetectContentType (dozens of WHATWG
/// sniffing-spec signatures this crate doesn't have a dependency for), but
/// close enough for the informational field this is: a UI hint, not a
/// security or routing decision (classify_payload's own code/category
/// fields are what submission/workbench actually route on).
fn mime_for(category: &str, head: &[u8]) -> String {
    match category {
        "executable" | "library" | "binary" if head.starts_with(b"MZ") => "application/x-msdownload".to_string(),
        "executable" | "library" if head.starts_with(&[0x7f, b'E', b'L', b'F']) => {
            "application/x-executable".to_string()
        }
        "document" if head.starts_with(b"%PDF-") => "application/pdf".to_string(),
        "document" => "application/x-ole-storage".to_string(),
        "archive" if head.starts_with(&[b'P', b'K', 3, 4]) => "application/zip".to_string(),
        "archive" if head.starts_with(b"Rar!") => "application/x-rar-compressed".to_string(),
        "archive" if head.starts_with(&[b'7', b'z', 0xbc, 0xaf]) => "application/x-7z-compressed".to_string(),
        "archive" if head.starts_with(&[0x1f, 0x8b]) => "application/gzip".to_string(),
        "text" | "script" => "text/plain; charset=utf-8".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}

fn fields_unchanged(existing: &Map<String, Value>, fresh: &Map<String, Value>) -> bool {
    fresh.iter().all(|(k, v)| existing.get(k) == Some(v))
}

/// Upserts every freshly-scanned file's inventory document — merged onto
/// any existing document rather than a blind overwrite, so dashboard-added
/// enrichment fields (GitHubAnalysisURL/GitHubAnalysisLabel) survive an
/// unrelated rescan. Skips the write entirely when every field this worker
/// owns already matches (fields_unchanged), same as scan.go's own
/// indexPayloadInventory.
async fn index_inventory(state: &AppState, files: &[CapturedFile]) -> u32 {
    let mut failures = 0u32;
    for file in files {
        let fresh_value = match serde_json::to_value(file) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(fresh_fields) = fresh_value.as_object().cloned() else { continue };

        let existing = match state.es.get_doc(INVENTORY_INDEX, &file.hash).await {
            Ok(existing) => existing,
            Err(error) => {
                tracing::warn!(%error, hash = %file.hash, "payload-inventory: get_doc failed");
                failures += 1;
                continue;
            }
        };

        let body = match existing.and_then(|v| v.as_object().cloned()) {
            Some(mut stored) => {
                if fields_unchanged(&stored, &fresh_fields) {
                    continue;
                }
                for (k, v) in fresh_fields {
                    stored.insert(k, v);
                }
                Value::Object(stored)
            }
            None => Value::Object(fresh_fields),
        };

        if let Err(error) = state.es.index_doc(INVENTORY_INDEX, &file.hash, body).await {
            tracing::warn!(%error, hash = %file.hash, "payload-inventory: index_doc failed");
            failures += 1;
        }
    }
    failures
}

/// Mirrors one file's raw bytes into dashboard-payload-bytes-v1 if no
/// document exists yet for it — the proactive counterpart to
/// payload_bytes.rs's on-demand self-heal. Ported from scan.go's
/// mirrorPayloadBytes.
async fn mirror_bytes(state: &AppState, hash: &str, path: &Path, size: u64) -> Result<(), ()> {
    match state.es.get_doc(BYTES_INDEX, hash).await {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, hash, "payload-inventory: bytes get_doc failed");
            return Err(());
        }
    }

    if size > BYTES_RAW_CAP {
        let marker = json!({"hash": hash, "size_bytes": size, "too_large": true});
        return state.es.index_doc(BYTES_INDEX, hash, marker).await.map_err(|error| {
            tracing::warn!(%error, hash, "payload-inventory: bytes marker index_doc failed");
        });
    }

    let owned_path = path.to_path_buf();
    let data = match tokio::task::spawn_blocking(move || std::fs::read(&owned_path)).await {
        Ok(Ok(data)) => data,
        _ => return Ok(()), // vanished/unreadable between scan and mirror — benign, matches Go's silent skip
    };
    let data_base64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&data)
    };
    let doc = json!({"hash": hash, "size_bytes": data.len(), "data_base64": data_base64});
    if serde_json::to_vec(&doc).map(|v| v.len()).unwrap_or(0) > BYTES_MAX_SERIALIZED {
        return Ok(()); // matches Go's silent skip on an oversized serialized body
    }
    state
        .es
        .index_doc(BYTES_INDEX, hash, doc)
        .await
        .map_err(|error| tracing::warn!(%error, hash, "payload-inventory: bytes index_doc failed"))
}

async fn run_scan(state: &AppState) {
    let dirs = payload_dirs();
    if dirs.is_empty() {
        return;
    }
    let (files, paths) = match tokio::task::spawn_blocking(move || scan_dirs(&dirs)).await {
        Ok(result) => result,
        Err(error) => {
            tracing::warn!(%error, "payload-inventory: scan panicked");
            return;
        }
    };
    if files.is_empty() {
        return;
    }
    let failures = index_inventory(state, &files).await;
    let mut bytes_failures = 0u32;
    for file in &files {
        if let Some((path, size)) = paths.get(&file.hash) {
            if mirror_bytes(state, &file.hash, path, *size).await.is_err() {
                bytes_failures += 1;
            }
        }
    }
    let total_failures = failures + bytes_failures;
    if total_failures > 0 {
        tracing::warn!(failures = total_failures, files = files.len(), "payload-inventory: scan complete with failures");
    } else {
        tracing::info!(files = files.len(), "payload-inventory: scan complete");
    }
}

/// Parses "5m"/"300s"/"1h" (the SCAN_INTERVAL contract) — a local copy of
/// worker.rs's own private parse_duration (not exported across the module
/// boundary; small enough not to be worth threading a pub through for).
fn parse_scan_interval(text: &str) -> Duration {
    let text = text.trim();
    if text.is_empty() {
        return Duration::from_secs(300);
    }
    let (digits, unit) = text.split_at(text.len().saturating_sub(1));
    match (digits.parse::<u64>(), unit) {
        (Ok(n), "h") => Duration::from_secs(n * 3600),
        (Ok(n), "m") => Duration::from_secs(n * 60),
        (Ok(n), "s") => Duration::from_secs(n),
        _ => Duration::from_secs(300),
    }
}

pub async fn payload_inventory_loop(state: AppState) {
    let interval = parse_scan_interval(&std::env::var("SCAN_INTERVAL").unwrap_or_default());
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        run_scan(&state).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_name_recognizes_known_labels() {
        assert_eq!(payload_source_name("/dionaea-lib/binaries"), "dionaea");
        assert_eq!(payload_source_name("/cowrie-downloads"), "cowrie");
        assert_eq!(payload_source_name("/state/script-payloads"), "scripts");
        assert_eq!(payload_source_name("/mnt/custom-drop"), "custom-drop");
    }

    #[test]
    fn source_name_falls_back_to_payloads_for_root() {
        assert_eq!(payload_source_name("/"), "payloads");
    }

    #[test]
    fn human_bytes_matches_go_formatting() {
        assert_eq!(human_bytes(500), "500 B");
        assert_eq!(human_bytes(1536), "1.5 KB");
        assert_eq!(human_bytes(1024 * 1024 * 3), "3.0 MB");
    }

    #[test]
    fn fields_unchanged_ignores_extra_stored_keys() {
        let existing = json!({"Hash": "a", "Size": 1, "GitHubAnalysisURL": "https://x"});
        let fresh = json!({"Hash": "a", "Size": 1});
        assert!(fields_unchanged(existing.as_object().unwrap(), fresh.as_object().unwrap()));
    }

    #[test]
    fn fields_unchanged_detects_a_real_change() {
        let existing = json!({"Hash": "a", "Size": 1});
        let fresh = json!({"Hash": "a", "Size": 2});
        assert!(!fields_unchanged(existing.as_object().unwrap(), fresh.as_object().unwrap()));
    }
}
