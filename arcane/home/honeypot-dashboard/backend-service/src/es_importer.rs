//! es-results-importer (#1610 worker migration), ported from
//! analysis/es-results-importer/importer.py. Local JSON/binary result files
//! from Ghidra/sandbox/GitHub-analysis/Rev·Deck/CAPE/YARA/cowrie/reporter
//! stay the source of truth; this is a read-only secondary indexer that
//! mirrors them into Elasticsearch on a poll interval, so they're queryable
//! alongside the raw honeypot-v2-*/suricata-v2-* event stream. Runs as its
//! own compose service (see compose.yml's `backend-worker-importer`) rather
//! than folded into `backend-worker`: it needs root + DAC_READ_SEARCH to
//! read root-owned host result directories (same requirement the Python
//! service's own compose block already has), which the other loops in
//! `backend-worker` don't need and shouldn't inherit, and it needs a
//! persistent local dedup-state file, unlike every other loop in this crate
//! (all state elsewhere lives in ES).
//!
//! Change detection is mtime-based, persisted to IMPORTER_STATE: a file is
//! only re-sent once its mtime advances past what was last recorded, so a
//! steady-state pass costs one stat() per file, not one ES write. Document
//! _id is deterministic (sha256/job id/filename) so a re-sent file
//! overwrites its own document instead of duplicating it.
//!
//! Horizontal scaling (unused today — single-instance deployment — but kept
//! for parity with the Python worker's observable behavior): files are
//! partitioned across replicas by sha256(path) % SHARD_COUNT, the same
//! lock-free partitioning idea as Elasticsearch's own hash-based shard
//! routing. SHARD_INDEX defaults to the trailing "-N" of $HOSTNAME (what
//! `docker compose up --scale ...=N` assigns replicas without an explicit
//! container_name).

use base64::Engine;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::AppState;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// One result source: an env var naming the host directory to poll, the ES
/// index/label it feeds, and how to turn a matching file into one or more
/// bulk-index operations. Mirrors importer.py's SOURCES table entries
/// field-for-field.
#[derive(Clone, Copy)]
struct Source {
    env: &'static str,
    label: &'static str,
    index: &'static str,
    /// Tried in order against the parsed JSON payload; first present,
    /// non-empty value becomes the doc id. Empty slice matches
    /// reporter_metrics's `id_fields: ()` (always falls back to the
    /// filename stem, giving one stable, always-overwritten document).
    id_fields: &'static [&'static str],
    glob: &'static str,
    skip: &'static [&'static str],
    binary: bool,
    chunked: bool,
    id_suffix: Option<&'static str>,
    artifact_kind: Option<&'static str>,
    content_type: Option<&'static str>,
    aggregate_samples: Option<&'static str>,
    /// #1611 workstream B: a plain binary source keyed by sha256(filename)
    /// rather than the filename itself (cowrie_ttylog's own convention —
    /// its filenames already ARE a content hash, so using them directly as
    /// doc ids is safe; mailoney's saved .eml filenames carry no such
    /// guarantee, so the doc id needs deriving instead — see #1611's own
    /// text: "id = sha of path so re-scans are idempotent"). The document
    /// shape is also different (body_path/eml_base64, not
    /// shasum/ttylog_base64) — see scan_source's binary branch.
    mailoney_mail: bool,
}

const fn source(env: &'static str, label: &'static str, index: &'static str, glob: &'static str) -> Source {
    Source {
        env,
        label,
        index,
        id_fields: &[],
        glob,
        skip: &[],
        binary: false,
        chunked: false,
        id_suffix: None,
        artifact_kind: None,
        content_type: None,
        aggregate_samples: None,
        mailoney_mail: false,
    }
}

/// The full source table: importer.py's 14 explicit entries, plus its
/// generated 9 (3 sandbox backends x 3 export-artifact kinds) chunked
/// sandbox-export sources. Call this once (es_importer_loop does, at
/// startup) and reuse the result — the 9 generated entries each Box::leak
/// their formatted glob string to get a `&'static str`, a one-time,
/// bounded, intentional leak for effectively-static data; calling this
/// repeatedly (e.g. once per tick) would leak on every call instead.
fn sources() -> Vec<Source> {
    let mut list = vec![
        Source { id_fields: &["sha256"], ..source("GHIDRA_RESULTS_DIR", "ghidra", "ghidra-analysis-v1", "*_ghidra.json") },
        Source {
            binary: true,
            id_suffix: Some("_ghidra_report.html"),
            artifact_kind: Some("report"),
            content_type: Some("text/html"),
            ..source("GHIDRA_RESULTS_DIR", "ghidra_report_html", "ghidra-report-artifacts-v1", "*_ghidra_report.html")
        },
        Source {
            binary: true,
            id_suffix: Some("_callgraph.svg"),
            artifact_kind: Some("callgraph"),
            content_type: Some("image/svg+xml"),
            ..source("GHIDRA_RESULTS_DIR", "ghidra_callgraph_svg", "ghidra-report-artifacts-v1", "*_callgraph.svg")
        },
        Source {
            id_fields: &["job", "sha256"],
            skip: &["status.json"],
            ..source("SANDBOX_RESULTS_DIR", "sandbox", "sandbox-analysis-v1", "*.json")
        },
        Source {
            id_fields: &["job", "sha256"],
            skip: &["status.json"],
            ..source("WINDOWS_SANDBOX_RESULTS_DIR", "sandbox", "sandbox-analysis-v1", "*.json")
        },
        Source {
            id_fields: &["job", "sha256"],
            skip: &["status.json"],
            ..source("GHOSTS_SANDBOX_RESULTS_DIR", "sandbox", "sandbox-analysis-v1", "*.json")
        },
        Source {
            id_fields: &["sha256"],
            skip: &["status.json"],
            ..source("GITHUB_ANALYSIS_RESULTS_DIR", "github_analysis", "github-analysis-v1", "*.json")
        },
        Source { id_fields: &["sha256"], ..source("REVDECK_RESULTS_DIR", "revdeck", "revdeck-analysis-v1", "*_revdeck.json") },
        Source {
            id_fields: &["sha256"],
            skip: &["status.json"],
            ..source("CAPE_RESULTS_DIR", "cape", "cape-analysis-v1", "*_cape.json")
        },
        Source { binary: true, ..source("COWRIE_TTYLOG_DIR", "cowrie_ttylog", "cowrie-ttylog-v1", "*") },
        // #1611 workstream B: mailoney's full .eml bodies — the ES event
        // document's own "mail-body" line carries session_id AND body_path
        // as sibling fields (mailoney/json_log_patch.py's _emit_json_event
        // call), but body_path is a relative filename this worker resolves
        // to actual bytes, not something derivable from the filename alone
        // (mailoney's upstream mail_storage.py, not vendored in this repo,
        // owns the naming — unverified against a real saved filename).
        // src/mail.rs's GET /api/v1/mail/{session_id} does the two-step
        // join: honeypot-v2-* for session_id -> body_path, then this index
        // for body_path -> content. Flat directory assumed (this importer
        // has no subdirectory recursion anywhere) — if mail_storage.py
        // nests files under a subdirectory this won't find them; worth
        // confirming against a real deployment.
        Source { binary: true, mailoney_mail: true, ..source("MAILONEY_MAIL_DIR", "mailoney_mail", "mailoney-mail-v1", "*") },
        Source { id_fields: &[], ..source("REPORTER_METRICS_DIR", "reporter_metrics", "reporter-metrics-v1", "metrics.json") },
        Source {
            aggregate_samples: Some("samples"),
            ..source("YARA_RESULTS_DIR", "yara", "yara-analysis-v1", "results.json")
        },
    ];

    const SANDBOX_ENVS: &[&str] = &["SANDBOX_RESULTS_DIR", "WINDOWS_SANDBOX_RESULTS_DIR", "GHOSTS_SANDBOX_RESULTS_DIR"];
    const EXPORT_KINDS: &[(&str, &str, &str)] = &[
        (".host.pcap", "host_pcap", "application/vnd.tcpdump.pcap"),
        (".guest.pcap", "guest_pcap", "application/vnd.tcpdump.pcap"),
        (".diagnostics.zip", "diagnostics", "application/zip"),
    ];
    for env in SANDBOX_ENVS {
        for (suffix, kind, content_type) in EXPORT_KINDS {
            list.push(Source {
                chunked: true,
                id_suffix: Some(suffix),
                artifact_kind: Some(kind),
                content_type: Some(content_type),
                glob: Box::leak(format!("*{suffix}").into_boxed_str()),
                ..source(env, "sandbox_export", "sandbox-export-artifacts-v1", "")
            });
        }
    }
    list
}

/// importer.py's glob patterns are all either "*" (match everything),
/// "*<suffix>" (suffix match), or an exact filename — no other glob syntax
/// appears anywhere in SOURCES, so a full glob crate would be overkill.
fn glob_matches(pattern: &str, filename: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return filename.ends_with(suffix);
    }
    filename == pattern
}

fn owns(path: &Path, shard_count: u64, shard_index: u64) -> bool {
    if shard_count <= 1 {
        return true;
    }
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(path.to_string_lossy().as_bytes());
    // Python: int(hexdigest, 16) % SHARD_COUNT — the full 256-bit digest
    // mod a small integer only needs the digest's low bytes; take it as a
    // big-endian number mod shard_count via repeated remainder folding,
    // exactly reproducing Python's arbitrary-precision `%`.
    let mut remainder: u64 = 0;
    for byte in digest.iter() {
        remainder = (remainder * 256 + *byte as u64) % shard_count;
    }
    remainder == shard_index
}

fn shard_index_default() -> u64 {
    let hostname = env_or("HOSTNAME", "");
    if let Some(dash) = hostname.rfind('-') {
        if let Ok(n) = hostname[dash + 1..].parse::<u64>() {
            return n;
        }
    }
    0
}

/// Mirrors importer.py's doc_id(): `value = payload.get(field); if value:
/// ...` — any Python-truthy scalar (a non-empty string, a nonzero number,
/// `true`) is coerced into the id, not just JSON strings. A numeric
/// id_field value (e.g. {"sha256": 12345}) must produce the same id here
/// as it does there, or the two importers mint different doc ids for the
/// same file.
fn first_present(payload: &Value, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| match payload.get(*field) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Number(n)) if n.as_f64() != Some(0.0) => Some(n.to_string()),
        Some(Value::Bool(true)) => Some("True".to_string()),
        _ => None,
    })
}

fn doc_id(source: &Source, payload: &Value, path: &Path) -> String {
    if let Some(value) = first_present(payload, source.id_fields) {
        return format!("{}:{value}", source.label);
    }
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
    format!("{}:{stem}", source.label)
}

/// Field-presence helper mirroring Python's `a or b or c` truthy-chain:
/// an empty string is not "present" and falls through to the next field,
/// same as first_present() above but for a plain string (not a doc-id).
fn first_non_empty_str<'a>(payload: &'a Value, fields: &[&str]) -> Option<&'a str> {
    fields.iter().find_map(|field| payload[*field].as_str().filter(|v| !v.is_empty()))
}

fn build_document(source: &Source, payload: &Value) -> Value {
    let mut doc = json!({
        source.label: payload,
        "event": {"category": source.label},
    });
    if let Some(ts) = first_non_empty_str(payload, &["completed_at", "updated_at", "requested_at"]) {
        doc["@timestamp"] = json!(ts);
    }
    if let Some(sha256) = first_non_empty_str(payload, &["sha256", "payload_sha256"]) {
        doc["file"] = json!({"hash": {"sha256": sha256}});
    }
    for field in ["exit_status", "risk_level", "risk_score", "family", "platform"] {
        if !payload[field].is_null() && payload[field] != json!("") {
            doc[field] = payload[field].clone();
        }
    }
    if source.label == "sandbox" {
        if let Some(family) = payload["classification"]["family"].as_str() {
            doc["family"] = json!(family);
        }
    }
    if source.label == "github_analysis" {
        if let Some(level) = payload["verdict"]["level"].as_str() {
            doc["risk_level"] = json!(level);
        }
    }
    doc
}

/// One pending bulk-index operation plus the dedup-state key/mtime it's
/// associated with — several actions can share one (key, mtime) pair
/// (chunked artifacts, aggregate_samples fan-out), matching importer.py's
/// (key, mtime, action) triples.
struct Pending {
    key: String,
    mtime: f64,
    index: &'static str,
    id: String,
    doc: Value,
}

const MAX_TTYLOG_BYTES: u64 = 20 * 1024 * 1024;
const CHUNK_BYTES: usize = 8 * 1024 * 1024;
const MAX_CHUNKED_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

fn mtime_secs(metadata: &fs::Metadata) -> f64 {
    metadata.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// Ports scan_source: walks root for files matching source.glob, skips
/// unchanged (state[key] == mtime) and unowned (sharding) files, and
/// returns pending bulk operations for the rest. Deliberately does not
/// touch `state` itself — the caller only records a file as imported once
/// the bulk write actually confirms it, so a transient ES error retries
/// next pass instead of being silently swallowed.
fn scan_source(source: &Source, root: &Path, state: &HashMap<String, f64>, shard_count: u64, shard_index: u64) -> Vec<Pending> {
    let mut pending = Vec::new();
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return pending,
    };
    let mut paths: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    paths.sort();

    for path in paths {
        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else { continue };
        if !path.is_file() || !glob_matches(source.glob, filename) || source.skip.contains(&filename) {
            continue;
        }
        if !owns(&path, shard_count, shard_index) {
            continue;
        }
        let key = path.to_string_lossy().to_string();
        let Ok(metadata) = path.metadata() else { continue };
        let mtime = mtime_secs(&metadata);
        if state.get(&key).is_some_and(|&m| m == mtime) {
            continue;
        }

        if let Some(samples_key) = source.aggregate_samples {
            let Ok(text) = fs::read_to_string(&path) else { continue };
            let Ok(payload) = serde_json::from_str::<Value>(&text) else {
                tracing::warn!(source = source.label, path = %path.display(), "skipping unreadable file");
                continue;
            };
            let updated_at = payload["updated_at"].clone();
            let mut report_context = payload.clone();
            if let Some(obj) = report_context.as_object_mut() {
                obj.remove(samples_key);
            }
            if let Some(samples) = payload[samples_key].as_object() {
                for (sample_id, sample) in samples {
                    if !sample.is_object() {
                        continue;
                    }
                    let sha256 = sample["sha256"].as_str().unwrap_or(sample_id).to_string();
                    let mut sample_doc = sample.clone();
                    sample_doc["report_updated_at"] = updated_at.clone();
                    let doc = json!({
                        source.label: sample_doc,
                        "report": report_context,
                        "event": {"category": source.label},
                        "@timestamp": updated_at,
                        "file": {"hash": {"sha256": sha256}},
                    });
                    pending.push(Pending { key: key.clone(), mtime, index: source.index, id: format!("{}:{sample_id}", source.label), doc });
                }
            }
            continue;
        }

        if source.chunked {
            let size = metadata.len();
            if size == 0 {
                continue;
            }
            if size > MAX_CHUNKED_ARTIFACT_BYTES {
                tracing::warn!(source = source.label, path = %path.display(), size, "skipping oversized chunked artifact");
                continue;
            }
            let Ok(data) = fs::read(&path) else {
                tracing::warn!(source = source.label, path = %path.display(), "skipping unreadable file");
                continue;
            };
            let suffix = source.id_suffix.unwrap_or("");
            let job = filename.strip_suffix(suffix).unwrap_or(filename).to_string();
            let kind = source.artifact_kind.unwrap_or("");
            let total_chunks = data.len().div_ceil(CHUNK_BYTES).max(1);
            let now = chrono::Utc::now().to_rfc3339();
            for index in 0..total_chunks {
                let start = index * CHUNK_BYTES;
                let end = (start + CHUNK_BYTES).min(data.len());
                let chunk = &data[start..end];
                let doc = json!({
                    "job": job,
                    "kind": kind,
                    "filename": filename,
                    "content_type": source.content_type,
                    "chunk_index": index,
                    "total_chunks": total_chunks,
                    "size_bytes": data.len(),
                    "imported_at": now,
                    "data_base64": base64::engine::general_purpose::STANDARD.encode(chunk),
                });
                pending.push(Pending { key: key.clone(), mtime, index: source.index, id: format!("{job}:{kind}:{index}"), doc });
            }
            continue;
        }

        if source.binary {
            let size = metadata.len();
            if size > MAX_TTYLOG_BYTES {
                tracing::warn!(source = source.label, path = %path.display(), size, "skipping oversized binary file");
                continue;
            }
            let Ok(raw) = fs::read(&path) else {
                tracing::warn!(source = source.label, path = %path.display(), "skipping unreadable file");
                continue;
            };
            let now = chrono::Utc::now().to_rfc3339();
            let (id, doc) = if let Some(suffix) = source.id_suffix {
                let sha256 = filename.strip_suffix(suffix).unwrap_or(filename).to_string();
                let kind = source.artifact_kind.unwrap_or("");
                (
                    format!("{sha256}:{kind}"),
                    json!({
                        "sha256": sha256,
                        "kind": kind,
                        "filename": filename,
                        "content_type": source.content_type,
                        "size_bytes": raw.len(),
                        "imported_at": now,
                        "data_base64": base64::engine::general_purpose::STANDARD.encode(&raw),
                    }),
                )
            } else if source.mailoney_mail {
                // #1611 workstream B: doc id is sha256(filename), not the
                // filename itself — unlike cowrie's ttylog names, mailoney's
                // saved filenames carry no content-hash guarantee, so the
                // path is what needs hashing for a stable, idempotent id.
                use sha2::{Digest, Sha256};
                let digest = Sha256::digest(filename.as_bytes());
                let id_hash: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                (
                    id_hash,
                    json!({
                        "body_path": filename,
                        "size_bytes": raw.len(),
                        "imported_at": now,
                        "eml_base64": base64::engine::general_purpose::STANDARD.encode(&raw),
                    }),
                )
            } else {
                (
                    filename.to_string(),
                    json!({
                        "shasum": filename,
                        "size_bytes": raw.len(),
                        "imported_at": now,
                        "ttylog_base64": base64::engine::general_purpose::STANDARD.encode(&raw),
                    }),
                )
            };
            pending.push(Pending { key: key.clone(), mtime, index: source.index, id, doc });
            continue;
        }

        let Ok(text) = fs::read_to_string(&path) else {
            tracing::warn!(source = source.label, path = %path.display(), "skipping unreadable file");
            continue;
        };
        let Ok(payload) = serde_json::from_str::<Value>(&text) else {
            tracing::warn!(source = source.label, path = %path.display(), "skipping unreadable file");
            continue;
        };
        let id = doc_id(source, &payload, &path);
        let doc = build_document(source, &payload);
        pending.push(Pending { key, mtime, index: source.index, id, doc });
    }
    pending
}

/// Only advance state[key] for keys whose every pending action succeeded —
/// a chunked/aggregate file's multiple actions share one key, so advancing
/// on the first success (rather than requiring all of them) risks marking
/// the whole file imported while an earlier action actually failed, which
/// would then never be retried (its mtime wouldn't change again).
fn advance_state_after_bulk(pending: &[Pending], failed_ids: &std::collections::HashSet<String>, state: &mut HashMap<String, f64>) {
    let failed_keys: std::collections::HashSet<&str> =
        pending.iter().filter(|p| failed_ids.contains(&p.id)).map(|p| p.key.as_str()).collect();
    for p in pending {
        if !failed_keys.contains(p.key.as_str()) {
            state.insert(p.key.clone(), p.mtime);
        }
    }
}

async fn run_pass(state: &AppState, sources: &[Source], dedup: &mut HashMap<String, f64>, shard_count: u64, shard_index: u64) -> u64 {
    let mut total = 0u64;
    for &source in sources {
        let root = env_or(source.env, "");
        if root.is_empty() {
            continue;
        }
        let root_path = PathBuf::from(&root);
        if !root_path.is_dir() {
            continue;
        }
        let label = source.label;
        let dedup_snapshot = dedup.clone();
        let pending = tokio::task::spawn_blocking({
            let root_path = root_path.clone();
            move || scan_source(&source, &root_path, &dedup_snapshot, shard_count, shard_index)
        })
        .await
        .unwrap_or_default();
        if pending.is_empty() {
            continue;
        }
        let ops: Vec<(&str, &str, Value)> = pending.iter().map(|p| (p.index, p.id.as_str(), p.doc.clone())).collect();
        let failed = match state.es.bulk_index(ops).await {
            Ok(f) => f,
            Err(error) => {
                tracing::warn!(source = label, %error, "bulk index request failed, will retry next pass");
                continue;
            }
        };
        if !failed.is_empty() {
            tracing::warn!(source = label, count = failed.len(), "document(s) failed to index, will retry next pass");
        }
        let indexed = pending.len() as u64 - failed.len() as u64;
        advance_state_after_bulk(&pending, &failed, dedup);
        total += indexed;
        if indexed > 0 {
            tracing::info!(source = label, indexed, "es-results-importer: indexed document(s)");
        }
    }
    total
}

fn load_state(path: &Path) -> HashMap<String, f64> {
    fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

fn save_state(path: &Path, state: &HashMap<String, f64>) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(body) = serde_json::to_string(state) {
        let tmp = path.with_extension("tmp");
        if fs::write(&tmp, body).is_ok() {
            let _ = fs::rename(&tmp, path);
        }
    }
}

pub async fn es_importer_loop(state: AppState) {
    let interval = Duration::from_secs(env_u64("IMPORT_INTERVAL", 300));
    let state_path = PathBuf::from(env_or("IMPORTER_STATE", "/state-importer/es-results-importer.json"));
    let shard_count = env_u64("SHARD_COUNT", 1).max(1);
    let shard_index = std::env::var("SHARD_INDEX").ok().and_then(|v| v.parse().ok()).unwrap_or_else(shard_index_default) % shard_count;

    tracing::info!(shard_index, shard_count, "es-results-importer starting");
    let all_sources = sources();
    let mut dedup = load_state(&state_path);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let indexed = run_pass(&state, &all_sources, &mut dedup, shard_count, shard_index).await;
        if indexed > 0 {
            save_state(&state_path, &dedup);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(key: &str, id: &str) -> Pending {
        Pending { key: key.to_string(), mtime: 1.0, index: "test-v1", id: id.to_string(), doc: json!({}) }
    }

    #[test]
    fn advance_state_skips_a_key_with_any_failed_action() {
        let items = vec![pending("chunked-file", "job:kind:0"), pending("chunked-file", "job:kind:1"), pending("chunked-file", "job:kind:2")];
        let mut failed = std::collections::HashSet::new();
        failed.insert("job:kind:1".to_string());
        let mut state = HashMap::new();
        advance_state_after_bulk(&items, &failed, &mut state);
        assert!(!state.contains_key("chunked-file"), "a partially-failed key must not advance");
    }

    #[test]
    fn advance_state_advances_a_fully_succeeded_key() {
        let items = vec![pending("plain-file", "ghidra:abc123")];
        let failed = std::collections::HashSet::new();
        let mut state = HashMap::new();
        advance_state_after_bulk(&items, &failed, &mut state);
        assert_eq!(state.get("plain-file"), Some(&1.0));
    }

    #[test]
    fn advance_state_leaves_unrelated_keys_advancing_independently() {
        let items = vec![pending("ok-file", "a:1"), pending("bad-file", "b:2")];
        let mut failed = std::collections::HashSet::new();
        failed.insert("b:2".to_string());
        let mut state = HashMap::new();
        advance_state_after_bulk(&items, &failed, &mut state);
        assert!(state.contains_key("ok-file"));
        assert!(!state.contains_key("bad-file"));
    }

    #[test]
    fn glob_matches_star_suffix_and_exact() {
        assert!(glob_matches("*", "anything"));
        assert!(glob_matches("*_ghidra.json", "abc_ghidra.json"));
        assert!(!glob_matches("*_ghidra.json", "abc_ghidra.json.bak"));
        assert!(glob_matches("metrics.json", "metrics.json"));
        assert!(!glob_matches("metrics.json", "metrics.json.bak"));
    }

    #[test]
    fn doc_id_falls_back_to_filename_stem() {
        let src = Source { id_fields: &["sha256"], ..source("X", "label", "idx", "*") };
        let id = doc_id(&src, &json!({}), Path::new("/tmp/somefile.json"));
        assert_eq!(id, "label:somefile");
    }

    #[test]
    fn doc_id_prefers_first_present_id_field() {
        let src = Source { id_fields: &["job", "sha256"], ..source("X", "sandbox", "idx", "*") };
        let id = doc_id(&src, &json!({"sha256": "deadbeef"}), Path::new("/tmp/x.json"));
        assert_eq!(id, "sandbox:deadbeef");
    }

    #[test]
    fn doc_id_coerces_a_numeric_id_field_same_as_importer_py() {
        // importer.py's doc_id() does `if value:` (any Python-truthy scalar),
        // not a string-type check — a numeric job id must still produce an id.
        let src = Source { id_fields: &["job"], ..source("X", "sandbox", "idx", "*") };
        let id = doc_id(&src, &json!({"job": 12345}), Path::new("/tmp/x.json"));
        assert_eq!(id, "sandbox:12345");
    }

    #[test]
    fn doc_id_treats_a_zero_id_field_as_falsy_same_as_python() {
        let src = Source { id_fields: &["job", "sha256"], ..source("X", "sandbox", "idx", "*") };
        let id = doc_id(&src, &json!({"job": 0, "sha256": "deadbeef"}), Path::new("/tmp/x.json"));
        assert_eq!(id, "sandbox:deadbeef");
    }

    #[test]
    fn build_document_timestamp_falls_through_an_empty_leading_field() {
        // Python's `a or b or c` treats "" as falsy and moves to the next
        // field; a naive Option::or_else on .as_str() does not, since
        // Some("") is still Some.
        let payload = json!({"completed_at": "", "updated_at": "2026-01-01T00:00:00Z"});
        let doc = build_document(&Source { id_fields: &[], ..source("X", "label", "idx", "*") }, &payload);
        assert_eq!(doc["@timestamp"], "2026-01-01T00:00:00Z");
    }

    #[test]
    fn build_document_sha256_falls_through_an_empty_leading_field() {
        let payload = json!({"sha256": "", "payload_sha256": "deadbeef"});
        let doc = build_document(&Source { id_fields: &[], ..source("X", "label", "idx", "*") }, &payload);
        assert_eq!(doc["file"]["hash"]["sha256"], "deadbeef");
    }
}
