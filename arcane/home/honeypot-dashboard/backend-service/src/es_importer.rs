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
use std::io::Read;
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
    /// #1696: only accept filenames matching this shape. cowrie_ttylog's
    /// whole contract is "the filename already IS the content hash", but that
    /// only becomes true when cowrie closes the session and renames the file.
    /// While a session is live the file is called
    /// `YYYYMMDD-HHMMSS-<session>-<pid>i.log`, and an importer pass that
    /// lands in that window indexed it under that temporary name — creating a
    /// truncated phantom document, keyed by a string that is not a hash of
    /// anything, that no later pass ever cleans up. 3,521 of 3,713 documents
    /// in the index were such phantoms when this was found. Requiring the
    /// hash shape makes the contract enforced rather than assumed.
    content_hash_names: bool,
    /// #1611 workstream B: a plain binary source keyed by sha256(filename)
    /// rather than the filename itself (cowrie_ttylog's own convention —
    /// its filenames already ARE a content hash, so using them directly as
    /// doc ids is safe; mailoney's saved .eml filenames carry no such
    /// guarantee, so the doc id needs deriving instead — see #1611's own
    /// text: "id = sha of path so re-scans are idempotent"). The document
    /// shape is also different (body_path/eml_base64, not
    /// shasum/ttylog_base64) — see scan_source's binary branch.
    mailoney_mail: bool,
    /// Walk subdirectories instead of only the root.
    ///
    /// Every other source writes into a flat directory, and the scan was
    /// written to match. mailoney does not: its mail_storage.py files land
    /// under `<date>/<relay-ip>/<session>.eml`, so a root-only scan saw
    /// three date directories, matched no files, and created no index --
    /// which is why every captured message 404'd at
    /// GET /api/v1/mail/{session_id} with "mail body not yet imported"
    /// while 24 .eml files sat on disk (#1856). The original source's own
    /// comment flagged this as unverified against a real deployment; it is
    /// verified now, and it nests.
    recursive: bool,
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
        content_hash_names: false,
        id_suffix: None,
        artifact_kind: None,
        content_type: None,
        aggregate_samples: None,
        mailoney_mail: false,
        recursive: false,
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
        Source {
            binary: true,
            content_hash_names: true,
            ..source("COWRIE_TTYLOG_DIR", "cowrie_ttylog", "cowrie-ttylog-v1", "*")
        },
        // #1611 workstream B: mailoney's full .eml bodies — the ES event
        // document's own "mail-body" line carries session_id AND body_path
        // as sibling fields (mailoney/json_log_patch.py's _emit_json_event
        // call), but body_path is a relative path this worker resolves to
        // actual bytes. src/mail.rs's GET /api/v1/mail/{session_id} does
        // the two-step join: honeypot-v2-* for session_id -> body_path,
        // then this index for body_path -> content.
        //
        // #1856: the original entry assumed a flat directory and its own
        // comment said so was unverified. It is verified now, and it is
        // wrong: mail_storage.py writes `<date>/<relay-ip>/<session>.eml`,
        // so the root-only scan matched nothing, the index was never
        // created, and every captured message 404'd while the files sat on
        // disk. `recursive` walks the tree, and the join key is the path
        // relative to the root — which is exactly the string the sensor
        // writes into honeypot.body_path, so the two sides now agree.
        Source {
            binary: true,
            mailoney_mail: true,
            recursive: true,
            ..source("MAILONEY_MAIL_DIR", "mailoney_mail", "mailoney-mail-v1", "*")
        },
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
/// #1696: a lowercase 64-character hex string, i.e. a rendered sha256 and
/// nothing else. Deliberately strict — cowrie's in-progress ttylog names
/// (`20260811-170124-None-48166i.log`) must not pass, and neither should any
/// other transient the sensor happens to leave in that directory.
fn is_content_hash_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// How deep a `recursive` source is allowed to walk.
///
/// mailoney needs two levels (`<date>/<relay-ip>/`). The bound exists so a
/// symlink loop or an unexpected tree in a sensor volume cannot turn one
/// importer pass into an unbounded walk — the scan runs on a timer against
/// directories the honeypot writes, which is exactly where a surprise
/// directory shape shows up.
const MAX_SCAN_DEPTH: usize = 4;

/// Every file at or below `root`, sorted, bounded by `MAX_SCAN_DEPTH`.
/// A non-recursive source stops at the root, which is what every source
/// other than mailoney_mail wants.
fn walk_files(root: &Path, recursive: bool, depth: usize) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(root) else { return files };
    let mut paths: Vec<PathBuf> = entries.filter_map(|entry| entry.ok()).map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            if recursive && depth + 1 < MAX_SCAN_DEPTH {
                files.extend(walk_files(&path, recursive, depth + 1));
            }
            continue;
        }
        files.push(path);
    }
    files
}

/// Rough resident size of a base64-encoded payload held as a JSON string —
/// 4 chars per 3 bytes. Exact for STANDARD (no line wrapping); used only
/// for #1978's pending-byte budget, where a constant-factor nudge is noise.
fn encoded_estimate(bytes: usize) -> usize {
    bytes.div_ceil(3).max(1) * 4
}

/// #1978: how much bulk payload one scan pass may hold resident before
/// further files are deferred to the next pass. mtime dedup makes deferral
/// free — an unclaimed file's key was never recorded, so it retries whole
/// next pass. 0 disables the cap. Defaults above any single guarded file
/// (chunked artifacts cap at MAX_CHUNKED_ARTIFACT_BYTES ≈ 341 MB encoded,
/// ttylogs at ~27 MB), so the budget only ever trims *aggregates* of large
/// artifacts landing in one pass, never one file by itself.
const DEFAULT_MAX_PENDING_BYTES: u64 = 512 * 1024 * 1024;

fn max_pending_bytes_from_env() -> u64 {
    env_u64("IMPORTER_MAX_PENDING_BYTES", DEFAULT_MAX_PENDING_BYTES)
}

fn scan_source(
    source: &Source,
    root: &Path,
    state: &HashMap<String, f64>,
    shard_count: u64,
    shard_index: u64,
    max_pending_bytes: u64,
) -> Vec<Pending> {
    let mut pending = Vec::new();
    let mut pending_bytes = 0usize;
    let paths = walk_files(root, source.recursive, 0);

    'file_pass: for path in paths {
        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else { continue };
        // The join key for a nested source is the path relative to the
        // root, because that is the string the sensor itself records.
        let relative = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().to_string();
        if !path.is_file() || !glob_matches(source.glob, filename) || source.skip.contains(&filename) {
            continue;
        }
        // #1696: a source whose ids are content hashes must not index a file
        // that has not been given its hash name yet — see Source's own field.
        if source.content_hash_names && !is_content_hash_name(filename) {
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

        // #1978: claimed-before-budget means a single oversized file still
        // goes through (the per-source byte guards bound it); the cap only
        // stops further files from piling onto an already-heavy pass.
        if max_pending_bytes > 0 && pending_bytes >= max_pending_bytes as usize {
            tracing::info!(
                source = source.label,
                path = %path.display(),
                budget = max_pending_bytes,
                "deferring file past the pending-byte budget to the next pass"
            );
            continue;
        }

        if let Some(samples_key) = source.aggregate_samples {
            let Ok(text) = fs::read_to_string(&path) else { continue };
            pending_bytes += text.len();
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
            // #1978: chunking exists to keep residency bounded, so the file
            // itself must never be buffered — one CHUNK_BYTES window is read
            // at a time and encoded straight into its own document. A short
            // read means the writer shrank or replaced the file mid-scan;
            // none of its chunks may be indexed (a partial set reassembles
            // into corrupt content client-side), and its dedup state was
            // never recorded, so a later pass retries the file whole.
            let suffix = source.id_suffix.unwrap_or("");
            let job = filename.strip_suffix(suffix).unwrap_or(filename).to_string();
            let kind = source.artifact_kind.unwrap_or("");
            let expected_bytes = size as usize;
            let total_chunks = expected_bytes.div_ceil(CHUNK_BYTES).max(1);
            let now = chrono::Utc::now().to_rfc3339();
            let Ok(mut file) = fs::File::open(&path) else {
                tracing::warn!(source = source.label, path = %path.display(), "skipping unreadable file");
                continue 'file_pass;
            };
            let mut buffer = vec![0u8; CHUNK_BYTES];
            // Collected separately so an aborted read drops only this
            // file's documents, whatever earlier artifacts already put in
            // `pending`.
            let mut file_pendings = Vec::with_capacity(total_chunks);
            let mut truncated = false;
            for index in 0..total_chunks {
                let expected_chunk = (expected_bytes - index * CHUNK_BYTES).min(CHUNK_BYTES);
                let mut filled = 0usize;
                while filled < expected_chunk {
                    match file.read(&mut buffer[filled..expected_chunk]) {
                        Ok(0) => break,
                        Ok(n) => filled += n,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => {
                            truncated = true;
                            break;
                        }
                    }
                }
                if filled != expected_chunk {
                    truncated = true;
                    break;
                }
                let doc = json!({
                    "job": job,
                    "kind": kind,
                    "filename": filename,
                    "content_type": source.content_type,
                    "chunk_index": index,
                    "total_chunks": total_chunks,
                    "size_bytes": expected_bytes,
                    "imported_at": now,
                    "data_base64": base64::engine::general_purpose::STANDARD.encode(&buffer[..filled]),
                });
                file_pendings.push(Pending { key: key.clone(), mtime, index: source.index, id: format!("{job}:{kind}:{index}"), doc });
            }
            if truncated {
                tracing::warn!(source = source.label, path = %path.display(), "artifact shrank mid-scan, will retry next pass");
                continue 'file_pass;
            }
            // #1978: count the encoded chunks, not the raw file — they are
            // what actually sits in memory until the bulk fires.
            pending_bytes += encoded_estimate(expected_bytes);
            pending.append(&mut file_pendings);
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
            // #1978: the encoded ttylog/report string is the resident cost.
            pending_bytes += encoded_estimate(raw.len());
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
                // #1611 workstream B: doc id is sha256(path), not the path
                // itself — unlike cowrie's ttylog names, mailoney's saved
                // filenames carry no content-hash guarantee, so the path is
                // what needs hashing for a stable, idempotent id.
                //
                // #1856: that path is the one relative to the source root,
                // not the bare filename. mailoney writes
                // `<date>/<relay-ip>/<session>.eml` into honeypot.body_path,
                // so hashing the basename produced an id and a body_path
                // that mail.rs could never match even once the file was
                // found.
                use sha2::{Digest, Sha256};
                let digest = Sha256::digest(relative.as_bytes());
                let id_hash: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                (
                    id_hash,
                    json!({
                        "body_path": relative,
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

// #1716: the per-recording attribution join that lived here is gone.
//
// It denormalized src_ip/country/session onto each `cowrie-ttylog-v1`
// document so the recordings list could render them without a per-row
// lookup. That list now pages over `cowrie.log.closed` events instead, one
// row per session, because the ttylog index is content-addressed and cannot
// answer "who ran this" for a document that thousands of different sessions
// produced (#1716). Nothing reads those fields any more, so computing them
// on every import was two Elasticsearch queries per batch for dead data.
//
// The documents already written keep their fields; they are simply ignored.

async fn run_pass(state: &AppState, sources: &[Source], dedup: &mut HashMap<String, f64>, shard_count: u64, shard_index: u64, max_pending_bytes: u64) -> u64 {
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
            move || scan_source(&source, &root_path, &dedup_snapshot, shard_count, shard_index, max_pending_bytes)
        })
        .await
        .unwrap_or_default();
        if pending.is_empty() {
            continue;
        }
        // #1978: borrow the documents instead of cloning every Value — a
        // full pass of large artifacts used to be duplicated wholesale for
        // one serialization call.
        let ops: Vec<(&str, &str, &Value)> = pending.iter().map(|p| (p.index, p.id.as_str(), &p.doc)).collect();
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
    let max_pending_bytes = max_pending_bytes_from_env();
    let shard_count = env_u64("SHARD_COUNT", 1).max(1);
    let shard_index = std::env::var("SHARD_INDEX").ok().and_then(|v| v.parse().ok()).unwrap_or_else(shard_index_default) % shard_count;

    tracing::info!(shard_index, shard_count, "es-results-importer starting");
    let all_sources = sources();
    let mut dedup = load_state(&state_path);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        // #2181: scan_source already isolates per source (spawn_blocking +
        // JoinHandle default), so this boundary covers everything around it
        // — the bulk-index phase and the in-memory dedup updates. A panicked
        // pass loses only progress since the last save; documents are keyed
        // by stable ids and re-import overwrites rather than duplicates.
        let indexed = crate::isolate::cycle(
            "es-results-importer",
            run_pass(&state, &all_sources, &mut dedup, shard_count, shard_index, max_pending_bytes),
        )
        .await
        .unwrap_or(0);
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

    /// A scratch directory scan_source() can read real files from — each
    /// test picks a distinct `name` (cargo test runs all tests in one
    /// process, parallel by default) and the directory is removed on drop,
    /// so a failed run doesn't leave stray fixtures behind either.
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("es_importer_test_{name}"));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            TmpDir(dir)
        }
        fn write(&self, filename: &str, contents: &[u8]) -> PathBuf {
            let path = self.0.join(filename);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&path, contents).unwrap();
            path
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn no_state() -> HashMap<String, f64> {
        HashMap::new()
    }

    #[test]
    fn scan_source_plain_json_computes_doc_id_and_document_from_the_file() {
        let dir = TmpDir::new("plain_json");
        dir.write("abc_ghidra.json", br#"{"sha256": "abc", "completed_at": "2026-01-01T00:00:00Z"}"#);
        let src = Source { id_fields: &["sha256"], ..source("X", "ghidra", "ghidra-analysis-v1", "*_ghidra.json") };
        let pending = scan_source(&src, &dir.0, &no_state(), 1, 0, u64::MAX);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "ghidra:abc");
        assert_eq!(pending[0].doc["@timestamp"], "2026-01-01T00:00:00Z");
        assert_eq!(pending[0].doc["ghidra"]["sha256"], "abc");
    }

    #[test]
    fn scan_source_skips_a_file_whose_mtime_is_already_in_state() {
        let dir = TmpDir::new("mtime_skip");
        let path = dir.write("abc_ghidra.json", br#"{"sha256": "abc"}"#);
        let mtime = mtime_secs(&fs::metadata(&path).unwrap());
        let src = Source { id_fields: &["sha256"], ..source("X", "ghidra", "ghidra-analysis-v1", "*_ghidra.json") };
        let mut state = no_state();
        state.insert(path.to_string_lossy().to_string(), mtime);
        assert!(scan_source(&src, &dir.0, &state, 1, 0, u64::MAX).is_empty());
    }

    #[test]
    fn scan_source_binary_ttylog_encodes_the_whole_file_as_base64() {
        let dir = TmpDir::new("binary_ttylog");
        dir.write("deadbeef", b"raw ttylog bytes");
        let src = Source { binary: true, ..source("X", "cowrie_ttylog", "cowrie-ttylog-v1", "*") };
        let pending = scan_source(&src, &dir.0, &no_state(), 1, 0, u64::MAX);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "deadbeef");
        assert_eq!(pending[0].doc["shasum"], "deadbeef");
        assert_eq!(pending[0].doc["ttylog_base64"], base64::engine::general_purpose::STANDARD.encode(b"raw ttylog bytes"));
    }

    #[test]
    fn scan_source_content_hash_names_skips_cowries_in_progress_ttylog() {
        // #1696: cowrie names a live session's ttylog
        // YYYYMMDD-HHMMSS-<session>-<pid>i.log and only renames it to the
        // content hash on close. Indexing the former produced a truncated
        // phantom document keyed by a string that hashes nothing — 95% of the
        // index when this was found.
        let dir = TmpDir::new("ttylog_in_progress");
        let closed = "a".repeat(64);
        dir.write(&closed, b"finished recording");
        dir.write("20260811-170124-None-48166i.log", b"still being written");
        let src = Source {
            binary: true,
            content_hash_names: true,
            ..source("X", "cowrie_ttylog", "cowrie-ttylog-v1", "*")
        };
        let pending = scan_source(&src, &dir.0, &no_state(), 1, 0, u64::MAX);
        assert_eq!(pending.len(), 1, "only the renamed, closed recording is indexable");
        assert_eq!(pending[0].id, closed);
    }

    #[test]
    fn is_content_hash_name_accepts_only_lowercase_sha256() {
        assert!(is_content_hash_name(&"0".repeat(64)));
        assert!(is_content_hash_name(&"abcdef0123456789".repeat(4)));
        assert!(!is_content_hash_name(&"A".repeat(64)), "uppercase is not the rendered form");
        assert!(!is_content_hash_name(&"g".repeat(64)), "non-hex");
        assert!(!is_content_hash_name(&"a".repeat(63)), "too short");
        assert!(!is_content_hash_name(&"a".repeat(65)), "too long");
        assert!(!is_content_hash_name("20260811-170124-None-48166i.log"));
    }

    #[test]
    fn scan_source_binary_with_id_suffix_derives_sha256_and_kind_from_the_filename() {
        let dir = TmpDir::new("binary_report_html");
        dir.write("abc123_ghidra_report.html", b"<html></html>");
        let src = Source {
            binary: true,
            id_suffix: Some("_ghidra_report.html"),
            artifact_kind: Some("report"),
            content_type: Some("text/html"),
            ..source("X", "ghidra_report_html", "ghidra-report-artifacts-v1", "*_ghidra_report.html")
        };
        let pending = scan_source(&src, &dir.0, &no_state(), 1, 0, u64::MAX);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "abc123:report");
        assert_eq!(pending[0].doc["sha256"], "abc123");
        assert_eq!(pending[0].doc["kind"], "report");
        assert_eq!(pending[0].doc["content_type"], "text/html");
    }

    #[test]
    fn scan_source_mailoney_mail_ids_by_sha256_of_the_filename_not_the_filename_itself() {
        // #1611 workstream B: mailoney's saved filenames carry no
        // content-hash guarantee (unlike cowrie's ttylog names), so the
        // doc id has to be derived by hashing the filename.
        let dir = TmpDir::new("binary_mailoney");
        dir.write("some-saved-mail.eml", b"From: attacker@example.com\r\n\r\nbody");
        let src = Source { binary: true, mailoney_mail: true, ..source("X", "mailoney_mail", "mailoney-mail-v1", "*") };
        let pending = scan_source(&src, &dir.0, &no_state(), 1, 0, u64::MAX);
        assert_eq!(pending.len(), 1);
        let expected_id = {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"some-saved-mail.eml").iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        assert_eq!(pending[0].id, expected_id);
        assert_eq!(pending[0].doc["body_path"], "some-saved-mail.eml");
        assert!(pending[0].doc.get("eml_base64").is_some());
    }

    #[test]
    fn scan_source_ignores_subdirectories_unless_the_source_is_recursive() {
        // Every source but mailoney_mail writes flat, and a stray directory
        // in a sensor volume must not change what a flat source indexes.
        let dir = TmpDir::new("nested_non_recursive");
        dir.write("top.eml", b"top");
        dir.write("2026-08-24/nested.eml", b"nested");
        let src = Source { binary: true, mailoney_mail: true, ..source("X", "mailoney_mail", "mailoney-mail-v1", "*") };
        let pending = scan_source(&src, &dir.0, &no_state(), 1, 0, u64::MAX);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].doc["body_path"], "top.eml");
    }

    #[test]
    fn scan_source_recursive_mailoney_keys_by_the_path_the_sensor_records() {
        // #1856: mailoney writes `<date>/<relay-ip>/<session>.eml` and puts
        // that same relative path in the event's honeypot.body_path. The
        // root-only scan found no files at all, so the index never existed
        // and every message 404'd; keying by the basename would have found
        // the file and still never joined. Both halves are asserted here.
        let dir = TmpDir::new("nested_mailoney");
        dir.write("2026-08-24/10.8.0.1/ca6c3e0e.eml", b"From: attacker@example.com\r\n\r\nbody");
        let src = Source {
            binary: true,
            mailoney_mail: true,
            recursive: true,
            ..source("X", "mailoney_mail", "mailoney-mail-v1", "*")
        };
        let pending = scan_source(&src, &dir.0, &no_state(), 1, 0, u64::MAX);
        assert_eq!(pending.len(), 1);
        assert_eq!(
            pending[0].doc["body_path"], "2026-08-24/10.8.0.1/ca6c3e0e.eml",
            "the join key must be what the sensor writes, not the basename"
        );
        let expected_id = {
            use sha2::{Digest, Sha256};
            Sha256::digest(b"2026-08-24/10.8.0.1/ca6c3e0e.eml")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(pending[0].id, expected_id);
    }

    #[test]
    fn walk_files_stops_at_the_depth_bound() {
        let dir = TmpDir::new("walk_depth");
        dir.write("a/b/c/deep.eml", b"deep");
        dir.write("a/b/c/d/e/too-deep.eml", b"too deep");
        let found = walk_files(&dir.0, true, 0);
        let names: Vec<String> = found.iter().map(|p| p.to_string_lossy().to_string()).collect();
        assert!(names.iter().any(|n| n.ends_with("deep.eml")), "{names:?}");
        assert!(!names.iter().any(|n| n.ends_with("too-deep.eml")), "{names:?}");
    }

    #[test]
    fn scan_source_chunked_artifact_splits_into_one_chunk_when_under_the_size_cap() {
        let dir = TmpDir::new("chunked");
        dir.write("abc.host.pcap", b"small pcap bytes");
        let src = Source {
            chunked: true,
            id_suffix: Some(".host.pcap"),
            artifact_kind: Some("host_pcap"),
            content_type: Some("application/vnd.tcpdump.pcap"),
            ..source("X", "sandbox_export", "sandbox-export-artifacts-v1", "*.host.pcap")
        };
        let pending = scan_source(&src, &dir.0, &no_state(), 1, 0, u64::MAX);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, "abc:host_pcap:0");
        assert_eq!(pending[0].doc["job"], "abc");
        assert_eq!(pending[0].doc["kind"], "host_pcap");
        assert_eq!(pending[0].doc["chunk_index"], 0);
        assert_eq!(pending[0].doc["total_chunks"], 1);
        assert_eq!(
            pending[0].doc["data_base64"],
            base64::engine::general_purpose::STANDARD.encode(b"small pcap bytes"),
            "#1978: the streamed read must encode the same bytes the buffered read did"
        );
    }

    #[test]
    fn scan_source_defers_files_past_the_pending_byte_budget() {
        // #1978: once a pass's payload budget is spent, further files stay
        // unclaimed — their dedup keys never advance, so the next pass
        // retries them whole. A burst of large artifacts spreads across
        // passes instead of stacking into an OOM.
        let dir = TmpDir::new("budget_spill");
        dir.write("aaa.host.pcap", b"first artifact bytes");
        dir.write("bbb.host.pcap", b"second artifact bytes");
        let src = Source {
            chunked: true,
            id_suffix: Some(".host.pcap"),
            artifact_kind: Some("host_pcap"),
            content_type: Some("application/vnd.tcpdump.pcap"),
            ..source("X", "sandbox_export", "sandbox-export-artifacts-v1", "*.host.pcap")
        };
        // Enough budget for exactly the first file (walk order is
        // alphabetical): the second must be deferred.
        let first_bytes = b"first artifact bytes";
        let pending = scan_source(&src, &dir.0, &no_state(), 1, 0, encoded_estimate(first_bytes.len()) as u64);
        assert_eq!(pending.len(), 1);
        assert!(pending[0].id.starts_with("aaa:host_pcap"), "{}", pending[0].id);
    }

    #[test]
    fn scan_source_claims_a_file_even_when_it_alone_exceeds_the_budget() {
        // The cap trims aggregates, never single files — the per-source
        // byte guards bound one artifact by itself.
        let dir = TmpDir::new("budget_single");
        dir.write("aaa.host.pcap", b"bytes far beyond a one-byte budget");
        let src = Source {
            chunked: true,
            id_suffix: Some(".host.pcap"),
            artifact_kind: Some("host_pcap"),
            content_type: Some("application/vnd.tcpdump.pcap"),
            ..source("X", "sandbox_export", "sandbox-export-artifacts-v1", "*.host.pcap")
        };
        let pending = scan_source(&src, &dir.0, &no_state(), 1, 0, 1);
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn scan_source_zero_budget_disables_deferral() {
        let dir = TmpDir::new("budget_zero");
        dir.write("aaa.host.pcap", b"first");
        dir.write("bbb.host.pcap", b"second");
        let src = Source {
            chunked: true,
            id_suffix: Some(".host.pcap"),
            artifact_kind: Some("host_pcap"),
            content_type: Some("application/vnd.tcpdump.pcap"),
            ..source("X", "sandbox_export", "sandbox-export-artifacts-v1", "*.host.pcap")
        };
        let pending = scan_source(&src, &dir.0, &no_state(), 1, 0, 0);
        assert_eq!(pending.len(), 2);
    }

    #[test]
    fn scan_source_aggregate_samples_fans_out_one_pending_action_per_sample() {
        let dir = TmpDir::new("aggregate_samples");
        dir.write(
            "results.json",
            br#"{"updated_at": "2026-01-01T00:00:00Z", "samples": {"s1": {"sha256": "aaa", "match": "rule1"}, "s2": {"sha256": "bbb", "match": "rule2"}}}"#,
        );
        let src = Source { aggregate_samples: Some("samples"), ..source("X", "yara", "yara-analysis-v1", "results.json") };
        let mut pending = scan_source(&src, &dir.0, &no_state(), 1, 0, u64::MAX);
        pending.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].id, "yara:s1");
        assert_eq!(pending[0].doc["@timestamp"], "2026-01-01T00:00:00Z");
        assert_eq!(pending[0].doc["file"]["hash"]["sha256"], "aaa");
        assert_eq!(pending[0].doc["yara"]["match"], "rule1");
        // report_context carries the rest of the file minus the samples
        // key itself — every sample doc gets the same shared context.
        assert_eq!(pending[0].doc["report"]["updated_at"], "2026-01-01T00:00:00Z");
        assert!(pending[0].doc["report"].get("samples").is_none());
        assert_eq!(pending[1].id, "yara:s2");
    }

    #[test]
    fn scan_source_aggregate_samples_falls_back_to_the_map_key_when_a_sample_has_no_sha256() {
        let dir = TmpDir::new("aggregate_no_sha");
        dir.write("results.json", br#"{"samples": {"s1": {"match": "rule1"}}}"#);
        let src = Source { aggregate_samples: Some("samples"), ..source("X", "yara", "yara-analysis-v1", "results.json") };
        let pending = scan_source(&src, &dir.0, &no_state(), 1, 0, u64::MAX);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].doc["file"]["hash"]["sha256"], "s1");
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
