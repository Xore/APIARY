//! /api/v1/recordings/{shasum} — fetch one Cowrie ttylog from
//! cowrie-ttylog-v1 and decode its frame stream into a terminal
//! transcript. Frame layout matches Cowrie's playlog reader
//! (`<iLiiLL`, all little-endian): op i32, tty u32, length i32, dir i32,
//! sec u32, usec u32, then `length` bytes of data for OP_WRITE frames.
//! The transcript concatenates output-direction writes; raw base64 rides
//! along for a future in-browser player.
//!
//! Two download forms sit alongside it, ported from the Go dashboard's
//! `tty_replay.go` (`/tty/<shasum>.cast` and `.raw`), which the port
//! dropped entirely — the events explorer offered "view recording",
//! ".cast" and "raw", and only the first survived, so a recording could be
//! watched in-browser but never taken out of the dashboard:
//!
//!   /api/v1/recordings/{shasum}/cast  asciinema v2, for real replay and
//!                                     upload tooling
//!   /api/v1/recordings/{shasum}/raw   the original cowrie ttylog binary,
//!                                     byte-for-byte

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::Engine;
use serde::Serialize;
use serde_json::json;

use crate::AppState;

const OP_WRITE: i32 = 3;
const DIR_OUTPUT: i32 = 2;
const HEADER: usize = 24;

#[derive(Serialize)]
pub struct Replay {
    pub shasum: String,
    pub size_bytes: u64,
    pub imported_at: String,
    pub frames: usize,
    pub duration_seconds: f64,
    /// Lossy UTF-8 of the session's terminal output (ANSI sequences kept —
    /// the frontend renders them or strips them for the plain view).
    pub transcript: String,
    pub ttylog_base64: String,
}

fn decode(raw: &[u8]) -> (usize, f64, String) {
    let mut cursor = 0usize;
    let mut frames = 0usize;
    let mut first: Option<f64> = None;
    let mut last = 0.0f64;
    let mut output: Vec<u8> = Vec::new();
    while cursor + HEADER <= raw.len() {
        let op = i32::from_le_bytes(raw[cursor..cursor + 4].try_into().unwrap());
        let length = i32::from_le_bytes(raw[cursor + 8..cursor + 12].try_into().unwrap());
        let dir = i32::from_le_bytes(raw[cursor + 12..cursor + 16].try_into().unwrap());
        let sec = u32::from_le_bytes(raw[cursor + 16..cursor + 20].try_into().unwrap());
        let usec = u32::from_le_bytes(raw[cursor + 20..cursor + 24].try_into().unwrap());
        cursor += HEADER;
        if length < 0 {
            break; // corrupt frame — stop rather than misparse
        }
        let length = length as usize;
        if cursor + length > raw.len() {
            break;
        }
        let timestamp = sec as f64 + usec as f64 / 1_000_000.0;
        first.get_or_insert(timestamp);
        last = timestamp;
        if op == OP_WRITE && dir == DIR_OUTPUT {
            output.extend_from_slice(&raw[cursor..cursor + length]);
        }
        cursor += length;
        frames += 1;
    }
    let duration = first.map(|start| (last - start).max(0.0)).unwrap_or(0.0);
    (frames, duration, String::from_utf8_lossy(&output).into_owned())
}

/// Output frames as (absolute unix seconds, bytes) — what the asciicast
/// writer needs, and deliberately separate from `decode` so the existing
/// transcript path keeps its single-pass concatenation.
fn output_records(raw: &[u8]) -> Vec<(f64, Vec<u8>)> {
    let mut cursor = 0usize;
    let mut records = Vec::new();
    while cursor + HEADER <= raw.len() {
        let op = i32::from_le_bytes(raw[cursor..cursor + 4].try_into().unwrap());
        let length = i32::from_le_bytes(raw[cursor + 8..cursor + 12].try_into().unwrap());
        let dir = i32::from_le_bytes(raw[cursor + 12..cursor + 16].try_into().unwrap());
        let sec = u32::from_le_bytes(raw[cursor + 16..cursor + 20].try_into().unwrap());
        let usec = u32::from_le_bytes(raw[cursor + 20..cursor + 24].try_into().unwrap());
        cursor += HEADER;
        if length < 0 {
            break; // corrupt frame — stop rather than misparse
        }
        let length = length as usize;
        if cursor + length > raw.len() {
            break;
        }
        if op == OP_WRITE && dir == DIR_OUTPUT {
            let timestamp = sec as f64 + usec as f64 / 1_000_000.0;
            records.push((timestamp, raw[cursor..cursor + length].to_vec()));
        }
        cursor += length;
    }
    records
}

/// asciinema v2: a JSON header line, then one `[elapsed, "o", text]` line
/// per output frame. Matches `ttyToAsciicast` in the Go tier, including
/// its lossy UTF-8 handling — attacker-controlled bytes are not guaranteed
/// valid UTF-8, and one malformed session must not make the whole cast
/// file unwritable.
fn to_asciicast(records: &[(f64, Vec<u8>)]) -> String {
    let start = records.first().map(|(t, _)| *t).unwrap_or(0.0);
    let mut header = json!({
        "version": 2,
        "width": 80,
        "height": 24,
        "env": {"TERM": "xterm-256color", "SHELL": "/bin/bash"},
    });
    if !records.is_empty() {
        header["timestamp"] = json!(start as i64);
    }
    let mut out = header.to_string();
    out.push('\n');
    for (timestamp, data) in records {
        let elapsed = (timestamp - start).max(0.0);
        let text = String::from_utf8_lossy(data);
        out.push_str(&json!([elapsed, "o", text]).to_string());
        out.push('\n');
    }
    out
}

/// The ES round trip both the JSON view and the two downloads need.
async fn fetch_ttylog(
    state: &AppState,
    shasum: &str,
) -> Result<(serde_json::Value, Vec<u8>, String), (StatusCode, String)> {
    let body = json!({
        "size": 1,
        "query": {"term": {"shasum": shasum}}
    });
    let result = state
        .es
        .search_index(&["cowrie-ttylog-v1"], body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let hit = result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .ok_or((StatusCode::NOT_FOUND, "no such recording".to_string()))?;
    let source = hit["_source"].clone();
    let encoded = source["ttylog_base64"].as_str().unwrap_or("").to_string();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .map_err(|error| (StatusCode::BAD_GATEWAY, format!("ttylog decode: {error}")))?;
    Ok((source, raw, encoded))
}

/// `attachment` rather than inline: both of these are files an analyst
/// takes elsewhere (asciinema upload, a local player), never something to
/// render in the browser — and the raw log is attacker-controlled bytes,
/// which must not be handed to the browser as anything it might sniff.
fn attachment(shasum: &str, extension: &str) -> String {
    format!("attachment; filename=\"{shasum}.{extension}\"")
}

pub async fn replay_cast(
    State(state): State<AppState>,
    Path(shasum): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (_, raw, _) = fetch_ttylog(&state, &shasum).await?;
    let cast = to_asciicast(&output_records(&raw));
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-asciicast+json".to_string()),
            (header::CONTENT_DISPOSITION, attachment(&shasum, "cast")),
        ],
        cast,
    ))
}

pub async fn replay_raw(
    State(state): State<AppState>,
    Path(shasum): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (_, raw, _) = fetch_ttylog(&state, &shasum).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, attachment(&shasum, "ttylog")),
        ],
        raw,
    ))
}

pub async fn replay(
    State(state): State<AppState>,
    Path(shasum): Path<String>,
) -> Result<Json<Replay>, (StatusCode, String)> {
    let (source, raw, encoded) = fetch_ttylog(&state, &shasum).await?;
    let (frames, duration_seconds, transcript) = decode(&raw);
    Ok(Json(Replay {
        shasum: source["shasum"].as_str().unwrap_or("").to_string(),
        size_bytes: source["size_bytes"].as_u64().unwrap_or(raw.len() as u64),
        imported_at: source["imported_at"].as_str().unwrap_or("").to_string(),
        frames,
        duration_seconds,
        transcript,
        ttylog_base64: encoded,
    }))
}
