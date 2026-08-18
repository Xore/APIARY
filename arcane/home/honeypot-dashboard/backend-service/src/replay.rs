//! /api/v1/recordings/{shasum} — fetch one Cowrie ttylog from
//! cowrie-ttylog-v1 and decode its frame stream into a terminal
//! transcript. Frame layout matches Cowrie's playlog reader
//! (`<iLiiLL`, all little-endian): op i32, tty u32, length i32, dir i32,
//! sec u32, usec u32, then `length` bytes of data for OP_WRITE frames.
//! The transcript concatenates output-direction writes; raw base64 rides
//! along for a future in-browser player.

use axum::{
    extract::{Path, State},
    http::StatusCode,
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

pub async fn replay(
    State(state): State<AppState>,
    Path(shasum): Path<String>,
) -> Result<Json<Replay>, (StatusCode, String)> {
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
    let source = &hit["_source"];
    let encoded = source["ttylog_base64"].as_str().unwrap_or("");
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| (StatusCode::BAD_GATEWAY, format!("ttylog decode: {error}")))?;
    let (frames, duration_seconds, transcript) = decode(&raw);
    Ok(Json(Replay {
        shasum: source["shasum"].as_str().unwrap_or("").to_string(),
        size_bytes: source["size_bytes"].as_u64().unwrap_or(raw.len() as u64),
        imported_at: source["imported_at"].as_str().unwrap_or("").to_string(),
        frames,
        duration_seconds,
        transcript,
        ttylog_base64: encoded.to_string(),
    }))
}
