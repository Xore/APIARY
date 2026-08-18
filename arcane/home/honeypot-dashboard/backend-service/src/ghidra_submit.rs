//! Ghidra submission, ported from ghidra_submit.go. Same shape as
//! sandbox_submit's submit handler and the same trust boundary — the
//! dashboard/BFF only ever confirms the capture exists and writes a marker
//! file; it never talks to the Ghidra REST service. Unlike sandbox
//! submission there is no dynamic/static classification: Ghidra
//! disassembles anything with code in it, including payloads the sandbox
//! refuses to detonate.

use axum::{http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::payload_paths::resolve_payload_path;
use crate::sandbox_submit::create_request_marker;

pub fn ghidra_request_dir() -> String {
    std::env::var("GHIDRA_REQUEST_DIR").unwrap_or_default()
}

#[derive(Deserialize)]
pub struct SubmitBody {
    hash: String,
}

pub async fn submit(Json(body): Json<SubmitBody>) -> (StatusCode, Json<Value>) {
    let hash = body.hash.to_lowercase();
    if !crate::payload_paths::is_valid_hash(&hash) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid payload hash"})));
    }
    if resolve_payload_path(&hash).is_err() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "captured payload not found"})),
        );
    }
    let dir = ghidra_request_dir();
    if dir.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Ghidra analysis is not configured on this host"})),
        );
    }
    match create_request_marker(&dir, &hash) {
        Ok(()) => (StatusCode::OK, Json(json!({"queued": true}))),
        Err(reason) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": reason}))),
    }
}
