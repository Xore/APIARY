//! Sandbox submission + golden-image staleness, ported from
//! sandbox_submit.go and sandbox.go's loadGoldenImageStatus. Adapted from
//! Go's form-POST-plus-redirect flow to plain JSON — the caller here is
//! the BFF, not a browser form, so there is no return-URL/open-redirect
//! concern to port (safeReturnPath has no equivalent needed).
//!
//! Same trust boundary as the rest of this crate: the service token is the
//! only gate. admin-role/same-origin checks stay the BFF's job.

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::Path;

use crate::payload_kind::classify_payload;
use crate::payload_paths::{read_payload_head, resolve_payload_path};
use crate::AppState;

fn env_dir(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// windows | linux | ghosts. Ghosts is never auto-picked by classification
/// (WAN-permitted route, opt-in only via the Workbench) — mirrors
/// determineSandboxTarget exactly.
fn determine_sandbox_target(data: &[u8]) -> Option<&'static str> {
    let classification = classify_payload(data);
    if !classification.dynamic {
        return None;
    }
    Some(if classification.platform == "Windows" {
        "windows"
    } else {
        "linux"
    })
}

pub fn sandbox_request_dir(target: &str) -> String {
    match target {
        "windows" => env_dir("WINDOWS_SANDBOX_REQUEST_DIR"),
        "ghosts" => env_dir("GHOSTS_SANDBOX_REQUEST_DIR"),
        _ => {
            let dir = env_dir("SANDBOX_REQUEST_DIR");
            if dir.is_empty() {
                "/sandbox-requests".to_string()
            } else {
                dir
            }
        }
    }
}

/// Creates {dir}/{hash}.request, O_CREATE|O_EXCL. An already-existing
/// marker is success, not an error — the same idempotence a second click
/// on an already-queued job relies on in the Go tier.
pub fn create_request_marker(dir: &str, hash: &str) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::io::ErrorKind;
    if dir.is_empty() {
        return Err("spool is not configured".into());
    }
    let path = Path::new(dir).join(format!("{hash}.request"));
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(format!("request spool unavailable: {error}")),
    }
}

#[derive(Deserialize)]
pub struct SubmitBody {
    hash: String,
}

pub async fn submit(State(_state): State<AppState>, Json(body): Json<SubmitBody>) -> (StatusCode, Json<Value>) {
    let hash = body.hash.to_lowercase();
    if !crate::payload_paths::is_valid_hash(&hash) {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "invalid payload hash"})));
    }
    let path = match resolve_payload_path(&hash) {
        Ok(path) => path,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "captured payload not found"})),
            )
        }
    };
    let head = match read_payload_head(&path) {
        Ok(head) => head,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "captured payload is unreadable"})),
            )
        }
    };
    let Some(target) = determine_sandbox_target(&head) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "this payload has no dynamic detonation path — see its static analysis instead"})),
        );
    };
    let dir = sandbox_request_dir(target);
    if dir.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": format!("the {target} sandbox is not configured on this host")})),
        );
    }
    match create_request_marker(&dir, &hash) {
        Ok(()) => (StatusCode::OK, Json(json!({"target": target, "queued": true}))),
        Err(reason) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": reason}))),
    }
}

/// goldenImageStatus (#86): win11-analysis.qcow2 staleness, written by a
/// host-side timer into WINDOWS_SANDBOX_RESULTS_DIR — the same directory
/// already mounted read-only for per-job results, no new mount needed.
/// Missing/unreadable/unset is not an error: informational badge only.
pub async fn golden_image_status() -> Json<Value> {
    let dir = env_dir("WINDOWS_SANDBOX_RESULTS_DIR");
    if dir.is_empty() {
        return Json(json!({"configured": false}));
    }
    let path = Path::new(&dir).join("golden-image-status.json");
    let Ok(body) = std::fs::read(&path) else {
        return Json(json!({"configured": false}));
    };
    if body.len() > 16 * 1024 {
        return Json(json!({"configured": false}));
    }
    let Ok(mut value) = serde_json::from_slice::<Value>(&body) else {
        return Json(json!({"configured": false}));
    };
    if let Value::Object(ref mut map) = value {
        map.insert("configured".into(), json!(true));
    }
    Json(value)
}

/// windowsSandboxLiveJob's regex, ported: run_pending.sh claims one
/// request at a time by renaming {sha}.request to {sha}.request.running
/// before it starts the guest, and the single-VM/flock design means at
/// most one such file can exist at a time.
fn running_sha_from(name: &str) -> Option<&str> {
    let sha = name.strip_suffix(".request.running")?;
    (sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())).then_some(sha)
}

/// GET /api/v1/sandbox/vnc — read-only live-view status, ported from
/// sandbox_vnc.go's serveSandboxVNC + windowsSandboxLiveJob. This tier
/// never touches libvirt or the VNC stream itself — it only reports
/// whether a Windows-sandbox detonation is currently running and where
/// the operator-configured bridge WebSocket lives; the browser's noVNC
/// client connects to that bridge directly. Admin-gated at the BFF, same
/// posture as every other admin action here — watching a live malware
/// detonation is at least as sensitive as downloading its capture.
pub async fn vnc_status() -> Result<Json<Value>, (StatusCode, String)> {
    let bridge_ws = env_dir("SANDBOX_VNC_BRIDGE_WS");
    if bridge_ws.is_empty() {
        return Err((StatusCode::NOT_FOUND, "the VNC bridge is not configured on this host (SANDBOX_VNC_BRIDGE_WS unset)".into()));
    }
    let dir = sandbox_request_dir("windows");
    if dir.is_empty() {
        return Err((StatusCode::NOT_FOUND, "no Windows-sandbox detonation is currently running".into()));
    }
    let running_sha = std::fs::read_dir(&dir)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str().and_then(|name| running_sha_from(name).map(str::to_string)))
        .next();
    let Some(sha256) = running_sha else {
        return Err((StatusCode::NOT_FOUND, "no Windows-sandbox detonation is currently running".into()));
    };
    Ok(Json(json!({"sha256": sha256, "bridge_ws": bridge_ws})))
}
