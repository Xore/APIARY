//! HTTP client for the honeyfs-implant service (arcane/home/honeypot-cowrie/
//! honeyfs-implant), ported from dashboard/honeyfs_implant_client.go.
//! WireGuard-tunnel-only, same reachability posture as canarytokens.rs's
//! CANARYTOKENS_API_URL — off unless HONEYFS_IMPLANT_URL is set.
//!
//! Request/response shape mirrors the Go client exactly (confirmed against
//! honeyfs-implant/main.go, not guessed):
//!
//!   POST /implant  {"path", "content_base64", "memo"} JSON
//!                  -> {"ok", "path", "bytes_written", "error"}

use base64::Engine;
use serde_json::{json, Value};

pub struct ImplantResult {
    #[allow(dead_code)]
    pub path: String,
    #[allow(dead_code)]
    pub bytes_written: i64,
}

fn base_url() -> Option<String> {
    let url = std::env::var("HONEYFS_IMPLANT_URL").ok()?;
    if url.is_empty() {
        return None;
    }
    Some(url.trim_end_matches('/').to_string())
}

fn token() -> String {
    std::env::var("HONEYFS_IMPLANT_TOKEN").unwrap_or_default()
}

pub fn configured() -> bool {
    base_url().is_some()
}

/// POST {HONEYFS_IMPLANT_URL}/implant. path must already be validated as
/// honeyfs-root-relative by the caller — this client does not re-derive
/// containment itself, honeyfs-implant's own resolveHoneyfsPath is the
/// actual enforcement point, this is just belt-and-suspenders.
pub async fn implant(path: &str, content: &[u8], memo: &str) -> Result<ImplantResult, String> {
    let Some(base) = base_url() else {
        return Err("honeyfs-implant: not configured".to_string());
    };
    let payload = json!({
        "path": path,
        "content_base64": base64::engine::general_purpose::STANDARD.encode(content),
        "memo": memo,
    });
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|error| error.to_string())?;
    let mut request = client.post(format!("{base}/implant")).json(&payload);
    let token = token();
    if !token.is_empty() {
        request = request.bearer_auth(token);
    }
    let response = request.send().await.map_err(|error| error.to_string())?;
    let status = response.status();
    // /implant only ever answers a small JSON status object, never the
    // artifact itself — bounded read matches honeyfsImplantMaxResponseBytes.
    let bytes = response.bytes().await.map_err(|error| error.to_string())?;
    if bytes.len() > 1 << 20 {
        return Err("honeyfs-implant: response too large".to_string());
    }
    let result: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("honeyfs-implant: malformed response (status {status}): {error}"))?;
    let ok = result["ok"].as_bool().unwrap_or(false);
    if !ok || !status.is_success() {
        let message = result["error"].as_str().filter(|text| !text.is_empty());
        return Err(message
            .map(String::from)
            .unwrap_or_else(|| format!("honeyfs-implant: request failed with status {status}")));
    }
    Ok(ImplantResult {
        path: result["path"].as_str().unwrap_or_default().to_string(),
        bytes_written: result["bytes_written"].as_i64().unwrap_or(0),
    })
}
