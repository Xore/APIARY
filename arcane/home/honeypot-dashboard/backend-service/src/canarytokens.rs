//! Canarytoken management (#1487), ported from canarytokens_client.go /
//! canarytokens_api.go: create against the self-hosted Canarytokens
//! platform's REST API (WireGuard-tunnel-only; CANARYTOKENS_API_URL +
//! CANARYTOKENS_API_ROOT), persist the record to
//! dashboard-canarytokens-v1, and proxy artifact downloads. The trigger
//! webhook stays the adapter (fired events flow through the existing
//! pipeline unchanged).

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::AppState;

const ADAPTER_WEBHOOK_URL: &str = "http://canarytokens-adapter.internal:8090/";
/// frontend/app.py's ROOT_API_ENDPOINT at the pinned CANARYTOKENS_REF —
/// deliberately non-guessable (upstream anti-scraping), not "/api".
const DEFAULT_API_ROOT: &str = "/d3aece8093b71007b5ccfedad91ebb11";
const MAX_UPLOAD_BYTES: usize = 8 << 20;

/// (type, label, description, download fmt, content type, suffix,
/// requires upload, supports snippet)
pub const TYPES: &[(&str, &str, &str, &str, &str, &str, bool, bool)] = &[
    ("adobe_pdf", "PDF document", "A decoy PDF that fires when opened.", "pdf", "application/pdf", ".pdf", false, false),
    ("ms_word", "Word document", "A decoy .docx that fires when opened.", "msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx", false, true),
    ("ms_excel", "Excel workbook", "A decoy .xlsx that fires when opened.", "msexcel", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx", false, true),
    ("web_image", "Custom web image", "A web bug behind your own image; fires on load.", "", "", "", true, false),
    ("windows_dir", "Windows Folder token", "A desktop.ini + icon bundle that fires when the folder is opened in Explorer.", "zip", "application/zip", ".zip", false, false),
    ("qr_code", "QR code", "A PNG QR code that fires when scanned and opened.", "qr_code", "image/png", ".png", false, false),
];

fn base_url() -> Option<String> {
    let api = std::env::var("CANARYTOKENS_API_URL").ok()?;
    if api.is_empty() {
        return None;
    }
    let root = std::env::var("CANARYTOKENS_API_ROOT").unwrap_or_else(|_| DEFAULT_API_ROOT.into());
    Some(format!("{}{}", api.trim_end_matches('/'), root))
}

fn type_info(token_type: &str) -> Option<&'static (&'static str, &'static str, &'static str, &'static str, &'static str, &'static str, bool, bool)> {
    TYPES.iter().find(|entry| entry.0 == token_type)
}

pub async fn types() -> Json<Value> {
    Json(json!(TYPES
        .iter()
        .map(|(id, label, description, _, _, _, upload, snippet)| json!({
            "token_type": id,
            "label": label,
            "description": description,
            "requires_upload": upload,
            "supports_snippet": snippet,
        }))
        .collect::<Vec<_>>()))
}

#[derive(Deserialize)]
pub struct CreateBody {
    pub token_type: String,
    pub memo: String,
    #[serde(default)]
    pub created_by: String,
    #[serde(default)]
    pub include_text_snippet: bool,
    #[serde(default)]
    pub text_snippet: String,
    /// web_image upload, base64 (the BFF forwards the browser file).
    #[serde(default)]
    pub file_base64: String,
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub file_content_type: String,
}

#[derive(Serialize)]
pub struct CreatedToken {
    pub id: String,
    pub token_type: String,
    pub memo: String,
    pub token_url: String,
    pub hostname: String,
    pub created_by: String,
    pub created_at: String,
}

pub async fn create(
    State(state): State<AppState>,
    Json(body): Json<CreateBody>,
) -> Result<Json<CreatedToken>, (StatusCode, String)> {
    let base = base_url().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "canarytoken creation is not configured on this host".to_string(),
    ))?;
    let info = type_info(&body.token_type)
        .ok_or((StatusCode::BAD_REQUEST, "unsupported token_type".to_string()))?;
    let memo = body.memo.trim().to_string();
    if memo.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "memo is required".into()));
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;

    let request = client.post(format!("{base}/generate"));
    let response = if info.6 {
        // upload-required type (web_image): multipart form.
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&body.file_base64)
            .map_err(|_| (StatusCode::BAD_REQUEST, "a file upload is required for this token type".to_string()))?;
        if bytes.is_empty() || bytes.len() > MAX_UPLOAD_BYTES {
            return Err((StatusCode::BAD_REQUEST, "invalid upload size".into()));
        }
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(body.file_name.clone())
            .mime_str(if body.file_content_type.is_empty() { "application/octet-stream" } else { &body.file_content_type })
            .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?;
        let form = reqwest::multipart::Form::new()
            .text("token_type", body.token_type.clone())
            .text("memo", memo.clone())
            .text("webhook_url", ADAPTER_WEBHOOK_URL)
            .part(body.token_type.clone(), part);
        request.multipart(form).send().await
    } else {
        let mut payload = json!({
            "token_type": body.token_type,
            "memo": memo,
            "webhook_url": ADAPTER_WEBHOOK_URL,
        });
        if info.7 && body.include_text_snippet {
            payload["include_text_snippet"] = json!(true);
            payload["text_snippet"] = json!(body.text_snippet.trim());
        }
        request.json(&payload).send().await
    }
    .map_err(|error| (StatusCode::BAD_GATEWAY, format!("canarytokens: {error}")))?;

    let status = response.status();
    let result: Value = response
        .json()
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, format!("canarytokens: malformed generate response: {error}")))?;
    let token = result["token"].as_str().unwrap_or("");
    let auth = result["auth_token"].as_str().unwrap_or("");
    if !status.is_success() || token.is_empty() || auth.is_empty() {
        let message = result["error_message"]
            .as_str()
            .filter(|text| !text.is_empty())
            .map(String::from)
            .unwrap_or_else(|| format!("canarytokens: generate failed with status {status}"));
        return Err((StatusCode::BAD_GATEWAY, message));
    }

    let created_at = chrono::Utc::now().to_rfc3339();
    let record = json!({
        "id": token,
        "token_type": body.token_type,
        "memo": memo,
        "token_url": result["token_url"].as_str().unwrap_or(""),
        "hostname": result["hostname"].as_str().unwrap_or(""),
        "filename_hint": body.file_name,
        "auth_token": auth,
        "created_by": body.created_by,
        "created_at": created_at,
    });
    state
        .es
        .index_doc("dashboard-canarytokens-v1", token, record)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

    Ok(Json(CreatedToken {
        id: token.to_string(),
        token_type: body.token_type,
        memo,
        token_url: result["token_url"].as_str().unwrap_or("").to_string(),
        hostname: result["hostname"].as_str().unwrap_or("").to_string(),
        created_by: body.created_by,
        created_at,
    }))
}

#[derive(Deserialize)]
pub struct DownloadQuery {
    #[serde(default)]
    pub fmt: String,
}

/// GET /api/v1/canarytokens/{id}/download — proxy the token's artifact.
/// web_image never goes through /download (fetching the trigger URL
/// server-side would itself fire the token).
pub async fn download(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(_query): Query<DownloadQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let base = base_url().ok_or((StatusCode::SERVICE_UNAVAILABLE, "not configured".to_string()))?;
    let record = state
        .es
        .search_index(
            &["dashboard-canarytokens-v1"],
            json!({"size": 1, "query": {"term": {"id": id}}}),
        )
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let source = record["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .map(|hit| hit["_source"].clone())
        .ok_or((StatusCode::NOT_FOUND, "no such token".to_string()))?;
    let token_type = source["token_type"].as_str().unwrap_or("");
    let info = type_info(token_type).ok_or((StatusCode::BAD_REQUEST, "unknown token type".to_string()))?;
    if info.3.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "this token type has no downloadable artifact".into()));
    }
    let auth = source["auth_token"].as_str().unwrap_or("");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let upstream = client
        .get(format!("{base}/download"))
        .query(&[("token", id.as_str()), ("auth", auth), ("fmt", info.3)])
        .send()
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, format!("canarytokens: {error}")))?;
    if !upstream.status().is_success() {
        return Err((StatusCode::BAD_GATEWAY, format!("canarytokens: download failed with status {}", upstream.status())));
    }
    let bytes = upstream
        .bytes()
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let filename = format!("canarytoken-{}{}", &id[..id.len().min(12)], info.5);
    Ok((
        [
            (header::CONTENT_TYPE, info.4.to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
        ],
        bytes.to_vec(),
    ))
}
