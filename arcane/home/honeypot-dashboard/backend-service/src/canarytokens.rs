//! Canarytoken management (#1487), ported from canarytokens_client.go /
//! canarytokens_api.go: create against the self-hosted Canarytokens
//! platform's REST API (WireGuard-tunnel-only; CANARYTOKENS_API_URL +
//! CANARYTOKENS_API_ROOT), persist the record to
//! dashboard-canarytokens-v1, and proxy artifact downloads. The trigger
//! webhook stays the adapter (fired events flow through the existing
//! pipeline unchanged).

use axum::{
    extract::{Path, State},
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

pub struct TokenType {
    id: &'static str,
    label: &'static str,
    description: &'static str,
    download_fmt: &'static str,
    content_type: &'static str,
    filename_suffix: &'static str,
    requires_upload: bool,
    supports_snippet: bool,
}

pub const TYPES: &[TokenType] = &[
    TokenType { id: "adobe_pdf", label: "PDF document", description: "A decoy PDF that fires when opened.", download_fmt: "pdf", content_type: "application/pdf", filename_suffix: ".pdf", requires_upload: false, supports_snippet: false },
    TokenType { id: "ms_word", label: "Word document", description: "A decoy .docx that fires when opened.", download_fmt: "msword", content_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", filename_suffix: ".docx", requires_upload: false, supports_snippet: true },
    TokenType { id: "ms_excel", label: "Excel workbook", description: "A decoy .xlsx that fires when opened.", download_fmt: "msexcel", content_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", filename_suffix: ".xlsx", requires_upload: false, supports_snippet: true },
    TokenType { id: "web_image", label: "Custom web image", description: "A web bug behind your own image; fires on load.", download_fmt: "", content_type: "", filename_suffix: "", requires_upload: true, supports_snippet: false },
    TokenType { id: "windows_dir", label: "Windows Folder token", description: "A desktop.ini + icon bundle that fires when the folder is opened in Explorer.", download_fmt: "zip", content_type: "application/zip", filename_suffix: ".zip", requires_upload: false, supports_snippet: false },
    TokenType { id: "qr_code", label: "QR code", description: "A PNG QR code that fires when scanned and opened.", download_fmt: "qr_code", content_type: "image/png", filename_suffix: ".png", requires_upload: false, supports_snippet: false },
];

fn base_url() -> Option<String> {
    let api = std::env::var("CANARYTOKENS_API_URL").ok()?;
    if api.is_empty() {
        return None;
    }
    let root = std::env::var("CANARYTOKENS_API_ROOT").unwrap_or_else(|_| DEFAULT_API_ROOT.into());
    Some(format!("{}{}", api.trim_end_matches('/'), root))
}

fn type_info(token_type: &str) -> Option<&'static TokenType> {
    TYPES.iter().find(|entry| entry.id == token_type)
}

pub async fn types() -> Json<Value> {
    Json(json!(TYPES
        .iter()
        .map(|entry| json!({
            "token_type": entry.id,
            "label": entry.label,
            "description": entry.description,
            "requires_upload": entry.requires_upload,
            "supports_snippet": entry.supports_snippet,
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
    let response = if info.requires_upload {
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
        if info.supports_snippet && body.include_text_snippet {
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

/// GET /api/v1/canarytokens — every created token's history record, newest
/// first, for the Settings pane's history table and credentials'
/// link-token id validation. auth_token is the platform's own management
/// credential for that token (equivalent to a password) and must never
/// reach a browser — see create()'s CreatedToken response for the same
/// redaction, this list applies it too rather than encoding the ES
/// document straight through.
///
/// Restored (2026-08-19) after a prior pass deleted this as "dead code" on
/// the theory that frontend-next only reads the list through the generic
/// /api/v1/store/canarytokens proxy — true for canarytokens.tsx, but
/// credentials.tsx (added in the same PR that deleted this) calls this
/// exact route by name to populate its link-token dropdown, and the
/// generic proxy returns a different shape ({total, rows}, not {tokens})
/// and does not redact auth_token. Deleting this silently broke that
/// dropdown (serviceJSON swallows the resulting 404 as null) with no
/// visible error anywhere.
pub async fn list(State(state): State<AppState>) -> Result<Json<Value>, (StatusCode, String)> {
    let result = state
        .es
        .search_index(&["dashboard-canarytokens-v1"], json!({"size": 1000}))
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let mut records: Vec<Value> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| {
            let mut record = hit["_source"].clone();
            if let Some(object) = record.as_object_mut() {
                object.remove("auth_token");
            }
            record
        })
        .collect();
    records.sort_by(|a, b| {
        let a = a["created_at"].as_str().unwrap_or_default();
        let b = b["created_at"].as_str().unwrap_or_default();
        b.cmp(a)
    });
    Ok(Json(json!({"tokens": records})))
}

/// GET /api/v1/canarytokens/{id}/download — proxy the token's artifact.
/// web_image never goes through /download (fetching the trigger URL
/// server-side would itself fire the token).
pub async fn download(
    State(state): State<AppState>,
    Path(id): Path<String>,
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
    if info.download_fmt.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "this token type has no downloadable artifact".into()));
    }
    let auth = source["auth_token"].as_str().unwrap_or("");
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    let upstream = client
        .get(format!("{base}/download"))
        .query(&[("token", id.as_str()), ("auth", auth), ("fmt", info.download_fmt)])
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
    let filename = format!("canarytoken-{}{}", &id[..id.len().min(12)], info.filename_suffix);
    Ok((
        [
            (header::CONTENT_TYPE, info.content_type.to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
        ],
        bytes.to_vec(),
    ))
}
