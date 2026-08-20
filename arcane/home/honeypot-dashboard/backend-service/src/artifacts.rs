//! Analysis artifact stores: ghidra-report-artifacts-v1 (one doc per
//! artifact) and sandbox-export-artifacts-v1 (chunked — reassembled here
//! by chunk_index). List endpoints exclude the data; download endpoints
//! stream the decoded bytes with the stored content type.

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::Engine;
use serde_json::{json, Value};

use crate::AppState;

fn store_for(kind: &str) -> Option<(&'static str, &'static str)> {
    // (index, key field)
    match kind {
        "ghidra" => Some(("ghidra-report-artifacts-v1", "sha256")),
        "sandbox" => Some(("sandbox-export-artifacts-v1", "job")),
        _ => None,
    }
}

pub async fn list(
    State(state): State<AppState>,
    Path((kind, key)): Path<(String, String)>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let (index, field) = store_for(&kind).ok_or((StatusCode::NOT_FOUND, "unknown artifact kind".to_string()))?;
    let body = json!({
        "size": 100,
        "_source": {"excludes": ["data_base64"]},
        "query": {"term": {field: key}},
        "sort": [{"imported_at": {"order": "desc", "unmapped_type": "date"}}]
    });
    let result = state
        .es
        .search_index(&[index], body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    // Chunked artifacts collapse to one row per filename.
    let mut rows: Vec<Value> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for hit in result["hits"]["hits"].as_array().into_iter().flatten() {
        let source = &hit["_source"];
        let filename = source["filename"].as_str().unwrap_or("").to_string();
        if filename.is_empty() || !seen.insert(filename.clone()) {
            continue;
        }
        rows.push(json!({
            "filename": filename,
            "kind": source["kind"],
            "content_type": source["content_type"],
            "size_bytes": source["size_bytes"],
            "imported_at": source["imported_at"],
        }));
    }
    Ok(Json(json!({"rows": rows})))
}

pub async fn download(
    State(state): State<AppState>,
    Path((kind, key, filename)): Path<(String, String, String)>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (index, field) = store_for(&kind).ok_or((StatusCode::NOT_FOUND, "unknown artifact kind".to_string()))?;
    let body = json!({
        "size": 1000,
        "query": {"bool": {"filter": [
            {"term": {field: key}},
            {"term": {"filename": filename}}
        ]}},
        "sort": [{"chunk_index": {"order": "asc", "unmapped_type": "long"}}]
    });
    let result = state
        .es
        .search_index(&[index], body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let hits = result["hits"]["hits"].as_array().cloned().unwrap_or_default();
    if hits.is_empty() {
        return Err((StatusCode::NOT_FOUND, "no such artifact".into()));
    }
    let mut bytes: Vec<u8> = Vec::new();
    let mut content_type = "application/octet-stream".to_string();
    for hit in &hits {
        let source = &hit["_source"];
        if let Some(ct) = source["content_type"].as_str() {
            content_type = ct.to_string();
        }
        let chunk = base64::engine::general_purpose::STANDARD
            .decode(source["data_base64"].as_str().unwrap_or(""))
            .map_err(|error| (StatusCode::BAD_GATEWAY, format!("artifact decode: {error}")))?;
        bytes.extend_from_slice(&chunk);
    }
    let safe_name = filename.replace(['"', '\\', '\n', '\r', '/'], "_");
    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{safe_name}\"")),
        ],
        bytes,
    ))
}
