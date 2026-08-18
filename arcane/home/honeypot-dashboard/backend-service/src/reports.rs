//! /api/v1/reports/{id}/pdf — stream one generated report's PDF bytes
//! from dashboard-generated-reports-v1 (the reporter stores the finished
//! PDF as pdf_base64; the list endpoint excludes that field).

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    response::IntoResponse,
};
use base64::Engine;
use serde_json::json;

use crate::AppState;

pub async fn pdf(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let body = json!({"size": 1, "query": {"term": {"id": id}}});
    let result = state
        .es
        .search_index(&["dashboard-generated-reports-v1"], body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let hit = result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .ok_or((StatusCode::NOT_FOUND, "no such report".to_string()))?;
    let source = &hit["_source"];
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(source["pdf_base64"].as_str().unwrap_or(""))
        .map_err(|error| (StatusCode::BAD_GATEWAY, format!("pdf decode: {error}")))?;
    let name = source["name"].as_str().unwrap_or("report").replace(['"', '\\', '\n', '\r'], "_");
    Ok((
        [
            (header::CONTENT_TYPE, "application/pdf".to_string()),
            (header::CONTENT_DISPOSITION, format!("inline; filename=\"{name}.pdf\"")),
        ],
        bytes,
    ))
}
