//! /api/v1/payloads/{hash} — one captured payload's full picture: the
//! inventory row, static analysis (dashboard-static-analysis-v1), YARA
//! results, and a bounded hex preview from dashboard-payload-bytes-v1
//! (the full artifact stays server-side; only the preview crosses the
//! wire, mirroring the legacy static-analysis page's posture).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};

use crate::AppState;

const PREVIEW_BYTES: usize = 512;

#[derive(Serialize)]
pub struct PayloadDetail {
    pub hash: String,
    pub inventory: Option<Value>,
    pub analysis: Option<Value>,
    pub yara: Vec<Value>,
    pub size_bytes: u64,
    /// classic hexdump rows of the first bytes ("00000000  4d 5a 90 …  |MZ..|").
    pub hex_preview: Vec<String>,
}

fn hexdump(bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks(16)
        .enumerate()
        .map(|(index, chunk)| {
            let hex: Vec<String> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
            let ascii: String = chunk
                .iter()
                .map(|byte| if byte.is_ascii_graphic() || *byte == b' ' { *byte as char } else { '.' })
                .collect();
            format!("{:08x}  {:<47}  |{}|", index * 16, hex.join(" "), ascii)
        })
        .collect()
}

pub async fn detail(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<PayloadDetail>, (StatusCode, String)> {
    let bad_gateway = |error: anyhow::Error| (StatusCode::BAD_GATEWAY, error.to_string());
    let first_hit = |result: &Value| -> Option<Value> {
        result["hits"]["hits"].as_array().and_then(|hits| hits.first()).map(|hit| hit["_source"].clone())
    };

    let (inventory, analysis, yara, bytes) = tokio::try_join!(
        state.es.search_index(
            &["dashboard-payload-inventory-v1"],
            json!({"size": 1, "query": {"term": {"Hash": hash}}}),
        ),
        state.es.search_index(
            &["dashboard-static-analysis-v1"],
            json!({"size": 1, "query": {"term": {"Fingerprint": hash}}}),
        ),
        state.es.search_index(
            &["yara-analysis-v1"],
            json!({"size": 10, "query": {"bool": {"should": [
                {"term": {"file.hash.sha256": hash}},
                {"term": {"file.hash.md5": hash}}
            ], "minimum_should_match": 1}}}),
        ),
        state.es.search_index(
            &["dashboard-payload-bytes-v1"],
            json!({"size": 1, "query": {"term": {"hash": hash}}}),
        ),
    )
    .map_err(bad_gateway)?;

    let bytes_source = first_hit(&bytes);
    let (size_bytes, hex_preview) = match &bytes_source {
        Some(source) => {
            let size = source["size_bytes"].as_u64().unwrap_or(0);
            let encoded = source["data_base64"].as_str().unwrap_or("");
            // Decode only enough base64 for the preview window.
            let prefix_len = (PREVIEW_BYTES * 4 / 3 + 4).min(encoded.len());
            let mut prefix = &encoded[..prefix_len];
            while !prefix.len().is_multiple_of(4) {
                prefix = &prefix[..prefix.len() - 1];
            }
            let decoded = base64::engine::general_purpose::STANDARD.decode(prefix).unwrap_or_default();
            (size, hexdump(&decoded[..decoded.len().min(PREVIEW_BYTES)]))
        }
        None => (0, Vec::new()),
    };

    let yara_rows: Vec<Value> = yara["hits"]["hits"]
        .as_array()
        .map(|hits| hits.iter().map(|hit| hit["_source"].clone()).collect())
        .unwrap_or_default();

    let inventory = first_hit(&inventory);
    let analysis = first_hit(&analysis);
    if inventory.is_none() && analysis.is_none() && bytes_source.is_none() && yara_rows.is_empty() {
        return Err((StatusCode::NOT_FOUND, "no such payload".into()));
    }

    Ok(Json(PayloadDetail { hash, inventory, analysis, yara: yara_rows, size_bytes, hex_preview }))
}
