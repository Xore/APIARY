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

    // #2111: validate the chunk set BEFORE decoding anything into the
    // response. A partially indexed artifact — reachable while #764's
    // per-file retry loop is still failing (#2109's oversized-bulk loop is
    // one standing way it keeps failing) — used to be served as a 200 OK
    // truncated pcap. Now the operator gets an explicit retry-later error
    // naming the gap instead of evidence bytes that lie.
    let sources: Vec<&Value> = hits.iter().map(|hit| &hit["_source"]).collect();
    let (_, declared_size) =
        validated_chunk_set(&sources).map_err(|message| (StatusCode::SERVICE_UNAVAILABLE, message))?;

    // Reassembly holds one decoded copy in memory. The import tiers cap
    // stored artifacts at MAX_CHUNKED_ARTIFACT_BYTES (256MiB — es_importer.rs
    // and importer.py share the constant's semantics), already half of this
    // service's 512M container; refuse anything declaring larger before
    // allocating, so drift between the tiers' caps fails loudly here instead
    // of inside an OOM kill.
    if declared_size.unwrap_or(0) > MAX_ARTIFACT_DOWNLOAD_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "artifact declares {} bytes, over the {MAX_ARTIFACT_DOWNLOAD_BYTES}-byte reassembly cap",
                declared_size.unwrap_or(0)
            ),
        ));
    }

    let mut bytes: Vec<u8> = Vec::with_capacity(declared_size.unwrap_or(0).min(MAX_ARTIFACT_DOWNLOAD_BYTES) as usize);
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
    // Manifest cross-check: size_bytes describes the whole artifact, so the
    // reassembled byte count must agree even when the chunk COUNT was right.
    if let Some(size) = declared_size {
        if size != bytes.len() as u64 {
            return Err((
                StatusCode::BAD_GATEWAY,
                format!("artifact reassembled to {} bytes but its manifest declares {size}", bytes.len()),
            ));
        }
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

/// Upper bound on a single download's reassembled buffer — mirrors
/// MAX_CHUNKED_ARTIFACT_BYTES in es_importer.rs (kept a literal here so the
/// serving tier's contract doesn't move silently with the import tier's).
const MAX_ARTIFACT_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;

/// Chunk-set validation for download (#2111). Every chunk carries
/// chunk_index/total_chunks (and the manifest's size_bytes rides along on
/// each), so a reader CAN tell a partial set from a complete one — this is
/// the check the writer's own comment always assumed someone does. Returns
/// `(total_chunks, manifest size_bytes)` or an operator-facing description
/// of exactly what is wrong with the set. Input must be sorted by
/// chunk_index ascending, as the download query guarantees.
fn validated_chunk_set(sources: &[&Value]) -> Result<(u64, Option<u64>), String> {
    let mut total_chunks: Option<u64> = None;
    let mut declared_size: Option<u64> = None;
    let mut indices: Vec<u64> = Vec::with_capacity(sources.len());
    for source in sources {
        let total = source["total_chunks"].as_u64().unwrap_or(0);
        if total == 0 {
            return Err("artifact chunk is missing its total_chunks stamp".to_string());
        }
        if total_chunks.is_some_and(|known| known != total) {
            return Err(format!(
                "artifact chunks disagree on total_chunks ({total} vs {})",
                total_chunks.unwrap_or(0)
            ));
        }
        total_chunks = Some(total);
        let index = source["chunk_index"].as_u64().unwrap_or(u64::MAX);
        if indices.contains(&index) {
            return Err(format!("artifact holds chunk {index} twice"));
        }
        indices.push(index);
        declared_size = source["size_bytes"].as_u64().or(declared_size);
    }
    let total = total_chunks.unwrap_or_default();
    if indices.len() as u64 != total {
        let have: std::collections::HashSet<u64> = indices.iter().copied().collect();
        let missing: Vec<String> =
            (0..total).filter(|index| !have.contains(index)).map(|index| index.to_string()).collect();
        return Err(format!(
            "artifact is only partially indexed: have {} of {total} chunks (missing {}); retry after the next import pass",
            indices.len(),
            missing.join(", ")
        ));
    }
    if indices.iter().enumerate().any(|(position, &index)| index != position as u64) {
        return Err("artifact chunk indices are not contiguous from zero".to_string());
    }
    Ok((total, declared_size))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(index: u64, total: u64, size: u64) -> Value {
        json!({"chunk_index": index, "total_chunks": total, "size_bytes": size, "data_base64": ""})
    }

    #[test]
    fn a_complete_contiguous_set_validates() {
        let sources = [chunk(0, 3, 90), chunk(1, 3, 90), chunk(2, 3, 90)];
        let (total, size) = validated_chunk_set(&sources.iter().collect::<Vec<_>>()).expect("complete set");
        assert_eq!(total, 3);
        assert_eq!(size, Some(90));
    }

    #[test]
    fn a_missing_middle_chunk_is_named_in_the_error() {
        let sources = [chunk(0, 3, 90), chunk(2, 3, 90)];
        let message = validated_chunk_set(&sources.iter().collect::<Vec<_>>()).unwrap_err();
        assert!(message.contains("1 of 3 chunks missing") || message.contains("missing 1"), "{message}");
        assert!(message.contains("partially indexed"), "{message}");
    }

    #[test]
    fn a_missing_tail_chunk_is_rejected_too() {
        // The shape #764/#2109 retry loops actually produce: a prefix of
        // chunks lands, the rest never do until the next successful pass.
        let sources = [chunk(0, 4, 40), chunk(1, 4, 40), chunk(2, 4, 40)];
        let message = validated_chunk_set(&sources.iter().collect::<Vec<_>>()).unwrap_err();
        assert!(message.contains("3 of 4"), "{message}");
        assert!(message.contains("missing 3"), "{message}");
    }

    #[test]
    fn a_duplicate_index_cannot_pass_as_a_full_set() {
        let sources = [chunk(0, 3, 30), chunk(1, 3, 30), chunk(1, 3, 30)];
        let message = validated_chunk_set(&sources.iter().collect::<Vec<_>>()).unwrap_err();
        assert!(message.contains("twice"), "{message}");
    }

    #[test]
    fn chunks_disagreeing_on_total_are_rejected() {
        let sources = [chunk(0, 3, 30), chunk(1, 5, 30)];
        let message = validated_chunk_set(&sources.iter().collect::<Vec<_>>()).unwrap_err();
        assert!(message.contains("disagree"), "{message}");
    }

    #[test]
    fn a_chunk_without_the_total_stamp_is_rejected() {
        let sources = [json!({"chunk_index": 0, "data_base64": ""})];
        let message = validated_chunk_set(&sources.iter().collect::<Vec<_>>()).unwrap_err();
        assert!(message.contains("total_chunks"), "{message}");
    }
}
