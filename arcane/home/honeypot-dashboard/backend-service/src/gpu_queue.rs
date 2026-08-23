//! /api/v1/gpu-queue — visibility into, and abort control over, the shared
//! GPU job queue (#1611 workstream E.6, abort added in #1692). Ported from
//! dashboard/gpu_queue.go's loadGPUQueue: analysis/gpu-queue/gpu_queue.py's
//! queued/running/completed jobs, invisible before this (the issue's live
//! audit found 2 stuck queued jobs with nothing surfacing them).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use serde_json::json;

use crate::AppState;

const INDEX: &str = "gpu-job-queue";

#[derive(Serialize)]
pub struct GpuJob {
    pub job_id: String,
    pub job_type: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub model: String,
    pub estimated_vram_mib: i64,
    pub status: String,
    pub requested_at: String,
    pub started_at: String,
    pub finished_at: String,
    pub abort_requested: bool,
    pub error: String,
    pub attempts: i64,
}

pub async fn list(State(state): State<AppState>) -> Result<Json<Vec<GpuJob>>, (StatusCode, String)> {
    let body = json!({
        "size": 500,
        "sort": [{"requested_at": {"order": "desc", "unmapped_type": "date"}}]
    });
    let result = state
        .es
        .search_index(&[INDEX], body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let text = |value: &serde_json::Value| value.as_str().unwrap_or("").to_string();
    let jobs = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| {
            let source = &hit["_source"];
            GpuJob {
                job_id: text(&source["job_id"]),
                job_type: text(&source["job_type"]),
                reference: text(&source["ref"]),
                model: text(&source["model"]),
                estimated_vram_mib: source["estimated_vram_mib"].as_i64().unwrap_or(0),
                status: text(&source["status"]),
                requested_at: text(&source["requested_at"]),
                started_at: text(&source["started_at"]),
                finished_at: text(&source["finished_at"]),
                abort_requested: source["abort_requested"].as_bool().unwrap_or(false),
                error: text(&source["error"]),
                attempts: source["attempts"].as_i64().unwrap_or(0),
            }
        })
        .collect();
    Ok(Json(jobs))
}

/// POST /api/v1/gpu-queue/{job_id}/abort — request cancellation of a queued job.
///
/// This is the exact equivalent of gpu_queue.py's `request_abort`: set
/// `abort_requested` on the job document, whose `_id` is the job_id itself
/// (see that module's `enqueue`). Deliberately nothing more.
///
/// **It only has an effect while the job is still `queued`.** The drainer
/// checks the flag once, before committing to the Ollama call
/// (analysis/ghidra/worker/gpu-queue-drain.py:53, which moves the job to
/// `aborted`); cancelling an in-flight generation is out of scope by the same
/// contract documented at analysis/gpu-queue/gpu_queue.py:51. Setting it on a
/// running or finished job is harmless and simply does nothing, which is why
/// this does not read the job first to reject those states — the queue is
/// racy by nature and a job can finish between the operator seeing the row
/// and clicking. Refusing here would only convert a harmless no-op into a
/// confusing error.
pub async fn abort(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    state
        .es
        .update_doc(INDEX, &job_id, json!({"abort_requested": true}))
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    Ok(Json(json!({"ok": true, "job_id": job_id, "abort_requested": true})))
}
