//! /api/v1/gpu-queue — read-only visibility into the shared GPU job queue
//! (#1611 workstream E.6). Ported from dashboard/gpu_queue.go's
//! loadGPUQueue: analysis/gpu-queue/gpu_queue.py's queued/running/completed
//! jobs, invisible today (the issue's live audit found 2 stuck queued jobs
//! with nothing surfacing them). Read-only — gpu_queue.go's abort action is
//! an operator write against a queue/spool, out of scope for this pass;
//! this only closes the "can't even see it" gap.

use axum::{extract::State, http::StatusCode, Json};
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
