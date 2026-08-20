//! Payload Workbench HTTP surface — JSON adaptation of dashboard/
//! settings_api-style identity (owner supplied as a plain BFF param, same
//! precedent as preferences.rs/services_control.rs) over
//! workbench_orchestrator.rs's run/child logic and workbench_es.rs's
//! recipe storage.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::workbench_domain::{self, WorkbenchRecipe, WorkbenchSelection};
use crate::workbench_es::{self, SaveRecipeError, UpdateRunError};
use crate::workbench_orchestrator::{self, CreateRunError, CreateRunRequest};
use crate::AppState;

fn error(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<Value>) {
    (status, Json(json!({"error": message.into()})))
}

#[derive(Deserialize)]
pub struct AnalyzersQuery {
    hash: String,
}

pub async fn analyzers(
    Query(query): Query<AnalyzersQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let hash = query.hash.trim().to_lowercase();
    if !crate::payload_paths::is_valid_hash(&hash) {
        return Err(error(StatusCode::BAD_REQUEST, "invalid payload hash"));
    }
    let path = crate::payload_paths::resolve_payload_path(&hash)
        .map_err(|_| error(StatusCode::NOT_FOUND, "captured payload not found"))?;
    let head = crate::payload_paths::read_payload_head(&path)
        .map_err(|_| error(StatusCode::NOT_FOUND, "captured payload is unreadable"))?;
    let classification = crate::payload_kind::classify_payload(&head);
    let registry = workbench_domain::registry(&classification);
    Ok(Json(
        json!({"classification": classification, "analyzers": registry}),
    ))
}

#[derive(Deserialize)]
pub struct CreateRunBody {
    payload_sha256: String,
    owner: String,
    #[serde(default)]
    recipe_id: String,
    #[serde(default)]
    recipe_revision: i64,
    #[serde(default)]
    recipe_name: String,
    #[serde(default)]
    analyzers: Vec<WorkbenchSelection>,
}

pub async fn create_run(
    State(state): State<AppState>,
    Json(body): Json<CreateRunBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if body.owner.trim().is_empty() {
        return Err(error(StatusCode::BAD_REQUEST, "owner is required"));
    }
    let request = CreateRunRequest {
        payload_sha256: body.payload_sha256,
        owner: body.owner,
        recipe_id: body.recipe_id,
        recipe_revision: body.recipe_revision,
        recipe_name: body.recipe_name,
        analyzers: body.analyzers,
    };
    match workbench_orchestrator::create_run(&state, request).await {
        Ok((run, reused)) => Ok(Json(json!({"run": run, "reused": reused}))),
        Err(CreateRunError::Validation(message)) => Err(error(StatusCode::BAD_REQUEST, message)),
        Err(CreateRunError::NotFound) => {
            Err(error(StatusCode::NOT_FOUND, "captured payload not found"))
        }
        Err(CreateRunError::Storage(err)) => Err(error(StatusCode::BAD_GATEWAY, err.to_string())),
    }
}

#[derive(Deserialize)]
pub struct OwnerQuery {
    #[serde(default)]
    owner: String,
}

pub async fn get_run(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<OwnerQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match workbench_orchestrator::get_run(&state, &id, &query.owner).await {
        Ok(run) => Ok(Json(json!({"run": run}))),
        Err(UpdateRunError::NotFound) => {
            Err(error(StatusCode::NOT_FOUND, "workbench record not found"))
        }
        Err(UpdateRunError::Mutate(message)) => Err(error(StatusCode::BAD_REQUEST, message)),
        Err(UpdateRunError::Storage(err)) => Err(error(StatusCode::BAD_GATEWAY, err.to_string())),
    }
}

#[derive(Deserialize)]
pub struct ListRunsQuery {
    #[serde(default)]
    owner: String,
    #[serde(default)]
    hash: String,
    #[serde(default)]
    limit: usize,
}

pub async fn list_runs(
    State(state): State<AppState>,
    Query(query): Query<ListRunsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if query.owner.trim().is_empty() {
        return Err(error(StatusCode::BAD_REQUEST, "owner is required"));
    }
    let runs = workbench_es::list_runs_for_owner_and_hash(
        &state.es,
        &query.owner,
        &query.hash,
        query.limit,
    )
    .await
    .map_err(|err| error(StatusCode::BAD_GATEWAY, err.to_string()))?;
    Ok(Json(json!({"runs": runs})))
}

#[derive(Deserialize)]
pub struct ChildActionBody {
    #[serde(default)]
    owner: String,
}

pub async fn child_action(
    State(state): State<AppState>,
    Path((run_id, analyzer_id, action)): Path<(String, String, String)>,
    Json(body): Json<ChildActionBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match workbench_orchestrator::child_action(&state, &run_id, &analyzer_id, &action, &body.owner)
        .await
    {
        Ok(run) => Ok(Json(json!({"run": run}))),
        Err(UpdateRunError::NotFound) => {
            Err(error(StatusCode::NOT_FOUND, "workbench record not found"))
        }
        Err(UpdateRunError::Mutate(message)) => Err(error(StatusCode::BAD_REQUEST, message)),
        Err(UpdateRunError::Storage(err)) => Err(error(StatusCode::BAD_GATEWAY, err.to_string())),
    }
}

pub async fn list_recipes(
    State(state): State<AppState>,
    Query(query): Query<OwnerQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let recipes = workbench_es::list_recipes(&state.es, &query.owner)
        .await
        .map_err(|err| error(StatusCode::BAD_GATEWAY, err.to_string()))?;
    Ok(Json(json!({"recipes": recipes})))
}

#[derive(Deserialize)]
pub struct SaveRecipeBody {
    #[serde(default)]
    id: String,
    name: String,
    #[serde(default)]
    description: String,
    owner: String,
    scope: String,
    analyzers: Vec<WorkbenchSelection>,
    #[serde(default)]
    base_revision: i64,
}

pub async fn save_recipe(
    State(state): State<AppState>,
    Json(body): Json<SaveRecipeBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if body.owner.trim().is_empty() {
        return Err(error(StatusCode::BAD_REQUEST, "owner is required"));
    }
    let input = WorkbenchRecipe {
        id: body.id,
        name: body.name,
        description: body.description,
        scope: body.scope,
        analyzers: body.analyzers,
        ..Default::default()
    };
    match workbench_es::save_recipe(&state.es, input, &body.owner, body.base_revision).await {
        Ok(recipe) => Ok(Json(json!({"recipe": recipe}))),
        Err(SaveRecipeError::Validation(message)) => Err(error(StatusCode::BAD_REQUEST, message)),
        Err(SaveRecipeError::Conflict) => {
            Err(error(StatusCode::CONFLICT, "recipe revision conflict"))
        }
        Err(SaveRecipeError::NotFound) => {
            Err(error(StatusCode::NOT_FOUND, "workbench record not found"))
        }
        Err(SaveRecipeError::Storage(err)) => Err(error(StatusCode::BAD_GATEWAY, err.to_string())),
    }
}
