//! Payload Workbench HTTP surface over workbench_orchestrator.rs's run/child
//! logic and workbench_es.rs's recipe storage.
//!
//! #3110: ownership used to be a plain BFF-supplied `owner` body/query
//! field, same precedent as preferences.rs/services_control.rs — fine for
//! those (audit logging, admin-only panes), but here it was also the
//! *authorization* check, so anyone who could reach this service (the
//! shared x-service-token, not a per-user secret) could act on any
//! operator's runs by naming them. Identity is now taken from
//! x-actor-username/x-actor-role, headers only the BFF's serviceFetch/
//! proxyToRust seam sets (see backend.server.ts) from its own verified
//! session — never from client-controlled JSON/query. The `owner` field
//! stays on the wire so existing request bodies don't break, but it is now
//! only a display hint, plus (for a verified admin only) an explicit
//! override to view/act on another operator's runs.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
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

/// Caller identity verified by the BFF and forwarded as headers — see the
/// module doc comment. `is_admin` reflects the forwarded role claim as-is;
/// there is no further verification possible at this tier, the same trust
/// level the shared service token already carries.
#[derive(Debug)]
struct Actor {
    username: String,
    is_admin: bool,
}

fn require_actor(headers: &HeaderMap) -> Result<Actor, (StatusCode, Json<Value>)> {
    let username = headers
        .get("x-actor-username")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match username {
        Some(username) => {
            let is_admin = headers
                .get("x-actor-role")
                .and_then(|value| value.to_str().ok())
                == Some("admin");
            Ok(Actor {
                username: username.to_string(),
                is_admin,
            })
        }
        None => Err(error(StatusCode::UNAUTHORIZED, "actor identity required")),
    }
}

/// Every non-admin request is forced to its own identity regardless of what
/// `requested` (the wire-level `owner` field) says. A verified admin may
/// name a different operator to view or act on their runs — the one
/// deliberate override, same posture admins already get elsewhere in this
/// dashboard (services_control.rs).
fn resolve_owner(actor: &Actor, requested: &str) -> String {
    let requested = requested.trim();
    if actor.is_admin && !requested.is_empty() {
        requested.to_string()
    } else {
        actor.username.clone()
    }
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
    // Display-hint only since #3110 — never authoritative, see module doc.
    #[allow(dead_code)]
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
    headers: HeaderMap,
    Json(body): Json<CreateRunBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let actor = require_actor(&headers)?;
    let request = CreateRunRequest {
        payload_sha256: body.payload_sha256,
        owner: actor.username,
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
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(query): Query<OwnerQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let actor = require_actor(&headers)?;
    let owner = resolve_owner(&actor, &query.owner);
    match workbench_orchestrator::get_run(&state, &id, &owner).await {
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
    headers: HeaderMap,
    Query(query): Query<ListRunsQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let actor = require_actor(&headers)?;
    let owner = resolve_owner(&actor, &query.owner);
    let runs = workbench_es::list_runs_for_owner_and_hash(&state.es, &owner, &query.hash, query.limit)
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
    headers: HeaderMap,
    Path((run_id, analyzer_id, action)): Path<(String, String, String)>,
    Json(body): Json<ChildActionBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let actor = require_actor(&headers)?;
    let owner = resolve_owner(&actor, &body.owner);
    match workbench_orchestrator::child_action(&state, &run_id, &analyzer_id, &action, &owner).await
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
    headers: HeaderMap,
    Query(_query): Query<OwnerQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let actor = require_actor(&headers)?;
    let recipes = workbench_es::list_recipes(&state.es, &actor.username)
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
    // Display-hint only since #3110 — never authoritative, see module doc.
    #[allow(dead_code)]
    #[serde(default)]
    owner: String,
    scope: String,
    analyzers: Vec<WorkbenchSelection>,
    #[serde(default)]
    base_revision: i64,
}

pub async fn save_recipe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SaveRecipeBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let actor = require_actor(&headers)?;
    let input = WorkbenchRecipe {
        id: body.id,
        name: body.name,
        description: body.description,
        scope: body.scope,
        analyzers: body.analyzers,
        ..Default::default()
    };
    match workbench_es::save_recipe(&state.es, input, &actor.username, body.base_revision).await {
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

#[cfg(test)]
mod tests {
    use super::{require_actor, resolve_owner, Actor};
    use axum::http::{HeaderMap, StatusCode};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            let name: axum::http::HeaderName = name.parse().expect("valid header name");
            headers.insert(name, value.parse().expect("valid header value"));
        }
        headers
    }

    fn actor(username: &str, is_admin: bool) -> Actor {
        Actor {
            username: username.to_string(),
            is_admin,
        }
    }

    #[test]
    fn require_actor_rejects_missing_identity() {
        // No forwarded identity at all -- the BFF didn't attach one, or a
        // request reached this tier some other way. Must refuse outright,
        // never fall back to a default trusted state.
        let (status, _) = require_actor(&HeaderMap::new()).expect_err("must reject");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn require_actor_rejects_blank_username() {
        // Whitespace-only counts as absent, same as no header at all.
        let (status, _) =
            require_actor(&headers(&[("x-actor-username", "   ")])).expect_err("must reject");
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn require_actor_reads_and_trims_the_username() {
        let actor = require_actor(&headers(&[("x-actor-username", "  alice  ")]))
            .expect("must accept a present username");
        assert_eq!(actor.username, "alice");
        assert!(!actor.is_admin);
    }

    #[test]
    fn require_actor_only_recognizes_the_exact_admin_role() {
        let admin = require_actor(&headers(&[
            ("x-actor-username", "root"),
            ("x-actor-role", "admin"),
        ]))
        .expect("must accept");
        assert!(admin.is_admin);

        // A near-miss role claim is not the admin override -- exact match
        // only, same as the header being absent.
        let not_admin = require_actor(&headers(&[
            ("x-actor-username", "root"),
            ("x-actor-role", "Administrator"),
        ]))
        .expect("must accept");
        assert!(!not_admin.is_admin);
    }

    #[test]
    fn non_admin_owner_field_is_ignored_entirely() {
        // The core of #3110: operator A naming operator B in the
        // wire-level `owner` field must never change whose runs are read,
        // listed, cancelled, or retried.
        let a = actor("operator-a", false);
        assert_eq!(resolve_owner(&a, "operator-b"), "operator-a");
        assert_eq!(resolve_owner(&a, "  operator-b  "), "operator-a");
        assert_eq!(resolve_owner(&a, ""), "operator-a");
    }

    #[test]
    fn self_access_resolves_to_the_caller_regardless_of_role() {
        // Legitimate self-access: an empty requested owner always means
        // "my own runs", admin or not.
        assert_eq!(resolve_owner(&actor("operator-a", false), ""), "operator-a");
        assert_eq!(resolve_owner(&actor("root", true), ""), "root");
        assert_eq!(resolve_owner(&actor("root", true), "   "), "root");
    }

    #[test]
    fn admin_can_override_to_a_named_owner() {
        // The one deliberate override: a verified admin naming another
        // operator is honored, unlike the non-admin case above.
        let admin = actor("root", true);
        assert_eq!(resolve_owner(&admin, "operator-b"), "operator-b");
        assert_eq!(resolve_owner(&admin, "  operator-b  "), "operator-b");
    }
}
