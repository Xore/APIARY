//! Payload Workbench recipe/run persistence, ported from dashboard/
//! workbench_es.go. A run's own document id IS its idempotency key
//! (workbench_domain::idempotency_key), so `es.index_doc_create` gives
//! atomic, cross-instance create-or-conflict for free — a losing race is a
//! genuine "someone already submitted this," not a retry case. Recipes get
//! the analogous treatment: each revision is its own document
//! (`{id}:{revision}`), also written via create, so two racing saves can't
//! both claim the same revision number.

use crate::es::{Es, WriteError};
use crate::workbench_domain::{WorkbenchRecipe, WorkbenchRun};

pub const RUNS_INDEX: &str = "dashboard-workbench-runs-v1";
pub const RECIPES_INDEX: &str = "dashboard-workbench-recipes-v1";
const UPDATE_RETRIES: u32 = 5;

pub fn recipe_doc_id(id: &str, revision: i64) -> String {
    format!("{id}:{revision}")
}

pub async fn list_recipes(es: &Es, owner: &str) -> anyhow::Result<Vec<WorkbenchRecipe>> {
    let result = es
        .search_index(&[RECIPES_INDEX], serde_json::json!({"size": 10000}))
        .await?;
    let mut visible: Vec<WorkbenchRecipe> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| serde_json::from_value::<WorkbenchRecipe>(hit["_source"].clone()).ok())
        .filter(|recipe| {
            recipe.schema_version == crate::workbench_domain::SCHEMA_VERSION
                && crate::workbench_domain::valid_id(&recipe.id, "recipe_")
                && recipe.revision > 0
                && !recipe.owner.is_empty()
        })
        .filter(|recipe| recipe.scope == "shared" || recipe.owner == owner)
        .collect();
    visible.sort_by(|a, b| match b.created_at.cmp(&a.created_at) {
        std::cmp::Ordering::Equal => b.revision.cmp(&a.revision),
        other => other,
    });
    Ok(visible)
}

pub async fn recipe(es: &Es, id: &str, revision: i64, owner: &str) -> Option<WorkbenchRecipe> {
    let doc = es
        .get_doc(RECIPES_INDEX, &recipe_doc_id(id, revision))
        .await
        .ok()
        .flatten()?;
    let recipe: WorkbenchRecipe = serde_json::from_value(doc).ok()?;
    if recipe.scope != "shared" && recipe.owner != owner {
        return None;
    }
    Some(recipe)
}

pub enum SaveRecipeError {
    Validation(String),
    Conflict,
    NotFound,
    Storage(anyhow::Error),
}

/// input.id == "" creates a new recipe (revision 1); otherwise saves a new
/// revision of an existing one owned by `owner`, gated on `base_revision`
/// matching the current latest (a stale base is Conflict, mirroring the
/// old file-backed store's optimistic-concurrency contract).
pub async fn save_recipe(
    es: &Es,
    mut input: WorkbenchRecipe,
    owner: &str,
    base_revision: i64,
) -> Result<WorkbenchRecipe, SaveRecipeError> {
    input.name = input.name.trim().to_string();
    input.description = input.description.trim().to_string();
    if input.name.len() < 2 || input.name.len() > 80 || input.description.len() > 400 {
        return Err(SaveRecipeError::Validation(
            "recipe name or description is outside the allowed length".into(),
        ));
    }
    if input.scope != "private" && input.scope != "shared" {
        return Err(SaveRecipeError::Validation(
            "recipe scope must be private or shared".into(),
        ));
    }
    input.analyzers = crate::workbench_domain::validate_selections(input.analyzers)
        .map_err(SaveRecipeError::Validation)?;

    let result = es
        .search_index(&[RECIPES_INDEX], serde_json::json!({"size": 10000}))
        .await
        .map_err(SaveRecipeError::Storage)?;
    let hits: Vec<WorkbenchRecipe> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| serde_json::from_value::<WorkbenchRecipe>(hit["_source"].clone()).ok())
        .collect();

    if input.id.is_empty() {
        let distinct: std::collections::HashSet<&str> =
            hits.iter().map(|r| r.id.as_str()).collect();
        if distinct.len() >= crate::workbench_domain::MAX_RECIPES {
            return Err(SaveRecipeError::Validation("recipe limit reached".into()));
        }
        input.id = crate::workbench_domain::random_id("recipe");
        input.revision = 1;
    } else {
        if !crate::workbench_domain::valid_id(&input.id, "recipe_") {
            return Err(SaveRecipeError::Validation("invalid recipe id".into()));
        }
        let mut latest = 0;
        for existing in &hits {
            if existing.id != input.id {
                continue;
            }
            if existing.owner != owner {
                return Err(SaveRecipeError::NotFound);
            }
            latest = latest.max(existing.revision);
        }
        if latest == 0 {
            return Err(SaveRecipeError::NotFound);
        }
        if base_revision != latest {
            return Err(SaveRecipeError::Conflict);
        }
        input.revision = latest + 1;
    }
    input.schema_version = crate::workbench_domain::SCHEMA_VERSION;
    input.owner = owner.to_string();
    input.created_at = chrono::Utc::now().to_rfc3339();

    let doc =
        serde_json::to_value(&input).map_err(|error| SaveRecipeError::Storage(error.into()))?;
    match es
        .index_doc_create(
            RECIPES_INDEX,
            &recipe_doc_id(&input.id, input.revision),
            doc,
        )
        .await
    {
        Ok(()) => Ok(input),
        Err(WriteError::Conflict) => Err(SaveRecipeError::Conflict),
        Err(WriteError::Other(error)) => Err(SaveRecipeError::Storage(error)),
    }
}

pub async fn find_run(es: &Es, id: &str, owner: &str) -> Option<WorkbenchRun> {
    if !crate::workbench_domain::valid_run_id(id) {
        return None;
    }
    let doc = es.get_doc(RUNS_INDEX, id).await.ok().flatten()?;
    let run: WorkbenchRun = serde_json::from_value(doc).ok()?;
    if run.id != id || run.owner != owner {
        return None;
    }
    Some(run)
}

pub async fn list_runs_for_owner_and_hash(
    es: &Es,
    owner: &str,
    hash: &str,
    limit: usize,
) -> anyhow::Result<Vec<WorkbenchRun>> {
    let limit = if limit == 0 || limit > crate::workbench_domain::MAX_RUNS {
        crate::workbench_domain::MAX_RUNS
    } else {
        limit
    };
    let result = es
        .search_index(&[RUNS_INDEX], serde_json::json!({"size": 10000}))
        .await?;
    let mut all: Vec<WorkbenchRun> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| serde_json::from_value::<WorkbenchRun>(hit["_source"].clone()).ok())
        .filter(|run| {
            run.schema_version == crate::workbench_domain::SCHEMA_VERSION
                && crate::workbench_domain::valid_run_id(&run.id)
        })
        .collect();
    all.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(all
        .into_iter()
        .filter(|run| run.owner == owner && (hash.is_empty() || run.payload_sha256 == hash))
        .take(limit)
        .collect())
}

pub async fn count_runs(es: &Es) -> anyhow::Result<usize> {
    let result = es
        .search_index(&[RUNS_INDEX], serde_json::json!({"size": 10000}))
        .await?;
    Ok(result["hits"]["hits"]
        .as_array()
        .map(|hits| hits.len())
        .unwrap_or(0))
}

/// Atomic create-or-reuse: run.id is already the idempotency key, so
/// op_type=create either wins (genuinely new) or collides with an
/// identical prior submission — in which case the existing run is fetched
/// and returned as reused=true.
pub async fn create_or_reuse_run(
    es: &Es,
    run: WorkbenchRun,
) -> anyhow::Result<(WorkbenchRun, bool)> {
    let doc = serde_json::to_value(&run)?;
    match es.index_doc_create(RUNS_INDEX, &run.id, doc).await {
        Ok(()) => Ok((run, false)),
        Err(WriteError::Conflict) => {
            let existing = es.get_doc(RUNS_INDEX, &run.id).await?.ok_or_else(|| {
                anyhow::anyhow!("workbench run creation conflict could not be resolved")
            })?;
            let existing: WorkbenchRun = serde_json::from_value(existing)?;
            Ok((existing, true))
        }
        Err(WriteError::Other(error)) => Err(error),
    }
}

pub enum UpdateRunError {
    NotFound,
    Mutate(String),
    Storage(anyhow::Error),
}

/// Read-modify-write primitive every in-place run mutation goes through:
/// fetch, let `mutate` decide the new state and whether anything actually
/// changed, persist only if so. A lost compare-and-swap race retries
/// against a fresh read, same shape as the alert notifier's own retry loop.
pub async fn update_run<F>(
    es: &Es,
    id: &str,
    owner: &str,
    mut mutate: F,
) -> Result<WorkbenchRun, UpdateRunError>
where
    F: FnMut(&mut WorkbenchRun) -> Result<bool, String>,
{
    if !crate::workbench_domain::valid_run_id(id) {
        return Err(UpdateRunError::NotFound);
    }
    for _ in 0..UPDATE_RETRIES {
        let Some((doc, seq_no, primary_term)) = es
            .get_doc_meta(RUNS_INDEX, id)
            .await
            .map_err(UpdateRunError::Storage)?
        else {
            return Err(UpdateRunError::NotFound);
        };
        let mut run: WorkbenchRun =
            serde_json::from_value(doc).map_err(|error| UpdateRunError::Storage(error.into()))?;
        if run.id != id || run.owner != owner {
            return Err(UpdateRunError::NotFound);
        }
        let changed = mutate(&mut run).map_err(UpdateRunError::Mutate)?;
        if !changed {
            return Ok(run);
        }
        let body =
            serde_json::to_value(&run).map_err(|error| UpdateRunError::Storage(error.into()))?;
        match es
            .index_doc_cas(RUNS_INDEX, id, body, seq_no, primary_term)
            .await
        {
            Ok(()) => return Ok(run),
            Err(WriteError::Conflict) => continue,
            Err(WriteError::Other(error)) => return Err(UpdateRunError::Storage(error)),
        }
    }
    Err(UpdateRunError::Storage(anyhow::anyhow!(
        "workbench run update conflict; retry"
    )))
}
