//! Reports studio HTTP layer (#1612): template/element catalog, definitions
//! CRUD, and the on-demand generate trigger. Ported from
//! reports_api.go's serveReportTemplates/serveReportDefinitions/
//! createReportDefinition/serveReportDefinitionByID/replaceReportDefinition/
//! removeReportDefinition/generateReport/renderDefinitionToStored/
//! renderDefinitionPDFBytes — only the `default` (generic telemetry)
//! branch of renderDefinitionPDFBytes; the sandbox/payload/ghidra
//! artifact-referenced templates are validated but not yet rendered here
//! (see reports_store.rs's module doc comment for the scope decision).
//!
//! No admin-role/same-origin/If-Match machinery — this crate's trust
//! boundary is the BFF's service token, same posture as every other write
//! path here (config.rs/preferences.rs).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::reports_store::{
    self, put_definition, report_template_catalog, GeneratedReportMeta, ReportDefinition,
    REPORT_ELEMENT_CATALOG,
};
use crate::AppState;

fn bad_request(message: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, message.into())
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

pub async fn templates() -> Json<Value> {
    let templates: Vec<Value> = report_template_catalog()
        .into_iter()
        .map(|t| {
            json!({
                "id": t.id, "name": t.name, "description": t.description, "title": t.title,
                "theme": t.theme, "window": t.window, "elements": t.elements,
                "sandbox": t.sandbox, "payload": t.payload, "ghidra": t.ghidra,
            })
        })
        .collect();
    let elements: Vec<Value> = REPORT_ELEMENT_CATALOG
        .iter()
        .map(|e| json!({"id": e.id, "label": e.label, "description": e.description}))
        .collect();
    Json(json!({"templates": templates, "elements": elements}))
}

pub async fn list_definitions(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let definitions = reports_store::list_definitions(&state)
        .await
        .map_err(bad_gateway)?;
    Ok(Json(json!({"definitions": definitions})))
}

pub async fn get_definition(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let definition = reports_store::get_definition(&state, &id)
        .await
        .map_err(bad_gateway)?
        .ok_or((
            StatusCode::NOT_FOUND,
            "no such report definition".to_string(),
        ))?;
    Ok(Json(json!({"definition": definition})))
}

pub async fn create_definition(
    State(state): State<AppState>,
    Json(mut def): Json<ReportDefinition>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, String)> {
    if !def.id.is_empty() {
        return Err(bad_request(
            "id is assigned by the server; omit it when creating a definition",
        ));
    }
    def.id = String::new();
    let created = put_definition(&state, def).await.map_err(map_store_error)?;
    Ok((StatusCode::CREATED, Json(json!({"definition": created}))))
}

pub async fn replace_definition(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(mut def): Json<ReportDefinition>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if !def.id.is_empty() && def.id != id {
        return Err(bad_request(
            "id in the body must match the path or be omitted",
        ));
    }
    def.id = id;
    let updated = put_definition(&state, def).await.map_err(map_store_error)?;
    Ok(Json(json!({"definition": updated})))
}

pub async fn delete_definition(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    reports_store::delete_definition(&state, &id)
        .await
        .map_err(map_store_error)?;
    Ok(Json(json!({"deleted": id})))
}

fn map_store_error(message: String) -> (StatusCode, String) {
    if message.contains("no report definition with this id") {
        (StatusCode::NOT_FOUND, message)
    } else if message.contains("limit reached") {
        (StatusCode::CONFLICT, message)
    } else {
        (StatusCode::UNPROCESSABLE_ENTITY, message)
    }
}

#[derive(Deserialize)]
pub struct GenerateBody {
    #[serde(default = "default_origin")]
    origin: String,
}

fn default_origin() -> String {
    "manual".into()
}

pub async fn generate(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<GenerateBody>>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, String)> {
    let origin = body
        .map(|b| b.origin.clone())
        .unwrap_or_else(default_origin);
    let definition = reports_store::get_definition(&state, &id)
        .await
        .map_err(bad_gateway)?
        .ok_or((
            StatusCode::NOT_FOUND,
            "no such report definition".to_string(),
        ))?;
    let meta = render_definition_to_stored(&state, &definition, &origin)
        .await
        .map_err(map_render_error)?;
    Ok((StatusCode::CREATED, Json(json!({"generated": meta}))))
}

fn map_render_error(message: String) -> (StatusCode, String) {
    if message.contains("not yet implemented") {
        (StatusCode::NOT_IMPLEMENTED, message)
    } else if message.contains("does not resolve") {
        (StatusCode::UNPROCESSABLE_ENTITY, message)
    } else {
        (StatusCode::BAD_GATEWAY, message)
    }
}

/// Up to 20 sandbox-analysis-v1 runs matching a captured payload's hash,
/// newest first — payload_pdf.go's own `binaryAnalysis.SandboxRuns` slice,
/// assembled here from the promoted `file.hash.sha256` field every
/// es_importer.rs-mirrored source carries (same field ghidra_run/cape_run
/// query elsewhere in this crate). Raw `_source` docs, same shape
/// render_sandbox_pdf itself reads.
async fn sandbox_runs_for_hash(state: &AppState, hash: &str) -> anyhow::Result<Vec<Value>> {
    let result = state
        .es
        .search_index(
            &["sandbox-analysis-v1"],
            json!({"size": 20, "sort": [{"@timestamp": {"order": "desc"}}], "query": {"term": {"file.hash.sha256": hash}}}),
        )
        .await?;
    Ok(result["hits"]["hits"].as_array().into_iter().flatten().map(|hit| hit["_source"].clone()).collect())
}

/// renderDefinitionToStored + renderDefinitionPDFBytes, shared by the
/// manual generate endpoint and the scheduler (worker.rs). The sandbox/
/// payload/ghidra branches each resolve their scope reference to one
/// artifact and hand it to report_pdf.rs's matching renderer; `default`
/// keeps the generic telemetry path unchanged.
pub async fn render_definition_to_stored(
    state: &AppState,
    def: &ReportDefinition,
    origin: &str,
) -> Result<GeneratedReportMeta, String> {
    let template = crate::reports_store::report_template_catalog()
        .into_iter()
        .find(|t| t.id == def.template)
        .ok_or_else(|| "unknown report template".to_string())?;

    let title = {
        let trimmed = def.branding.title.trim();
        if trimmed.is_empty() {
            template.title.to_string()
        } else {
            trimmed.to_string()
        }
    };
    let theme = crate::report_pdf::pdf_theme_named(&def.theme);
    let branding = def.branding.to_pdf_branding();
    let generated = chrono::Utc::now();

    let pdf = if template.sandbox {
        let job = def.scope.job.trim();
        if job.is_empty() {
            return Err("scope.job does not resolve to a completed sandbox result".to_string());
        }
        let doc = crate::detail::sandbox_run(State(state.clone()), Path(job.to_string()))
            .await
            .map_err(|_| "scope.job does not resolve to a completed sandbox result".to_string())?
            .0;
        crate::report_pdf::render_sandbox_pdf(&doc, generated, theme, branding)
    } else if template.ghidra {
        let hash = def.scope.hash.trim();
        if hash.is_empty() {
            return Err("scope.hash does not resolve to a completed ghidra result".to_string());
        }
        let doc = crate::detail::ghidra_run(State(state.clone()), Path(hash.to_string()))
            .await
            .map_err(|_| "scope.hash does not resolve to a completed ghidra result".to_string())?
            .0;
        crate::report_pdf::render_ghidra_pdf(&doc, generated, theme, branding)
    } else if template.payload {
        let hash = def.scope.hash.trim();
        if hash.is_empty() {
            return Err("scope.hash does not resolve to a captured payload".to_string());
        }
        let detail = crate::payload_detail::detail(State(state.clone()), Path(hash.to_string()))
            .await
            .map_err(|_| "scope.hash does not resolve to a captured payload".to_string())?
            .0;
        let inventory = detail.inventory.unwrap_or(Value::Null);
        let analysis = detail.analysis.unwrap_or(Value::Null);
        let sandbox_runs = sandbox_runs_for_hash(state, hash).await.map_err(|e| e.to_string())?;
        let github_analysis = crate::detail::github_analysis_run(State(state.clone()), Path(hash.to_string()))
            .await
            .map(|json| json.0)
            .unwrap_or(Value::Null);
        crate::report_pdf::render_payload_pdf(
            hash,
            &inventory,
            &analysis,
            &detail.yara,
            &sandbox_runs,
            &github_analysis,
            generated,
            theme,
            branding,
        )
    } else {
        let appendix_limit = if def.appendix_limit <= 0 { 120 } else { def.appendix_limit };
        let mut data = crate::reports_data::report_data_for(state, &def.scope, title.clone(), appendix_limit)
            .await
            .map_err(|e| e.to_string())?;
        data.title = title.clone();
        crate::report_pdf::render_report_pdf(&data, theme, branding, &def.elements, appendix_limit)
    };

    reports_store::add_generated(
        state,
        GeneratedReportMeta {
            id: String::new(),
            definition_id: def.id.clone(),
            name: def.name.clone(),
            template: def.template.clone(),
            theme: def.theme.clone(),
            title,
            size_bytes: 0,
            created_at: String::new(),
            origin: origin.to_string(),
        },
        pdf,
    )
    .await
    .map_err(|e| e.to_string())
}
