//! Small read endpoints backing the detail/drill-down UI (visual pass;
//! the write-path/worker backends live on #1612):
//! - /api/v1/sandbox/{job} and /api/v1/ghidra/{sha} — one analysis doc.
//! - /api/v1/attackers-graph?id= — hub/spoke/overflow node-edge list for
//!   cytoscape, ported from attackers_graph.go (same 60-node cap).
//! - /api/v1/attack-vectors?sensor= — the overview heatmap's per-sensor
//!   companion panel (#471): ports + protocols the sensor saw in 24h.
//! - POST /api/v1/ml-anomalies/ack — ack state keyed by the anomaly doc
//!   _id in dashboard-ml-anomaly-ack-v1 (#913 contract).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::AppState;

const GRAPH_MAX_NODES: usize = 60;
const ML_ACK_INDEX: &str = "dashboard-ml-anomaly-ack-v1";

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

async fn one_doc(
    state: &AppState,
    index: &str,
    query: Value,
) -> Result<Json<Value>, (StatusCode, String)> {
    let result = state
        .es
        .search_index(&[index], json!({"size": 1, "query": query}))
        .await
        .map_err(bad_gateway)?;
    result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .map(|hit| {
            let mut doc = hit["_source"].clone();
            doc["_doc_id"] = hit["_id"].clone();
            Json(doc)
        })
        .ok_or((StatusCode::NOT_FOUND, "not found".to_string()))
}

pub async fn sandbox_run(
    State(state): State<AppState>,
    Path(job): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    one_doc(
        &state,
        "sandbox-analysis-v1",
        json!({"bool": {"should": [
            {"term": {"sandbox.job": job}},
            {"term": {"job": job}}
        ], "minimum_should_match": 1}}),
    )
    .await
}

pub async fn ghidra_run(
    State(state): State<AppState>,
    Path(sha): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    one_doc(&state, "ghidra-analysis-v1", json!({"term": {"file.hash.sha256": sha}})).await
}

/// /api/v1/revdeck/{sha} — #1611 workstream E.8: revdeck-analysis-v1 had
/// no detail endpoint at all, so an unconfigured-worker error state (the
/// live audit's own example) rendered as a blank page rather than a
/// visible error. es_importer.rs wraps the raw revdeck output (itself
/// `{exit_status, revdeck: {...}, sha256, ...}`) one level deeper under
/// the source label, doc id `revdeck:{sha256}` (es_importer.rs's doc_id);
/// same nesting attacker_identity.rs's revdeck_verdict already reads.
pub async fn revdeck_run(
    State(state): State<AppState>,
    Path(sha): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let doc = state
        .es
        .get_doc("revdeck-analysis-v1", &format!("revdeck:{sha}"))
        .await
        .map_err(bad_gateway)?
        .ok_or((StatusCode::NOT_FOUND, "not found".to_string()))?;
    Ok(Json(doc["revdeck"].clone()))
}

/// /api/v1/cape/{sha} — one CAPE detonation result, ported from cape.go's
/// capeData. `report` is CAPE's own raw report — tens of thousands of
/// API-call entries per traced process is normal — so it's never shipped
/// whole; only the bounded `report_summary` this handler reduces it to
/// crosses the wire (mirrors cape.go's own capeReportSummary). The full
/// report stays in Elasticsearch for anyone who needs it, same posture
/// Go's page takes ("too large for this page" — Go links to the raw-JSON
/// API route instead).
pub async fn cape_run(
    State(state): State<AppState>,
    Path(sha): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let doc = state
        .es
        .get_doc("cape-analysis-v1", &format!("cape:{sha}"))
        .await
        .map_err(bad_gateway)?
        .ok_or((StatusCode::NOT_FOUND, "not found".to_string()))?;
    let mut result = doc["cape"].clone();
    let summary = summarize_cape_report(&result["report"]);
    if let Some(object) = result.as_object_mut() {
        object.remove("report");
    }
    result["report_summary"] = summary;
    Ok(Json(result))
}

/// /api/v1/cape/{sha}/raw — the untouched result, full report included.
/// A distinct route from cape_run above (not a query flag on it) so the
/// page's own fetch never accidentally pulls the full report in — this is
/// only ever reached by an explicit "download raw report" click.
pub async fn cape_raw(
    State(state): State<AppState>,
    Path(sha): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let doc = state
        .es
        .get_doc("cape-analysis-v1", &format!("cape:{sha}"))
        .await
        .map_err(bad_gateway)?
        .ok_or((StatusCode::NOT_FOUND, "not found".to_string()))?;
    Ok(Json(doc["cape"].clone()))
}

/// /api/v1/github-analysis/{sha} — one publication result, ported from
/// github_analysis.go's githubAnalysisData. Adds two fields the producer
/// scripts never write, computed here the same way Go's dashboard layer
/// does: `requested_by` (looked up from the audit log — this tier has no
/// session of its own, so "who submitted this" only exists as an audit
/// trail) and `view_url` (a validated raw.githubusercontent.com link to
/// the rendered PDF report, when one genuinely exists).
pub async fn github_analysis_run(
    State(state): State<AppState>,
    Path(sha): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let doc = state
        .es
        .get_doc("github-analysis-v1", &format!("github_analysis:{sha}"))
        .await
        .map_err(bad_gateway)?
        .ok_or((StatusCode::NOT_FOUND, "not found".to_string()))?;
    let mut result = doc["github_analysis"].clone();
    result["requested_by"] = json!(requester_for(&state, &sha));
    result["view_url"] = github_analysis_pdf_url(&result).map_or(Value::Null, |url| json!(url));
    Ok(Json(result))
}

/// Mirrors githubAnalysisRequester: the newest queued github_analysis.submit
/// audit entry for this hash, preferring the username over the bare
/// subject — same posture every other actor-attributed field in this
/// crate takes.
fn requester_for(state: &AppState, sha: &str) -> String {
    for event in state.audit.read(500) {
        if event["action"].as_str() != Some("github_analysis.submit") || event["result"].as_str() != Some("queued") {
            continue;
        }
        let first_field = event["fields"].as_array().and_then(|fields| fields.first()).and_then(Value::as_str);
        if !first_field.is_some_and(|field| field.eq_ignore_ascii_case(sha)) {
            continue;
        }
        let username = event["actor_username"].as_str().unwrap_or("");
        return if username.is_empty() { event["actor_subject"].as_str().unwrap_or("").to_string() } else { username.to_string() };
    }
    String::new()
}

/// Mirrors githubAnalysisPDFURL: report_commit (falling back to commit)
/// must be a real 40-hex-char sha, and report_pdf can't escape the
/// repository via ".." or an absolute path — both are producer-controlled
/// strings that become URL path segments, so validated the same way
/// resolve_payload_path treats a worker-written filename before it
/// becomes a filesystem path.
fn github_analysis_pdf_url(row: &Value) -> Option<String> {
    let commit = row["report_commit"]
        .as_str()
        .filter(|value| !value.is_empty())
        .or_else(|| row["commit"].as_str().filter(|value| !value.is_empty()))?;
    let report_pdf = row["report_pdf"].as_str().filter(|value| !value.is_empty())?;
    if !commit_re().is_match(commit) || report_pdf.contains("..") || report_pdf.starts_with('/') {
        return None;
    }
    Some(format!("https://raw.githubusercontent.com/Xore/honeypot/{commit}/{report_pdf}"))
}

fn commit_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^[0-9a-f]{40}$").expect("static commit pattern"))
}

fn summarize_cape_report(report: &Value) -> Value {
    if !report.is_object() {
        return Value::Null;
    }
    let mut summary_keys: Vec<&String> = report["behavior"]["summary"].as_object().into_iter().flatten().map(|(key, _)| key).collect();
    summary_keys.sort();

    let processes: Vec<Value> = report["behavior"]["processes"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|process| {
            let call_count = process["calls"].as_array().map_or(0, Vec::len);
            json!({
                "process_id": process["process_id"],
                "process_name": process["process_name"],
                "parent_id": process["parent_id"],
                "module_path": process["module_path"],
                "first_seen": process["first_seen"],
                "call_count": call_count,
            })
        })
        .collect();
    let total_calls: i64 = processes.iter().map(|process| process["call_count"].as_i64().unwrap_or(0)).sum();

    json!({
        "machine": report["info"]["machine"]["label"],
        "package": report["info"]["package"],
        "route": report["info"]["route"],
        "timeout": report["info"]["timeout"],
        "duration": report["info"]["duration"],
        "malscore": report["malscore"],
        "malstatus": report["malstatus"],
        "summary": report["behavior"]["summary"],
        "summary_keys": summary_keys,
        "processes": processes,
        "total_calls": total_calls,
        "payloads": report["CAPE"]["payloads"],
        "configs": report["CAPE"]["configs"],
        "debug_log": report["debug"]["log"],
        "debug_errors": report["debug"]["errors"],
    })
}

#[derive(Deserialize)]
pub struct GraphQuery {
    pub id: String,
}

pub async fn attackers_graph(
    State(state): State<AppState>,
    Query(query): Query<GraphQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let entity = state
        .es
        .search_index(&["attackers-v1"], json!({"size": 1, "query": {"term": {"id": query.id}}}))
        .await
        .map_err(bad_gateway)?;
    let source = entity["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .map(|hit| hit["_source"].clone())
        .ok_or((StatusCode::NOT_FOUND, "no such attacker entity".to_string()))?;
    let ips: Vec<&str> = source["ips"].as_array().into_iter().flatten().filter_map(|v| v.as_str()).collect();

    let hub_id = format!("hub:{}", query.id);
    let hub_label: String = query.id.chars().take(8).collect();
    let mut nodes = vec![json!({"id": hub_id, "label": hub_label, "kind": "hub"})];
    let mut edges = Vec::new();
    let (spokes, overflow) = if ips.len() > GRAPH_MAX_NODES {
        (&ips[..GRAPH_MAX_NODES - 1], ips.len() - (GRAPH_MAX_NODES - 1))
    } else {
        (&ips[..], 0)
    };
    for ip in spokes {
        nodes.push(json!({"id": ip, "label": ip, "kind": "spoke"}));
        edges.push(json!({"source": hub_id, "target": ip}));
    }
    if overflow > 0 {
        let overflow_id = format!("overflow:{}", query.id);
        nodes.push(json!({"id": overflow_id, "label": format!("+{overflow}"), "kind": "overflow"}));
        edges.push(json!({"source": hub_id, "target": overflow_id}));
    }
    Ok(Json(json!({"nodes": nodes, "edges": edges})))
}

#[derive(Deserialize)]
pub struct VectorsQuery {
    pub sensor: String,
}

pub async fn attack_vectors(
    State(state): State<AppState>,
    Query(query): Query<VectorsQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let sensor = query.sensor.trim();
    // suricata/portbridge ship to their own index families — a query here
    // would silently return empty (same rejection as the Go handler).
    if sensor.is_empty() || sensor == "suricata" || sensor == "portbridge" {
        return Err((StatusCode::BAD_REQUEST, "a specific sensor is required".into()));
    }
    let body = json!({
        "size": 0,
        "query": {"bool": {"filter": [
            {"term": {"event.sensor": sensor}},
            {"range": {"@timestamp": {"gte": "now-24h"}}}
        ]}},
        "aggs": {
            "ports": {"terms": {"field": "destination.port", "size": 12}},
            "protocols": {"terms": {"field": "network.protocol", "size": 12}}
        }
    });
    let result = state
        .es
        .search_index(&["honeypot-v2-*"], body)
        .await
        .map_err(bad_gateway)?;
    let rows = |agg: &str, link_key: &str| -> Vec<Value> {
        result["aggregations"][agg]["buckets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|bucket| {
                let key = bucket["key"]
                    .as_str()
                    .map(String::from)
                    .or_else(|| bucket["key"].as_i64().map(|n| n.to_string()))?;
                Some(json!({
                    "key": key,
                    "count": bucket["doc_count"],
                    "link": format!("/events?sensor={sensor}&{link_key}={key}"),
                }))
            })
            .collect()
    };
    Ok(Json(json!({
        "sensor": sensor,
        "ports": rows("ports", "port"),
        "protocols": rows("protocols", "proto"),
    })))
}

#[derive(Deserialize)]
pub struct MlAckBody {
    /// The anomaly document's _id (surfaced as _doc_id on store rows).
    pub key: String,
    pub ack: bool,
    #[serde(default)]
    pub actor: String,
}

pub async fn ml_anomaly_ack(
    State(state): State<AppState>,
    Json(body): Json<MlAckBody>,
) -> Result<Json<Value>, (StatusCode, String)> {
    if body.key.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "missing anomaly key".into()));
    }
    let record = json!({
        "Key": body.key,
        "Acknowledged": body.ack,
        "AckedBy": body.actor,
        "AckedAt": chrono::Utc::now().to_rfc3339(),
    });
    state
        .es
        .index_doc(ML_ACK_INDEX, &body.key, record.clone())
        .await
        .map_err(bad_gateway)?;
    Ok(Json(record))
}

/// GET /api/v1/ml-anomalies/acks — key → ack record, merged client-side
/// into the anomalies list (mirrors refreshMLAnomalyAcks).
pub async fn ml_anomaly_acks(State(state): State<AppState>) -> Result<Json<Value>, (StatusCode, String)> {
    let result = state
        .es
        .search_index(&[ML_ACK_INDEX], json!({"size": 10000, "query": {"match_all": {}}}))
        .await
        .map_err(bad_gateway)?;
    let mut map = serde_json::Map::new();
    for hit in result["hits"]["hits"].as_array().into_iter().flatten() {
        if let Some(id) = hit["_id"].as_str() {
            map.insert(id.to_string(), hit["_source"].clone());
        }
    }
    Ok(Json(Value::Object(map)))
}
