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
