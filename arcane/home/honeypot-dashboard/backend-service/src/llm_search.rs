//! /api/v1/llm-search?q= — semantic search over llm-analysis session
//! summaries (#151), ported from llm_analysis_search.go: embed the
//! operator's free-text query via Ollama (/api/embed, same model and
//! request shape llm-worker uses for the write side), then a bounded ES
//! kNN over the versioned embedding field. Local-only endpoint contract
//! preserved; unreachable Ollama reports unavailable, never a broken
//! page or a fake non-semantic result set.

use axum::{
    extract::{Query, State},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::IpAddr;

use crate::AppState;

const SEARCH_K: usize = 10;
const SEARCH_CANDIDATES: usize = 100;

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub limit: usize,
}

/// Mirrors llm-worker's endpoint_is_local(): plain http, bare host, and a
/// known service name / localhost / private address only.
fn ollama_url() -> Option<String> {
    let raw = std::env::var("OLLAMA_URL").ok().filter(|value| !value.is_empty())?;
    let url = reqwest::Url::parse(&raw).ok()?;
    if url.scheme() != "http" || !url.username().is_empty() || url.query().is_some() {
        return None;
    }
    if !matches!(url.path(), "" | "/") {
        return None;
    }
    let host = url.host_str()?.to_lowercase();
    let local = host == "ollama"
        || host == "localhost"
        || host.parse::<IpAddr>().map(|ip| match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => v6.is_loopback(),
        }).unwrap_or(false);
    local.then(|| raw.trim_end_matches('/').to_string())
}

async fn embed(base: &str, model: &str, text: &str) -> anyhow::Result<Vec<f64>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let response = client
        .post(format!("{base}/api/embed"))
        .json(&json!({"model": model, "input": text}))
        .send()
        .await?;
    if !response.status().is_success() {
        anyhow::bail!("ollama embed: {}", response.status());
    }
    let payload: Value = response.json().await?;
    let vector: Vec<f64> = payload["embeddings"]
        .as_array()
        .and_then(|embeddings| embeddings.first())
        .and_then(|first| first.as_array())
        .map(|values| values.iter().filter_map(|v| v.as_f64()).collect())
        .unwrap_or_default();
    if vector.is_empty() {
        anyhow::bail!("ollama embed: response did not carry exactly one non-empty vector");
    }
    Ok(vector)
}

pub async fn search(State(state): State<AppState>, Query(query): Query<SearchQuery>) -> Json<Value> {
    let mut text = query.q.trim().to_string();
    if text.is_empty() {
        return Json(json!({"available": true, "hits": []}));
    }
    let Some(base) = ollama_url() else {
        return Json(json!({"available": false, "reason": "semantic search is not configured on this deployment"}));
    };
    text.truncate(512);
    let model = std::env::var("LLM_EMBEDDING_MODEL").unwrap_or_else(|_| "nomic-embed-text:latest".into());
    let vector = match embed(&base, &model, &text).await {
        Ok(vector) => vector,
        Err(error) => {
            return Json(json!({"available": false, "reason": format!("embedding the query failed: {error}")}));
        }
    };
    let limit = if query.limit == 0 || query.limit > SEARCH_K { SEARCH_K } else { query.limit };
    let body = json!({
        "knn": {
            "field": "embedding",
            "query_vector": vector,
            "k": limit,
            "num_candidates": SEARCH_CANDIDATES,
            "filter": {"term": {"doc_type": "session"}}
        },
        "_source": {"excludes": ["embedding"]}
    });
    match state.es.search_index(&["llm-analysis"], body).await {
        Ok(result) => {
            let hits: Vec<Value> = result["hits"]["hits"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|hit| {
                    let mut doc = hit["_source"].clone();
                    doc["score"] = hit["_score"].clone();
                    doc
                })
                .collect();
            Json(json!({"available": true, "hits": hits}))
        }
        Err(error) => Json(json!({"available": false, "reason": error.to_string()})),
    }
}
