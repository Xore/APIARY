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

/// The kNN request for one query vector (#2117): the filter pins BOTH
/// doc_type and embedding_model, so ranking happens only inside the vector
/// space the query was embedded in. The write side (llm-worker) stamps
/// embedding_model on every document precisely because a model switch —
/// an env edit, or a registry tag moving under `:latest` — leaves the
/// index holding two incompatible same-dimension spaces that ES will
/// otherwise happily score against each other: plausible-looking
/// similarities, wrong ranking, no error anywhere. Documents from other
/// models drop out of results until the planned digest-keyed backfill
/// re-embeds them; search() reports that shrink rather than disguising it.
fn knn_body(model: &str, vector: &[f64], limit: usize) -> Value {
    json!({
        "knn": {
            "field": "embedding",
            "query_vector": vector,
            "k": limit,
            "num_candidates": SEARCH_CANDIDATES,
            "filter": {"bool": {"filter": [
                {"term": {"doc_type": "session"}},
                {"term": {"embedding_model": model}}
            ]}}
        },
        "_source": {"excludes": ["embedding"]}
    })
}

/// The empty-result body, made explicit about WHY it is empty when the
/// index does hold session embeddings from other models (#2117): "no
/// matches" and "matches exist but are not re-embedded yet" need different
/// operator responses. Either way available stays true — this is a
/// filtered-out result, not a failure.
fn empty_hits_response(foreign_embeddings: u64) -> Value {
    if foreign_embeddings > 0 {
        json!({
            "available": true,
            "hits": [],
            "foreign_embeddings": foreign_embeddings,
            "note": format!("{foreign_embeddings} session summaries are embedded by a different model and are excluded until re-embedding")
        })
    } else {
        json!({"available": true, "hits": []})
    }
}

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
    match state.es.search_index(&["llm-analysis"], knn_body(&model, &vector, limit)).await {
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
            // #2117: distinguish a genuinely empty index from one holding
            // only other models' embeddings — the count query runs just for
            // this report, and only when the filtered search came back empty.
            if hits.is_empty() {
                let foreign = json!({
                    "size": 0,
                    "query": {"bool": {
                        "filter": [{"term": {"doc_type": "session"}}],
                        "must_not": [{"term": {"embedding_model": model}}]
                    }}
                });
                let foreign_count = match state.es.search_index(&["llm-analysis"], foreign).await {
                    Ok(count) => count["hits"]["total"]["value"].as_u64().unwrap_or(0),
                    Err(_) => 0,
                };
                return Json(empty_hits_response(foreign_count));
            }
            Json(json!({"available": true, "hits": hits}))
        }
        Err(error) => Json(json!({"available": false, "reason": error.to_string()})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #2117: the kNN filter must pin the query's own model — that term is
    /// what keeps a model switch from ranking across two incompatible
    /// same-dimension vector spaces.
    #[test]
    fn knn_filter_pins_both_doc_type_and_embedding_model() {
        let body = knn_body("nomic-embed-text:latest", &[0.1, 0.2], 5);
        let filter = &body["knn"]["filter"]["bool"]["filter"];
        assert_eq!(filter[0]["term"]["doc_type"], json!("session"));
        assert_eq!(filter[1]["term"]["embedding_model"], json!("nomic-embed-text:latest"));
        assert_eq!(body["knn"]["k"], json!(5));
        // The query vector rides through unchanged.
        assert_eq!(body["knn"]["query_vector"], json!([0.1, 0.2]));
        // Raw vectors never leave the index.
        assert_eq!(body["_source"]["excludes"], json!(["embedding"]));
    }

    #[test]
    fn a_different_configured_model_filters_by_that_model() {
        let body = knn_body("all-minimal:l6", &[0.0], SEARCH_K);
        assert_eq!(body["knn"]["filter"]["bool"]["filter"][1]["term"]["embedding_model"], json!("all-minimal:l6"));
    }

    /// Empty-after-filter is still available:true with zero hits — a
    /// filtered-out result, not an error (#2117 acceptance criterion 3).
    #[test]
    fn empty_without_foreign_embeddings_stays_plain() {
        let body = empty_hits_response(0);
        assert_eq!(body["available"], json!(true));
        assert_eq!(body["hits"], json!([]));
        assert!(body.get("note").is_none());
    }

    #[test]
    fn empty_with_foreign_embeddings_reports_the_exclusion() {
        let body = empty_hits_response(41);
        assert_eq!(body["available"], json!(true));
        assert_eq!(body["hits"], json!([]));
        assert_eq!(body["foreign_embeddings"], json!(41));
        assert!(body["note"].as_str().unwrap_or_default().contains("different model"));
    }
}
