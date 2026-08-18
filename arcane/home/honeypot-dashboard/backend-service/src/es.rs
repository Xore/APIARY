//! Thin Elasticsearch access layer. Index families and field names mirror
//! the Go dashboard's es_aggregate.go exactly (ECS: honeypot-v2-* for every
//! decoy sensor, suricata-v2-* for Suricata -- one multi-index pattern per
//! query, #1136), so both tiers agree on the data until the Go tier
//! retires at cutover.

use elasticsearch::{cluster::ClusterHealthParts, http::transport::Transport, Elasticsearch, SearchParts};
use serde_json::Value;

pub const EVENT_INDICES: &[&str] = &["honeypot-v2-*", "suricata-v2-*"];

pub struct Es {
    client: Elasticsearch,
}

impl Es {
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        let transport = Transport::single_node(url)?;
        Ok(Self { client: Elasticsearch::new(transport) })
    }

    /// Cluster color (green/yellow/red), "unreachable" on transport error.
    pub async fn cluster_status(&self) -> String {
        match self.client.cluster().health(ClusterHealthParts::None).send().await {
            Ok(response) => response
                .json::<Value>()
                .await
                .ok()
                .and_then(|value| value["status"].as_str().map(String::from))
                .unwrap_or_else(|| "unknown".into()),
            Err(_) => "unreachable".into(),
        }
    }

    /// Cluster-wide index stats summary: (index_count, doc_count, bytes).
    pub async fn storage_summary(&self) -> anyhow::Result<(u64, u64, u64)> {
        let response = self
            .client
            .indices()
            .stats(elasticsearch::indices::IndicesStatsParts::None)
            .send()
            .await?;
        let json = response.json::<Value>().await?;
        let indices = json["indices"].as_object().map(|map| map.len() as u64).unwrap_or(0);
        let docs = json["_all"]["total"]["docs"]["count"].as_u64().unwrap_or(0);
        let bytes = json["_all"]["total"]["store"]["size_in_bytes"].as_u64().unwrap_or(0);
        Ok((indices, docs, bytes))
    }

    /// Partial-document update with conflict retries — the idiomatic
    /// equivalent of the Go tier's optimistic seq_no/primary_term loop.
    pub async fn update_doc(&self, index: &str, id: &str, doc: Value) -> anyhow::Result<()> {
        let response = self
            .client
            .update(elasticsearch::UpdateParts::IndexId(index, id))
            .retry_on_conflict(3)
            .body(serde_json::json!({"doc": doc}))
            .send()
            .await?;
        let status = response.status_code();
        if !status.is_success() {
            let body = response.json::<Value>().await.unwrap_or_default();
            anyhow::bail!("elasticsearch update {}: {}", status, body);
        }
        Ok(())
    }

    pub async fn ping(&self) -> bool {
        self.client.ping().send().await.map(|r| r.status_code().is_success()).unwrap_or(false)
    }

    /// One `_search` against the shared event indices; body is the caller's
    /// full query DSL. `ignore_unavailable` matches the Go client's posture
    /// so a not-yet-created index family never fails the whole query.
    pub async fn search(&self, body: Value) -> anyhow::Result<Value> {
        self.search_index(EVENT_INDICES, body).await
    }

    /// `_search` against arbitrary indices — the worker/store index
    /// families (campaigns-v1, attackers-v1, dashboard-*-v1, ...).
    pub async fn search_index(&self, indices: &[&str], body: Value) -> anyhow::Result<Value> {
        let response = self
            .client
            .search(SearchParts::Index(indices))
            .ignore_unavailable(true)
            .body(body)
            .send()
            .await?;
        let status = response.status_code();
        let json = response.json::<Value>().await?;
        if !status.is_success() {
            anyhow::bail!("elasticsearch {}: {}", status, json);
        }
        Ok(json)
    }
}
