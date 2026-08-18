//! Thin Elasticsearch access layer. Index families and field names mirror
//! the Go dashboard's es_aggregate.go exactly (ECS: honeypot-v2-* for every
//! decoy sensor, suricata-v2-* for Suricata -- one multi-index pattern per
//! query, #1136), so both tiers agree on the data until the Go tier
//! retires at cutover.

use elasticsearch::{http::transport::Transport, Elasticsearch, SearchParts};
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
