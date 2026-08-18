//! Thin Elasticsearch access layer. Index families and field names mirror
//! the Go dashboard's es_aggregate.go exactly (ECS: honeypot-v2-* for every
//! decoy sensor, suricata-v2-* for Suricata -- one multi-index pattern per
//! query, #1136), so both tiers agree on the data until the Go tier
//! retires at cutover.

use elasticsearch::{
    cluster::ClusterHealthParts,
    http::transport::Transport,
    params::{OpType, Refresh},
    Elasticsearch, SearchParts,
};
use serde_json::Value;

pub const EVENT_INDICES: &[&str] = &["honeypot-v2-*", "suricata-v2-*"];

pub struct Es {
    client: Elasticsearch,
}

/// A document write that can lose an optimistic-concurrency race. Distinct
/// from `anyhow::Error` so callers doing their own create-or-reuse /
/// compare-and-swap retry logic (workbench runs/recipes) can match on
/// `Conflict` without string-sniffing an error message.
#[derive(thiserror::Error, Debug)]
pub enum WriteError {
    #[error("elasticsearch write conflict")]
    Conflict,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Es {
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        let transport = Transport::single_node(url)?;
        Ok(Self {
            client: Elasticsearch::new(transport),
        })
    }

    /// Cluster color (green/yellow/red), "unreachable" on transport error.
    pub async fn cluster_status(&self) -> String {
        match self
            .client
            .cluster()
            .health(ClusterHealthParts::None)
            .send()
            .await
        {
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
        let indices = json["indices"]
            .as_object()
            .map(|map| map.len() as u64)
            .unwrap_or(0);
        let docs = json["_all"]["total"]["docs"]["count"].as_u64().unwrap_or(0);
        let bytes = json["_all"]["total"]["store"]["size_in_bytes"]
            .as_u64()
            .unwrap_or(0);
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

    /// Fetch one document's _source by id; Ok(None) on 404.
    pub async fn get_doc(&self, index: &str, id: &str) -> anyhow::Result<Option<Value>> {
        Ok(self
            .get_doc_meta(index, id)
            .await?
            .map(|(source, _, _)| source))
    }

    /// get_doc plus the seq_no/primary_term a caller needs to make a
    /// conditional overwrite (index_doc_cas) — the compare-and-swap
    /// primitive Go's docGet+docIndex(create=false, seqNo, primaryTerm)
    /// pair gives for free, needed by any read-modify-write loop (workbench
    /// run/recipe updates) beyond this crate's existing update_doc (which
    /// only ever does a partial-field merge with server-side conflict
    /// retries, not a caller-driven read-modify-write).
    pub async fn get_doc_meta(
        &self,
        index: &str,
        id: &str,
    ) -> anyhow::Result<Option<(Value, i64, i64)>> {
        let response = self
            .client
            .get(elasticsearch::GetParts::IndexId(index, id))
            .send()
            .await?;
        if response.status_code().as_u16() == 404 {
            return Ok(None);
        }
        let status = response.status_code();
        let json = response.json::<Value>().await?;
        if !status.is_success() {
            anyhow::bail!("elasticsearch get {}: {}", status, json);
        }
        let Some(source) = json.get("_source").cloned() else {
            return Ok(None);
        };
        let seq_no = json["_seq_no"].as_i64().unwrap_or(0);
        let primary_term = json["_primary_term"].as_i64().unwrap_or(0);
        Ok(Some((source, seq_no, primary_term)))
    }

    /// Creates a document that must not already exist (`op_type=create`),
    /// waiting for the write to become search-visible before returning —
    /// the primitive workbench run/recipe creation uses for atomic,
    /// cross-instance idempotent dedup: the document's own id IS the
    /// caller's idempotency key, so a losing race is a genuine, correct
    /// "someone already submitted this" rather than an error to retry.
    /// `WriteError::Conflict` on a 409 (id already exists); the caller
    /// fetches the existing document itself to decide what "reused" means.
    pub async fn index_doc_create(
        &self,
        index: &str,
        id: &str,
        doc: Value,
    ) -> Result<(), WriteError> {
        let response = self
            .client
            .index(elasticsearch::IndexParts::IndexId(index, id))
            .op_type(OpType::Create)
            .refresh(Refresh::WaitFor)
            .body(doc)
            .send()
            .await
            .map_err(|error| WriteError::Other(error.into()))?;
        let status = response.status_code();
        if status.as_u16() == 409 {
            return Err(WriteError::Conflict);
        }
        if !status.is_success() {
            let body = response.json::<Value>().await.unwrap_or_default();
            return Err(WriteError::Other(anyhow::anyhow!(
                "elasticsearch create {}: {}",
                status,
                body
            )));
        }
        Ok(())
    }

    /// Conditional overwrite: only applies if the document's current
    /// seq_no/primary_term still match what the caller read (from
    /// get_doc_meta). `WriteError::Conflict` on a lost race (409) — the
    /// idiomatic Rust equivalent of Go's docIndex(create=false, seqNo,
    /// primaryTerm) compare-and-swap, for a caller-driven read-modify-write
    /// retry loop (workbench run updates: reconcile-on-read, child
    /// cancel/retry actions).
    pub async fn index_doc_cas(
        &self,
        index: &str,
        id: &str,
        doc: Value,
        seq_no: i64,
        primary_term: i64,
    ) -> Result<(), WriteError> {
        let response = self
            .client
            .index(elasticsearch::IndexParts::IndexId(index, id))
            .if_seq_no(seq_no)
            .if_primary_term(primary_term)
            .body(doc)
            .send()
            .await
            .map_err(|error| WriteError::Other(error.into()))?;
        let status = response.status_code();
        if status.as_u16() == 409 {
            return Err(WriteError::Conflict);
        }
        if !status.is_success() {
            let body = response.json::<Value>().await.unwrap_or_default();
            return Err(WriteError::Other(anyhow::anyhow!(
                "elasticsearch index {}: {}",
                status,
                body
            )));
        }
        Ok(())
    }

    /// Index (upsert) one document by id.
    pub async fn index_doc(&self, index: &str, id: &str, doc: Value) -> anyhow::Result<()> {
        let response = self
            .client
            .index(elasticsearch::IndexParts::IndexId(index, id))
            .body(doc)
            .send()
            .await?;
        let status = response.status_code();
        if !status.is_success() {
            let body = response.json::<Value>().await.unwrap_or_default();
            anyhow::bail!("elasticsearch index {}: {}", status, body);
        }
        Ok(())
    }

    /// Deletes one document by id. Ok(()) even if it was already gone
    /// (404) — the same idempotent-delete posture Go's docDelete callers
    /// (pruneGenerated's best-effort retention sweep) rely on.
    pub async fn delete_doc(&self, index: &str, id: &str) -> anyhow::Result<()> {
        let response = self
            .client
            .delete(elasticsearch::DeleteParts::IndexId(index, id))
            .send()
            .await?;
        let status = response.status_code();
        if !status.is_success() && status.as_u16() != 404 {
            let body = response.json::<Value>().await.unwrap_or_default();
            anyhow::bail!("elasticsearch delete {}: {}", status, body);
        }
        Ok(())
    }

    pub async fn ping(&self) -> bool {
        self.client
            .ping()
            .send()
            .await
            .map(|r| r.status_code().is_success())
            .unwrap_or(false)
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
