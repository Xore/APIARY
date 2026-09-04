//! Thin Elasticsearch access layer. Index families and field names mirror
//! the Go dashboard's es_aggregate.go exactly (ECS: honeypot-v2-* for every
//! decoy sensor, suricata-v2-* for Suricata -- one multi-index pattern per
//! query, #1136), so both tiers agree on the data until the Go tier
//! retires at cutover.

use elasticsearch::{
    cluster::ClusterHealthParts,
    http::transport::{SingleNodeConnectionPool, TransportBuilder},
    params::{OpType, Refresh},
    BulkOperation, BulkParts, Elasticsearch, SearchParts,
};
use serde_json::Value;
use std::collections::HashSet;
use std::time::Duration;

/// Every index family that carries sensor events, keyed by `event.sensor`.
///
/// This is what `Es::search` targets, so it decides what the whole dashboard
/// can see: the source-health feed list, the sensor filter values, the
/// overview KPIs and the event explorer all read through it. An index absent
/// here is invisible everywhere, silently -- the page renders fine, it just
/// never mentions the sensor. #1742's sensors were missing for exactly that
/// reason, 573,463 documents of them, and portbridge had been missing since
/// long before that.
///
/// Each family here was checked for what `source.ip` actually means on it,
/// because an index whose source is our own infrastructure would re-create
/// #1677 by attributing its events to us:
///
///   portbridge-v2-*   real attacker address (zero fleet-sourced documents)
///   zeek-v1-*         real attacker address -- it sniffs the public NIC
///   traefik-v1-*      real client address
///   huginn-v1-*       often OUR VPS: it records the responder's SYN-ACK and
///                     server-uptime observations as well as the client's SYN
///   zeek-proxy-v1-*   usually the tunnel peer: it watches the relay side, so
///                     the originator is our own VPS forwarding inward
///
/// The last two are still included, because the exclusion that makes them
/// safe already exists and is applied at query level: dashboard.rs's
/// `self_addresses()` (#1677/#1779) drops the tunnel peer and everything in
/// HONEYPOT_SELF_IPS from the attacker-ranking aggregations, and charts.rs
/// inherits it. Their event counts and freshness are still worth surfacing --
/// "is this sensor alive" is the question source-health exists to answer.
pub const EVENT_INDICES: &[&str] = &[
    "honeypot-v2-*",
    "suricata-v2-*",
    "portbridge-v2-*",
    "zeek-v1-*",
    "zeek-proxy-v1-*",
    "huginn-v1-*",
    "traefik-v1-*",
];

/// The "is this a login/auth attempt" query fragment (#1611 workstream C),
/// shared by every login-counting aggregation (aggregates.rs's sources
/// page, dashboard.rs's overview KPIs, reports_data.rs's report
/// summaries). The original `honeypot.event ∈ {login, auth_attempt}`
/// filter missed most real auth activity — audited against the live
/// per-sensor vocabularies (#1611's own live-cluster audit):
/// - cowrie logs cowrie.login.success/failed on `honeypot.eventid`, never
///   `honeypot.event`, and is the single largest auth source (1.26M docs
///   on the audited deployment) — entirely uncounted before this.
/// - rdp-honeypot's auth rides on a plain `connect` event with a non-empty
///   `honeypot.username` (the mstshash), no dedicated login/auth_attempt
///   kind of its own.
/// - `honeypot.canonical_user`'s existence is a sensor-agnostic catch-all:
///   ip-enrichment-worker promotes it for beelzebub/dionaea today and will
///   cover more sensors as that promotion's own coverage grows (#1611
///   workstreams D/G) — this clause benefits automatically as it does,
///   with no further change needed here.
pub fn logins_filter() -> Value {
    serde_json::json!({"bool": {"should": [
        {"terms": {"honeypot.event": ["login", "auth_attempt"]}},
        {"terms": {"honeypot.eventid": ["cowrie.login.success", "cowrie.login.failed"]}},
        {"bool": {"filter": [
            {"term": {"event.sensor": "rdp-honeypot"}},
            {"exists": {"field": "honeypot.username"}}
        ]}},
        {"exists": {"field": "honeypot.canonical_user"}}
    ], "minimum_should_match": 1}})
}

/// The ingest-time health-check probe exclusion (#1902 residue, audited in
/// #2145): the ip-enrichment worker marks every fleet/self healthcheck
/// event with `honeypot.internal_probe = true` (ip_enrichment/sensors.rs)
/// and strips its `source.ip`, but the documents still land in
/// `honeypot-v2-*` — roughly 92k/day on the audited deployment — so any
/// honeypot-v2 aggregation built without this clause silently counts
/// sensor liveness probes as attacker traffic. Every attacker-facing
/// aggregation over the index must carry this term in its `must_not`;
/// reads that exist to observe the probes themselves (source-health
/// pages, lag/activity sampling) deliberately omit it — that asymmetry is
/// the recorded #2145 decision to keep probes indexed rather than move
/// them to a separate index.
pub fn internal_probe_exclusion() -> Value {
    serde_json::json!({"term": {"honeypot.internal_probe": true}})
}

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
        // Transport::single_node's own default carries no request timeout at
        // all -- confirmed live during #1628's preflight: backend-worker's
        // /healthz calls this same shared client's ping() (main.rs's healthz
        // handler), and a slow/stuck query from any of its four bundled
        // worker loops (correlator's aggregation was hitting Elasticsearch's
        // own too_many_buckets_exception on every cycle against real data,
        // plausibly saturating the cluster's search queue for a while) could
        // therefore hang ping() indefinitely too, since nothing ever timed
        // out client-side -- the container never crashed, /healthz just
        // never returned, and something external kept restarting it every
        // few minutes on the resulting healthcheck failure. 30s bounds the
        // worst case without punishing legitimately slower real-data
        // queries the way CI's fixture-sized indices never needed to.
        let conn_pool = SingleNodeConnectionPool::new(url.parse()?);
        let transport = TransportBuilder::new(conn_pool)
            .timeout(Duration::from_secs(30))
            .build()?;
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

    /// Builds `delete_by_query_except`'s "everything except these ids"
    /// query as **one** `ids` clause holding every kept id in its `values`
    /// array, rather than one `must_not` clause per id (#2899).
    ///
    /// Some callers build large `keep` lists — correlations.rs's flow sweep
    /// caps at 2,000 (`FLOW_BUCKET_CAP`), its credential-reuse sweep at 800
    /// (`CRED_PAIR_CAP * 4`), correlator.rs's cluster sweep at 1,000 (four
    /// `terms` aggs of `size: 250`) — and correlator.rs's campaign sweep
    /// derives its ids from `ip_prefix` aggregations that carry no `size`
    /// key at all, so its keep list is unbounded by construction. The
    /// per-id form made the query's own bool clause count scale with
    /// `keep.len()`, independent of how many documents actually exist.
    ///
    /// What that risks, measured rather than assumed.
    /// `indices.query.bool.max_clause_count` reports **4096** as its default
    /// and is untuned on the deployed cluster (`persistent` and `transient`
    /// both empty) — but 4096 is not the number that gets enforced. The node
    /// derives the limit it actually applies from its own heap. Reproduced
    /// on Elasticsearch 9.5.1 / Lucene 10.5.0, same version the deployment
    /// runs, 2026-09-03:
    ///
    /// | node heap | setting reports | actually enforced | 5,000 clauses | 20,000 clauses |
    /// |---|---|---|---|---|
    /// | 1 GiB | 4096 | 3449 | rejected, 0.9 s | — |
    /// | 4 GiB | 4096 | 13797 | accepted, 1.4 s | rejected, 11.2 s (688 KB body) |
    ///
    /// So the wall is a property of the node, not a constant a caller can
    /// reason about, and it moves under the deployment: the same 5,000-clause
    /// probe that fails on a small node succeeded against the production
    /// cluster (HTTP 200, 2.3 s), while a 20,000-clause probe there never
    /// returned at all and coincided with that node going hard-down (#2914).
    /// Crossing it is a `query_shard_exception` — which aborts the whole
    /// resync sweep, after the node has already spent real time parsing the
    /// request. A single `ids` clause holds an arbitrary number of values
    /// without adding bool clauses, so the growth disappears regardless of
    /// how large any caller's keep list gets, and the primitive stops
    /// depending on how much heap the cluster happens to have.
    fn except_query(keep: &[String]) -> Value {
        serde_json::json!({"query": {"bool": {"must_not": [{"ids": {"values": keep}}]}}})
    }

    /// Deletes every document in `index` whose id is not in `keep` — a
    /// "delete-by-query minus explicit ids" full-resync primitive for a
    /// worker that recomputes its whole output set every cycle and is the
    /// index's sole writer (correlator-worker's campaigns-v1/attacker-
    /// clusters-v1: upsert this cycle's fresh docs, then this call removes
    /// whatever's left over from a group/cluster that no longer qualifies).
    /// `conflicts=proceed` matches the Go worker's own posture — a
    /// concurrent version conflict on a doc mid-delete is not worth
    /// aborting the sweep over. A missing index (404, first run) is not an
    /// error, same idempotent posture as `delete_doc`.
    pub async fn delete_by_query_except(&self, index: &str, keep: &[String]) -> anyhow::Result<()> {
        let body = Self::except_query(keep);
        let response = self
            .client
            .delete_by_query(elasticsearch::DeleteByQueryParts::Index(&[index]))
            .conflicts(elasticsearch::params::Conflicts::Proceed)
            .body(body)
            .send()
            .await?;
        let status = response.status_code();
        if !status.is_success() && status.as_u16() != 404 {
            let body = response.json::<Value>().await.unwrap_or_default();
            anyhow::bail!("elasticsearch delete_by_query {}: {}", status, body);
        }
        Ok(())
    }

    /// `_delete_by_query` with a caller-supplied query, returning the
    /// deleted count — the general-purpose sibling of
    /// `delete_by_query_except`'s keep-list-shaped one. Ported from
    /// elastic.go's purgeDeadLetters: `conflicts=proceed`, same reasoning
    /// as above (a version conflict mid-sweep isn't worth aborting over).
    pub async fn delete_by_query(&self, index: &str, query: Value) -> anyhow::Result<u64> {
        let response = self
            .client
            .delete_by_query(elasticsearch::DeleteByQueryParts::Index(&[index]))
            .conflicts(elasticsearch::params::Conflicts::Proceed)
            .body(serde_json::json!({"query": query}))
            .send()
            .await?;
        let status = response.status_code();
        let body = response.json::<Value>().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("elasticsearch delete_by_query {}: {}", status, body);
        }
        Ok(body["deleted"].as_u64().unwrap_or(0))
    }

    /// `_update_by_query` across `indices` with a caller-supplied query and
    /// painless script (`script_params` become the script's `params`),
    /// returning the updated count. `conflicts=proceed` — same reasoning as
    /// `delete_by_query`: a version conflict racing an in-flight write
    /// isn't worth aborting the whole sweep over, the next cycle will
    /// pick it up.
    pub async fn update_by_query(
        &self,
        indices: &[&str],
        query: Value,
        script_source: &str,
        script_params: Value,
    ) -> anyhow::Result<u64> {
        let body = serde_json::json!({
            "query": query,
            "script": {"source": script_source, "lang": "painless", "params": script_params},
        });
        let response = self
            .client
            .update_by_query(elasticsearch::UpdateByQueryParts::Index(indices))
            .conflicts(elasticsearch::params::Conflicts::Proceed)
            .body(body)
            .send()
            .await?;
        let status = response.status_code();
        let body = response.json::<Value>().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("elasticsearch update_by_query {}: {}", status, body);
        }
        Ok(body["updated"].as_u64().unwrap_or(0))
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

    /// Bulk `index` (plain upsert, not `create`) a batch of documents, each
    /// against its own (index, id) — the primitive es_importer.rs needs to
    /// mirror analysis/es-results-importer/importer.py's `bulk(es, actions,
    /// stats_only=False, raise_on_error=False)` call. Returns the `_id` of
    /// every operation the cluster reported as failed (network/transport
    /// failure fails every id in the batch); an empty set means every
    /// document in `operations` was indexed. Deliberately per-item, not a
    /// single pass/fail for the whole batch — callers need this to only
    /// advance dedup state for documents that actually made it into ES,
    /// matching the Python importer's own advance_state_after_bulk
    /// semantics on a partial batch failure.
    /// `#1978`: documents are borrowed — the caller's pending batch (which
    /// for chunked artifacts is hundreds of megabytes of base64 strings)
    /// must not be duplicated just to serialize it once.
    pub async fn bulk_index(
        &self,
        operations: Vec<(&str, &str, &Value)>,
    ) -> anyhow::Result<HashSet<String>> {
        if operations.is_empty() {
            return Ok(HashSet::new());
        }
        let all_ids: HashSet<String> = operations.iter().map(|(_, id, _)| id.to_string()).collect();
        let ops: Vec<BulkOperation<&Value>> = operations
            .into_iter()
            .map(|(index, id, doc)| BulkOperation::index(doc).index(index).id(id).into())
            .collect();
        let response = self.client.bulk(BulkParts::None).body(ops).send().await;
        let response = match response {
            Ok(r) => r,
            Err(_) => return Ok(all_ids), // transport failure: every op unconfirmed, retry next pass
        };
        let status = response.status_code();
        let json = response.json::<Value>().await?;
        if !status.is_success() {
            // A bulk-level rejection (e.g. auth, malformed request) fails
            // every operation in the batch, same as a transport error above.
            return Ok(all_ids);
        }
        let mut failed = HashSet::new();
        for item in json["items"].as_array().into_iter().flatten() {
            // Every op here is "index" (see BulkOperation::index above), so
            // the per-item result always nests under "index".
            let result = &item["index"];
            let ok = result["status"].as_u64().map(|s| (200..300).contains(&s)).unwrap_or(false);
            if !ok {
                if let Some(id) = result["_id"].as_str() {
                    failed.insert(id.to_string());
                }
            }
        }
        Ok(failed)
    }

    /// Point-in-time + search_after pagination, needed because
    /// Elasticsearch's *default* `index.max_result_window` is 10,000 — a
    /// single oversized `size` request hard-fails past that, not just
    /// returns less. Every other query in this crate stays under that cap
    /// by design; attacker-identity-worker's event fetch and existing-
    /// entity load can legitimately exceed it. `body_fn` receives the
    /// previous page's `search_after` value (`None` on the first call) and
    /// returns the query body for the next page — the caller owns `query`/
    /// `sort`/`_source`, this primitive only injects `size`/`pit` and walks
    /// `search_after` forward. Returns every hit object as-is (including
    /// `_source`/`sort`) across up to `max_pages` pages of `page_size` each.
    /// Ported from attacker-identity-worker's own es.go
    /// (openPointInTime/closePointInTime/docScrollAll).
    pub async fn search_paginated(
        &self,
        index_pattern: &str,
        mut body_fn: impl FnMut(Option<&Value>) -> Value,
        page_size: u64,
        max_pages: u32,
    ) -> anyhow::Result<Vec<Value>> {
        // A PIT open on an index that doesn't exist yet returns 404 — the
        // expected state before a caller's very first successful write
        // (every dashboard-owned index here is created lazily on first
        // index_doc). Ported from attacker-identity-worker's own
        // docScrollAll: treating that as "zero existing documents" rather
        // than an error is what lets a caller like attacker_identity.rs's
        // load_existing_entities bootstrap past its first cycle instead of
        // looping forever on a load failure.
        let exists = self.client.indices().exists(elasticsearch::indices::IndicesExistsParts::Index(&[index_pattern])).send().await?;
        if exists.status_code().as_u16() == 404 {
            return Ok(Vec::new());
        }

        let open = self
            .client
            .open_point_in_time(elasticsearch::OpenPointInTimeParts::Index(&[index_pattern]))
            .keep_alive("2m")
            .send()
            .await?;
        let open_json = open.json::<Value>().await?;
        let pit_id = open_json["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("open_point_in_time: no id in response: {open_json}"))?
            .to_string();

        let mut out = Vec::new();
        let mut search_after: Option<Value> = None;
        let result: anyhow::Result<()> = async {
            for _ in 0..max_pages {
                let mut body = body_fn(search_after.as_ref());
                body["size"] = Value::from(page_size);
                body["pit"] = serde_json::json!({"id": pit_id, "keep_alive": "2m"});
                let response = self.client.search(SearchParts::None).body(body).send().await?;
                let status = response.status_code();
                let json = response.json::<Value>().await?;
                if !status.is_success() {
                    anyhow::bail!("elasticsearch pit search {status}: {json}");
                }
                let hits = json["hits"]["hits"].as_array().cloned().unwrap_or_default();
                if hits.is_empty() {
                    break;
                }
                let got = hits.len() as u64;
                let last_sort = hits.last().and_then(|h| h.get("sort")).cloned();
                out.extend(hits);
                if got < page_size {
                    break;
                }
                search_after = last_sort;
            }
            Ok(())
        }
        .await;

        // Best-effort close regardless of the loop's outcome above — a PIT
        // left open only holds a small amount of cluster state until its
        // own keep_alive lapses, not worth masking the real error above.
        let _ = self
            .client
            .close_point_in_time()
            .body(serde_json::json!({"id": pit_id}))
            .send()
            .await;
        result?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logins_filter_has_four_should_clauses_any_one_matches() {
        let f = logins_filter();
        let should = f["bool"]["should"].as_array().expect("should array");
        assert_eq!(should.len(), 4);
        assert_eq!(f["bool"]["minimum_should_match"], 1);
        assert_eq!(should[0]["terms"]["honeypot.event"], serde_json::json!(["login", "auth_attempt"]));
        assert_eq!(should[1]["terms"]["honeypot.eventid"], serde_json::json!(["cowrie.login.success", "cowrie.login.failed"]));
        assert_eq!(should[2]["bool"]["filter"][0]["term"]["event.sensor"], "rdp-honeypot");
        assert_eq!(should[2]["bool"]["filter"][1]["exists"]["field"], "honeypot.username");
        assert_eq!(should[3]["exists"]["field"], "honeypot.canonical_user");
    }

    // -- #2899: delete_by_query_except must not scale bool clause count
    // with keep.len() --

    /// The clause ceiling this test holds the construction to. 4096 is what
    /// `indices.query.bool.max_clause_count` reports as its default on the
    /// deployed cluster, untuned -- not 1024, which is what an earlier draft
    /// of this fix asserted. It is a *reference point*, not the enforced
    /// limit: the enforced value is derived from node heap and was measured
    /// at 3449 (1 GiB heap) and 13797 (4 GiB heap) on Elasticsearch 9.5.1,
    /// so no single number is the wall. See `Es::except_query` for the
    /// measurements. What matters is the contract below -- clause count
    /// independent of `keep.len()` -- which holds at any of them.
    const REPORTED_MAX_CLAUSE_COUNT: usize = 4096;

    /// The largest keep list any *bounded* caller can produce today:
    /// correlations.rs's `FLOW_BUCKET_CAP`. correlator.rs's campaign sweep
    /// has no cap at all.
    const LARGEST_BOUNDED_CALLER_KEEP: usize = 2_000;

    fn bool_clause_count(body: &Value) -> usize {
        body["query"]["bool"]["must_not"].as_array().map(|clauses| clauses.len()).unwrap_or(0)
    }

    /// The actual contract, and the one assertion that fails against the
    /// pre-fix construction at every size: the clause count is O(1) in
    /// `keep.len()`. Stated against the largest bounded caller's keep list
    /// (correlations.rs's flow sweep, 2,000 ids) so a regression shows up
    /// at a size a real caller reaches, not only past the cluster ceiling.
    #[test]
    fn clause_count_does_not_scale_with_keep_len() {
        let keep: Vec<String> = (0..LARGEST_BOUNDED_CALLER_KEEP).map(|i| format!("id-{i}")).collect();
        let body = Es::except_query(&keep);
        assert_eq!(
            bool_clause_count(&body),
            1,
            "built {} bool clauses for {} kept ids — the query must stay one `ids` clause regardless of keep.len()",
            bool_clause_count(&body),
            keep.len()
        );
    }

    /// The regression case the correlator's real callers can actually
    /// produce (#2047/#2238): the campaign path's `ip_prefix` aggregation
    /// carries no `size` key, so its keep list is unbounded. At 8,192 ids a
    /// must_not-per-id query builds 8,192 bool clauses — past every enforced
    /// limit measured on 9.5.1 (3449 at 1 GiB heap, 13797 at 4 GiB is the
    /// only one it stays under) — and this assertion fails against that
    /// construction, which is what this test exists to catch.
    #[test]
    fn stays_under_the_clause_ceiling_past_the_wall() {
        let keep: Vec<String> = (0..(REPORTED_MAX_CLAUSE_COUNT * 2)).map(|i| format!("id-{i}")).collect();
        let body = Es::except_query(&keep);
        assert!(
            bool_clause_count(&body) <= REPORTED_MAX_CLAUSE_COUNT,
            "built {} bool clauses for {} kept ids — must_not-per-id would run past the cluster's clause ceiling",
            bool_clause_count(&body),
            keep.len()
        );
    }

    #[test]
    fn keep_list_survives_intact_in_the_single_ids_clause() {
        let keep = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let body = Es::except_query(&keep);
        assert_eq!(bool_clause_count(&body), 1, "expected exactly one must_not clause regardless of keep.len()");
        assert_eq!(body["query"]["bool"]["must_not"][0]["ids"]["values"], serde_json::json!(["a", "b", "c"]));
    }

    #[test]
    fn empty_keep_list_still_produces_a_valid_query() {
        let body = Es::except_query(&[]);
        assert_eq!(body["query"]["bool"]["must_not"][0]["ids"]["values"], serde_json::json!([]));
    }
}
