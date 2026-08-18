//! Background worker loops (#1610), ported from the Go dashboard's
//! embedded producers. Enabled per-role via WORKER_LOOPS (comma list;
//! empty = pure API role), so the same image serves as API replica or
//! worker on any docker host — stateless, env-configured, all state in
//! ES (per Xore's cross-host requirement).
//!
//! Currently ported: `alert-notifier` — the notifyLoop/alertManager pair
//! (store.go/alerts.go): every ES-derivable alert signal, upserted into
//! dashboard-alert-state-v1 with cooldown + optional webhook. Signals
//! that need host-local file mounts (log-stream sizes, sandbox/ghidra
//! spool health, filebeat stats) move in a later #1610 slice with the
//! mounted worker role.

use serde_json::{json, Value};
use std::time::Duration;

use crate::AppState;

const ALERT_INDEX: &str = "dashboard-alert-state-v1";
const INTERVAL: Duration = Duration::from_secs(60);

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())
}

/// Parse "6h"/"30m"/"90s" (the ALERT_COOLDOWN contract).
fn parse_duration(text: &str) -> Duration {
    let text = text.trim();
    let (digits, unit) = text.split_at(text.len().saturating_sub(1));
    match (digits.parse::<u64>(), unit) {
        (Ok(n), "h") => Duration::from_secs(n * 3600),
        (Ok(n), "m") => Duration::from_secs(n * 60),
        (Ok(n), "s") => Duration::from_secs(n),
        _ => Duration::from_secs(6 * 3600),
    }
}

pub fn spawn_enabled(state: AppState) {
    let loops = env_or("WORKER_LOOPS", "");
    for name in loops.split(',').map(str::trim).filter(|name| !name.is_empty()) {
        match name {
            "alert-notifier" => {
                let state = state.clone();
                tokio::spawn(async move { alert_notifier_loop(state).await });
                tracing::info!("worker loop enabled: alert-notifier");
            }
            other => tracing::warn!(loop_name = other, "unknown worker loop requested"),
        }
    }
}

struct Notifier {
    state: AppState,
    cooldown: Duration,
    webhook: String,
    client: reqwest::Client,
    messages: Vec<String>,
}

impl Notifier {
    /// Ported alertManager.observe: upsert the alert record, return
    /// whether this observation should notify. Single-notifier deployment
    /// — plain get→index, no seq_no fencing (the Go loop's retries guard
    /// against its own web handlers; acks racing a 60s pass lose at most
    /// one count increment).
    async fn observe(&mut self, key: &str, message: String, link: &str, mark_only: bool) {
        let now = chrono::Utc::now().to_rfc3339();
        let existing = self.state.es.get_doc(ALERT_INDEX, key).await.ok().flatten();
        let mut record = existing.unwrap_or_else(|| {
            json!({"Key": key, "FirstSeen": now, "Count": 0, "Acknowledged": false, "LastNotified": null})
        });
        let acknowledged = record["Acknowledged"].as_bool().unwrap_or(false);
        let last_notified = record["LastNotified"]
            .as_str()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok());
        let cooled_down = match last_notified {
            None => true,
            Some(at) => (chrono::Utc::now() - at.with_timezone(&chrono::Utc)).num_seconds() as u64
                >= self.cooldown.as_secs(),
        };
        let notify = !mark_only && !acknowledged && cooled_down;
        record["Message"] = json!(message);
        record["Link"] = json!(link);
        record["LastSeen"] = json!(now);
        record["Count"] = json!(record["Count"].as_u64().unwrap_or(0) + 1);
        if notify || (mark_only && last_notified.is_none()) {
            record["LastNotified"] = json!(now);
        }
        if let Err(error) = self.state.es.index_doc(ALERT_INDEX, key, record).await {
            tracing::warn!(%error, key, "alert upsert failed");
            return;
        }
        if notify {
            self.messages.push(message);
        }
    }

    async fn search(&self, indices: &[&str], body: Value) -> Option<Value> {
        match self.state.es.search_index(indices, body).await {
            Ok(result) => Some(result),
            Err(error) => {
                tracing::warn!(%error, "notifier query failed");
                None
            }
        }
    }

    async fn pass(&mut self, mark_only: bool) {
        self.messages.clear();

        // 1. High-scoring campaigns (campaigns-v1).
        let threshold: u64 = env_or("ALERT_CAMPAIGN_SCORE", "80").parse().unwrap_or(80).clamp(1, 100);
        if let Some(result) = self
            .search(
                &["campaigns-v1"],
                json!({"size": 200, "query": {"range": {"score": {"gte": threshold}}}}),
            )
            .await
        {
            for hit in result["hits"]["hits"].as_array().cloned().unwrap_or_default() {
                let source = &hit["_source"];
                let cidr = source["cidr"].as_str().unwrap_or("");
                if cidr.is_empty() {
                    continue;
                }
                let message = format!(
                    "honeypot campaign {cidr} score={} events={} sensors={:?} ports={:?}",
                    source["score"], source["events"], source["sensors"], source["ports"]
                );
                self.observe(&format!("campaign:{cidr}"), message, &format!("/events?cidr={cidr}"), mark_only)
                    .await;
            }
        }

        // 2. Stale sensor feeds + 3. activity spike + dead letters — one agg.
        if let Some(result) = self
            .search(
                &["honeypot-v2-*", "suricata-v2-*"],
                json!({"size": 0, "query": {"range": {"@timestamp": {"gte": "now-48h"}}},
                       "aggs": {
                           "sensors": {"terms": {"field": "event.sensor", "size": 50},
                                        "aggs": {"last": {"max": {"field": "@timestamp"}}}},
                           "last24h": {"filter": {"range": {"@timestamp": {"gte": "now-24h"}}}},
                           "prev24h": {"filter": {"range": {"@timestamp": {"gte": "now-48h", "lt": "now-24h"}}}}
                       }}),
            )
            .await
        {
            let now_ms = chrono::Utc::now().timestamp_millis();
            for bucket in result["aggregations"]["sensors"]["buckets"].as_array().cloned().unwrap_or_default() {
                let name = bucket["key"].as_str().unwrap_or("").to_string();
                let last_ms = bucket["last"]["value"].as_f64().unwrap_or(0.0) as i64;
                let age_min = ((now_ms - last_ms) / 60000).max(0);
                if age_min >= 60 {
                    let message = format!("honeypot feed stale: {name} (last event {age_min}m ago)");
                    self.observe(&format!("stale:{name}"), message, "", mark_only).await;
                }
            }
            let last = result["aggregations"]["last24h"]["doc_count"].as_i64().unwrap_or(0);
            let prev = result["aggregations"]["prev24h"]["doc_count"].as_i64().unwrap_or(0);
            if prev > 0 {
                let pct = (last - prev) * 100 / prev;
                if pct >= 100 {
                    let message =
                        format!("honeypot activity spike: {last} events in 24h ({pct:+}% vs previous 24h)");
                    self.observe("activity:spike", message, "", mark_only).await;
                }
            }
        }
        if let Some(result) = self
            .search(
                &["dead-letter-honeypot"],
                json!({"size": 0, "track_total_hits": true,
                       "query": {"range": {"@timestamp": {"gte": "now-24h"}}}}),
            )
            .await
        {
            let count = result["hits"]["total"]["value"].as_u64().unwrap_or(0);
            if count > 0 {
                let message = format!("honeypot ingest rejected {count} documents in the last 24h");
                self.observe("pipeline:dead-letters", message, "", mark_only).await;
            }
        }

        // 4. YARA payload matches.
        if let Some(result) = self
            .search(
                &["yara-analysis-v1"],
                json!({"size": 200, "query": {"exists": {"field": "yara.matches"}},
                       "sort": [{"@timestamp": {"order": "desc"}}]}),
            )
            .await
        {
            for hit in result["hits"]["hits"].as_array().cloned().unwrap_or_default() {
                let yara = &hit["_source"]["yara"];
                let matches: Vec<&str> = yara["matches"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|value| value.as_str())
                    .collect();
                let hash = yara["sha256"].as_str().unwrap_or("");
                if matches.is_empty() || hash.is_empty() {
                    continue;
                }
                let message = format!(
                    "YARA payload match: {hash} rules={} source={}",
                    matches.join(","),
                    yara["source"].as_str().unwrap_or("")
                );
                self.observe(&format!("yara:{hash}"), message, &format!("/payload-analysis/{hash}"), mark_only)
                    .await;
            }
        }

        // 5. Sandbox high-risk detonations.
        let risk_threshold: u64 = env_or("SANDBOX_ALERT_RISK_SCORE", "50").parse().unwrap_or(50).clamp(1, 100);
        if let Some(result) = self
            .search(
                &["sandbox-analysis-v1"],
                json!({"size": 100, "query": {"range": {"risk_score": {"gte": risk_threshold}}}}),
            )
            .await
        {
            for hit in result["hits"]["hits"].as_array().cloned().unwrap_or_default() {
                let source = &hit["_source"];
                let job = source["sandbox"]["job"].as_str().or(source["job"].as_str()).unwrap_or("");
                let sha = source["file"]["hash"]["sha256"].as_str().unwrap_or("");
                if job.is_empty() {
                    continue;
                }
                let message = format!(
                    "sandbox high-risk behavior: sha256={sha} score={} level={}",
                    source["risk_score"], source["risk_level"].as_str().unwrap_or("")
                );
                self.observe(&format!("sandbox:risk:{job}"), message, &format!("/sandbox/{job}"), mark_only)
                    .await;
            }
        }

        // 6. LLM-flagged analyses (severity allowlist; AI-guessed, labeled).
        let severities: Vec<String> = env_or("LLM_ANALYSIS_ALERT_SEVERITIES", "high,critical")
            .split(',')
            .map(|level| level.trim().to_lowercase())
            .filter(|level| !level.is_empty())
            .collect();
        if let Some(result) = self
            .search(
                &["llm-analysis"],
                json!({"size": 100, "query": {"terms": {"severity": severities}},
                       "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]}),
            )
            .await
        {
            for hit in result["hits"]["hits"].as_array().cloned().unwrap_or_default() {
                let source = &hit["_source"];
                let id = source["analysis_id"].as_str().unwrap_or("");
                if id.is_empty() {
                    continue;
                }
                let message = format!(
                    "llm-analysis flagged {}: analysis_id={id} AI-guessed severity={} (UNVERIFIED, model={}) intent={}",
                    source["doc_type"].as_str().unwrap_or(""),
                    source["severity"].as_str().unwrap_or(""),
                    source["model"].as_str().unwrap_or(""),
                    source["intent"].as_str().unwrap_or("")
                );
                self.observe(&format!("llm-analysis:flagged:{id}"), message, "/llm-analysis", mark_only)
                    .await;
            }
        }

        // Webhook fan-out for everything that newly notified.
        if !mark_only && !self.webhook.is_empty() {
            for message in self.messages.clone() {
                let body = json!({"content": message, "text": message});
                if let Err(error) = self.client.post(&self.webhook).json(&body).send().await {
                    tracing::warn!(%error, "alert webhook failed");
                }
            }
        }
    }
}

async fn alert_notifier_loop(state: AppState) {
    let mut notifier = Notifier {
        state,
        cooldown: parse_duration(&env_or("ALERT_COOLDOWN", "6h")),
        webhook: env_or("ALERT_WEBHOOK_URL", ""),
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(8))
            .build()
            .expect("reqwest client"),
        messages: Vec::new(),
    };
    // Baseline pass: mark existing conditions without paging about
    // history at boot (same posture as the Go loop's current(true)).
    notifier.pass(true).await;
    let mut ticker = tokio::time::interval(INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        notifier.pass(false).await;
    }
}
