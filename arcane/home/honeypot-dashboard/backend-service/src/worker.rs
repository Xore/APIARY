//! Background worker loops (#1610), ported from the Go dashboard's
//! embedded producers. Enabled per-role via WORKER_LOOPS (comma list;
//! empty = pure API role), so the same image serves as API replica or
//! worker on any docker host — stateless, env-configured, all state in
//! ES (per Xore's cross-host requirement).
//!
//! Currently ported: `alert-notifier` — the notifyLoop/alertManager pair
//! (store.go/alerts.go): every alert signal store.go's notifyLoop combines,
//! ES-derivable and host-local alike (#1612 finished the latter: log-stream
//! sizes, sandbox/ghidra/cape/github-analysis spool health, filebeat stats,
//! OT command detection), upserted into dashboard-alert-state-v1 with
//! cooldown + optional webhook. The host-local signals need this loop's
//! container (backend-worker) to have the same bind mounts/service URLs the
//! Go dashboard had — see compose.yml's backend-worker volumes/environment.
//! `user-retention-sweep` (#1612) — orphaned preference expiry (roadmap
//! Milestone F), ported from userStore.SweepRetention: no in-memory cache to
//! poll here, so this just re-reads the users doc on its own interval rather
//! than the Go store's 3s poll tick.

use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;

use crate::audit::AuditEvent;
use crate::AppState;

const ALERT_INDEX: &str = "dashboard-alert-state-v1";
const INTERVAL: Duration = Duration::from_secs(60);
const GHIDRA_INDEX: &str = "ghidra-analysis-v1";
const GITHUB_ANALYSIS_INDEX: &str = "github-analysis-v1";
const SPOOL_STALE_AFTER: Duration = Duration::from_secs(30 * 60);
const HANDOFF_STALE_AFTER: Duration = Duration::from_secs(5 * 60);

/// Ports payloads_data.go's humanBytes: binary-prefix size, one decimal.
fn human_bytes(n: u64) -> String {
    const UNIT: u64 = 1024;
    if n < UNIT {
        return format!("{n} B");
    }
    let mut div = UNIT;
    let mut exp = 0usize;
    let mut x = n / UNIT;
    while x >= UNIT {
        div *= UNIT;
        exp += 1;
        x /= UNIT;
    }
    let suffix = [b'K', b'M', b'G', b'T', b'P', b'E'][exp] as char;
    format!("{:.1} {suffix}B", n as f64 / div as f64)
}

/// A Go-style time.Duration.String() approximation (whole seconds only —
/// good enough for a log-stream age in an alert message).
fn format_go_duration(d: Duration) -> String {
    let total = d.as_secs();
    let (h, m, s) = (total / 3600, (total % 3600) / 60, total % 60);
    if h > 0 {
        format!("{h}h{m}m{s}s")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

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
            "user-retention-sweep" => {
                let state = state.clone();
                tokio::spawn(async move { retention_sweep_loop(state).await });
                tracing::info!("worker loop enabled: user-retention-sweep");
            }
            "reports-scheduler" => {
                let state = state.clone();
                tokio::spawn(async move { reports_scheduler_loop(state).await });
                tracing::info!("worker loop enabled: reports-scheduler");
            }
            "es-results-importer" => {
                let state = state.clone();
                tokio::spawn(async move { crate::es_importer::es_importer_loop(state).await });
                tracing::info!("worker loop enabled: es-results-importer");
            }
            "attacker-identity" => {
                let state = state.clone();
                tokio::spawn(async move { crate::attacker_identity::attacker_identity_loop(state).await });
                tracing::info!("worker loop enabled: attacker-identity");
            }
            "agent-intrusion" => {
                let state = state.clone();
                tokio::spawn(async move { crate::agent_intrusion::agent_intrusion_loop(state).await });
                tracing::info!("worker loop enabled: agent-intrusion");
            }
            "payload-inventory" => {
                let state = state.clone();
                tokio::spawn(async move { crate::payload_inventory::payload_inventory_loop(state).await });
                tracing::info!("worker loop enabled: payload-inventory");
            }
            "ip-enrichment" => {
                let state = state.clone();
                tokio::spawn(async move { crate::ip_enrichment::ip_enrichment_loop(state).await });
                tracing::info!("worker loop enabled: ip-enrichment");
            }
            "correlator" => {
                let state = state.clone();
                tokio::spawn(async move { crate::correlator::correlator_loop(state).await });
                tracing::info!("worker loop enabled: correlator");
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

    /// OT command alerts (T1692.001) — the one host-local-adjacent signal
    /// that is actually pure ES: honeypot.canonical_attck_techniques is
    /// already flattened onto every event (see kill_chain.rs's
    /// technique_counts), no mount needed. Ports store.go's otSources loop.
    async fn ot_command_alerts(&mut self, mark_only: bool) {
        let Some(result) = self
            .search(
                &["honeypot-v2-*", "suricata-v2-*"],
                json!({"size": 500, "query": {"bool": {"filter": [
                    {"range": {"@timestamp": {"gte": "now-10m"}}},
                    {"term": {"honeypot.canonical_attck_techniques": "T1692.001"}}
                ]}}}),
            )
            .await
        else {
            return;
        };
        let mut seen = std::collections::HashSet::new();
        for hit in result["hits"]["hits"].as_array().cloned().unwrap_or_default() {
            let source = &hit["_source"];
            let src_ip = source["source"]["ip"].as_str().unwrap_or("").to_string();
            let sensor = source["event"]["sensor"].as_str().unwrap_or("").to_string();
            if src_ip.is_empty() || !seen.insert((src_ip.clone(), sensor.clone())) {
                continue;
            }
            let label = format!("{src_ip} via {sensor}");
            let message = format!("industrial control command/write attempt: {label}");
            self.observe(&format!("ot-command:{label}"), message, &format!("/events?ip={src_ip}"), mark_only)
                .await;
        }
    }

    /// Log-stream size alerts (#1389 self-rotation regression guard). Ports
    /// log_streams.go's scanLogStreams/logStreamAlerts.
    async fn log_stream_alerts(&mut self, mark_only: bool) {
        let log_dir = env_or("LOG_DIR", "/logs");
        let max_bytes: i64 = env_or("LOG_STREAM_MAX_BYTES", "67108864").parse().unwrap_or(67108864);
        if max_bytes <= 0 {
            return;
        }
        let alert_percent: i64 = env_or("LOG_STREAM_ALERT_PERCENT", "90").parse().unwrap_or(90);
        let alert_percent = if (1..=99).contains(&alert_percent) { alert_percent } else { 90 };
        let threshold = (max_bytes * alert_percent + 99) / 100;

        let mut candidates: Vec<(String, std::path::PathBuf)> = Vec::new();
        let enriched_dir = Path::new(&log_dir).join("enriched");
        if let Ok(mut entries) = tokio::fs::read_dir(&enriched_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Ok(rel) = path.strip_prefix(Path::new(&log_dir)) {
                        candidates.push((rel.to_string_lossy().replace('\\', "/"), path.clone()));
                    }
                }
            }
        }
        for fixed in ["dionaea/dionaea.json", "dionaea/dionaea_incident.json"] {
            candidates.push((fixed.to_string(), Path::new(&log_dir).join(fixed)));
        }

        for (name, path) in candidates {
            let Ok(meta) = tokio::fs::metadata(&path).await else { continue };
            if !meta.is_file() || (meta.len() as i64) < threshold {
                continue;
            }
            let age = meta.modified().ok().and_then(|m| m.elapsed().ok()).unwrap_or_default();
            let message = format!(
                "honeypot JSON stream approaching rotation limit: {name} size={} limit={} age={}",
                human_bytes(meta.len()),
                human_bytes(max_bytes as u64),
                format_go_duration(age)
            );
            self.observe(&format!("log-stream-size:{name}"), message, "", mark_only).await;
        }
    }

    /// Sandbox spool + worker-status health. Ports sandbox.go's
    /// loadSandboxStatus (merged across Linux/Windows/GHOSTS backends) and
    /// store.go's sandbox:handoff/sandbox:worker/sandbox:failed alerts.
    async fn sandbox_alerts(&mut self, mark_only: bool) {
        let mut results_dirs = vec![env_or("SANDBOX_RESULTS_DIR", "/sandbox-results")];
        for var in ["WINDOWS_SANDBOX_RESULTS_DIR", "GHOSTS_SANDBOX_RESULTS_DIR"] {
            let dir = env_or(var, "");
            if !dir.is_empty() && !results_dirs.contains(&dir) {
                results_dirs.push(dir);
            }
        }
        let mut request_dirs = vec![env_or("SANDBOX_REQUEST_DIR", "/sandbox-requests")];
        for var in ["WINDOWS_SANDBOX_REQUEST_DIR", "GHOSTS_SANDBOX_REQUEST_DIR"] {
            let dir = env_or(var, "");
            if !dir.is_empty() && !request_dirs.contains(&dir) {
                request_dirs.push(dir);
            }
        }

        let (mut merged_state, mut counts, mut any_ok) = (String::new(), (0i64, 0i64, 0i64, 0i64), false);
        for dir in &results_dirs {
            let Some((state, c)) = read_sandbox_queue_file(dir).await else { continue };
            if !any_ok {
                merged_state = state;
                counts = c;
                any_ok = true;
            } else {
                counts.0 += c.0;
                counts.1 += c.1;
                counts.2 += c.2;
                counts.3 += c.3;
                if sandbox_state_rank(&state) > sandbox_state_rank(&merged_state) {
                    merged_state = state;
                }
            }
        }

        let (mut handoff, mut handoff_old) = (0i64, false);
        for dir in &request_dirs {
            let (count, old) = scan_request_dir(dir).await;
            handoff += count;
            handoff_old = handoff_old || old;
        }

        if handoff_old {
            let message =
                format!("sandbox handoff stalled: {handoff} dashboard request(s) are waiting for the host watcher");
            self.observe("sandbox:handoff", message, "", mark_only).await;
        }
        if merged_state == "stale" || merged_state == "error" {
            let message =
                format!("sandbox worker unhealthy: state={merged_state} queued={} running={}", counts.0, counts.1);
            self.observe("sandbox:worker", message, "", mark_only).await;
        }
        if counts.3 > 0 {
            self.observe("sandbox:failed", format!("sandbox queue has {} failed job(s)", counts.3), "", mark_only)
                .await;
        }
    }

    /// Ghidra spool + worker-status health + flagged findings. Ports
    /// ghidra.go's loadGhidraStatus/ghidraAlerts.
    async fn ghidra_alerts(&mut self, mark_only: bool) {
        let results_dir = env_or("GHIDRA_RESULTS_DIR", "");
        let request_dir = env_or("GHIDRA_REQUEST_DIR", "");
        let status = read_spool_status(&results_dir, &request_dir).await;
        if !status.configured {
            return;
        }
        if status.stale {
            let message = format!(
                "ghidra worker not draining: queue file is stale, {} queued, {} running (check honeypot-ghidra-worker.path)",
                status.queued, status.running
            );
            self.observe("ghidra:worker", message, "", mark_only).await;
        }
        if status.failed > 0 {
            self.observe("ghidra:failed", format!("ghidra queue has {} failed request(s)", status.failed), "", mark_only)
                .await;
        }

        let alert_levels: std::collections::HashSet<String> = env_or("GHIDRA_ALERT_RISK_LEVELS", "high,critical")
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        let alert_on_crypto = env_or("GHIDRA_ALERT_ON_CRYPTO", "false").eq_ignore_ascii_case("true");

        if let Some(result) =
            self.search(&[GHIDRA_INDEX], json!({"size": 300, "query": {"exists": {"field": "ghidra.sha256"}}})).await
        {
            for hit in result["hits"]["hits"].as_array().cloned().unwrap_or_default() {
                let g = &hit["_source"]["ghidra"];
                let sha = g["sha256"].as_str().unwrap_or("").to_string();
                if sha.is_empty() {
                    continue;
                }
                if g["exit_status"].as_str() == Some("error") {
                    let message =
                        format!("ghidra analysis failed: sha256={sha} reason={}", g["error"].as_str().unwrap_or(""));
                    self.observe(&format!("ghidra:error:{sha}"), message, "", mark_only).await;
                    continue;
                }
                let risk_level = g["ai_triage"]["risk_level"].as_str().unwrap_or("").to_lowercase();
                let risky = !risk_level.is_empty() && alert_levels.contains(&risk_level);
                let findcrypt_len = g["findcrypt"].as_array().map(|a| a.len()).unwrap_or(0);
                let crypto = alert_on_crypto && findcrypt_len > 0;
                if !risky && !crypto {
                    continue;
                }
                let imports_len = g["imports"].as_array().map(|a| a.len()).unwrap_or(0);
                let detail = if risky {
                    format!(
                        "AI-guessed risk={} (UNVERIFIED, {})",
                        g["ai_triage"]["risk_level"].as_str().unwrap_or(""),
                        g["ai_triage"]["model"].as_str().unwrap_or("")
                    )
                } else {
                    "crypto constants only".to_string()
                };
                let message =
                    format!("ghidra flagged sample: sha256={sha} crypto_hits={findcrypt_len} imports={imports_len} {detail}");
                self.observe(&format!("ghidra:flagged:{sha}"), message, "", mark_only).await;
            }
        }
    }

    /// CAPE spool + worker-status health only (no findings loop — #319's
    /// issue text asked specifically for worker-health surfacing). Ports
    /// cape.go's loadCapeStatus/capeAlerts.
    async fn cape_alerts(&mut self, mark_only: bool) {
        let results_dir = env_or("CAPE_RESULTS_DIR", "");
        let request_dir = env_or("CAPE_REQUEST_DIR", "");
        let status = read_spool_status(&results_dir, &request_dir).await;
        if !status.configured {
            return;
        }
        if status.stale {
            let message = format!(
                "cape worker not draining: queue file is stale, {} queued, {} running (check honeypot-cape-worker.path)",
                status.queued, status.running
            );
            self.observe("cape:worker", message, "", mark_only).await;
        }
        if status.failed > 0 {
            self.observe("cape:failed", format!("cape queue has {} failed request(s)", status.failed), "", mark_only)
                .await;
        }
    }

    /// GitHub-analysis spool + worker-status health + verdict findings.
    /// Ports github_analysis.go's loadGitHubAnalysisStatus/
    /// githubAnalysisAlerts. Unlike ghidra/cape, staleness here is a plain
    /// mtime check (no live-spool recheck) — mirrors the Go source exactly.
    async fn github_analysis_alerts(&mut self, mark_only: bool) {
        let results_dir = env_or("GITHUB_ANALYSIS_RESULTS_DIR", "");
        if results_dir.is_empty() {
            return; // not configured — no noise for an unopted-in subsystem
        }
        let request_dir = env_or("GITHUB_ANALYSIS_REQUEST_DIR", "");
        let path = Path::new(&results_dir).join("status.json");
        let (mut stale, mut queued, mut running, mut failed) = (false, 0i64, 0i64, 0i64);
        match tokio::fs::read(&path).await.ok().and_then(|body| serde_json::from_slice::<Value>(&body).ok()) {
            Some(value) => {
                queued = value["queued"].as_i64().unwrap_or(0);
                running = value["running"].as_i64().unwrap_or(0);
                failed = value["failed"].as_i64().unwrap_or(0);
                if let Ok(meta) = tokio::fs::metadata(&path).await {
                    if let Ok(modified) = meta.modified() {
                        stale = modified.elapsed().unwrap_or_default() > SPOOL_STALE_AFTER;
                    }
                }
            }
            None => stale = true,
        }

        let (handoff, handoff_old) = scan_request_dir(&request_dir).await;

        if handoff_old {
            let message = format!("github-analysis handoff stalled: {handoff} request(s) waiting for the host publisher");
            self.observe("github-analysis:handoff", message, "", mark_only).await;
        }
        if stale {
            let message = format!("github-analysis worker unhealthy: status.json stale, queued={queued} running={running}");
            self.observe("github-analysis:worker", message, "", mark_only).await;
        }
        if failed > 0 {
            self.observe(
                "github-analysis:failed",
                format!("github-analysis queue has {failed} failed request(s)"),
                "",
                mark_only,
            )
            .await;
        }

        let threshold: i64 = env_or("GITHUB_ANALYSIS_ALERT_POSITIVES", "10").parse().unwrap_or(10).max(1);
        if let Some(result) = self
            .search(&[GITHUB_ANALYSIS_INDEX], json!({"size": 300, "query": {"exists": {"field": "github_analysis.sha256"}}}))
            .await
        {
            for hit in result["hits"]["hits"].as_array().cloned().unwrap_or_default() {
                let g = &hit["_source"]["github_analysis"];
                let sha = g["sha256"].as_str().unwrap_or("").to_string();
                let Some(malicious) = g["verdict"]["malicious"].as_i64() else { continue };
                if sha.is_empty() || malicious < threshold {
                    continue;
                }
                let total = g["verdict"]["total"].as_i64().unwrap_or(0);
                let family = g["family"].as_str().unwrap_or("");
                let message =
                    format!("github-analysis high-verdict sample: sha256={sha} malicious={malicious}/{total} family={family}");
                self.observe(&format!("github-analysis:verdict:{sha}"), message, &format!("/github-analysis/{sha}"), mark_only)
                    .await;
            }
        }
    }

    /// Filebeat ingestion health via FILEBEAT_URL. Ports elastic.go's
    /// refreshFilebeat's two alert-relevant halves (state + loss counters);
    /// the Go message also folds in a separate in-memory IngestState this
    /// Rust tier doesn't track, so this covers the filebeat half faithfully
    /// rather than inventing an ingest-staleness computation.
    async fn filebeat_alerts(&mut self, mark_only: bool) {
        let url = env_or("FILEBEAT_URL", "");
        if url.is_empty() {
            return;
        }
        let stats_url = format!("{}/stats", url.trim_end_matches('/'));
        let (state, failed, dropped, active) = match self.client.get(&stats_url).send().await {
            Err(_) => ("unreachable".to_string(), 0i64, 0i64, 0i64),
            Ok(response) if !response.status().is_success() => (response.status().to_string(), 0, 0, 0),
            Ok(response) => match response.json::<Value>().await {
                Ok(body) => {
                    let events = &body["libbeat"]["output"]["events"];
                    (
                        "healthy".to_string(),
                        events["failed"].as_i64().unwrap_or(0),
                        events["dropped"].as_i64().unwrap_or(0),
                        events["active"].as_i64().unwrap_or(0),
                    )
                }
                Err(_) => (String::new(), 0, 0, 0),
            },
        };
        if state != "healthy" {
            self.observe("pipeline:ingestion", format!("honeypot ingestion unhealthy: filebeat={state}"), "", mark_only)
                .await;
        }
        if failed > 0 || dropped > 0 {
            let message = format!("Filebeat reports failed={failed} dropped={dropped} active={active}");
            self.observe("pipeline:filebeat-loss", message, "", mark_only).await;
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

        // 7. OT command alerts (T1692.001) — ES-derived, no mount needed.
        self.ot_command_alerts(mark_only).await;
        // 8. Log-stream size alerts.
        self.log_stream_alerts(mark_only).await;
        // 9. Sandbox spool + worker-status health.
        self.sandbox_alerts(mark_only).await;
        // 10. Ghidra spool + worker-status health + flagged findings.
        self.ghidra_alerts(mark_only).await;
        // 11. CAPE spool + worker-status health.
        self.cape_alerts(mark_only).await;
        // 12. GitHub-analysis spool + worker-status health + verdict findings.
        self.github_analysis_alerts(mark_only).await;
        // 13. Filebeat ingestion health via FILEBEAT_URL.
        self.filebeat_alerts(mark_only).await;

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

fn sandbox_state_rank(state: &str) -> u8 {
    match state {
        "idle" => 1,
        "running" => 2,
        "stale" => 3,
        _ => 0,
    }
}

/// Reads one sandbox backend's status.json (sandbox.go's
/// readSandboxQueueFile). None on missing/oversized/corrupt file — the
/// caller's merge just skips that backend, same observable effect as Go's
/// ok=false path (which never contributes to the "stale"/"error" alert
/// either way). Returns (worker_state, (queued, running, completed, failed)).
async fn read_sandbox_queue_file(dir: &str) -> Option<(String, (i64, i64, i64, i64))> {
    let path = Path::new(dir).join("status.json");
    let body = tokio::fs::read(&path).await.ok()?;
    if body.len() > 256 * 1024 {
        return None;
    }
    let value: Value = serde_json::from_slice(&body).ok()?;
    let mut state = value["worker_state"].as_str().unwrap_or("").to_string();
    let counts = (
        value["counts"]["queued"].as_i64().unwrap_or(0),
        value["counts"]["running"].as_i64().unwrap_or(0),
        value["counts"]["completed"].as_i64().unwrap_or(0),
        value["counts"]["failed"].as_i64().unwrap_or(0),
    );
    if state == "running" {
        if let Some(updated) =
            value["updated_at"].as_str().and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        {
            if (chrono::Utc::now() - updated.with_timezone(&chrono::Utc)).num_minutes() > 10 {
                state = "stale".to_string();
            }
        }
    }
    Some((state, counts))
}

/// Counts `*.request` markers in a spool dir and reports whether the oldest
/// is older than HANDOFF_STALE_AFTER. Shared by sandbox/github-analysis
/// handoff scans (sandbox.go's request-dir loop / githubAnalysisHandoffCounts).
async fn scan_request_dir(dir: &str) -> (i64, bool) {
    if dir.is_empty() {
        return (0, false);
    }
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else { return (0, false) };
    let (mut count, mut old) = (0i64, false);
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with(".request") {
            continue;
        }
        count += 1;
        if let Ok(meta) = entry.metadata().await {
            if let Ok(modified) = meta.modified() {
                if modified.elapsed().unwrap_or_default() > HANDOFF_STALE_AFTER {
                    old = true;
                }
            }
        }
    }
    (count, old)
}

struct SpoolStatus {
    configured: bool,
    stale: bool,
    queued: i64,
    running: i64,
    failed: i64,
}

/// Ports loadGhidraStatus/loadCapeStatus's shared shape: a flat status.json
/// written by a small host script, re-checked against the live request
/// spool when it looks stale — a systemd *path* unit only rewrites
/// status.json when a request lands, so a quiet honeypot with an empty spool
/// is healthy, not dead; only a stale file over a *non-empty* live spool is
/// a real stall.
async fn read_spool_status(results_dir: &str, request_dir: &str) -> SpoolStatus {
    if results_dir.is_empty() {
        return SpoolStatus { configured: false, stale: false, queued: 0, running: 0, failed: 0 };
    }
    let path = Path::new(results_dir).join("status.json");
    let Some(value) = tokio::fs::read(&path).await.ok().and_then(|body| serde_json::from_slice::<Value>(&body).ok())
    else {
        return SpoolStatus { configured: true, stale: true, queued: 0, running: 0, failed: 0 };
    };
    let mut queued = value["queued"].as_i64().unwrap_or(0);
    let mut running = value["running"].as_i64().unwrap_or(0);
    let failed = value["failed"].as_i64().unwrap_or(0);
    let mut stale = false;
    if let Ok(meta) = tokio::fs::metadata(&path).await {
        if let Ok(modified) = meta.modified() {
            if modified.elapsed().unwrap_or_default() > SPOOL_STALE_AFTER {
                let Ok(mut entries) = tokio::fs::read_dir(request_dir).await else {
                    return SpoolStatus { configured: true, stale: true, queued, running, failed };
                };
                let (mut live_q, mut live_r) = (0i64, 0i64);
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".request.running") {
                        live_r += 1;
                    } else if name.ends_with(".request") {
                        live_q += 1;
                    }
                }
                stale = live_q + live_r > 0;
                if stale {
                    queued = live_q;
                    running = live_r;
                }
            }
        }
    }
    SpoolStatus { configured: true, stale, queued, running, failed }
}

const USERS_INDEX: &str = "dashboard-users-v1";
const USERS_ID: &str = "users";
const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

async fn retention_sweep_loop(state: AppState) {
    let mut ticker = tokio::time::interval(RETENTION_SWEEP_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        retention_sweep_once(&state).await;
    }
}

/// Removes projections — including their stored preferences — whose
/// last_seen_at predates the retention window, and audits each removal.
/// An empty sweep never writes (matches SweepRetention's contract).
async fn retention_sweep_once(state: &AppState) {
    let retention_days: i64 = env_or("DASHBOARD_USER_RETENTION_DAYS", "90").parse().unwrap_or(90);
    if retention_days <= 0 {
        return;
    }
    let mut doc = match state.es.get_doc(USERS_INDEX, USERS_ID).await {
        Ok(Some(doc)) => doc,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(%error, "retention sweep: users doc fetch failed");
            return;
        }
    };
    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days);
    let users = doc["payload"]["users"].as_array().cloned().unwrap_or_default();
    let mut kept = Vec::with_capacity(users.len());
    let mut removed = Vec::new();
    for user in users {
        let last_seen =
            user["last_seen_at"].as_str().and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok());
        let expired = match last_seen {
            Some(at) => at.with_timezone(&chrono::Utc) < cutoff,
            None => false,
        };
        if expired {
            removed.push(user);
        } else {
            kept.push(user);
        }
    }
    if removed.is_empty() {
        return;
    }
    doc["payload"]["users"] = json!(kept);
    doc["revision"] = json!(doc["revision"].as_u64().unwrap_or(0) + 1);
    doc["updated"] = json!(chrono::Utc::now().to_rfc3339());
    if let Err(error) = state.es.index_doc(USERS_INDEX, USERS_ID, doc).await {
        tracing::warn!(%error, "retention sweep: users doc write failed");
        return;
    }
    let removed_count = removed.len();
    for user in removed {
        state.audit.log(AuditEvent {
            actor_subject: "system".into(),
            actor_username: "retention".into(),
            action: "users.retention".into(),
            fields: vec![
                user["subject"].as_str().unwrap_or_default().to_string(),
                user["last_username"].as_str().unwrap_or_default().to_string(),
            ],
            result: "success".into(),
            ..Default::default()
        });
    }
    tracing::info!(removed = removed_count, "user retention sweep removed orphaned projection(s)");
}

const REPORTS_SCHEDULER_INTERVAL: Duration = Duration::from_secs(30);

/// Ports reports_scheduler.go's reportScheduleLoop: every tick, render
/// every due definition through the same pipeline as the manual generate
/// endpoint (origin "schedule"), then advance its schedule. Unlike Go's
/// goroutine model, a panic inside this spawned task can't take the whole
/// process down (tokio isolates it), so there's no need to port
/// runDueReportsRecovered's explicit recover() wrapping — Result::Err from
/// one definition's render simply doesn't stop the rest of the tick.
async fn reports_scheduler_loop(state: AppState) {
    let mut ticker = tokio::time::interval(REPORTS_SCHEDULER_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        reports_scheduler_tick(&state).await;
    }
}

async fn reports_scheduler_tick(state: &AppState) {
    let due = match crate::reports_store::due_definitions(state).await {
        Ok(due) => due,
        Err(error) => {
            tracing::warn!(%error, "reports scheduler: due-definitions fetch failed");
            return;
        }
    };
    for definition in due {
        let ran_at = chrono::Utc::now();
        let result = crate::reports_api::render_definition_to_stored(state, &definition, "schedule").await;
        let success = result.is_ok();
        if let Err(error) = result {
            tracing::warn!(id = %definition.id, name = %definition.name, %error, "scheduled report failed");
        }
        crate::reports_store::mark_scheduled_run(state, &definition.id, ran_at, success).await;
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
