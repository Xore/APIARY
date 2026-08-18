//! agent-intrusion-worker port (#1610 worker migration — "campaign
//! correlator"), worker.py half: wires decode_correlate.rs,
//! campaign_correlator.rs, and criticality_rules.rs against real
//! Elasticsearch data, writing provenance-rich campaign verdicts to
//! `agent-intrusion-campaigns` (dashboard/agent_campaigns.go's own
//! `/agent-campaigns` route reads this — see src/stores.rs's generic
//! passthrough entry, fixed in the same pass as this port to sort
//! `@timestamp` instead of a nonexistent `last_seen` field).
//!
//! Every event this worker reads/correlates/scores is the raw sensor
//! sub-document (source.honeypot, or source.suricata.eve, or the bare
//! _source) — NOT this crate's usual flattened honeypot.canonical_*
//! convention every other module queries. campaign_correlator.rs and
//! criticality_rules.rs read sensor-native field names directly (session,
//! src_ip, host, actor, input, payload_printable, eventid, sensor, ...),
//! ported faithfully from the Python corpus/production fixtures — do not
//! narrow the ES `_source` filter to a canonical-field allowlist here.
//!
//! Pure ES, no host mounts, no local state — runs as the `agent-intrusion`
//! WORKER_LOOPS entry on the existing (stateless-by-design) backend-worker
//! service, alongside `alert-notifier`/`attacker-identity`.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;

use crate::campaign_correlator::{self, Campaign, CorrelatorEvent};
use crate::criticality_rules::{self, RuleMatch};
use crate::AppState;

const SOURCE_INDICES: &[&str] = &["honeypot-v2-*", "suricata-v2-*"];
const CAMPAIGN_INDEX: &str = "agent-intrusion-campaigns";
const EVENT_PAGE_SIZE: u64 = 1_000;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

fn env_duration_secs(name: &str, default: Duration) -> Duration {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(default)
}

/// Returns the sensor-native portion of a live ECS document. Corpus
/// fixtures already use the sensor-native shape at the top level, while
/// production ingest retains it below `honeypot` or `suricata.eve`.
fn sensor_raw(source: &serde_json::Value) -> serde_json::Value {
    if let Some(honeypot) = source.get("honeypot") {
        if honeypot.is_object() {
            return honeypot.clone();
        }
    }
    if let Some(eve) = source.get("suricata").and_then(|s| s.get("eve")) {
        if eve.is_object() {
            return eve.clone();
        }
    }
    source.clone()
}

/// Scrolls the newest capped events at or after `since`, mapped into the
/// shape campaign_correlator.rs/criticality_rules.rs consume. Real ES
/// `_id`s are used directly as event_id so a dashboard page can link
/// straight back to raw evidence.
async fn fetch_window_events(
    state: &AppState,
    index_pattern: &str,
    since: &str,
    page_size: u64,
    max_events: u64,
) -> Vec<CorrelatorEvent> {
    // max_pages bounds total fetched at page_size*max_pages >= max_events,
    // with headroom since a page may partially exceed the cap (checked
    // per-hit below, matching the Python worker's own early-break).
    let max_pages = ((max_events / page_size) + 2) as u32;
    let hits = match state
        .es
        .search_paginated(
            index_pattern,
            |search_after| {
                let mut body = serde_json::json!({
                    "query": {"range": {"@timestamp": {"gte": since}}},
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "_source": {"excludes": ["suricata.eve.packet", "suricata.eve.payload"]}
                });
                if let Some(sa) = search_after {
                    body["search_after"] = sa.clone();
                }
                body
            },
            page_size,
            max_pages,
        )
        .await
    {
        Ok(hits) => hits,
        Err(error) => {
            tracing::warn!(%error, index_pattern, "agent-intrusion: fetch error");
            return Vec::new();
        }
    };

    let mut events = Vec::new();
    for hit in hits {
        let source = &hit["_source"];
        let Some(ts) = source.get("@timestamp").and_then(|v| v.as_str()) else {
            continue;
        };
        let event_id = hit["_id"].as_str().unwrap_or_default().to_string();
        let source_index = hit["_index"].as_str().unwrap_or_default().to_string();
        events.push((
            CorrelatorEvent {
                event_id,
                timestamp: ts.to_string(),
                raw: sensor_raw(source),
            },
            source_index,
        ));
        if events.len() as u64 >= max_events {
            tracing::warn!(
                index_pattern,
                max_events,
                "agent-intrusion: fetch cap reached, processing only the newest events this cycle"
            );
            break;
        }
    }
    events.into_iter().map(|(e, _source_index)| e).collect()
}

/// campaign_correlator.rs's parse_ts expects a bare "%Y-%m-%dT%H:%M:%SZ";
/// real Elasticsearch @timestamp values are full ISO 8601 and routinely
/// carry fractional seconds and/or a numeric UTC offset. Normalizes to
/// whole seconds, UTC, "Z"-suffixed.
fn normalize_timestamp(ts: &str) -> Option<String> {
    let parsed = chrono::DateTime::parse_from_rfc3339(ts).ok()?;
    Some(
        parsed
            .with_timezone(&chrono::Utc)
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string(),
    )
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Runs criticality_rules against every member event, scores the whole
/// campaign, and returns a full provenance-rich verdict document — or
/// None if the campaign doesn't clear the high/critical write threshold.
/// Deterministic campaign_id (sha256 of the sorted event_id list) makes
/// re-processing the same campaign on a later poll an idempotent upsert.
fn build_campaign_verdict(
    campaign: &Campaign,
    events_by_id: &HashMap<String, CorrelatorEvent>,
) -> Option<serde_json::Value> {
    let raw_by_id: HashMap<String, serde_json::Value> = events_by_id
        .iter()
        .map(|(id, e)| (id.clone(), e.raw.clone()))
        .collect();
    let mut matches_per_event: HashMap<String, Vec<RuleMatch>> = campaign
        .event_ids
        .iter()
        .map(|eid| {
            (
                eid.clone(),
                criticality_rules::evaluate_event(&events_by_id[eid].raw),
            )
        })
        .collect();

    // The breadcrumb-followed match needs the full per-event match set
    // already built above (it looks for a prior breadcrumb-reference
    // match), so it runs after evaluate_event, not inside it.
    if let Some((followed_eid, followed_match)) = criticality_rules::campaign_breadcrumb_followed(
        &campaign.event_ids,
        &raw_by_id,
        &matches_per_event,
    ) {
        matches_per_event
            .get_mut(&followed_eid)
            .unwrap()
            .push(followed_match);
    }

    let (severity, categories) = criticality_rules::campaign_severity(&matches_per_event);
    if severity != "high" && severity != "critical" {
        return None;
    }

    let mut sorted_event_ids = campaign.event_ids.clone();
    sorted_event_ids.sort();
    let campaign_id = &sha256_hex(sorted_event_ids.join("|").as_bytes())[..16];

    let event_docs: Vec<serde_json::Value> = campaign
        .event_ids
        .iter()
        .map(|eid| {
            let event = &events_by_id[eid];
            let matches = &matches_per_event[eid];
            serde_json::json!({
                "event_id": eid,
                "timestamp": event.timestamp,
                "matched_rules": matches.iter().map(|m| serde_json::json!({
                    "rule": m.rule,
                    "reason": m.reason,
                    "trust_boundary": criticality_rules::TRUST_BOUNDARIES.get(m.rule.as_str()).copied().unwrap_or(""),
                    "decode_chain": m.decode_chain.iter().map(|s| serde_json::json!({
                        "transform": s.transform,
                        "input_sha256": s.input_sha256,
                        "output_sha256": s.output_sha256,
                        "output_len": s.output_len,
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    let mut categories_sorted: Vec<&String> = categories.iter().collect();
    categories_sorted.sort();
    let mut identifiers_sorted: Vec<&String> = campaign.identifiers.iter().collect();
    identifiers_sorted.sort();

    Some(serde_json::json!({
        "@timestamp": chrono::Utc::now().to_rfc3339(),
        "campaign_id": campaign_id,
        "start": campaign.start,
        "end": campaign.end,
        "severity": severity,
        "matched_categories": categories_sorted,
        "correlation_identifiers": identifiers_sorted,
        "event_count": campaign.event_ids.len(),
        "events": event_docs,
    }))
}

async fn write_campaign_verdict(state: &AppState, verdict: &serde_json::Value) {
    let id = verdict["campaign_id"].as_str().unwrap_or_default();
    if let Err(error) = state
        .es
        .index_doc(CAMPAIGN_INDEX, id, verdict.clone())
        .await
    {
        tracing::warn!(%error, campaign_id = id, "agent-intrusion: failed to write campaign verdict (non-fatal)");
    }
}

/// One full fetch -> correlate -> score -> write pass. Returns the number
/// of campaign verdicts written. Never panics — a fetch/index error
/// degrades this cycle's output, not the loop.
async fn run_cycle(state: &AppState, fetch_window: Duration, max_events_per_source: u64) -> u64 {
    let since = (chrono::Utc::now() - chrono::Duration::from_std(fetch_window).unwrap())
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    let mut events = Vec::new();
    for index_pattern in SOURCE_INDICES {
        events.extend(
            fetch_window_events(
                state,
                index_pattern,
                &since,
                EVENT_PAGE_SIZE,
                max_events_per_source,
            )
            .await,
        );
    }
    if events.is_empty() {
        return 0;
    }

    for event in &mut events {
        if let Some(normalized) = normalize_timestamp(&event.timestamp) {
            event.timestamp = normalized;
        }
    }
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    // Correlate against the slice first, then move events into the lookup
    // map — avoids cloning every event just to satisfy both call sites.
    let campaigns = campaign_correlator::correlate_campaigns(&events, chrono::Duration::hours(72));
    let events_by_id: HashMap<String, CorrelatorEvent> = events
        .into_iter()
        .map(|e| (e.event_id.clone(), e))
        .collect();

    let mut written = 0u64;
    for campaign in &campaigns {
        if let Some(verdict) = build_campaign_verdict(campaign, &events_by_id) {
            write_campaign_verdict(state, &verdict).await;
            written += 1;
        }
    }
    written
}

pub async fn agent_intrusion_loop(state: AppState) {
    let poll_interval =
        env_duration_secs("AGENT_INTRUSION_POLL_INTERVAL", Duration::from_secs(300));
    let max_events_per_source = env_u64("AGENT_INTRUSION_MAX_EVENTS_PER_SOURCE", 10_000);
    let fetch_window_days = env_u64("AGENT_INTRUSION_FETCH_WINDOW_DAYS", 10);
    let fetch_window = Duration::from_secs(fetch_window_days * 24 * 3600);

    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let written = run_cycle(&state, fetch_window, max_events_per_source).await;
        tracing::info!(written, "agent-intrusion: cycle complete");
    }
}
