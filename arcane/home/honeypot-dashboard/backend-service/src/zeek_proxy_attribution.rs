//! Resolve the real attacker behind a zeek-proxy observation.
//!
//! zeek-proxy watches `wg0`, where every flow is `10.8.0.1 -> 10.8.0.2`: the
//! VPS forwarding inward. That is genuinely what crossed the wire, so the
//! sensor is not wrong — but a record whose `source.ip` is our own tunnel is
//! useless as attacker attribution, and reads on the dashboard as though our
//! infrastructure were attacking itself.
//!
//! The attacker is recoverable, just not by that sensor alone. portbridge
//! logs both halves of every relayed connection: `community_id` for the
//! attacker's tuple as it arrived on the public NIC, and
//! `community_id_relayed` for the tunnel-side tuple it dialled inward. That
//! second value is exactly what zeek-proxy computes for the same flow, so one
//! is a key into the other.
//!
//! Why a worker loop and not an ingest processor: the join needs a lookup
//! against another index, which a painless script in a pipeline cannot do.
//! And it cannot be done at write time in any case — the two sensors write
//! independently and either may land first.
//!
//! What it writes:
//!
//!   source.ip                     the attacker, replacing the tunnel address
//!   network.relay_ip              the tunnel address, preserved
//!   network.community_id_attacker the attacker-side key, so a zeek-proxy
//!                                 record can be joined to the VPS sensor's
//!                                 view of the same session
//!
//! Overwriting `source.ip` rather than adding a field is deliberate: every
//! existing aggregation, filter and pivot already reads it, and the observed
//! value is not lost — Zeek's own `zeek.id.orig_h` still carries it, and
//! `network.relay_ip` records it explicitly.

use crate::AppState;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

/// zeek-proxy documents considered per pass.
///
/// Bounded for the same reason every sweep here is: unresolved documents
/// accumulate while the loop is down, and a pass that tries to catch up all at
/// once is the one that falls over. Oldest-first, so nothing is starved.
const BATCH: usize = 500;

/// How far back to look for unresolved documents.
///
/// portbridge and zeek-proxy write independently, so a zeek-proxy record can
/// arrive before the portbridge record that explains it. A window well past
/// that skew means a late partner is still picked up on a later pass, rather
/// than the document being permanently unattributed because we looked once,
/// too early.
const LOOKBACK: &str = "now-6h";

fn interval() -> Duration {
    let secs = std::env::var("ZEEK_PROXY_ATTRIBUTION_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(120);
    Duration::from_secs(secs)
}

pub async fn zeek_proxy_attribution_loop(state: AppState) {
    let mut ticker = tokio::time::interval(interval());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        if let Err(error) = resolve_once(&state).await {
            tracing::warn!(%error, "zeek-proxy-attribution: pass failed");
        }
    }
}

/// Relayed-tuple key -> (attacker address, attacker-side key).
fn relay_map(hits: &Value) -> HashMap<String, (String, String)> {
    let mut map = HashMap::new();
    for hit in hits["hits"]["hits"].as_array().into_iter().flatten() {
        let pb = &hit["_source"]["portbridge"];
        let (Some(relayed), Some(attacker)) = (
            pb["community_id_relayed"].as_str(),
            pb["src_ip"].as_str(),
        ) else {
            continue;
        };
        if relayed.is_empty() || attacker.is_empty() {
            continue;
        }
        map.insert(
            relayed.to_string(),
            (
                attacker.to_string(),
                pb["community_id"].as_str().unwrap_or_default().to_string(),
            ),
        );
    }
    map
}

async fn resolve_once(state: &AppState) -> anyhow::Result<()> {
    // Documents this loop has not already attributed. The marker is the
    // presence of network.relay_ip rather than a boolean, so a document that
    // was attributed carries the evidence of it rather than a flag whose
    // meaning has to be looked up.
    let pending = state
        .es
        .search_index(
            &["zeek-proxy-v1-*"],
            json!({
                "size": BATCH,
                "track_total_hits": false,
                "query": {"bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": LOOKBACK}}},
                        {"exists": {"field": "network.community_id"}}
                    ],
                    "must_not": [{"exists": {"field": "network.relay_ip"}}]
                }},
                "sort": [{"@timestamp": {"order": "asc"}}],
                "_source": ["network.community_id"]
            }),
        )
        .await?;

    let keys: Vec<String> = pending["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| hit["_source"]["network"]["community_id"].as_str().map(String::from))
        .collect();
    if keys.is_empty() {
        return Ok(());
    }

    // One lookup for the whole batch.
    let relayed = state
        .es
        .search_index(
            &["portbridge-v2-*"],
            json!({
                "size": BATCH,
                "track_total_hits": false,
                "query": {"terms": {"portbridge.community_id_relayed": keys}},
                "_source": [
                    "portbridge.community_id_relayed",
                    "portbridge.community_id",
                    "portbridge.src_ip"
                ]
            }),
        )
        .await?;

    let map = relay_map(&relayed);
    if map.is_empty() {
        // Nothing matched. Normal when portbridge has not written its side
        // yet, or when the flow was not relayed at all — internal traffic on
        // the tunnel has no attacker behind it and never will.
        return Ok(());
    }

    let attacker: HashMap<&str, &str> =
        map.iter().map(|(k, v)| (k.as_str(), v.0.as_str())).collect();
    let attacker_key: HashMap<&str, &str> =
        map.iter().map(|(k, v)| (k.as_str(), v.1.as_str())).collect();

    let updated = state
        .es
        .update_by_query(
            &["zeek-proxy-v1-*"],
            json!({"bool": {
                "filter": [{"terms": {"network.community_id": map.keys().collect::<Vec<_>>()}}],
                "must_not": [{"exists": {"field": "network.relay_ip"}}]
            }}),
            // Keep what the sensor saw, then state who was actually behind it.
            "String key = ctx._source.network.community_id;\
             if (key == null || !params.attacker.containsKey(key)) { ctx.op = 'noop'; return; }\
             if (ctx._source.source == null) { ctx._source.source = new HashMap(); }\
             def observed = ctx._source.source.ip;\
             if (observed != null) { ctx._source.network.relay_ip = observed; }\
             ctx._source.source.ip = params.attacker.get(key);\
             def akey = params.attacker_key.get(key);\
             if (akey != null && akey != '') { ctx._source.network.community_id_attacker = akey; }",
            json!({"attacker": attacker, "attacker_key": attacker_key}),
        )
        .await?;

    if updated > 0 {
        tracing::debug!(
            resolved = updated,
            candidates = keys.len(),
            "zeek-proxy-attribution: attributed relayed flows"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(relayed: &str, attacker: &str, key: &str) -> Value {
        json!({"_source": {"portbridge": {
            "community_id_relayed": relayed,
            "community_id": key,
            "src_ip": attacker
        }}})
    }

    #[test]
    fn maps_the_relayed_key_to_the_attacker() {
        let hits = json!({"hits": {"hits": [
            hit("1:relayedAAA=", "203.0.113.9", "1:attackerAAA="),
            hit("1:relayedBBB=", "198.51.100.4", "1:attackerBBB=")
        ]}});
        let map = relay_map(&hits);
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get("1:relayedAAA="),
            Some(&("203.0.113.9".to_string(), "1:attackerAAA=".to_string()))
        );
    }

    #[test]
    fn skips_records_that_cannot_attribute_anything() {
        // A portbridge record with no relayed key, or no source address, tells
        // us nothing about who was behind a tunnel flow -- keeping it would
        // mean writing an empty attacker over a real observation.
        let hits = json!({"hits": {"hits": [
            json!({"_source": {"portbridge": {"community_id": "1:x="}}}),
            hit("", "203.0.113.9", "1:y="),
            hit("1:relayedCCC=", "", "1:z=")
        ]}});
        assert!(relay_map(&hits).is_empty());
    }

    #[test]
    fn tolerates_a_missing_attacker_side_key() {
        // community_id is the useful extra, not a requirement: the attacker
        // address alone is still worth writing.
        let hits = json!({"hits": {"hits": [
            json!({"_source": {"portbridge": {
                "community_id_relayed": "1:relayedDDD=",
                "src_ip": "203.0.113.7"
            }}})
        ]}});
        let map = relay_map(&hits);
        assert_eq!(
            map.get("1:relayedDDD="),
            Some(&("203.0.113.7".to_string(), String::new()))
        );
    }
}
