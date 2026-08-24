//! Resolve the real attacker behind a zeek-proxy observation.
//!
//! zeek-proxy watches `wg0`, where every flow is `10.8.0.1 -> 10.8.0.2`: the
//! VPS forwarding inward. That is genuinely what crossed the wire, so the
//! sensor is not wrong — but a record whose `source.ip` is our own tunnel is
//! useless as attacker attribution, and reads on the dashboard as though our
//! infrastructure were attacking itself.
//!
//! portbridge logs both halves of every relayed connection: `community_id`
//! for the attacker's tuple as it arrived on the public NIC, and
//! `community_id_relayed` for the tunnel-side tuple it dialled inward. The
//! second is what zeek-proxy computes for the same flow, so one is a key into
//! the other.
//!
//! # The key is not unique, and that is the whole difficulty
//!
//! The relayed tuple is `10.8.0.1:<ephemeral> -> 10.8.0.2:<service>`, and the
//! ephemeral port is reused within seconds under this traffic. Measured on the
//! live cluster: one `community_id_relayed` matched four portbridge records
//! belonging to different attackers. Joining on the key alone and taking any
//! match attributes a flow to whoever happened to reuse that port — and a
//! wrong attacker is indistinguishable from a right one, which is worse than
//! leaving the tunnel address in place.
//!
//! This is the same trap #1771 documented for the `via_port` join, and the
//! constraint that fixes it is the one `ip_enrichment::viamap` already uses:
//! portbridge logs at *dial* time, strictly before the relayed flow can exist,
//! so a candidate dialled after the flow cannot explain it. Among those that
//! remain, the most recent opened it.
//!
//! Where no candidate survives, nothing is written. An unattributed flow is
//! honest; a confidently wrong attacker is not.
//!
//! # What it writes
//!
//!   source.ip                     the attacker, replacing the tunnel address
//!   network.relay_ip              the tunnel address, preserved
//!   network.community_id_attacker the attacker-side key, so a zeek-proxy
//!                                 record can also be joined to the VPS
//!                                 sensor's view of the same session
//!
//! Overwriting `source.ip` rather than adding a field is deliberate: every
//! existing aggregation, filter and pivot already reads it, and the observed
//! value is not lost — Zeek's own `zeek.id.orig_h` still carries it, and
//! `network.relay_ip` records it explicitly. That field doubles as the
//! "already attributed" marker, so the write is idempotent and fully
//! reversible.

use crate::AppState;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

/// zeek-proxy documents considered per pass. Each resolved one costs its own
/// update, so this is deliberately smaller than a bulk-rewrite batch.
const BATCH: usize = 200;

/// How far back to look for unresolved documents. portbridge and zeek-proxy
/// write independently, so a zeek-proxy record can arrive before the
/// portbridge record that explains it; a narrow window would leave it
/// permanently unattributed for having been looked at once, too early.
const LOOKBACK: &str = "now-6h";

/// How long before a relayed flow a portbridge dial may have happened and
/// still explain it. Same bound, for the same reason, as
/// `ip_enrichment::viamap`'s MAX_AGE_SECONDS.
const MAX_DIAL_AGE_SECONDS: i64 = 6 * 3600;

/// One portbridge dial: when it happened, and who was behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct Dial {
    pub at: i64,
    pub attacker: String,
    pub attacker_key: String,
}

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

/// The dial that opened a flow seen at `flow_at`, or None.
///
/// Two rules, both there to refuse rather than guess:
///   * a dial after the flow cannot have opened it — portbridge logs at dial
///     time, strictly before the relayed connection exists;
///   * a dial older than the window is a different session that happened to
///     reuse the ephemeral port.
pub fn dial_for(dials: &[Dial], flow_at: i64) -> Option<&Dial> {
    dials
        .iter()
        .filter(|dial| dial.at <= flow_at && flow_at - dial.at <= MAX_DIAL_AGE_SECONDS)
        .max_by_key(|dial| dial.at)
}

fn parse_seconds(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|parsed| parsed.timestamp())
}

/// Relayed key -> every dial seen for it. Keeping all of them is the point:
/// collapsing to one is exactly the bug this module exists to avoid.
fn dials_by_key(hits: &Value) -> HashMap<String, Vec<Dial>> {
    let mut map: HashMap<String, Vec<Dial>> = HashMap::new();
    for hit in hits["hits"]["hits"].as_array().into_iter().flatten() {
        let source = &hit["_source"];
        let pb = &source["portbridge"];
        let (Some(relayed), Some(attacker), Some(at)) = (
            pb["community_id_relayed"].as_str(),
            pb["src_ip"].as_str(),
            source["@timestamp"].as_str().and_then(parse_seconds),
        ) else {
            continue;
        };
        if relayed.is_empty() || attacker.is_empty() {
            continue;
        }
        map.entry(relayed.to_string()).or_default().push(Dial {
            at,
            attacker: attacker.to_string(),
            attacker_key: pb["community_id"].as_str().unwrap_or_default().to_string(),
        });
    }
    map
}

async fn resolve_once(state: &AppState) -> anyhow::Result<()> {
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
                "_source": ["network.community_id", "source.ip", "@timestamp"]
            }),
        )
        .await?;

    struct Pending {
        index: String,
        id: String,
        key: String,
        at: i64,
        observed: String,
    }

    let docs: Vec<Pending> = pending["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| {
            let source = &hit["_source"];
            Some(Pending {
                index: hit["_index"].as_str()?.to_string(),
                id: hit["_id"].as_str()?.to_string(),
                key: source["network"]["community_id"].as_str()?.to_string(),
                at: source["@timestamp"].as_str().and_then(parse_seconds)?,
                observed: source["source"]["ip"].as_str().unwrap_or_default().to_string(),
            })
        })
        .collect();
    if docs.is_empty() {
        return Ok(());
    }

    let keys: Vec<&str> = docs.iter().map(|doc| doc.key.as_str()).collect();
    let relayed = state
        .es
        .search_index(
            &["portbridge-v2-*"],
            json!({
                // Several dials per key is the normal case, not an anomaly --
                // that is what makes the time constraint necessary -- so fetch
                // generously and let dial_for choose.
                "size": BATCH * 8,
                "track_total_hits": false,
                "query": {"terms": {"portbridge.community_id_relayed": keys}},
                "_source": [
                    "@timestamp",
                    "portbridge.community_id_relayed",
                    "portbridge.community_id",
                    "portbridge.src_ip"
                ]
            }),
        )
        .await?;

    let dials = dials_by_key(&relayed);
    if dials.is_empty() {
        // Normal: portbridge may not have written its side yet, or the flow
        // was never relayed at all -- internal tunnel traffic has no attacker
        // behind it and never will.
        return Ok(());
    }

    let (mut resolved, mut unattributable) = (0usize, 0usize);
    for doc in &docs {
        let Some(candidates) = dials.get(&doc.key) else { continue };
        let Some(dial) = dial_for(candidates, doc.at) else {
            // Candidates existed but none could have opened this flow.
            // Leaving it alone is the point of the exercise.
            unattributable += 1;
            continue;
        };
        let mut network = json!({"relay_ip": doc.observed});
        if !dial.attacker_key.is_empty() {
            network["community_id_attacker"] = json!(dial.attacker_key);
        }
        let update = json!({"source": {"ip": dial.attacker}, "network": network});
        if let Err(error) = state.es.update_doc(&doc.index, &doc.id, update).await {
            tracing::warn!(%error, doc_id = %doc.id, "zeek-proxy-attribution: update failed");
            continue;
        }
        resolved += 1;
    }

    if resolved > 0 || unattributable > 0 {
        tracing::debug!(
            resolved,
            unattributable,
            candidates = docs.len(),
            "zeek-proxy-attribution pass complete"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dial(at: i64, attacker: &str) -> Dial {
        Dial { at, attacker: attacker.into(), attacker_key: format!("key-{attacker}") }
    }

    #[test]
    fn picks_the_most_recent_dial_before_the_flow() {
        // The live shape that broke the first attempt: one relayed key, several
        // dials, different attackers. Taking any match attributes the flow to
        // whoever reused the ephemeral port.
        let dials = vec![
            dial(1_000, "203.0.113.1"),
            dial(2_000, "198.51.100.2"),
            dial(3_000, "203.0.113.9"),
        ];
        assert_eq!(dial_for(&dials, 3_500).unwrap().attacker, "203.0.113.9");
        assert_eq!(dial_for(&dials, 2_500).unwrap().attacker, "198.51.100.2");
    }

    #[test]
    fn refuses_a_dial_that_happened_after_the_flow() {
        // portbridge logs at dial time, strictly before the relayed connection
        // can exist, so a later dial cannot explain this flow.
        let dials = vec![dial(5_000, "203.0.113.1")];
        assert!(dial_for(&dials, 4_999).is_none());
    }

    #[test]
    fn refuses_a_dial_older_than_the_window() {
        // Same port, a different session hours earlier.
        let dials = vec![dial(1_000, "203.0.113.1")];
        assert!(dial_for(&dials, 1_000 + MAX_DIAL_AGE_SECONDS + 1).is_none());
        assert!(dial_for(&dials, 1_000 + MAX_DIAL_AGE_SECONDS).is_some());
    }

    #[test]
    fn no_candidates_attributes_nothing() {
        assert!(dial_for(&[], 1_000).is_none());
    }

    #[test]
    fn groups_dials_by_relayed_key_and_keeps_all_of_them() {
        let hits = json!({"hits": {"hits": [
            {"_source": {"@timestamp": "2026-08-24T07:00:00Z", "portbridge": {
                "community_id_relayed": "1:same=", "community_id": "1:a=", "src_ip": "203.0.113.1"}}},
            {"_source": {"@timestamp": "2026-08-24T07:05:00Z", "portbridge": {
                "community_id_relayed": "1:same=", "community_id": "1:b=", "src_ip": "198.51.100.2"}}}
        ]}});
        let map = dials_by_key(&hits);
        // Both must survive -- collapsing them is precisely the bug.
        assert_eq!(map.get("1:same=").map(Vec::len), Some(2));
    }

    #[test]
    fn skips_portbridge_records_that_explain_nothing() {
        let hits = json!({"hits": {"hits": [
            {"_source": {"@timestamp": "2026-08-24T07:00:00Z", "portbridge": {"community_id": "1:a="}}},
            {"_source": {"portbridge": {"community_id_relayed": "1:x=", "src_ip": "203.0.113.1"}}},
            {"_source": {"@timestamp": "2026-08-24T07:00:00Z", "portbridge": {
                "community_id_relayed": "1:y=", "src_ip": ""}}}
        ]}});
        assert!(dials_by_key(&hits).is_empty());
    }
}
