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
//!   network.relay_unresolved      set on a flow old enough that a missing
//!                                 portbridge dial is an answer rather than a
//!                                 delay: this one was never relayed. It
//!                                 records that the question was asked and
//!                                 settled, which is what stops the flow from
//!                                 being reconsidered on every later pass
//!
//! # The pipeline gets the last word on source.ip
//!
//! `geoip-honeypot` is these indices' `default_pipeline`, and a
//! `default_pipeline` runs on `_update`, not only on index. Its Zeek branch
//! derives `source.ip` from `zeek.id.orig_h`, which on zeek-proxy is always
//! the tunnel -- so it re-derived the tunnel address immediately after this
//! loop wrote the attacker, and the write appeared to succeed: ES returned
//! `"result":"updated"` with a bumped `_version` every time. Only `network.*`
//! survived, because the pipeline does not touch those fields, which made a
//! pipeline problem look like a join problem for a while.
//!
//! The pipeline now skips that assignment when `network.relay_ip` is present.
//! If this module ever stops writing that field, the pipeline will start
//! silently overwriting attacker attributions again.
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
/// update, so this is not a bulk-rewrite batch -- but it does have to clear
/// the arrival rate, or the loop falls permanently behind. Measured on the
/// live cluster: ~9,200 zeek-proxy conn records an hour, of which roughly
/// three quarters are relayed and therefore attributable. At one pass every
/// 120s this ceiling is 15,000/hour, which keeps pace and still drains a
/// backlog. 200 did not: it capped the loop at 6,000/hour against 9,200
/// arriving, and the shortfall accumulated silently.
const BATCH: usize = 500;

/// How far back to look for unresolved documents. portbridge and zeek-proxy
/// write independently, so a zeek-proxy record can arrive before the
/// portbridge record that explains it; a narrow window would leave it
/// permanently unattributed for having been looked at once, too early.
const LOOKBACK: &str = "now-6h";

/// How long before a relayed flow a portbridge dial may have happened and
/// still explain it. Same bound, for the same reason, as
/// `ip_enrichment::viamap`'s MAX_AGE_SECONDS.
const MAX_DIAL_AGE_SECONDS: i64 = 6 * 3600;

/// How long to keep re-examining a flow that nothing explains yet.
///
/// Two very different situations look identical on any single pass: portbridge
/// simply has not written its side of a flow that *is* relayed, or the flow was
/// never relayed at all. wg0 carries our own traffic too -- the dashboard's
/// queries to Elasticsearch, the pcap sync hop, WireGuard's own keepalives --
/// and none of that has an attacker behind it or ever will.
///
/// Age separates them. portbridge logs at dial time, strictly before the
/// relayed flow exists, so once a flow is this old a missing dial is an answer
/// rather than a delay. Below the threshold the flow is left alone and looked
/// at again next pass; above it, it is marked so it stops being a candidate.
///
/// Marking matters more than it looks. Without it these flows stay candidates
/// forever, so every pass re-reads and re-rejects the same growing set, and
/// the share of each batch spent on work that can never succeed only rises --
/// a loop that looks busy while resolving less and less. That is true under
/// any sort order; reading newest-first bounds how far back the waste reaches
/// but does not remove it.
const GRACE_SECONDS: i64 = 30 * 60;

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

/// What to do with a flow that no dial explains.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Unmatched {
    /// Too recent to conclude anything -- portbridge's side may still arrive.
    Retry,
    /// Old enough that a missing dial is the answer: this flow was not relayed.
    Mark,
}

pub fn unmatched_action(flow_at: i64, now: i64) -> Unmatched {
    if now - flow_at > GRACE_SECONDS {
        Unmatched::Mark
    } else {
        Unmatched::Retry
    }
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
                    "must_not": [
                        {"exists": {"field": "network.relay_ip"}},
                        {"exists": {"field": "network.relay_unresolved"}}
                    ]
                }},
                // Newest first. Oldest-first is the intuitive choice and it is
                // the wrong one: with a backlog larger than a pass, the loop
                // pins itself to the trailing edge of the window and spends
                // every batch on flows that are minutes from ageing out of it,
                // while the flows someone is actually looking at on the
                // dashboard stay unattributed. Measured that way: oldest
                // candidate 04:45 against a newest document of 10:45, six
                // hours of lag that would have taken most of a day to close.
                //
                // Capacity exceeds the arrival rate (BATCH per pass against
                // ~9,200/hour), so newest-first attributes new flows within a
                // pass or two of arrival and spends what is left over working
                // backwards into the backlog. The tail still ages out, but it
                // ages out having been the lowest-value part of the window
                // rather than the only part that got attention.
                "sort": [{"@timestamp": {"order": "desc"}}],
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
    let now = chrono::Utc::now().timestamp();

    let (mut resolved, mut marked, mut deferred) = (0usize, 0usize, 0usize);
    for doc in &docs {
        let matched = dials.get(&doc.key).and_then(|candidates| dial_for(candidates, doc.at));

        let Some(dial) = matched else {
            // Nothing explains this flow. Whether that is temporary or
            // permanent is a question of age, not of this pass -- see
            // GRACE_SECONDS. Marking the permanent ones is what keeps the
            // candidate window from silting up.
            match unmatched_action(doc.at, now) {
                Unmatched::Retry => deferred += 1,
                Unmatched::Mark => {
                    let update = json!({"network": {"relay_unresolved": true}});
                    match state.es.update_doc(&doc.index, &doc.id, update).await {
                        Ok(()) => marked += 1,
                        Err(error) => tracing::warn!(
                            %error, doc_id = %doc.id,
                            "zeek-proxy-attribution: could not mark unresolved"
                        ),
                    }
                }
            }
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

    if resolved > 0 || marked > 0 || deferred > 0 {
        tracing::debug!(
            resolved,
            marked,
            deferred,
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
    fn a_recent_unmatched_flow_is_retried_not_written_off() {
        // portbridge's side may still be in flight; concluding "never relayed"
        // this early would mark a real attacker's flow as internal traffic.
        let now = 100_000;
        assert_eq!(unmatched_action(now - 60, now), Unmatched::Retry);
        assert_eq!(unmatched_action(now - GRACE_SECONDS, now), Unmatched::Retry);
    }

    #[test]
    fn an_old_unmatched_flow_is_marked_so_the_window_can_move() {
        // Past the grace period a missing dial is the answer. Without the mark
        // these flows stay candidates forever and crowd out attributable work.
        let now = 100_000;
        assert_eq!(unmatched_action(now - GRACE_SECONDS - 1, now), Unmatched::Mark);
        assert_eq!(unmatched_action(now - 6 * 3600, now), Unmatched::Mark);
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
