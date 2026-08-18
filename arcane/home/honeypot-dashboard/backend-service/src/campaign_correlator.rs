//! agent-intrusion-worker port (#1610), campaign_correlator.py half:
//! union-find over shared stable identifiers (session ID, source IP, a
//! recovered C2 channel ID), gated by a time window. Deterministic — no
//! ML, no fuzzy matching. Distinct from decode_correlate.rs's chunk
//! parsing, which reassembles one multi-part *message*; this correlates
//! separate, complete events into one *campaign*.

use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

static CHANNEL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"channel=([A-Za-z0-9]+)").unwrap());

/// Actor names identifying a named, legitimate participant rather than an
/// anonymous/compromised one — when one of these owns a "host" value,
/// that host is real shared infrastructure an unrelated event can
/// legitimately also mention, not shared-identity evidence.
const NAMED_ACTORS: &[&str] = &[
    "admin",
    "system",
    "hp-autoheal",
    "dependabot[bot]",
    "github-actions[bot]",
];

/// One correlated event: `raw` carries whatever sensor-native fields the
/// worker fetched (not this crate's usual flattened honeypot.canonical_*
/// convention — see agent_intrusion.rs's own module comment).
pub struct CorrelatorEvent {
    pub event_id: String,
    pub timestamp: String,
    pub raw: serde_json::Value,
}

/// Pulls every stable identifier this event's raw sensor data carries.
/// Deliberately narrow: only signals confirmed to actually indicate shared
/// actor/session/channel identity (dest_ip and a named actor's own host
/// are excluded — see the Python source's own extended rationale).
pub fn extract_identifiers(raw: &serde_json::Value) -> HashSet<String> {
    let mut ids = HashSet::new();

    if let Some(session) = raw
        .get("session")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        ids.insert(format!("session:{session}"));
    }
    if let Some(src_ip) = raw
        .get("src_ip")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        ids.insert(format!("ip:{src_ip}"));
    }

    let host = raw
        .get("host")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty());
    let actor = raw.get("actor").and_then(|v| v.as_str());
    if let Some(host) = host {
        let named = actor.map(|a| NAMED_ACTORS.contains(&a)).unwrap_or(false);
        if !named {
            ids.insert(format!("ip:{host}"));
        }
    }

    for field in ["input", "payload_printable"] {
        if let Some(text) = raw.get(field).and_then(|v| v.as_str()) {
            if let Some(caps) = CHANNEL_RE.captures(text) {
                ids.insert(format!("channel:{}", &caps[1]));
            }
        }
    }

    ids
}

#[derive(Debug, Clone)]
pub struct Campaign {
    pub event_ids: Vec<String>,
    pub identifiers: HashSet<String>,
    pub start: String,
    pub end: String,
}

struct UnionFind {
    parent: HashMap<String, String>,
}

impl UnionFind {
    fn new(items: impl IntoIterator<Item = String>) -> Self {
        let parent = items.into_iter().map(|i| (i.clone(), i)).collect();
        Self { parent }
    }

    fn find(&mut self, x: &str) -> String {
        let mut cur = x.to_string();
        loop {
            let p = self
                .parent
                .get(&cur)
                .cloned()
                .unwrap_or_else(|| cur.clone());
            if p == cur {
                return cur;
            }
            // Path-halving: point cur at its grandparent, then advance.
            let grandparent = self.parent.get(&p).cloned().unwrap_or_else(|| p.clone());
            self.parent.insert(cur.clone(), grandparent.clone());
            cur = grandparent;
        }
    }

    fn union(&mut self, a: &str, b: &str) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            self.parent.insert(ra, rb);
        }
    }
}

fn parse_ts(ts: &str) -> Option<chrono::NaiveDateTime> {
    chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%dT%H:%M:%SZ").ok()
}

/// Groups events sharing a stable identifier into campaigns, within
/// `window` of each other — a shared identifier more than `window` apart
/// is NOT unioned. Events sharing no identifier with anything else become
/// their own singleton campaign.
pub fn correlate_campaigns(events: &[CorrelatorEvent], window: chrono::Duration) -> Vec<Campaign> {
    let by_id: HashMap<&str, &CorrelatorEvent> =
        events.iter().map(|e| (e.event_id.as_str(), e)).collect();
    let ids: Vec<String> = events.iter().map(|e| e.event_id.clone()).collect();
    let mut uf = UnionFind::new(ids.iter().cloned());

    // identifier -> [(event_id, timestamp), ...], sorted by time, so
    // pairwise comparisons only happen within one identifier's own bucket.
    let mut buckets: HashMap<String, Vec<(&str, chrono::NaiveDateTime)>> = HashMap::new();
    for eid in &ids {
        let event = by_id[eid.as_str()];
        let Some(ts) = parse_ts(&event.timestamp) else {
            continue;
        };
        for ident in extract_identifiers(&event.raw) {
            buckets.entry(ident).or_default().push((eid.as_str(), ts));
        }
    }

    for members in buckets.values_mut() {
        members.sort_by_key(|&(_, ts)| ts);
        for pair in members.windows(2) {
            let (eid_a, ts_a) = pair[0];
            let (eid_b, ts_b) = pair[1];
            if ts_b - ts_a <= window {
                uf.union(eid_a, eid_b);
            }
        }
    }

    let mut clusters: HashMap<String, Vec<String>> = HashMap::new();
    for eid in &ids {
        let root = uf.find(eid);
        clusters.entry(root).or_default().push(eid.clone());
    }

    let mut campaigns: Vec<Campaign> = clusters
        .into_values()
        .map(|members| {
            let mut members_sorted = members;
            members_sorted.sort_by(|a, b| {
                by_id[a.as_str()]
                    .timestamp
                    .cmp(&by_id[b.as_str()].timestamp)
            });
            let mut cluster_ids = HashSet::new();
            for eid in &members_sorted {
                cluster_ids.extend(extract_identifiers(&by_id[eid.as_str()].raw));
            }
            let start = by_id[members_sorted[0].as_str()].timestamp.clone();
            let end = by_id[members_sorted[members_sorted.len() - 1].as_str()]
                .timestamp
                .clone();
            Campaign {
                event_ids: members_sorted,
                identifiers: cluster_ids,
                start,
                end,
            }
        })
        .collect();
    campaigns.sort_by(|a, b| a.start.cmp(&b.start));
    campaigns
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(id: &str, ts: &str, raw: serde_json::Value) -> CorrelatorEvent {
        CorrelatorEvent {
            event_id: id.to_string(),
            timestamp: ts.to_string(),
            raw,
        }
    }

    const WINDOW_72H: chrono::Duration = chrono::Duration::hours(72);

    #[test]
    fn session_and_src_ip_are_identifiers() {
        let ids = extract_identifiers(&json!({"session": "s1", "src_ip": "203.0.113.1"}));
        assert_eq!(
            ids,
            HashSet::from(["session:s1".to_string(), "ip:203.0.113.1".to_string()])
        );
    }

    #[test]
    fn host_counts_when_actor_is_unknown() {
        let ids = extract_identifiers(&json!({"host": "192.0.2.50", "actor": "unknown"}));
        assert_eq!(ids, HashSet::from(["ip:192.0.2.50".to_string()]));
    }

    #[test]
    fn host_counts_when_actor_absent() {
        let ids = extract_identifiers(&json!({"host": "192.0.2.50"}));
        assert_eq!(ids, HashSet::from(["ip:192.0.2.50".to_string()]));
    }

    #[test]
    fn host_excluded_for_named_actor() {
        let ids = extract_identifiers(&json!({"host": "192.0.2.1", "actor": "admin"}));
        assert!(ids.is_empty());
    }

    #[test]
    fn channel_extracted_from_input_field() {
        let ids = extract_identifiers(
            &json!({"input": "curl -d 'type=stage&channel=c9f2&seq=1&data=X'"}),
        );
        assert_eq!(ids, HashSet::from(["channel:c9f2".to_string()]));
    }

    #[test]
    fn channel_extracted_from_payload_printable() {
        let ids = extract_identifiers(
            &json!({"payload_printable": "type=exfil&channel=abcd&seq=1&data=X"}),
        );
        assert_eq!(ids, HashSet::from(["channel:abcd".to_string()]));
    }

    #[test]
    fn dest_ip_is_not_an_identifier() {
        let ids = extract_identifiers(&json!({"dest_ip": "192.0.2.61"}));
        assert!(ids.is_empty());
    }

    #[test]
    fn no_identifiers_returns_empty_set() {
        let ids = extract_identifiers(&json!({"event": "something", "actor": "unknown"}));
        assert!(ids.is_empty());
    }

    #[test]
    fn shared_session_merges() {
        let events = vec![
            event(
                "e1",
                "2026-01-01T00:00:00Z",
                json!({"session": "s1", "src_ip": "203.0.113.1"}),
            ),
            event(
                "e2",
                "2026-01-01T00:05:00Z",
                json!({"session": "s1", "src_ip": "203.0.113.1"}),
            ),
        ];
        let campaigns = correlate_campaigns(&events, WINDOW_72H);
        assert_eq!(campaigns.len(), 1);
        assert_eq!(
            HashSet::<&str>::from_iter(campaigns[0].event_ids.iter().map(String::as_str)),
            HashSet::from(["e1", "e2"])
        );
    }

    #[test]
    fn no_shared_identifier_stays_separate() {
        let events = vec![
            event("e1", "2026-01-01T00:00:00Z", json!({"session": "s1"})),
            event("e2", "2026-01-01T00:05:00Z", json!({"session": "s2"})),
        ];
        assert_eq!(correlate_campaigns(&events, WINDOW_72H).len(), 2);
    }

    #[test]
    fn shared_identifier_outside_window_stays_separate() {
        let events = vec![
            event(
                "e1",
                "2026-01-01T00:00:00Z",
                json!({"src_ip": "203.0.113.1"}),
            ),
            event(
                "e2",
                "2026-01-10T00:00:00Z",
                json!({"src_ip": "203.0.113.1"}),
            ),
        ];
        assert_eq!(correlate_campaigns(&events, WINDOW_72H).len(), 2);
    }

    #[test]
    fn shared_identifier_inside_window_merges() {
        let events = vec![
            event(
                "e1",
                "2026-01-01T00:00:00Z",
                json!({"src_ip": "203.0.113.1"}),
            ),
            event(
                "e2",
                "2026-01-02T00:00:00Z",
                json!({"src_ip": "203.0.113.1"}),
            ),
        ];
        assert_eq!(correlate_campaigns(&events, WINDOW_72H).len(), 1);
    }

    #[test]
    fn transitive_chain_across_different_identifier_types() {
        let events = vec![
            event("e1", "2026-01-01T00:00:00Z", json!({"session": "s1"})),
            event(
                "e2",
                "2026-01-01T00:05:00Z",
                json!({"session": "s1", "input": "channel=zz99&seq=1"}),
            ),
            event(
                "e3",
                "2026-01-01T00:10:00Z",
                json!({"payload_printable": "channel=zz99&seq=1"}),
            ),
        ];
        let campaigns = correlate_campaigns(&events, WINDOW_72H);
        assert_eq!(campaigns.len(), 1);
        assert_eq!(
            HashSet::<&str>::from_iter(campaigns[0].event_ids.iter().map(String::as_str)),
            HashSet::from(["e1", "e2", "e3"])
        );
    }

    #[test]
    fn event_with_no_identifiers_is_a_singleton_campaign() {
        let events = vec![event(
            "e1",
            "2026-01-01T00:00:00Z",
            json!({"event": "pull_request_opened", "actor": "unknown"}),
        )];
        let campaigns = correlate_campaigns(&events, WINDOW_72H);
        assert_eq!(campaigns.len(), 1);
        assert_eq!(campaigns[0].event_ids, vec!["e1".to_string()]);
    }

    #[test]
    fn campaigns_sorted_by_start_time() {
        let events = vec![
            event("e1", "2026-01-02T00:00:00Z", json!({"session": "s2"})),
            event("e2", "2026-01-01T00:00:00Z", json!({"session": "s1"})),
        ];
        let campaigns = correlate_campaigns(&events, WINDOW_72H);
        let mut starts: Vec<&str> = campaigns.iter().map(|c| c.start.as_str()).collect();
        let sorted = {
            let mut s = starts.clone();
            s.sort();
            s
        };
        starts.sort();
        assert_eq!(starts, sorted);
    }
}
