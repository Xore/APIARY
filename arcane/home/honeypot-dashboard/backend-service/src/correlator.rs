//! correlator-worker port (#1610 worker migration): periodically
//! recomputes two flat, backend-computed Elasticsearch indices --
//! campaigns-v1 (CIDR-grouped) and attacker-clusters-v1
//! (fingerprint/payload/ASN/provider-grouped) -- over a rolling window of
//! recent honeypot-v2-* events, so no dashboard instance has to recompute
//! the same correlation itself on every render. Entirely Elasticsearch-
//! native aggregations (`"size": 0`, no raw-document paging, no PIT/
//! search_after needed at all -- unlike the sibling attacker-identity/
//! agent-intrusion ports).
//!
//! Ported from honeypot-correlator-worker/correlator-worker/
//! (main.go/fetch.go/correlate.go/es.go). Pure ES, no host mounts, no
//! local state -- runs as the `correlator` WORKER_LOOPS entry on the
//! existing (stateless-by-design) backend-worker service.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::time::Duration;

use crate::AppState;

const CAMPAIGNS_INDEX: &str = "campaigns-v1";
const CLUSTERS_INDEX: &str = "attacker-clusters-v1";
const HONEYPOT_INDEX_PATTERN: &str = "honeypot-v2-*";
const SURICATA_ALERT_INDEX_PATTERN: &str = "suricata-v2-alert-*";
const TUNNEL_PEER_IP: &str = "10.8.0.1";
const ALERT_BUCKET_CAP: u64 = 10_000;

fn env_duration(name: &str, default: Duration) -> Duration {
    let raw = std::env::var(name).unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return default;
    }
    let (digits, unit) = raw.split_at(raw.len().saturating_sub(1));
    match (digits.parse::<u64>(), unit) {
        (Ok(n), "h") => Duration::from_secs(n * 3600),
        (Ok(n), "m") => Duration::from_secs(n * 60),
        (Ok(n), "s") => Duration::from_secs(n),
        _ => default,
    }
}

/// Ported verbatim from dashboard/links.go via correlate.go's own copy --
/// gates which canonical_user/canonical_pass pairs count as a real
/// credential signal. Deliberately duplicated (not shared with
/// attacker_identity.rs's private copy of the same logic) -- both ported
/// from the same Go source, kept as two small independent copies rather
/// than introducing a shared module for one ~15-line function.
fn valid_credential_pair(user: &str, pass: &str) -> bool {
    if (user.is_empty() && pass.is_empty()) || user.len() > 128 || pass.len() > 512 {
        return false;
    }
    for value in [user, pass] {
        let lower = value.to_lowercase();
        if value.contains(['\0', '\r', '\n']) || lower.contains("\\x00") || lower.contains("\\u0000") {
            return false;
        }
    }
    if user.contains([' ', '\t', '/', ';', '|', '&', '<', '>']) {
        return false;
    }
    let lower_pass = pass.trim().to_lowercase();
    for marker in ["/bin/", "busybox", "linuxshell", "powershell", "cmd.exe"] {
        if lower_pass.contains(marker) {
            return false;
        }
    }
    true
}

fn is_routable(addr: &IpAddr) -> bool {
    // Rust stable has no direct IsGlobalUnicast(); global-unicast-and-not-
    // private-or-loopback-or-link-local is equivalent to "not unspecified,
    // not loopback, not link-local, not private, not multicast" for the
    // address classes this deployment's own traffic actually produces.
    if addr.is_unspecified() || addr.is_loopback() || addr.is_multicast() {
        return false;
    }
    match addr {
        IpAddr::V4(v4) => !v4.is_private() && !v4.is_link_local(),
        IpAddr::V6(v6) => {
            // Unique local (fc00::/7) and link-local (fe80::/10) -- IsPrivate/
            // IsLinkLocalUnicast's own IPv6 scope in Go's netip.
            let seg0 = v6.segments()[0];
            let is_unique_local = (seg0 & 0xfe00) == 0xfc00;
            let is_link_local = (seg0 & 0xffc0) == 0xfe80;
            !is_unique_local && !is_link_local
        }
    }
}

/// is_routable_network mirrors dashboard/campaigns.go's campaignCIDR
/// filter, applied to an aggregation bucket's already-masked network
/// address (not a full IP+prefix) -- see fetch.go's own header for why
/// this policy isn't duplicated as Elasticsearch query clauses instead.
fn is_routable_network(network_addr: &str) -> bool {
    match network_addr.parse::<IpAddr>() {
        Ok(addr) => is_routable(&addr),
        Err(_) => false,
    }
}

/// campaign_cidr mirrors dashboard/campaigns.go's function of the same
/// name: derives one raw member IP's own CIDR group (/24 v4, /64 v6) --
/// distinct from is_routable_network above, which takes an already-masked
/// network address. Used only to re-bucket fetch_suricata_alert_counts'
/// flat per-IP result back into whichever CIDR group each alerting IP
/// belongs to (the aggregation-based campaign fetch no longer carries a
/// per-group member-IP list to look alert counts up against directly).
fn campaign_cidr(ip: &str) -> Option<String> {
    let addr: IpAddr = ip.parse().ok()?;
    if !is_routable(&addr) {
        return None;
    }
    match addr {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            let masked = std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0);
            Some(format!("{masked}/64"))
        }
    }
}

fn cluster_doc_id(kind: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update([0u8]);
    hasher.update(value.as_bytes());
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn str_terms(buckets: &[Value], limit: usize) -> Vec<String> {
    buckets
        .iter()
        .filter_map(|b| b["key"].as_str())
        .filter(|s| !s.is_empty())
        .take(limit)
        .map(String::from)
        .collect()
}

fn port_terms(buckets: &[Value]) -> Vec<String> {
    buckets
        .iter()
        .filter_map(|b| {
            if let Some(n) = b["key"].as_f64() {
                Some((n as i64).to_string())
            } else {
                b["key"].as_str().filter(|s| !s.is_empty()).map(String::from)
            }
        })
        .collect()
}

fn any_to_string(v: &Value) -> String {
    if let Some(s) = v.as_str() {
        s.to_string()
    } else if let Some(n) = v.as_f64() {
        (n as i64).to_string()
    } else {
        String::new()
    }
}

/// campaign_bucket -- one already-aggregated, already-scored-input group,
/// before alert-count folding/scoring (correlate.go's own campaignBucket).
struct CampaignBucket {
    cidr: String,
    events: i64,
    unique_ips: i64,
    sensors: Vec<String>,
    ports: Vec<String>,
    creds: i64,
    payloads: i64,
    fingerprints: i64,
    providers: Vec<String>,
    first: String,
    last: String,
}

fn campaign_sub_aggs() -> Value {
    json!({
        "unique_ips": {"cardinality": {"field": "source.ip"}},
        "sensors": {"terms": {"field": "event.sensor", "size": 20}},
        "ports": {"terms": {"field": "destination.port", "size": 20}},
        "cred_pairs": {
            "terms": {
                "size": 50,
                "script": {
                    "source": "def u = doc.containsKey(params.uf) && !doc[params.uf].empty ? doc[params.uf].value : ''; def p = doc.containsKey(params.pf) && !doc[params.pf].empty ? doc[params.pf].value : ''; return u + ' / ' + p;",
                    "params": {"uf": "honeypot.canonical_user", "pf": "honeypot.canonical_pass"}
                }
            }
        },
        "payloads": {"cardinality": {"field": "honeypot.canonical_shasum"}},
        "fingerprints": {"cardinality": {"field": "honeypot.canonical_fingerprint"}},
        "providers": {"terms": {"field": "source.as.type", "size": 10}},
        "first": {"min": {"field": "@timestamp"}},
        "last": {"max": {"field": "@timestamp"}}
    })
}

fn to_bucket(key: &str, prefix_length: i64, b: &Value) -> CampaignBucket {
    let mut creds = 0i64;
    for pair in b["cred_pairs"]["buckets"].as_array().into_iter().flatten() {
        let Some(s) = pair["key"].as_str() else { continue };
        let Some((user, pass)) = s.split_once(" / ") else { continue };
        if valid_credential_pair(user, pass) {
            creds += 1;
        }
    }
    CampaignBucket {
        cidr: format!("{key}/{prefix_length}"),
        events: b["doc_count"].as_i64().unwrap_or(0),
        unique_ips: b["unique_ips"]["value"].as_i64().unwrap_or(0),
        sensors: str_terms(b["sensors"]["buckets"].as_array().unwrap_or(&vec![]), 6),
        ports: port_terms(b["ports"]["buckets"].as_array().unwrap_or(&vec![])),
        creds,
        payloads: b["payloads"]["value"].as_i64().unwrap_or(0),
        fingerprints: b["fingerprints"]["value"].as_i64().unwrap_or(0),
        providers: str_terms(b["providers"]["buckets"].as_array().unwrap_or(&vec![]), 4),
        first: b["first"]["value_as_string"].as_str().unwrap_or_default().to_string(),
        last: b["last"]["value_as_string"].as_str().unwrap_or_default().to_string(),
    }
}

async fn fetch_campaign_aggregates(state: &AppState, since: chrono::DateTime<chrono::Utc>) -> anyhow::Result<Vec<CampaignBucket>> {
    let sub_aggs = campaign_sub_aggs();
    let body = json!({
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since.to_rfc3339()}}},
            {"exists": {"field": "source.ip"}}
        ]}},
        "aggs": {
            "cidrs_v4": {
                "ip_prefix": {"field": "source.ip", "prefix_length": 24, "is_ipv6": false, "min_doc_count": 2},
                "aggs": sub_aggs
            },
            "cidrs_v6": {
                "ip_prefix": {"field": "source.ip", "prefix_length": 64, "is_ipv6": true, "min_doc_count": 2},
                "aggs": sub_aggs
            }
        }
    });
    let result = state.es.search_index(&[HONEYPOT_INDEX_PATTERN], body).await?;
    let mut out = Vec::new();
    for agg_name in ["cidrs_v4", "cidrs_v6"] {
        for b in result["aggregations"][agg_name]["buckets"].as_array().into_iter().flatten() {
            let Some(key) = b["key"].as_str() else { continue };
            if !is_routable_network(key) {
                continue;
            }
            let prefix_length = b["prefix_length"].as_i64().unwrap_or(0);
            out.push(to_bucket(key, prefix_length, b));
        }
    }
    Ok(out)
}

struct ClusterBucket {
    kind: String,
    value: String,
    events: i64,
    unique_ips: i64,
    sensors: Vec<String>,
}

async fn fetch_cluster_aggregates(state: &AppState, since: chrono::DateTime<chrono::Utc>) -> anyhow::Result<Vec<ClusterBucket>> {
    let with_unique_and_sensors = |extra: Value| -> Value {
        let mut aggs = json!({
            "unique_ips": {"cardinality": {"field": "source.ip"}},
            "sensors": {"terms": {"field": "event.sensor", "size": 10}}
        });
        if let Value::Object(extra_map) = extra {
            let obj = aggs.as_object_mut().unwrap();
            for (k, v) in extra_map {
                obj.insert(k, v);
            }
        }
        aggs
    };
    let body = json!({
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since.to_rfc3339()}}},
            {"exists": {"field": "source.ip"}}
        ]}},
        "aggs": {
            "fingerprints": {
                "terms": {"field": "honeypot.canonical_fingerprint", "size": 250, "min_doc_count": 2},
                "aggs": with_unique_and_sensors(json!({}))
            },
            "payloads": {
                "terms": {"field": "honeypot.canonical_shasum", "size": 250, "min_doc_count": 2},
                "aggs": with_unique_and_sensors(json!({}))
            },
            "asns": {
                "terms": {"field": "source.as.asn", "size": 250, "min_doc_count": 2},
                "aggs": with_unique_and_sensors(json!({"org": {"terms": {"field": "source.as.organization_name", "size": 1}}}))
            },
            "providers": {
                "terms": {"field": "source.as.type", "size": 250, "min_doc_count": 2},
                "aggs": with_unique_and_sensors(json!({}))
            }
        }
    });
    let result = state.es.search_index(&[HONEYPOT_INDEX_PATTERN], body).await?;
    let mut out = Vec::new();
    let add = |kind: &str, buckets: &[Value], value_of: &dyn Fn(&Value) -> String, out: &mut Vec<ClusterBucket>| {
        for b in buckets {
            let unique_ips = b["unique_ips"]["value"].as_i64().unwrap_or(0);
            if unique_ips < 2 {
                continue;
            }
            let value = value_of(b);
            if value.is_empty() {
                continue;
            }
            out.push(ClusterBucket {
                kind: kind.to_string(),
                value,
                events: b["doc_count"].as_i64().unwrap_or(0),
                unique_ips,
                sensors: str_terms(b["sensors"]["buckets"].as_array().unwrap_or(&vec![]), 6),
            });
        }
    };
    let empty = vec![];
    add(
        "fingerprint",
        result["aggregations"]["fingerprints"]["buckets"].as_array().unwrap_or(&empty),
        &|b| any_to_string(&b["key"]),
        &mut out,
    );
    add(
        "payload",
        result["aggregations"]["payloads"]["buckets"].as_array().unwrap_or(&empty),
        &|b| any_to_string(&b["key"]),
        &mut out,
    );
    add(
        "asn",
        result["aggregations"]["asns"]["buckets"].as_array().unwrap_or(&empty),
        &|b| {
            let asn = any_to_string(&b["key"]);
            if asn.is_empty() {
                return String::new();
            }
            let org = b["org"]["buckets"]
                .as_array()
                .and_then(|a| a.first())
                .map(|o| any_to_string(&o["key"]))
                .unwrap_or_default();
            format!("AS{asn} {org}")
        },
        &mut out,
    );
    add(
        "provider",
        result["aggregations"]["providers"]["buckets"].as_array().unwrap_or(&empty),
        &|b| any_to_string(&b["key"]),
        &mut out,
    );
    Ok(out)
}

/// A missing suricata-v2-alert-* index (no alerts ever shipped) degrades
/// gracefully via search_index's own ignore_unavailable(true) -- no special
/// 404 handling needed here, unlike the Go version's own status-code check.
async fn fetch_suricata_alert_counts(state: &AppState, since: chrono::DateTime<chrono::Utc>) -> anyhow::Result<std::collections::HashMap<String, i64>> {
    let body = json!({
        "size": 0,
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": since.to_rfc3339()}}},
            {"exists": {"field": "source.ip"}}
        ]}},
        "aggs": {"by_ip": {"terms": {"field": "source.ip", "size": ALERT_BUCKET_CAP}}}
    });
    let result = state.es.search_index(&[SURICATA_ALERT_INDEX_PATTERN], body).await?;
    let mut counts = std::collections::HashMap::new();
    for b in result["aggregations"]["by_ip"]["buckets"].as_array().into_iter().flatten() {
        if let Some(ip) = b["key"].as_str() {
            counts.insert(ip.to_string(), b["doc_count"].as_i64().unwrap_or(0));
        }
    }
    Ok(counts)
}

fn alert_counts_by_cidr(alert_counts: &std::collections::HashMap<String, i64>) -> std::collections::HashMap<String, i64> {
    let mut out = std::collections::HashMap::new();
    for (ip, count) in alert_counts {
        if ip == TUNNEL_PEER_IP {
            continue;
        }
        let Some(cidr) = campaign_cidr(ip) else { continue };
        *out.entry(cidr).or_insert(0) += count;
    }
    out
}

fn score_campaigns(buckets: Vec<CampaignBucket>, now: chrono::DateTime<chrono::Utc>, alert_counts: &std::collections::HashMap<String, i64>) -> Vec<Value> {
    let by_cidr = alert_counts_by_cidr(alert_counts);
    let mut docs: Vec<(i64, i64, String, Value)> = buckets
        .into_iter()
        .map(|b| {
            let alerts = *by_cidr.get(&b.cidr).unwrap_or(&0);
            let score = (b.events.min(30)
                + (b.sensors.len() as i64) * 15
                + b.unique_ips * 3
                + b.creds * 8
                + b.payloads * 20
                + alerts.min(15) * 2
                + b.fingerprints * 3
                + (b.providers.len() as i64) * 2)
                .min(100);
            let mut why = Vec::new();
            if b.sensors.len() > 1 {
                why.push(format!("cross-sensor activity ({})", b.sensors.len()));
            }
            if b.unique_ips > 1 {
                why.push(format!("{} related source IPs", b.unique_ips));
            }
            if b.payloads > 0 {
                why.push(format!("{} shared payloads", b.payloads));
            }
            if b.creds > 0 {
                why.push(format!("{} reused credentials", b.creds));
            }
            if alerts > 0 {
                why.push(format!("{alerts} IDS alerts"));
            }
            if b.fingerprints > 0 {
                why.push(format!("{} fingerprints", b.fingerprints));
            }
            if why.is_empty() {
                why.push("repeated activity from one routable network".to_string());
            }
            let doc = json!({
                "cidr": b.cidr, "score": score, "events": b.events, "unique_ips": b.unique_ips,
                "sensors": b.sensors, "ports": b.ports, "creds": b.creds, "payloads": b.payloads,
                "alerts": alerts, "providers": b.providers, "fingerprints": b.fingerprints,
                "first": b.first, "last": b.last, "generated": now.to_rfc3339(),
                "explanation": why.join("; ")
            });
            (score, b.events, b.cidr.clone(), doc)
        })
        .collect();
    docs.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)).then(a.2.cmp(&b.2)));
    docs.truncate(50);
    docs.into_iter().map(|(_, _, _, doc)| doc).collect()
}

fn finalize_clusters(buckets: Vec<ClusterBucket>, now: chrono::DateTime<chrono::Utc>) -> Vec<Value> {
    let mut docs: Vec<ClusterBucket> = buckets;
    docs.sort_by(|a, b| {
        b.unique_ips
            .cmp(&a.unique_ips)
            .then(b.events.cmp(&a.events))
            .then(a.kind.cmp(&b.kind))
            .then(a.value.cmp(&b.value))
    });
    docs.truncate(250);
    docs.into_iter()
        .map(|b| {
            json!({
                "kind": b.kind, "value": b.value, "events": b.events, "sources": b.unique_ips,
                "sensors": b.sensors, "generated": now.to_rfc3339()
            })
        })
        .collect()
}

async fn run_correlation(state: &AppState, window: Duration) {
    let start = chrono::Utc::now();
    let since = start - chrono::Duration::from_std(window).unwrap_or(chrono::Duration::days(7));

    let campaign_buckets = match fetch_campaign_aggregates(state, since).await {
        Ok(b) => b,
        Err(error) => {
            tracing::warn!(%error, "correlator: fetching campaign aggregates failed, skipping this cycle");
            return;
        }
    };
    let cluster_buckets = match fetch_cluster_aggregates(state, since).await {
        Ok(b) => b,
        Err(error) => {
            tracing::warn!(%error, "correlator: fetching cluster aggregates failed, skipping this cycle");
            return;
        }
    };
    let alert_counts = match fetch_suricata_alert_counts(state, since).await {
        Ok(c) => c,
        Err(error) => {
            tracing::warn!(%error, "correlator: fetching suricata alert counts failed, scoring this cycle without them");
            std::collections::HashMap::new()
        }
    };

    let campaigns = score_campaigns(campaign_buckets, start, &alert_counts);
    let mut campaign_ids = Vec::with_capacity(campaigns.len());
    for c in &campaigns {
        let id = c["cidr"].as_str().unwrap_or_default().to_string();
        if let Err(error) = state.es.index_doc(CAMPAIGNS_INDEX, &id, c.clone()).await {
            tracing::warn!(%error, id = %id, "correlator: index campaign failed");
        }
        campaign_ids.push(id);
    }
    if let Err(error) = state.es.delete_by_query_except(CAMPAIGNS_INDEX, &campaign_ids).await {
        tracing::warn!(%error, "correlator: clean up stale campaigns failed");
    }

    let clusters = finalize_clusters(cluster_buckets, start);
    let mut cluster_ids = Vec::with_capacity(clusters.len());
    for c in &clusters {
        let id = cluster_doc_id(c["kind"].as_str().unwrap_or_default(), c["value"].as_str().unwrap_or_default());
        if let Err(error) = state.es.index_doc(CLUSTERS_INDEX, &id, c.clone()).await {
            tracing::warn!(%error, id = %id, "correlator: index cluster failed");
        }
        cluster_ids.push(id);
    }
    if let Err(error) = state.es.delete_by_query_except(CLUSTERS_INDEX, &cluster_ids).await {
        tracing::warn!(%error, "correlator: clean up stale clusters failed");
    }

    tracing::info!(
        campaigns = campaigns.len(),
        clusters = clusters.len(),
        duration_ms = (chrono::Utc::now() - start).num_milliseconds(),
        "correlator: cycle complete"
    );
}

pub async fn correlator_loop(state: AppState) {
    let window = env_duration("CORRELATION_WINDOW", Duration::from_secs(7 * 24 * 3600));
    let interval = env_duration("CORRELATOR_RUN_INTERVAL", Duration::from_secs(15 * 60));
    loop {
        run_correlation(&state, window).await;
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket(cidr: &str, events: i64, sensors: usize, unique_ips: i64, creds: i64, payloads: i64, fingerprints: i64, providers: usize) -> CampaignBucket {
        CampaignBucket {
            cidr: cidr.to_string(),
            events,
            unique_ips,
            sensors: (0..sensors).map(|i| format!("sensor{i}")).collect(),
            ports: vec![],
            creds,
            payloads,
            fingerprints,
            providers: (0..providers).map(|i| format!("provider{i}")).collect(),
            first: "2026-01-01T00:00:00Z".to_string(),
            last: "2026-01-01T01:00:00Z".to_string(),
        }
    }

    #[test]
    fn score_formula_matches_go_and_caps_at_100() {
        let now = chrono::Utc::now();
        // events=100(cap 30) + sensors(2*15=30) + unique_ips(5*3=15) +
        // creds(3*8=24) + payloads(2*20=40) + fingerprints(4*3=12) +
        // providers(1*2=2) = 30+30+15+24+40+12+2 = 153, capped to 100.
        let docs = score_campaigns(vec![bucket("203.0.113.0/24", 100, 2, 5, 3, 2, 4, 1)], now, &std::collections::HashMap::new());
        assert_eq!(docs[0]["score"], 100);
    }

    #[test]
    fn score_explanation_falls_back_when_nothing_stands_out() {
        let now = chrono::Utc::now();
        let docs = score_campaigns(vec![bucket("203.0.113.0/24", 5, 1, 1, 0, 0, 0, 0)], now, &std::collections::HashMap::new());
        assert_eq!(docs[0]["explanation"], "repeated activity from one routable network");
    }

    #[test]
    fn campaigns_sorted_by_score_then_events_then_cidr_and_capped_at_50() {
        let now = chrono::Utc::now();
        let mut buckets = vec![bucket("198.51.100.0/24", 10, 1, 1, 0, 0, 0, 0)];
        for i in 0..60 {
            buckets.push(bucket(&format!("203.0.113.{i}/24"), 1, 1, 1, 0, 0, 0, 0));
        }
        let docs = score_campaigns(buckets, now, &std::collections::HashMap::new());
        assert_eq!(docs.len(), 50);
        assert_eq!(docs[0]["cidr"], "198.51.100.0/24");
    }

    #[test]
    fn clusters_below_two_unique_ips_excluded_by_caller_and_finalize_sorts() {
        let now = chrono::Utc::now();
        let buckets = vec![
            ClusterBucket { kind: "fingerprint".into(), value: "aaa".into(), events: 5, unique_ips: 3, sensors: vec![] },
            ClusterBucket { kind: "payload".into(), value: "bbb".into(), events: 50, unique_ips: 10, sensors: vec![] },
        ];
        let docs = finalize_clusters(buckets, now);
        assert_eq!(docs[0]["value"], "bbb");
        assert_eq!(docs[0]["sources"], 10);
    }

    #[test]
    fn is_routable_network_excludes_private_loopback_link_local_and_tunnel_subnet() {
        assert!(!is_routable_network("10.8.0.0"));
        assert!(!is_routable_network("192.168.1.0"));
        assert!(!is_routable_network("127.0.0.0"));
        assert!(!is_routable_network("169.254.0.0"));
        assert!(is_routable_network("203.0.113.0"));
    }

    #[test]
    fn campaign_cidr_masks_ipv4_to_slash24() {
        assert_eq!(campaign_cidr("203.0.113.42").as_deref(), Some("203.0.113.0/24"));
        assert_eq!(campaign_cidr("10.8.0.1"), None);
        assert_eq!(campaign_cidr(TUNNEL_PEER_IP), None);
    }

    #[test]
    fn valid_credential_pair_rejects_shell_markers() {
        assert!(!valid_credential_pair("root", "/bin/sh"));
        assert!(valid_credential_pair("admin", "hunter2"));
    }

    #[test]
    fn cluster_doc_id_is_stable_and_kind_scoped() {
        let a = cluster_doc_id("fingerprint", "abc");
        let b = cluster_doc_id("payload", "abc");
        assert_ne!(a, b);
        assert_eq!(a, cluster_doc_id("fingerprint", "abc"));
    }
}
