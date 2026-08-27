//! Background worker loop (`WORKER_LOOPS=threat-intel`): classifies source
//! IPs against a locally refreshed CIDR intel list (`threat-cidrs.csv`,
//! kept current by `refresh-threat-cidrs.sh` — see that script's own
//! header for sources/cadence), writing the result into `source.as.type`,
//! the same field the `geoip-honeypot` ingest pipeline's provider
//! classification (cloud/hosting/scanner/network) already populates.
//!
//! Ported from the Go dashboard's geoip.go (`loadIntelCIDRs`,
//! `threatIntelReloadLoop`, `lookup`'s intel-matching pass): that binary
//! classified a source IP inline on every page render and displayed
//! `firstNonEmpty(e.Intel, e.Provider)` wherever a single origin-class
//! value was shown — intel always wins over the plain provider class.
//! Folding intel into `source.as.type` here reproduces that precedence at
//! the data layer instead: every existing `source.as.type`
//! aggregation/filter/badge across the dashboard (Overview's provider
//! panel, campaigns/clusters correlation, events filters, investigate)
//! already works with intel labels with no frontend or API change, and
//! this loop runs standalone in `backend-worker` — no request-serving path
//! calls into it.
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use serde_json::json;

use crate::es::EVENT_INDICES;
use crate::AppState;

const RELOAD_INTERVAL: Duration = Duration::from_secs(5 * 60);
const RUN_INTERVAL: Duration = Duration::from_secs(15 * 60);
const LOOKBACK: chrono::Duration = chrono::Duration::hours(24);
const IP_TERMS_SIZE: u32 = 5_000;

#[derive(Clone)]
struct IntelPrefix {
    network: IpAddr,
    bits: u8,
    label: String,
}

impl IntelPrefix {
    fn contains(&self, addr: IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => u32::from(net) & mask32(self.bits) == u32::from(ip) & mask32(self.bits),
            (IpAddr::V6(net), IpAddr::V6(ip)) => u128::from(net) & mask128(self.bits) == u128::from(ip) & mask128(self.bits),
            _ => false,
        }
    }
}

fn mask32(bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(bits))
    }
}

fn mask128(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(bits))
    }
}

/// Severity rank, matching the Go dashboard's intelCategoryRank: an address
/// inside more than one overlapping intel CIDR resolves to the more severe
/// label, not whichever entry happened to load first.
fn category_rank(label: &str) -> u8 {
    if label.starts_with("blocklist:") {
        2
    } else if label == "tor-exit" {
        1
    } else {
        0
    }
}

fn parse_cidr(text: &str) -> Option<(IpAddr, u8)> {
    let (addr, bits) = text.trim().split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    let bits: u8 = bits.parse().ok()?;
    let max_bits = if addr.is_ipv4() { 32 } else { 128 };
    if bits > max_bits {
        return None;
    }
    // Mask down to the network address so `IntelPrefix::contains` never
    // depends on stray host bits the source file left set (netip.Prefix's
    // own `.Masked()` in the Go original).
    let masked = match addr {
        IpAddr::V4(v4) => IpAddr::V4((u32::from(v4) & mask32(bits)).into()),
        IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & mask128(bits)).into()),
    };
    Some((masked, bits))
}

fn load_intel_cidrs(path: &str) -> Vec<IntelPrefix> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for line in content.lines() {
        let mut fields = line.splitn(2, ',');
        let (Some(cidr), Some(label)) = (fields.next(), fields.next()) else {
            continue;
        };
        if let Some((network, bits)) = parse_cidr(cidr) {
            out.push(IntelPrefix { network, bits, label: label.trim().to_string() });
        }
    }
    out
}

/// Highest-severity label covering `addr`, ties broken by the most specific
/// (longest) prefix — same rule as geoip.go's `lookup`.
fn classify(prefixes: &[IntelPrefix], addr: IpAddr) -> Option<&str> {
    let mut best: Option<(&IntelPrefix, u8)> = None;
    for prefix in prefixes {
        if !prefix.contains(addr) {
            continue;
        }
        let rank = category_rank(&prefix.label);
        let better = match best {
            None => true,
            Some((current, current_rank)) => rank > current_rank || (rank == current_rank && prefix.bits > current.bits),
        };
        if better {
            best = Some((prefix, rank));
        }
    }
    best.map(|(prefix, _)| prefix.label.as_str())
}

pub async fn threat_intel_loop(state: AppState) {
    let path = std::env::var("THREAT_CIDRS_FILE").unwrap_or_default();
    if path.is_empty() {
        tracing::info!("threat-intel: THREAT_CIDRS_FILE unset, loop idle");
        return;
    }
    let mut prefixes = load_intel_cidrs(&path);
    let mut last_reload = SystemTime::now();
    tracing::info!(count = prefixes.len(), "threat-intel: loaded intel CIDRs");
    loop {
        if last_reload.elapsed().unwrap_or(Duration::MAX) >= RELOAD_INTERVAL {
            let fresh = load_intel_cidrs(&path);
            if !fresh.is_empty() {
                prefixes = fresh;
            }
            last_reload = SystemTime::now();
        }
        if !prefixes.is_empty() {
            // #2181: every fallible step inside (bucket parsing, tagging)
            // already returns Option/Result, so a per-bucket split would
            // guard nothing real — this cycle-level boundary is what keeps
            // future drift from ending the task. Tagging is scoped by IP +
            // time window and idempotent, so a degraded pass redoes itself.
            crate::isolate::cycle("threat-intel", run_classification(&state, &prefixes)).await;
        }
        tokio::time::sleep(RUN_INTERVAL).await;
    }
}

async fn run_classification(state: &AppState, prefixes: &[IntelPrefix]) {
    let since = (chrono::Utc::now() - LOOKBACK).to_rfc3339();
    let body = json!({
        "size": 0,
        // #2145: the source.ip terms agg already keeps probe docs (which
        // carry none) out of the intel loop; the term makes it explicit.
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": since}}}],
            "must_not": [crate::es::internal_probe_exclusion()]
        }},
        "aggs": {"ips": {"terms": {"field": "source.ip", "size": IP_TERMS_SIZE}}},
    });
    let response = match state.es.search(body).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(%error, "threat-intel: fetching recent source IPs failed");
            return;
        }
    };
    let buckets = response["aggregations"]["ips"]["buckets"].as_array().cloned().unwrap_or_default();
    if buckets.len() as u32 >= IP_TERMS_SIZE {
        tracing::warn!(cap = IP_TERMS_SIZE, "threat-intel: distinct source IPs hit the terms cap this cycle, some may be skipped");
    }
    let mut tagged = 0u64;
    for bucket in buckets {
        let Some(ip_text) = bucket["key"].as_str() else { continue };
        let Ok(addr) = ip_text.parse::<IpAddr>() else { continue };
        let Some(label) = classify(prefixes, addr) else { continue };
        match tag_ip(state, ip_text, label, &since).await {
            Ok(updated) => tagged += updated,
            Err(error) => tracing::warn!(%error, ip = ip_text, "threat-intel: tagging failed"),
        }
    }
    if tagged > 0 {
        tracing::info!(documents = tagged, "threat-intel: tagged documents this cycle");
    }
}

/// Sets `source.as.type` = `label` on every doc from `ip` within the
/// lookback window that doesn't already carry it — scoped by IP and time
/// rather than a full index rewrite, and idempotent (a repeat run over the
/// same window updates nothing further).
async fn tag_ip(state: &AppState, ip: &str, label: &str, since: &str) -> anyhow::Result<u64> {
    let query = json!({
        "bool": {
            "filter": [
                {"term": {"source.ip": ip}},
                {"range": {"@timestamp": {"gte": since}}},
            ],
            "must_not": [{"term": {"source.as.type": label}}],
        }
    });
    state
        .es
        .update_by_query(EVENT_INDICES, query, "ctx._source.source.as.type = params.label", json!({"label": label}))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(cidr: &str, label: &str) -> IntelPrefix {
        let (network, bits) = parse_cidr(cidr).unwrap();
        IntelPrefix { network, bits, label: label.to_string() }
    }

    #[test]
    fn contains_matches_within_prefix_only() {
        let p = prefix("198.51.100.0/24", "tor-exit");
        assert!(p.contains("198.51.100.42".parse().unwrap()));
        assert!(!p.contains("198.51.101.1".parse().unwrap()));
    }

    #[test]
    fn ipv6_prefix_matches() {
        let p = prefix("2001:db8::/32", "tor-exit");
        assert!(p.contains("2001:db8::1".parse().unwrap()));
        assert!(!p.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn classify_picks_highest_severity_over_load_order() {
        let prefixes = vec![prefix("203.0.113.0/24", "tor-exit"), prefix("203.0.113.0/28", "blocklist:spamhaus-drop")];
        let addr = "203.0.113.5".parse().unwrap();
        assert_eq!(classify(&prefixes, addr), Some("blocklist:spamhaus-drop"));
    }

    #[test]
    fn classify_breaks_severity_ties_with_longest_prefix() {
        let prefixes = vec![prefix("203.0.113.0/24", "blocklist:feed-a"), prefix("203.0.113.0/28", "blocklist:feed-b")];
        let addr = "203.0.113.5".parse().unwrap();
        assert_eq!(classify(&prefixes, addr), Some("blocklist:feed-b"));
    }

    #[test]
    fn classify_returns_none_outside_every_prefix() {
        let prefixes = vec![prefix("203.0.113.0/24", "tor-exit")];
        assert_eq!(classify(&prefixes, "192.0.2.1".parse().unwrap()), None);
    }

    #[test]
    fn load_intel_cidrs_skips_malformed_and_short_lines() {
        let dir = std::env::temp_dir().join(format!("threat-intel-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("threat-cidrs.csv");
        std::fs::write(&path, "203.0.113.0/24,tor-exit\nnot-a-cidr,tor-exit\nlonely-field\n2001:db8::/32,blocklist:x\n").unwrap();
        let loaded = load_intel_cidrs(path.to_str().unwrap());
        assert_eq!(loaded.len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_intel_cidrs_missing_file_returns_empty() {
        assert!(load_intel_cidrs("/nonexistent/threat-cidrs.csv").is_empty());
    }
}
