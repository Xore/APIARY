//! /api/v1/events — the event explorer's list slice: newest-first ECS
//! events with offset paging (the View-more contract: the client asks for
//! exactly the next batch, nothing loads on scroll) and the filter fields
//! the Go explorer exposes (ip, sensor, country, port, proto, since).

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{event_detail::detail_for, AppState};

#[derive(Deserialize, Clone)]
pub struct EventsQuery {
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_size")]
    pub size: u64,
    pub ip: Option<String>,
    /// #1682: comma-separated source IPs to narrow to — the "Isolate
    /// IP…" checklist (events.html:76-99) applies this alongside
    /// `fingerprint` to pick one attacker among several sharing it.
    /// Distinct from `ip` (the single-IP attack-chain view): this can
    /// carry more than one address.
    pub ips: Option<String>,
    pub sensor: Option<String>,
    pub country: Option<String>,
    pub port: Option<String>,
    pub proto: Option<String>,
    /// honeypot.event kind filter ("command", "login", ...).
    pub kind: Option<String>,
    /// Captured-payload hash pivot (a RevDeck/Ghidra/payload-analysis page
    /// linking back to "related events") — same honeypot.shasum field
    /// fusion.rs's own "Payload hash" pivot already filters on.
    pub shasum: Option<String>,
    /// #1783: one flow, across every sensor that saw it.
    ///
    /// network.community_id is the same v1 hash computed independently by
    /// Zeek, huginn, Suricata and portbridge, so filtering on it collapses a
    /// single TCP connection's records from all of them into one view. That
    /// is a different question from the src_ip filter above: an address
    /// answers "what else did this host do", a community_id answers "what
    /// happened on this connection".
    pub community_id: Option<String>,
    /// Free-text query_string search (the /history page's q=), same
    /// semantics as the Go tier's ES q= passthrough.
    pub q: Option<String>,
    /// Go-style duration ("24h", "7d") relative to now; defaults to the
    /// explorer's rolling window.
    pub since: Option<String>,
    // ── Pivot filters (#1653): the everow detail-pane links the Go
    // explorer rendered (events.html:23-26) all filter here. honeypot.*
    // is flattened — exact terms work; each pivot accepts the value its
    // corresponding link carries.
    /// Decoy persona (honeypot.persona_id).
    pub persona: Option<String>,
    /// Decoy site (honeypot.site_id).
    pub site: Option<String>,
    /// Decoy asset (honeypot.asset_id).
    pub asset: Option<String>,
    /// Client fingerprint — matches any of the fields sensors record one
    /// in (canonical_fingerprint, hassh, fingerprint, client, user_agent).
    pub fingerprint: Option<String>,
    /// Exact command text (canonical_command, command, input).
    pub cmd: Option<String>,
    /// "user / pass" credential pair, split on the legacy separator.
    pub cred: Option<String>,
    /// Request path (honeypot.path, honeypot.url).
    pub path: Option<String>,
    /// Session id (honeypot.session / session.id / honeypot.session_id).
    pub session: Option<String>,
    /// Source AS number (source.as.asn).
    pub asn: Option<String>,
    /// Source network organization (source.as.organization_name).
    pub org: Option<String>,
    /// Provider class (source.as.type).
    pub provider: Option<String>,
    /// IDS alert signature (suricata.eve.alert.signature).
    pub sig: Option<String>,
    /// Detection category (suricata alert category or honeypot.category).
    pub cat: Option<String>,
}

fn default_size() -> u64 {
    25
}

/// The pivot values the explorer's detail pane renders as link groups —
/// the Go tier's classified-event fields (decoy / pivot / origin /
/// detection / recording, events.html:23-27), extracted here so the
/// frontend never re-derives per-sensor field naming. Empty string means
/// "absent"; the pane skips empty groups.
#[derive(Serialize)]
pub struct EventPivots {
    pub persona: String,
    pub site: String,
    pub asset: String,
    pub fingerprint: String,
    pub fingerprint_kind: String,
    pub command: String,
    pub user: String,
    pub pass: String,
    pub path: String,
    pub shasum: String,
    pub asn: String,
    pub org: String,
    pub provider: String,
    pub alert: String,
    pub category: String,
    /// Route to the in-app TTY replay when this event closed a recorded
    /// session (cowrie.log.closed — its `shasum` is the recording's own
    /// hash, deliberately NOT surfaced as a payload hash; see
    /// classify.go's #638/#1266 note).
    pub tty_replay: String,
    /// DNP3 control-function severity ("critical"/"high"/""), from the
    /// frame's `app_function`. The Go tier carried this on
    /// `storedEvent.ICSSeverity` and badged it in the events explorer; the
    /// port dropped the field, so a DIRECT_OPERATE — a command that trips
    /// physical equipment with no confirmation step — rendered
    /// indistinguishably from a benign link-status read. See
    /// `ics_severity.rs`.
    pub ics_severity: String,
}

pub fn pivots_from_source(src: &Value) -> EventPivots {
    let text = |v: &Value| v.as_str().unwrap_or("").to_string();
    let hp = &src["honeypot"];
    let first = |keys: &[&str]| -> String {
        keys.iter().map(|k| text(&hp[*k])).find(|s| !s.is_empty()).unwrap_or_default()
    };
    let eventid = text(&hp["eventid"]);
    let is_tty_close = eventid == "cowrie.log.closed";
    let (fingerprint, fingerprint_kind) = {
        let canonical = text(&hp["canonical_fingerprint"]);
        if !canonical.is_empty() {
            (canonical, {
                let kind = text(&hp["canonical_fingerprint_kind"]);
                if kind.is_empty() { "fingerprint".to_string() } else { kind }
            })
        } else if !text(&hp["hassh"]).is_empty() {
            (text(&hp["hassh"]), "HASSH".to_string())
        } else if !text(&hp["fingerprint"]).is_empty() {
            (text(&hp["fingerprint"]), "SSH pubkey".to_string())
        } else if !text(&hp["client"]).is_empty() {
            (text(&hp["client"]), "client banner".to_string())
        } else if !text(&hp["user_agent"]).is_empty() {
            (text(&hp["user_agent"]), "User-Agent".to_string())
        } else {
            (String::new(), String::new())
        }
    };
    EventPivots {
        persona: text(&hp["persona_id"]),
        site: text(&hp["site_id"]),
        asset: text(&hp["asset_id"]),
        fingerprint,
        fingerprint_kind,
        command: first(&["canonical_command", "command", "input"]),
        user: first(&["canonical_user", "username"]),
        pass: first(&["canonical_pass", "password"]),
        path: first(&["path", "url", "query"]),
        shasum: if is_tty_close { String::new() } else { first(&["canonical_shasum", "shasum"]) },
        asn: src["source"]["as"]["asn"].as_u64().map(|n| n.to_string()).unwrap_or_default(),
        org: text(&src["source"]["as"]["organization_name"]),
        provider: text(&src["source"]["as"]["type"]),
        alert: text(&src["suricata"]["eve"]["alert"]["signature"]),
        category: {
            let sig_cat = text(&src["suricata"]["eve"]["alert"]["category"]);
            if sig_cat.is_empty() { text(&hp["category"]) } else { sig_cat }
        },
        tty_replay: if is_tty_close && !text(&hp["shasum"]).is_empty() {
            format!("/tty-replay/{}", text(&hp["shasum"]))
        } else {
            String::new()
        },
        ics_severity: crate::ics_severity::dnp3_function_severity(&text(&hp["app_function"])).to_string(),
    }
}

#[derive(Serialize)]
pub struct EventRow {
    pub time: String,
    pub sensor: String,
    pub src_ip: String,
    pub country: String,
    pub port: String,
    pub proto: String,
    pub detail: String,
    pub session: String,
    /// Detail-pane pivot groups (#1653) — see EventPivots.
    pub pivots: EventPivots,
    /// The complete normalized ECS document, for the record inspector pane
    /// (the row click opens it; nothing is hidden). #1611 workstream E.4:
    /// this is also where `network.community_id` (when suricata populated
    /// it) is already visible and copyable — it's the exact join key an
    /// Arkime cross-link needs, so no separate field/endpoint is required
    /// on this side; the pivot link itself is a frontend concern.
    pub record: Value,
}

/// One distinct source IP behind the current fingerprint match (#278 /
/// #1682's "Isolate IP…" checklist).
#[derive(Serialize)]
pub struct CorrelatedIp {
    pub ip: String,
    pub count: u64,
    pub checked: bool,
}

#[derive(Serialize)]
pub struct EventsPage {
    pub total: u64,
    pub offset: u64,
    pub rows: Vec<EventRow>,
    /// The distinct IPs behind `fingerprint`, pre-checked to match `ips`
    /// — absent unless a fingerprint filter is active AND more than one
    /// IP is behind it (nothing to isolate otherwise). Evaluated against
    /// every other active filter, but never `ips` itself, so narrowing
    /// the selection doesn't also shrink the checklist to just what's
    /// still checked (pages_data.go's fingerprintIPCorrelation).
    pub fingerprint_ips: Option<Vec<CorrelatedIp>>,
}

/// Distinct source IPs sharing the active fingerprint filter, most
/// frequent first (ties broken by IP for a stable order) — an ES terms
/// aggregation standing in for the Go tier's in-memory count-and-sort
/// over its full per-request event slice.
async fn fingerprint_ip_correlation(state: &AppState, q: &EventsQuery) -> Option<Vec<CorrelatedIp>> {
    if q.fingerprint.as_deref().unwrap_or("").is_empty() {
        return None;
    }
    let mut base = q.clone();
    base.ips = None;
    let filters = build_filters(&base);
    let body = json!({
        "size": 0,
        "query": {"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}},
        "aggs": {"ips": {"terms": {"field": "source.ip", "size": 50, "order": [{"_count": "desc"}, {"_key": "asc"}]}}}
    });
    let result = state.es.search(body).await.ok()?;
    let buckets = result["aggregations"]["ips"]["buckets"].as_array()?;
    if buckets.len() < 2 {
        return None;
    }
    let selected: Vec<&str> = q
        .ips
        .as_deref()
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect();
    Some(
        buckets
            .iter()
            .filter_map(|bucket| {
                let ip = bucket["key"].as_str()?.to_string();
                let count = bucket["doc_count"].as_u64().unwrap_or(0);
                let checked = selected.is_empty() || selected.contains(&ip.as_str());
                Some(CorrelatedIp { ip, count, checked })
            })
            .collect(),
    )
}

/// Excludes suricata's high-volume, low-signal event types (flow/netflow/
/// stats — 5700+/hour on a real deployment vs. 50 alert/anomaly events in
/// the same window) from the default events view, matching
/// dashboard/classify.go's own legacy posture (`ev.skip = true` for every
/// suricata event_type except alert/anomaly — classify.go:1117). #1611
/// workstream A: unlike classify.go, this crate DOES render http/tls/ssh/
/// smtp/dns/fileinfo detail (src/detail.rs), so only the three genuinely
/// swamping types stay excluded here.
pub fn suricata_noise_exclusion() -> Value {
    json!([
        {"terms": {"suricata.eve.event_type": ["flow", "netflow", "stats"]}},
        // #1873: the fleet probing itself is not an event.
        //
        // dashboard.rs, health.rs and worker.rs all drop internal_probe
        // traffic; the explorer never got the filter, so it was the one
        // surface rendering it. Measured over six hours: 68,115 documents
        // marked internal_probe and 68,819 sourced from 127.0.0.1, none
        // with a source.ip -- roughly 270k rows a day of the fleet talking
        // to itself, shown as events with no attacker. That is the bulk of
        // what reads as "unattributed" in the explorer.
        {"term": {"honeypot.internal_probe": true}}
    ])
}

/// Addresses that belong to this deployment rather than to an attacker.
///
/// #1873: attribution recovering a real address behind the tunnel is
/// best-effort -- 200 events a day carry no `network.community_id` at all,
/// so the zeek-proxy worker has no join key for them and can never reach
/// them. But failing to attribute must produce a *missing* answer, not a
/// *wrong* one: rendering our own WireGuard peer as the attacker states
/// something false, and it is the kind of false that gets acted on.
///
/// Membership is by shape, not by a list of literals, so a re-addressed
/// tunnel or a new docker network cannot quietly start being attributed.
/// Public addresses have no shape to match, so those come from the
/// deployment's existing `HONEYPOT_SELF_IPS` -- the same list #1677 added
/// for the overview aggregations, rather than a second env var that could
/// disagree with it. The two questions are the same question: is this
/// address ours?
pub fn is_fleet_address(ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    let Ok(parsed) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    if parsed.is_loopback() || parsed.is_unspecified() {
        return true;
    }
    // RFC1918 and link-local: the tunnel (10.8.0.0/24), the LAN
    // (192.168.42.0/24) and the container networks (172.16-31.x) are all
    // ours, and none of them can route in from outside.
    if let std::net::IpAddr::V4(v4) = parsed {
        if v4.is_private() || v4.is_link_local() {
            return true;
        }
    }
    if let std::net::IpAddr::V6(v6) = parsed {
        // fc00::/7 unique-local and fe80::/10 link-local.
        let first = v6.segments()[0];
        if (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 {
            return true;
        }
    }
    crate::dashboard::self_addresses().iter().any(|own| own == ip)
}

/// The attacker address for a document, or empty when there is not one.
///
/// #1873: three rules, in order.
///
/// dionaea emits two shapes and only the flat one was ever read. The raw
/// shape nests the peer under `data.connection.*` or `data.parent.*`, so
/// 1,638 documents in six hours were rendered unattributed while the real
/// address sat in the same document -- a SIP attacker at 46.19.138.10, for
/// one. Those nested paths are checked when the promoted field is empty.
///
/// A fleet address is never returned. The tunnel peer is what the sensor
/// genuinely saw, and saying so would be honest if the field were labelled
/// "peer"; in a column headed "source ip" it reads as an accusation.
fn attacker_ip(src: &Value) -> String {
    let text = |v: &Value| v.as_str().unwrap_or("").to_string();
    let candidates = [
        text(&src["source"]["ip"]),
        text(&src["honeypot"]["src_ip"]),
        text(&src["honeypot"]["data"]["connection"]["remote_ip"]),
        text(&src["honeypot"]["data"]["parent"]["remote_ip"]),
        text(&src["honeypot"]["data"]["child"]["remote_ip"]),
    ];
    candidates
        .into_iter()
        .find(|candidate| !candidate.is_empty() && !is_fleet_address(candidate))
        .unwrap_or_default()
}

fn since_to_range(since: &Option<String>) -> String {
    match since.as_deref() {
        Some(s) if !s.is_empty() && s.len() <= 8 && s.chars().all(|c| c.is_ascii_alphanumeric()) => {
            format!("now-{s}")
        }
        _ => "now-10d".to_string(),
    }
}

/// One list/stream row from a normalized ECS `_source` (shared with the
/// SSE live stream so both emit identical shapes).
pub fn row_from_source(src: &Value) -> EventRow {
    let text = |v: &Value| v.as_str().unwrap_or("").to_string();
    let sensor = text(&src["event"]["sensor"]);
    // Several sensors (multipot, conpot, dnp3) only ever carry proto/port
    // under honeypot.* — network.protocol/destination.port stay empty for
    // them, so fall back rather than showing a blank column (#1611
    // workstream A).
    let proto = {
        let p = text(&src["network"]["protocol"]);
        if p.is_empty() { text(&src["honeypot"]["proto"]) } else { p }
    };
    let num_or_str = |v: &Value| v.as_u64().map(|n| n.to_string()).unwrap_or_else(|| text(v));
    let port = [&src["destination"]["port"], &src["honeypot"]["port"], &src["honeypot"]["dst_port"]]
        .into_iter()
        .map(num_or_str)
        .find(|s| !s.is_empty())
        .unwrap_or_default();
    EventRow {
        time: text(&src["@timestamp"]),
        sensor: sensor.clone(),
        // #1873: never our own address, and dionaea's nested peer when
        // the promoted field is empty. See attacker_ip.
        src_ip: attacker_ip(src),
        country: text(&src["source"]["geo"]["country_iso_code"]),
        port,
        proto,
        // #1611 workstream A: per-sensor rich detail rendering, ported
        // from dashboard/classify.go (src/detail.rs).
        detail: detail_for(&sensor, src),
        session: {
            let s1 = text(&src["honeypot"]["session"]);
            if s1.is_empty() { text(&src["session"]["id"]) } else { s1 }
        },
        pivots: pivots_from_source(src),
        record: src.clone(),
    }
}

/// Shared between the paginated list below and exports.rs's full-scope CSV
/// export — same filter fields, same semantics, so an export always
/// matches exactly what the equivalent list view is currently showing
/// (#513's own "never a silently different scope than the page" rule).
pub fn build_filters(q: &EventsQuery) -> Vec<Value> {
    let mut filters = vec![json!({"range": {"@timestamp": {"gte": since_to_range(&q.since)}}})];
    if let Some(ip) = q.ip.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"source.ip": ip}}));
    }
    if let Some(ips) = q.ips.as_deref().filter(|v| !v.is_empty()) {
        let values: Vec<&str> = ips.split(',').map(str::trim).filter(|v| !v.is_empty()).collect();
        if !values.is_empty() {
            filters.push(json!({"terms": {"source.ip": values}}));
        }
    }
    if let Some(sensor) = q.sensor.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"event.sensor": sensor}}));
    }
    if let Some(country) = q.country.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"source.geo.country_iso_code": country}}));
    }
    if let Some(port) = q.port.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"destination.port": port}}));
    }
    if let Some(proto) = q.proto.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"network.protocol": proto}}));
    }
    if let Some(kind) = q.kind.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"honeypot.event": kind}}));
    }
    if let Some(shasum) = q.shasum.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"honeypot.shasum": shasum}}));
    }
    if let Some(flow) = q.community_id.as_deref().filter(|v| !v.is_empty()) {
        // Promoted to a real keyword field by the ingest pipeline on every
        // sensor family, so an exact term works and no per-sensor special
        // casing is needed.
        filters.push(json!({"term": {"network.community_id": flow}}));
    }
    if let Some(text) = q.q.as_deref().filter(|v| !v.is_empty()) {
        // lenient: a malformed user query returns no matches instead of a
        // shard failure, matching the legacy page's forgiving behavior.
        filters.push(json!({"query_string": {"query": text, "lenient": true}}));
    }
    // ── Pivot filters (#1653). A multi-field pivot is a should-of-terms:
    // the sensors record the same concept under different keys, and any
    // match is the semantics the Go in-memory filter had.
    let any_of = |fields: &[&str], value: &str| -> Value {
        let should: Vec<Value> = fields.iter().map(|f| json!({"term": {*f: value}})).collect();
        json!({"bool": {"should": should, "minimum_should_match": 1}})
    };
    if let Some(persona) = q.persona.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"honeypot.persona_id": persona}}));
    }
    if let Some(site) = q.site.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"honeypot.site_id": site}}));
    }
    if let Some(asset) = q.asset.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"honeypot.asset_id": asset}}));
    }
    if let Some(fp) = q.fingerprint.as_deref().filter(|v| !v.is_empty()) {
        filters.push(any_of(
            &[
                "honeypot.canonical_fingerprint",
                "honeypot.hassh",
                "honeypot.fingerprint",
                "honeypot.client",
                "honeypot.user_agent",
            ],
            fp,
        ));
    }
    if let Some(cmd) = q.cmd.as_deref().filter(|v| !v.is_empty()) {
        filters.push(any_of(&["honeypot.canonical_command", "honeypot.command", "honeypot.input"], cmd));
    }
    if let Some(cred) = q.cred.as_deref().filter(|v| !v.is_empty()) {
        // "user / pass", the exact separator the credential links carry.
        let (user, pass) = cred.split_once(" / ").unwrap_or((cred, ""));
        filters.push(any_of(&["honeypot.canonical_user", "honeypot.username"], user));
        filters.push(any_of(&["honeypot.canonical_pass", "honeypot.password"], pass));
    }
    if let Some(path) = q.path.as_deref().filter(|v| !v.is_empty()) {
        filters.push(any_of(&["honeypot.path", "honeypot.url"], path));
    }
    if let Some(session) = q.session.as_deref().filter(|v| !v.is_empty()) {
        filters.push(any_of(&["honeypot.session", "honeypot.session_id", "session.id"], session));
    }
    if let Some(asn) = q.asn.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"source.as.asn": asn}}));
    }
    if let Some(org) = q.org.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"source.as.organization_name": org}}));
    }
    if let Some(provider) = q.provider.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"source.as.type": provider}}));
    }
    if let Some(sig) = q.sig.as_deref().filter(|v| !v.is_empty()) {
        filters.push(json!({"term": {"suricata.eve.alert.signature": sig}}));
    }
    if let Some(cat) = q.cat.as_deref().filter(|v| !v.is_empty()) {
        filters.push(any_of(&["suricata.eve.alert.category", "honeypot.category"], cat));
    }
    filters
}

pub async fn list(
    State(state): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<EventsPage>, (StatusCode, String)> {
    let size = q.size.min(100);
    let offset = q.offset.min(10_000 - size); // ES from+size window guard
    let filters = build_filters(&q);

    let body = json!({
        "from": offset,
        "size": size,
        "track_total_hits": true,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}}
    });
    let result = state
        .es
        .search(body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

    let total = result["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let rows = result["hits"]["hits"]
        .as_array()
        .map(|hits| hits.iter().map(|hit| row_from_source(&hit["_source"])).collect())
        .unwrap_or_default();

    let fingerprint_ips = fingerprint_ip_correlation(&state, &q).await;
    Ok(Json(EventsPage { total, offset, rows, fingerprint_ips }))
}

#[cfg(test)]
mod fleet_attribution_tests {
    use super::*;

    #[test]
    fn a_fleet_address_is_never_an_attacker() {
        // #1873: the tunnel peer is what the sensor genuinely saw, but in a
        // column headed "source ip" it reads as an accusation. 200 events a
        // day carried 10.8.0.1 here.
        assert!(is_fleet_address("10.8.0.1"), "the VPS WireGuard peer");
        assert!(is_fleet_address("10.8.0.2"), "the homeserver WireGuard peer");
        assert!(is_fleet_address("127.0.0.1"), "loopback");
        assert!(is_fleet_address("192.168.42.7"), "a LAN address");
        assert!(is_fleet_address("172.16.10.3"), "a container network");
        assert!(is_fleet_address("0.0.0.0"), "unspecified");
        assert!(is_fleet_address("fe80::1"), "v6 link-local");
        assert!(is_fleet_address("fd00::1"), "v6 unique-local");
    }

    #[test]
    fn a_real_attacker_address_is_not_mistaken_for_ours() {
        // The guard must not swallow the addresses it exists to preserve.
        assert!(!is_fleet_address("46.19.138.10"));
        // Documentation range rather than the fleet's real WAN address:
        // this repo is public, and scripts/check-public-leaks.py rejects
        // those literals anywhere in tree. The behaviour under test is the
        // same either way -- a public address is ours only when configured.
        assert!(!is_fleet_address("203.0.113.4"), "an unconfigured public address");
        assert!(!is_fleet_address("8.8.8.8"));
        assert!(!is_fleet_address("2606:4700::1111"));
        assert!(!is_fleet_address(""), "absent is not ours");
        assert!(!is_fleet_address("not-an-ip"));
    }

    #[test]
    fn a_configured_public_address_is_recognised_as_ours() {
        // The fleet's WAN addresses have no shape to match, so they are
        // knowable only from configuration -- HONEYPOT_SELF_IPS, the list
        // #1677 already introduced for the overview aggregations. This is
        // the half of the guard that shape-matching cannot cover.
        unsafe { std::env::set_var("HONEYPOT_SELF_IPS", "203.0.113.4,198.51.100.7") };
        let configured = crate::dashboard::self_addresses();
        assert!(configured.iter().any(|own| own == "203.0.113.4"), "{configured:?}");
        unsafe { std::env::remove_var("HONEYPOT_SELF_IPS") };
    }

    #[test]
    fn the_tunnel_peer_is_dropped_rather_than_shown_as_the_source() {
        let doc = json!({
            "source": {"ip": "10.8.0.1"},
            "honeypot": {"src_ip": "10.8.0.1", "REMOTE_ADDR": "10.8.0.1:35518"}
        });
        assert_eq!(attacker_ip(&doc), "", "a fleet address must leave the field empty");
    }

    #[test]
    fn dionaeas_nested_peer_is_promoted_when_the_flat_field_is_absent() {
        // #1873: 1,638 documents in six hours read as unattributed while
        // the real address sat in the same document under data.*.
        let connection = json!({
            "honeypot": {"data": {"connection": {"remote_ip": "46.19.138.10", "protocol": "smbd"}}}
        });
        assert_eq!(attacker_ip(&connection), "46.19.138.10");

        let parent = json!({
            "honeypot": {"data": {"parent": {"remote_ip": "46.19.138.10", "protocol": "SipSession"}}}
        });
        assert_eq!(attacker_ip(&parent), "46.19.138.10");
    }

    #[test]
    fn a_nested_peer_that_is_also_ours_stays_unattributed() {
        // dionaea's own loopback health probe nests 127.0.0.1 the same way
        // a real attacker nests a routable address.
        let doc = json!({
            "honeypot": {"data": {"connection": {"remote_ip": "127.0.0.1", "protocol": "smbd"}}}
        });
        assert_eq!(attacker_ip(&doc), "");
    }

    #[test]
    fn the_promoted_field_still_wins_when_it_holds_a_real_address() {
        let doc = json!({
            "source": {"ip": "203.0.113.7"},
            "honeypot": {"data": {"connection": {"remote_ip": "198.51.100.9"}}}
        });
        assert_eq!(attacker_ip(&doc), "203.0.113.7", "source.ip is the promoted answer");
    }

    #[test]
    fn the_explorer_excludes_the_fleet_probing_itself() {
        // dashboard.rs, health.rs and worker.rs all drop internal_probe;
        // the explorer was the one surface that did not, and it was
        // rendering roughly 270k self-generated rows a day (#1873).
        let exclusion = suricata_noise_exclusion();
        let rendered = exclusion.to_string();
        assert!(rendered.contains("honeypot.internal_probe"), "{rendered}");
        assert!(rendered.contains("netflow"), "the suricata noise exclusion must survive: {rendered}");
    }
}
