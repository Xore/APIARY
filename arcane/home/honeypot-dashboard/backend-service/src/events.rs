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

#[derive(Deserialize)]
pub struct EventsQuery {
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_size")]
    pub size: u64,
    pub ip: Option<String>,
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
    /// Free-text query_string search (the /history page's q=), same
    /// semantics as the Go tier's ES q= passthrough.
    pub q: Option<String>,
    /// Go-style duration ("24h", "7d") relative to now; defaults to the
    /// explorer's rolling window.
    pub since: Option<String>,
}

fn default_size() -> u64 {
    25
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
    /// The complete normalized ECS document, for the record inspector pane
    /// (the row click opens it; nothing is hidden). #1611 workstream E.4:
    /// this is also where `network.community_id` (when suricata populated
    /// it) is already visible and copyable — it's the exact join key an
    /// Arkime cross-link needs, so no separate field/endpoint is required
    /// on this side; the pivot link itself is a frontend concern.
    pub record: Value,
}

#[derive(Serialize)]
pub struct EventsPage {
    pub total: u64,
    pub offset: u64,
    pub rows: Vec<EventRow>,
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
    json!([{"terms": {"suricata.eve.event_type": ["flow", "netflow", "stats"]}}])
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
    let port = {
        let p = src["destination"]["port"].as_u64().map(|p| p.to_string()).unwrap_or_else(|| text(&src["destination"]["port"]));
        if p.is_empty() {
            let hp_port = src["honeypot"]["port"].as_u64().map(|p| p.to_string()).unwrap_or_else(|| text(&src["honeypot"]["port"]));
            if hp_port.is_empty() {
                src["honeypot"]["dst_port"].as_u64().map(|p| p.to_string()).unwrap_or_else(|| text(&src["honeypot"]["dst_port"]))
            } else {
                hp_port
            }
        } else {
            p
        }
    };
    EventRow {
        time: text(&src["@timestamp"]),
        sensor: sensor.clone(),
        src_ip: text(&src["source"]["ip"]),
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
    if let Some(text) = q.q.as_deref().filter(|v| !v.is_empty()) {
        // lenient: a malformed user query returns no matches instead of a
        // shard failure, matching the legacy page's forgiving behavior.
        filters.push(json!({"query_string": {"query": text, "lenient": true}}));
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

    Ok(Json(EventsPage { total, offset, rows }))
}
