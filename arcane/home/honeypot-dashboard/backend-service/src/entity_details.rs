//! Detail and drill-down documents that are not covered by the store list routes.
//!
//! Where the data really is (checked against the live cluster, 2026-10-09,
//! #3554): sensor events live in `es::EVENT_INDICES` (`honeypot-v2-*` and the
//! alert families). Nothing writes `events-v1`, `sessions-v1`, `network-v1`,
//! `asn-v1`, `ioc-v1`, `ioc-catalog-v1`, `correlations-v1` or
//! `payload-delivery-v1`, so no handler searches them. Per-entity views are
//! aggregations over the event indices; endpoints whose producer does not exist
//! answer 501 with the missing producer named, not a 404 that looks like "no
//! such entity".

use std::net::IpAddr;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    events::{any_of, suricata_noise_exclusion, SESSION_FIELDS},
    AppState,
};

type Response = Result<(StatusCode, Json<Value>), (StatusCode, String)>;

#[derive(Deserialize)]
pub struct RangeQuery {
    #[serde(default = "default_range")]
    pub range: String,
}

fn default_range() -> String { "24h".into() }

fn range(query: &RangeQuery) -> Result<String, (StatusCode, String)> {
    match query.range.as_str() {
        "1h" | "6h" | "24h" | "7d" | "30d" => Ok(format!("now-{}", query.range)),
        _ => Err((StatusCode::BAD_REQUEST, "range must be 1h, 6h, 24h, 7d, or 30d".into())),
    }
}

fn validate_id(id: String) -> Result<String, (StatusCode, String)> {
    let id = id.trim().to_string();
    if id.is_empty() || id.len() > 512 { Err((StatusCode::BAD_REQUEST, "invalid id".into())) } else { Ok(id) }
}

fn source_ip(ip: String) -> Result<String, (StatusCode, String)> {
    let ip = ip.trim().to_string();
    ip.parse::<IpAddr>().map(|_| ip).map_err(|_| (StatusCode::BAD_REQUEST, "invalid ip".into()))
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) { (StatusCode::BAD_GATEWAY, error.to_string()) }

/// A 501 with a JSON body naming the producer that does not exist. Used
/// where the dashboard asks for data no index or aggregation can honestly
/// serve, so the answer is "not built", not "no such entity".
fn not_implemented(producer: &str, reason: &str) -> Response {
    Ok((StatusCode::NOT_IMPLEMENTED, Json(json!({"error": "not implemented", "missing_producer": producer, "reason": reason}))))
}

async fn doc(state: &AppState, index: &str, id: String) -> Response {
    let id = validate_id(id)?;
    match state.es.get_doc(index, &id).await.map_err(bad_gateway)? {
        Some(doc) => Ok((StatusCode::OK, Json(doc))),
        None => Ok((StatusCode::NOT_FOUND, Json(Value::Null))),
    }
}

/// Single document lookup by a non-id field: 404 when there is no match.
async fn first(state: &AppState, indices: &[&str], query: Value) -> Response {
    let result = state.es.search_index(indices, json!({"size": 1, "query": query})).await.map_err(bad_gateway)?;
    match result["hits"]["hits"].as_array().and_then(|hits| hits.first()) {
        Some(hit) => Ok((StatusCode::OK, Json(hit["_source"].clone()))),
        None => Ok((StatusCode::NOT_FOUND, Json(Value::Null))),
    }
}

/// One page of raw `_source` documents. `total` is exact.
fn list_body(result: &Value) -> Value {
    let rows: Vec<Value> = result["hits"]["hits"]
        .as_array()
        .map(|hits| hits.iter().map(|hit| hit["_source"].clone()).collect())
        .unwrap_or_default();
    json!({"total": result["hits"]["total"]["value"].as_u64().unwrap_or(0), "rows": rows})
}

/// Newest-first window reported oldest-first (timeline shape).
fn oldest_first(mut body: Value) -> Value {
    if let Some(rows) = body["rows"].as_array_mut() {
        rows.reverse();
    }
    body
}

/// Lists answer `200 {"total":0,"rows":[]}` when nothing matches (#3554);
/// they never 404.
async fn page(state: &AppState, indices: &[&str], query: Value, sort: Value) -> Response {
    let result = state.es.search_index(indices, json!({"size": 100, "track_total_hits": true, "sort": sort, "query": query})).await.map_err(bad_gateway)?;
    Ok((StatusCode::OK, Json(list_body(&result))))
}

/// Filter every event-level drill-down shares: the scope clause, the same
/// suricata noise exclusion the explorer applies.
fn event_scope(filters: Vec<Value>) -> Value {
    json!({"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}})
}

fn source_scope(ip: &str, range: &str) -> Value {
    event_scope(vec![json!({"term": {"source.ip": ip}}), json!({"range": {"@timestamp": {"gte": range}}})])
}

/// Newest 100 events for the scope. `oldest_first` turns it into a timeline.
fn source_event_body(ip: &str, range: &str) -> Value {
    json!({"size": 100, "track_total_hits": true, "sort": [{"@timestamp": {"order": "desc"}}], "query": source_scope(ip, range)})
}

/// Per-session buckets (honeypot.session, the field the IP profile in
/// investigate.rs aggregates on), newest session first.
fn session_aggs() -> Value {
    json!({
        "sessions": {
            "terms": {"field": "honeypot.session", "size": 100, "order": {"last": "desc"}},
            "aggs": {"first": {"min": {"field": "@timestamp"}}, "last": {"max": {"field": "@timestamp"}}}
        },
        "session_count": {"cardinality": {"field": "honeypot.session"}}
    })
}

fn session_list(result: &Value) -> Value {
    let rows: Vec<Value> = result["aggregations"]["sessions"]["buckets"]
        .as_array()
        .map(|buckets| buckets.iter().map(|bucket| json!({
            "session": bucket["key"],
            "events": bucket["doc_count"],
            "first": bucket["first"]["value_as_string"],
            "last": bucket["last"]["value_as_string"],
        })).collect())
        .unwrap_or_default();
    json!({"total": result["aggregations"]["session_count"]["value"].as_u64().unwrap_or(0), "rows": rows})
}

/// `[{key, count}]` for a terms aggregation.
fn key_counts(result: &Value, name: &str) -> Vec<Value> {
    result["aggregations"][name]["buckets"]
        .as_array()
        .map(|buckets| buckets.iter().map(|bucket| json!({"key": bucket["key"], "count": bucket["doc_count"]})).collect())
        .unwrap_or_default()
}

/// The single value of a size-1 terms aggregation, or null.
fn top_key(result: &Value, name: &str) -> Value {
    result["aggregations"][name]["buckets"][0]["key"].clone()
}

fn total(result: &Value) -> u64 {
    result["hits"]["total"]["value"].as_u64().unwrap_or(0)
}

fn source_network_body(ip: &str) -> Value {
    json!({
        "size": 0,
        "track_total_hits": true,
        "query": event_scope(vec![json!({"term": {"source.ip": ip}})]),
        "aggs": {
            "asn": {"terms": {"field": "source.as.asn", "size": 1}},
            "organization": {"terms": {"field": "source.as.organization_name", "size": 1}},
            "provider": {"terms": {"field": "source.as.type", "size": 1}},
            "country": {"terms": {"field": "source.geo.country_iso_code", "size": 1}}
        }
    })
}

fn asn_body(asn: i64) -> Value {
    json!({
        "size": 0,
        "track_total_hits": true,
        "query": event_scope(vec![json!({"term": {"source.as.asn": asn}})]),
        "aggs": {
            "first": {"min": {"field": "@timestamp"}},
            "last": {"max": {"field": "@timestamp"}},
            "organization": {"terms": {"field": "source.as.organization_name", "size": 1}},
            "provider": {"terms": {"field": "source.as.type", "size": 1}},
            "sources": {"terms": {"field": "source.ip", "size": 50}},
            "source_count": {"cardinality": {"field": "source.ip"}}
        }
    })
}

fn session_summary_body(id: &str) -> Value {
    json!({
        "size": 0,
        "track_total_hits": true,
        "query": event_scope(vec![any_of(SESSION_FIELDS, id)]),
        "aggs": {
            "first": {"min": {"field": "@timestamp"}},
            "last": {"max": {"field": "@timestamp"}},
            "sensors": {"terms": {"field": "event.sensor", "size": 20}},
            "commands": {"terms": {"field": "honeypot.canonical_command", "size": 50}},
            "sources": {"terms": {"field": "source.ip", "size": 20}}
        }
    })
}

/// Payload delivery is keyed on `honeypot.canonical_shasum`, the field the
/// IP profile's "payloads" aggregation and the payload cluster use. Plain
/// `honeypot.shasum` also carries TTY-recording hashes (events.rs `shasum`).
fn payload_delivery_body(hash: &str) -> Value {
    let mut aggs = session_aggs();
    aggs["sources"] = json!({"terms": {"field": "source.ip", "size": 50}});
    json!({
        "size": 100,
        "track_total_hits": true,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": event_scope(vec![json!({"term": {"honeypot.canonical_shasum": hash}})]),
        "aggs": aggs
    })
}

fn asn_number(id: &str) -> Result<i64, (StatusCode, String)> {
    id.trim().trim_start_matches("AS").parse::<i64>().map_err(|_| (StatusCode::BAD_REQUEST, "invalid asn".into()))
}

macro_rules! document_route {
    ($name:ident, $path:literal, $index:literal, $summary:literal) => {
        #[utoipa::path(get, path = $path, summary = $summary,
            params(("id" = inline(String), Path, description = "Document id.")),
            responses((status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"), (status = 404, description = "No such document.", body = inline(serde_json::Value), content_type = "application/json"), (status = 502, description = "Elasticsearch failed.", body = String, content_type = "text/plain")), security(("serviceToken" = [])))]
        pub async fn $name(State(state): State<AppState>, Path(id): Path<String>) -> Response { doc(&state, $index, id).await }
    };
}

#[utoipa::path(get, path = "/api/v1/store/{name}/{id}", summary = "One allowlisted store document.",
    params(("name" = inline(String), Path, description = "ml-anomalies, llm-analysis, or agent-campaigns."), ("id" = inline(String), Path, description = "Document id.")),
    responses((status = 200, description = "Success.", body = inline(serde_json::Value), content_type = "application/json"), (status = 404, description = "No such document or store.", body = inline(serde_json::Value), content_type = "application/json"), (status = 502, description = "Elasticsearch failed.", body = String, content_type = "text/plain")), security(("serviceToken" = [])))]
pub async fn store_detail(State(state): State<AppState>, Path((name, id)): Path<(String, String)>) -> Response {
    let index = match name.as_str() {
        "ml-anomalies" => "ml-worker-state",
        "llm-analysis" => "llm-worker-state",
        "agent-campaigns" => "agent-campaigns-v1",
        _ => return Ok((StatusCode::NOT_FOUND, Json(Value::Null))),
    };
    doc(&state, index, id).await
}

// campaigns-v1 is written by campaign_correlator; it is empty on a fresh
// cluster, so "no such campaign" is a 404 and an index error is a 502.
document_route!(campaign, "/api/v1/investigate/campaign/{id}", "campaigns-v1", "One campaign.");
// attackers-v1 documents are looked up by document id here.
document_route!(identity, "/api/v1/investigate/identity/{id}", "attackers-v1", "One attacker identity.");
document_route!(replay_detail, "/api/v1/replay/{id}", "cowrie-ttylog-v1", "One replay record.");

#[utoipa::path(get, path = "/api/v1/sources/{ip}/events", summary = "Newest events from one source.", params(("ip" = inline(String), Path, description = "Source IPv4 or IPv6 address."), ("range" = inline(Option<String>), Query, description = "1h, 6h, 24h (default), 7d or 30d.")), responses((status = 200, description = "Page of raw event documents from EVENT_INDICES, newest first, at most 100. Nothing in range is {\"total\":0,\"rows\":[]}.", body = inline(serde_json::Value)), (status = 400, description = "Invalid ip or range.", body = String), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_events(State(state): State<AppState>, Path(ip): Path<String>, Query(query): Query<RangeQuery>) -> Response {
    let (ip, range) = (source_ip(ip)?, range(&query)?);
    let result = state.es.search(source_event_body(&ip, &range)).await.map_err(bad_gateway)?;
    Ok((StatusCode::OK, Json(list_body(&result))))
}

#[utoipa::path(get, path = "/api/v1/sources/{ip}/sessions", summary = "Sessions from one source, aggregated from its events.", params(("ip" = inline(String), Path, description = "Source IPv4 or IPv6 address."), ("range" = inline(Option<String>), Query, description = "1h, 6h, 24h (default), 7d or 30d.")), responses((status = 200, description = "{total: distinct sessions, rows: [{session, events, first, last}]}, newest session first. Nothing in range is {\"total\":0,\"rows\":[]}.", body = inline(serde_json::Value)), (status = 400, description = "Invalid ip or range.", body = String), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_sessions(State(state): State<AppState>, Path(ip): Path<String>, Query(query): Query<RangeQuery>) -> Response {
    let (ip, range) = (source_ip(ip)?, range(&query)?);
    let body = json!({"size": 0, "query": source_scope(&ip, &range), "aggs": session_aggs()});
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    Ok((StatusCode::OK, Json(session_list(&result))))
}

#[utoipa::path(get, path = "/api/v1/sources/{ip}/timeline", summary = "Timeline for one source.", params(("ip" = inline(String), Path, description = "Source IPv4 or IPv6 address."), ("range" = inline(Option<String>), Query, description = "1h, 6h, 24h (default), 7d or 30d.")), responses((status = 200, description = "Page of raw event documents: the newest 100 in range, oldest first. Nothing in range is {\"total\":0,\"rows\":[]}.", body = inline(serde_json::Value)), (status = 400, description = "Invalid ip or range.", body = String), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_timeline(State(state): State<AppState>, Path(ip): Path<String>, Query(query): Query<RangeQuery>) -> Response {
    let (ip, range) = (source_ip(ip)?, range(&query)?);
    let result = state.es.search(source_event_body(&ip, &range)).await.map_err(bad_gateway)?;
    Ok((StatusCode::OK, Json(oldest_first(list_body(&result)))))
}

#[utoipa::path(get, path = "/api/v1/sources/{ip}/network", summary = "ASN, organization, provider and country for one source.", params(("ip" = inline(String), Path, description = "Source IPv4 or IPv6 address.")), responses((status = 200, description = "{ip, asn, organization, provider, country, events}, read from the source.as.* and source.geo.* fields of its events.", body = inline(serde_json::Value)), (status = 400, description = "Invalid ip.", body = String), (status = 404, description = "No events from this source.", body = inline(serde_json::Value)), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_network(State(state): State<AppState>, Path(ip): Path<String>) -> Response {
    let ip = source_ip(ip)?;
    let result = state.es.search(source_network_body(&ip)).await.map_err(bad_gateway)?;
    if total(&result) == 0 {
        return Ok((StatusCode::NOT_FOUND, Json(Value::Null)));
    }
    Ok((StatusCode::OK, Json(json!({
        "ip": ip,
        "asn": top_key(&result, "asn"),
        "organization": top_key(&result, "organization"),
        "provider": top_key(&result, "provider"),
        "country": top_key(&result, "country"),
        "events": total(&result),
    }))))
}

#[utoipa::path(get, path = "/api/v1/sources/{ip}/identities", summary = "Attacker identity for one source.", params(("ip" = inline(String), Path)), responses((status = 200, description = "Success.", body = inline(serde_json::Value)), (status = 404, description = "No such source.", body = inline(serde_json::Value)), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn source_identities(State(state): State<AppState>, Path(ip): Path<String>) -> Response { first(&state, &["attackers-v1"], json!({"term":{"ips.keyword":validate_id(ip)?}})).await }

#[utoipa::path(get, path = "/api/v1/investigate/blocked-ips", summary = "Blocked IP records.", responses((status = 200, description = "{total, rows} of dashboard-ip-block-v1 records, newest block first. No blocks yet is {\"total\":0,\"rows\":[]}.", body = inline(serde_json::Value)), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn blocked_ips(State(state): State<AppState>) -> Response { page(&state, &["dashboard-ip-block-v1"], json!({"match_all": {}}), json!([{"BlockedAt":{"order":"desc","unmapped_type":"date"}}])).await }

#[utoipa::path(get, path = "/api/v1/ioc/catalog", summary = "IOC catalog (not implemented).", responses((status = 501, description = "No producer writes the IOC catalog; ioc-catalog-v1 does not exist.", body = inline(serde_json::Value), content_type = "application/json")), security(("serviceToken" = [])))]
pub async fn ioc_catalog(State(_state): State<AppState>) -> Response {
    not_implemented("ioc-catalog-v1", "no producer writes an IOC catalog, and the hub-kind grouping (tor, vpn, malware, scanner) has no source data. Pivots that exist: /api/v1/investigate/ip/{ip}, /api/v1/investigate/cluster.")
}

#[utoipa::path(get, path = "/api/v1/ioc/{kind}/{value}", summary = "One IOC (not implemented).", params(("kind" = inline(String), Path), ("value" = inline(String), Path)), responses((status = 501, description = "No producer writes IOC documents; ioc-v1 does not exist.", body = inline(serde_json::Value), content_type = "application/json")), security(("serviceToken" = [])))]
pub async fn ioc(State(_state): State<AppState>, Path((_kind, _value)): Path<(String, String)>) -> Response {
    not_implemented("ioc-v1", "no producer writes IOC documents. Pivots that exist: /api/v1/investigate/ip/{ip}, /api/v1/investigate/cluster, /api/v1/payloads/{hash}.")
}

#[utoipa::path(get, path = "/api/v1/entities/{id}/timeline", summary = "Timeline for one entity (not implemented).", params(("id" = inline(String), Path)), responses((status = 501, description = "No entity.id field exists on the event indices; no entity model is written.", body = inline(serde_json::Value), content_type = "application/json")), security(("serviceToken" = [])))]
pub async fn entity_timeline(State(_state): State<AppState>, Path(_id): Path<String>) -> Response {
    not_implemented("entity.id", "no event carries entity.id, so there is no entity timeline to aggregate. Source timelines: /api/v1/sources/{ip}/timeline.")
}

#[utoipa::path(get, path = "/api/v1/entities/{id}/related", summary = "Entities related to one entity (not implemented).", params(("id" = inline(String), Path)), responses((status = 501, description = "No producer writes correlations-v1; the index does not exist.", body = inline(serde_json::Value), content_type = "application/json")), security(("serviceToken" = [])))]
pub async fn entity_related(State(_state): State<AppState>, Path(_id): Path<String>) -> Response {
    not_implemented("correlations-v1", "no producer writes correlations-v1. Correlation by cluster: /api/v1/investigate/cluster.")
}

#[utoipa::path(get, path = "/api/v1/investigate/asn/{id}", summary = "One ASN, aggregated from its events.", params(("id" = inline(String), Path, description = "AS number, with or without the AS prefix.")), responses((status = 200, description = "{asn, organization, provider, events, sources_total, first, last, sources: [{key, count}]} over EVENT_INDICES, top 50 sources.", body = inline(serde_json::Value), content_type = "application/json"), (status = 400, description = "Not an AS number.", body = String), (status = 404, description = "No events from this ASN.", body = inline(serde_json::Value), content_type = "application/json"), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn asn(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let asn = asn_number(&id)?;
    let result = state.es.search(asn_body(asn)).await.map_err(bad_gateway)?;
    if total(&result) == 0 {
        return Ok((StatusCode::NOT_FOUND, Json(Value::Null)));
    }
    Ok((StatusCode::OK, Json(json!({
        "asn": asn,
        "organization": top_key(&result, "organization"),
        "provider": top_key(&result, "provider"),
        "events": total(&result),
        "sources_total": result["aggregations"]["source_count"]["value"].clone(),
        "first": result["aggregations"]["first"]["value_as_string"].clone(),
        "last": result["aggregations"]["last"]["value_as_string"].clone(),
        "sources": key_counts(&result, "sources"),
    }))))
}

#[utoipa::path(get, path = "/api/v1/investigate/session/{id}/summary", summary = "One session summary, aggregated from its events.", params(("id" = inline(String), Path, description = "Session id.")), responses((status = 200, description = "{id, events, first, last, sensors, commands, sources} over EVENT_INDICES.", body = inline(serde_json::Value), content_type = "application/json"), (status = 404, description = "No such session.", body = inline(serde_json::Value), content_type = "application/json"), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn session_summary(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let id = validate_id(id)?;
    let result = state.es.search(session_summary_body(&id)).await.map_err(bad_gateway)?;
    if total(&result) == 0 {
        return Ok((StatusCode::NOT_FOUND, Json(Value::Null)));
    }
    Ok((StatusCode::OK, Json(json!({
        "id": id,
        "events": total(&result),
        "first": result["aggregations"]["first"]["value_as_string"].clone(),
        "last": result["aggregations"]["last"]["value_as_string"].clone(),
        "sensors": key_counts(&result, "sensors"),
        "commands": key_counts(&result, "commands"),
        "sources": key_counts(&result, "sources"),
    }))))
}

#[utoipa::path(get, path = "/api/v1/payloads/{id}/delivery", summary = "Events, sessions and sources that carried one payload hash.", params(("id" = inline(String), Path, description = "Payload SHA-256 (honeypot.canonical_shasum).")), responses((status = 200, description = "{total, events (newest 100), sessions: [{session, events, first, last}], sources: [{key, count}]}.", body = inline(serde_json::Value), content_type = "application/json"), (status = 404, description = "No event carries this payload hash.", body = inline(serde_json::Value), content_type = "application/json"), (status = 502, description = "Elasticsearch failed.", body = String)), security(("serviceToken" = [])))]
pub async fn payload_delivery(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let hash = validate_id(id)?;
    let result = state.es.search(payload_delivery_body(&hash)).await.map_err(bad_gateway)?;
    if total(&result) == 0 {
        return Ok((StatusCode::NOT_FOUND, Json(Value::Null)));
    }
    let events = list_body(&result)["rows"].clone();
    let sessions = session_list(&result)["rows"].clone();
    Ok((StatusCode::OK, Json(json!({
        "total": total(&result),
        "events": events,
        "sessions": sessions,
        "sources": key_counts(&result, "sources"),
    }))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(value: &Value) -> String { value.to_string() }

    #[test]
    fn source_ranges_are_bounded() {
        assert_eq!(range(&RangeQuery { range: "24h".into() }).unwrap(), "now-24h");
        assert!(range(&RangeQuery { range: "forever".into() }).is_err());
    }

    #[test]
    fn source_addresses_must_parse() {
        assert!(source_ip("203.0.113.7".into()).is_ok());
        assert!(source_ip("2001:db8::1".into()).is_ok());
        assert_eq!(source_ip("not-an-ip".into()).unwrap_err().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn source_events_are_scoped_to_ip_and_range_and_capped() {
        let body = source_event_body("203.0.113.7", "now-24h");
        let query = rendered(&body["query"]);
        assert!(query.contains("\"source.ip\":\"203.0.113.7\""), "{query}");
        assert!(query.contains("\"gte\":\"now-24h\""), "{query}");
        assert!(query.contains("\"must_not\""), "the explorer's noise exclusion must apply: {query}");
        assert_eq!(body["size"], 100);
        assert_eq!(body["sort"][0]["@timestamp"]["order"], "desc");
    }

    #[test]
    fn source_timeline_reads_the_newest_window_oldest_first() {
        let body = json!({"total": 3, "rows": [{"n": 3}, {"n": 2}, {"n": 1}]});
        assert_eq!(oldest_first(body)["rows"], json!([{"n": 1}, {"n": 2}, {"n": 3}]));
    }

    #[test]
    fn source_sessions_aggregate_on_the_session_field_the_ip_profile_uses() {
        let body = json!({"size": 0, "query": source_scope("203.0.113.7", "now-7d"), "aggs": session_aggs()});
        assert_eq!(body["aggs"]["sessions"]["terms"]["field"], "honeypot.session");
        assert_eq!(body["aggs"]["session_count"]["cardinality"]["field"], "honeypot.session");
        assert!(rendered(&body["query"]).contains("now-7d"));
    }

    #[test]
    fn source_network_reads_as_and_geo_fields() {
        let body = source_network_body("203.0.113.7");
        assert_eq!(body["aggs"]["asn"]["terms"]["field"], "source.as.asn");
        assert_eq!(body["aggs"]["organization"]["terms"]["field"], "source.as.organization_name");
        assert_eq!(body["aggs"]["provider"]["terms"]["field"], "source.as.type");
        assert_eq!(body["aggs"]["country"]["terms"]["field"], "source.geo.country_iso_code");
    }

    #[test]
    fn asn_takes_a_numeric_term_with_or_without_prefix() {
        assert_eq!(asn_number("51167").unwrap(), 51167);
        assert_eq!(asn_number("AS51167").unwrap(), 51167);
        assert_eq!(asn_number("AS").unwrap_err().0, StatusCode::BAD_REQUEST);
        assert!(rendered(&asn_body(51167)["query"]).contains("\"source.as.asn\":51167"));
    }

    #[test]
    fn session_summary_matches_every_session_id_field() {
        let rendered = rendered(&session_summary_body("abd1cc2740ad")["query"]);
        for field in SESSION_FIELDS {
            assert!(rendered.contains(field), "{field} missing: {rendered}");
        }
    }

    #[test]
    fn payload_delivery_keys_on_the_canonical_payload_hash() {
        let body = payload_delivery_body("4293c1d8");
        assert!(rendered(&body["query"]).contains("\"honeypot.canonical_shasum\":\"4293c1d8\""));
        assert_eq!(body["aggs"]["sources"]["terms"]["field"], "source.ip");
        assert_eq!(body["aggs"]["sessions"]["terms"]["field"], "honeypot.session");
    }

    #[test]
    fn event_drilldowns_read_the_event_indices() {
        // The handlers call state.es.search, which reads this constant.
        assert!(crate::es::EVENT_INDICES.contains(&"honeypot-v2-*"));
        assert!(!crate::es::EVENT_INDICES.iter().any(|index| index.starts_with("events-") || index.starts_with("sessions-")));
    }

    #[test]
    fn an_empty_list_is_200_with_zero_total_not_404() {
        let empty = json!({"hits": {"total": {"value": 0, "relation": "eq"}, "hits": []}});
        assert_eq!(list_body(&empty), json!({"total": 0, "rows": []}));
        // An index that does not exist answers with no hits block at all.
        assert_eq!(list_body(&json!({})), json!({"total": 0, "rows": []}));
    }

    #[test]
    fn an_empty_session_list_is_200_with_zero_total() {
        let empty = json!({"aggregations": {"sessions": {"buckets": []}, "session_count": {"value": 0}}});
        assert_eq!(session_list(&empty), json!({"total": 0, "rows": []}));
    }

    #[test]
    fn unimplemented_endpoints_name_the_missing_producer() {
        let Ok((status, Json(body))) = not_implemented("ioc-v1", "no writer") else { panic!("expected Ok") };
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert_eq!(body["missing_producer"], "ioc-v1");
        assert_eq!(body["error"], "not implemented");
    }
}
