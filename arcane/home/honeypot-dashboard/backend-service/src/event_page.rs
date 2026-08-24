//! `/api/v1/event/{id}` — everything behind one event, on one page.
//!
//! The events list opens a record pane beside the table, which is the
//! right shape for scanning: it keeps the list in view and shows the
//! document. It is the wrong shape for actually working an event, because
//! the pane is narrow, it dies on navigation, and it holds one document
//! and nothing around it — no session, no flow, no payload, no other
//! sensor that saw the same connection. There was no full view of an
//! event anywhere in the dashboard.
//!
//! This endpoint assembles that view. It returns the document itself plus
//! the things that are only findable by asking Elasticsearch a second
//! question: the rest of the session, the rest of the flow, and what else
//! the same source did. Those are counts and samples, not full lists — the
//! pages that own each of them do that better, and this page links to
//! them rather than reimplementing them.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::AppState;

/// How many neighbouring events to sample per relation. Enough to see the
/// shape of what happened; the owning page is one click away for the rest.
const RELATED_SAMPLE: u64 = 25;

#[derive(Serialize, Default)]
pub struct RelatedEvent {
    pub time: String,
    pub sensor: String,
    pub src_ip: String,
    pub detail: String,
}

/// One relation, as a count plus a sample. The count is the honest total;
/// the sample is what fits.
#[derive(Serialize, Default)]
pub struct Relation {
    pub key: String,
    pub total: u64,
    pub rows: Vec<RelatedEvent>,
}

#[derive(Serialize)]
pub struct EventPage {
    pub id: String,
    pub index: String,
    pub time: String,
    pub sensor: String,
    pub src_ip: String,
    pub session: String,
    pub community_id: String,
    /// Hashes named anywhere in the document, so the page can link to the
    /// payload record without knowing each sensor's field for it.
    pub hashes: Vec<String>,
    /// The complete document, exactly as indexed.
    pub record: Value,
    /// Other events in the same session.
    pub session_events: Relation,
    /// Other events on the same flow — the community_id every sensor
    /// computes independently for one connection.
    pub flow_events: Relation,
    /// What else this source address did, inside the recent window.
    pub source_events: Relation,
}

fn text(value: &Value) -> String {
    value.as_str().unwrap_or("").to_string()
}

/// First non-empty of several candidate paths. Sensors disagree about
/// where the same fact lives, and the document is the authority.
fn first(source: &Value, paths: &[&[&str]]) -> String {
    for path in paths {
        let mut node = source;
        for part in *path {
            node = &node[*part];
        }
        let value = text(node);
        if !value.is_empty() {
            return value;
        }
    }
    String::new()
}

/// Every 32/40/64/128-hex string in the document, deduplicated.
///
/// Walking for the shape rather than reading a field list because each
/// sensor names its hash differently (`md5hash`, `sha512`, `body_sha256`,
/// `file.hash.sha256`, …) and a field list would silently miss the next
/// one. A hex string of exactly those lengths is a hash and nothing else.
fn collect_hashes(node: &Value, into: &mut Vec<String>) {
    match node {
        Value::String(value) => {
            let length = value.len();
            if matches!(length, 32 | 40 | 64 | 128)
                && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && !into.iter().any(|seen| seen == value)
            {
                into.push(value.clone());
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_hashes(item, into)),
        Value::Object(fields) => fields.values().for_each(|value| collect_hashes(value, into)),
        _ => {}
    }
}

fn related_row(hit: &Value) -> RelatedEvent {
    let source = &hit["_source"];
    let sensor = first(source, &[&["event", "sensor"], &["honeypot", "sensor"]]);
    RelatedEvent {
        time: text(&source["@timestamp"]),
        detail: crate::event_detail::detail_for(&sensor, source),
        sensor,
        src_ip: first(source, &[&["honeypot", "src_ip"], &["source", "ip"]]),
    }
}

/// One relation: count everything that matches, return the newest few.
async fn relation(state: &AppState, key: &str, filter: Value, exclude_id: &str) -> Relation {
    if key.is_empty() {
        return Relation::default();
    }
    let body = json!({
        "size": RELATED_SAMPLE,
        "track_total_hits": true,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {
            "filter": [filter],
            "must_not": [{"ids": {"values": [exclude_id]}}]
        }}
    });
    let Ok(result) = state.es.search(body).await else {
        return Relation { key: key.to_string(), ..Default::default() };
    };
    Relation {
        key: key.to_string(),
        total: result["hits"]["total"]["value"].as_u64().unwrap_or(0),
        rows: result["hits"]["hits"]
            .as_array()
            .map(|hits| hits.iter().map(related_row).collect())
            .unwrap_or_default(),
    }
}

pub async fn get(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<EventPage>, (StatusCode, String)> {
    let id = id.trim().to_string();
    if id.is_empty() || id.len() > 512 {
        return Err((StatusCode::BAD_REQUEST, "invalid event id".into()));
    }

    // `ids` rather than a GET by index, so the caller needs only the id --
    // the events list does not currently carry which index a row came
    // from, and requiring it would leak an ES detail into every link.
    let body = json!({"size": 1, "query": {"ids": {"values": [id]}}});
    let result = state
        .es
        .search(body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    let hit = result["hits"]["hits"]
        .as_array()
        .and_then(|hits| hits.first())
        .cloned()
        .ok_or((StatusCode::NOT_FOUND, "no such event".to_string()))?;
    let source = hit["_source"].clone();

    let sensor = first(&source, &[&["event", "sensor"], &["honeypot", "sensor"]]);
    // #1873: the same guard the list applies, for the same reason.
    //
    // Found by checking the deployed endpoint against real data rather
    // than by reading it: the list had the guard and this page did not, so
    // one screen said "unattributed" and the page behind it named our own
    // tunnel peer as the attacker. Two answers to one question is worse
    // than either answer alone.
    let src_ip = {
        let observed = first(
            &source,
            &[
                &["honeypot", "src_ip"],
                &["source", "ip"],
                &["honeypot", "data", "connection", "remote_ip"],
                &["honeypot", "data", "parent", "remote_ip"],
            ],
        );
        if crate::events::is_fleet_address(&observed) { String::new() } else { observed }
    };
    let session = first(
        &source,
        &[
            &["honeypot", "session"],
            &["honeypot", "session_id"],
            &["session", "id"],
        ],
    );
    let community_id = first(&source, &[&["network", "community_id"]]);
    let mut hashes = Vec::new();
    collect_hashes(&source, &mut hashes);

    let (session_events, flow_events, source_events) = tokio::join!(
        relation(
            &state,
            &session,
            json!({"bool": {"should": [
                {"term": {"honeypot.session": session.clone()}},
                {"term": {"honeypot.session_id": session.clone()}},
                {"term": {"session.id": session.clone()}}
            ], "minimum_should_match": 1}}),
            &id,
        ),
        relation(&state, &community_id, json!({"term": {"network.community_id": community_id.clone()}}), &id),
        // The source relation is windowed: a busy scanner has millions of
        // events and "everything it ever did" is the attacker profile's
        // job, not this page's.
        // Keyed on the attributed address, so "what else did this source
        // do" cannot become "what else came through our own tunnel", which
        // is every relayed event on the fleet.
        relation(
            &state,
            &src_ip,
            json!({"bool": {"filter": [
                {"term": {"source.ip": src_ip.clone()}},
                {"range": {"@timestamp": {"gte": "now-24h"}}}
            ]}}),
            &id,
        ),
    );

    Ok(Json(EventPage {
        id,
        index: text(&hit["_index"]),
        time: text(&source["@timestamp"]),
        sensor,
        src_ip,
        session,
        community_id,
        hashes,
        record: source,
        session_events,
        flow_events,
        source_events,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_hashes_finds_hashes_by_shape_not_by_field_name() {
        // Each sensor names its hash differently, so a field list would
        // silently miss the next one. Shape is the reliable signal.
        let doc = json!({
            "honeypot": {"md5hash": "d41d8cd98f00b204e9800998ecf8427e"},
            "file": {"hash": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
            "note": "not a hash",
            "port": 445
        });
        let mut found = Vec::new();
        collect_hashes(&doc, &mut found);
        assert!(found.contains(&"d41d8cd98f00b204e9800998ecf8427e".to_string()));
        assert!(found.contains(&"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()));
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn collect_hashes_rejects_hex_looking_strings_of_the_wrong_length() {
        let doc = json!({"a": "abcdef", "b": "deadbeef", "c": "0123456789abcdef0123456789abcde"});
        let mut found = Vec::new();
        collect_hashes(&doc, &mut found);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn collect_hashes_deduplicates_a_hash_that_appears_twice() {
        let hash = "d41d8cd98f00b204e9800998ecf8427e";
        let doc = json!({"a": hash, "b": {"c": hash}});
        let mut found = Vec::new();
        collect_hashes(&doc, &mut found);
        assert_eq!(found, vec![hash.to_string()]);
    }

    #[test]
    fn the_full_page_agrees_with_the_list_about_a_fleet_address() {
        // #1873: the list guarded and this page did not, so one screen said
        // "unattributed" and the page behind it named our own tunnel peer
        // as the attacker. Caught on the deployed endpoint, not in review.
        let doc = json!({"honeypot": {"src_ip": "10.8.0.1"}, "source": {"ip": "10.8.0.1"}});
        let observed = first(&doc, &[&["honeypot", "src_ip"], &["source", "ip"]]);
        assert!(crate::events::is_fleet_address(&observed));
    }

    #[test]
    fn the_full_page_reads_dionaeas_nested_peer() {
        let doc = json!({"honeypot": {"data": {"parent": {"remote_ip": "198.51.100.4"}}}});
        let observed = first(
            &doc,
            &[
                &["honeypot", "src_ip"],
                &["source", "ip"],
                &["honeypot", "data", "connection", "remote_ip"],
                &["honeypot", "data", "parent", "remote_ip"],
            ],
        );
        assert_eq!(observed, "198.51.100.4");
        assert!(!crate::events::is_fleet_address(&observed));
    }

    #[test]
    fn first_returns_the_first_populated_path() {
        let doc = json!({"honeypot": {"src_ip": ""}, "source": {"ip": "203.0.113.5"}});
        assert_eq!(first(&doc, &[&["honeypot", "src_ip"], &["source", "ip"]]), "203.0.113.5");
        assert_eq!(first(&doc, &[&["nothing", "here"]]), "");
    }
}
