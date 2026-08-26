//! /api/v1/overview/dashboard — the whole overview page's panel data in
//! one call: every top-N leaderboard, the per-sensor hourly heatmap, the
//! geo map points, and sensor feed freshness. The main aggregation is
//! es_aggregate.go's esOverviewAggQuery ported field-for-field (same
//! window, sizes, exclusions); the attacker-behavior tables the Go tier
//! built in-process from its event cache are re-derived live from the
//! fields verified present in ES (multi_terms credential pairs,
//! honeypot.canonical_command, honeypot.version client banners,
//! honeypot.canonical_fingerprint, suricata alert signature/category).
//!
//! #1963: `?parts=` narrows the response to a comma-separated subset of
//! the Dashboard fields, and only the aggregations backing those fields
//! are sent to Elasticsearch at all. The overview page shows one tab at a
//! time and refreshes it on the shared tick; without this every tick paid
//! for all eighteen slices -- the most expensive aggregation sets on this
//! fleet -- while the visible tab rendered a third of them. Absent or
//! empty keeps the full payload; unknown names are ignored rather than
//! rejected, so an older frontend asking for a slice this build no longer
//! knows still gets everything it did before.

use std::collections::HashSet;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{es::logins_filter, AppState};

#[derive(Deserialize)]
pub struct DashboardQuery {
    /// Comma-separated subset of Dashboard field names (#1963). Absent or
    /// empty means every slice, which is also what any caller that has not
    /// learned about `parts` yet implicitly asks for.
    pub parts: Option<String>,
}

/// Which of the two searches a slice's aggregation lives in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Search {
    Main,
    Behavior,
}

/// Every response field mapped to where it comes from: the name the
/// frontend uses in `?parts=`, the search that computes it, and the agg
/// key inside that search. Kept next to the response assembly below so a
/// new slice is one row here plus its assembly line, with no way to add
/// one and forget the other.
const SLICES: &[(&str, Search, &str)] = &[
    ("sensors", Search::Main, "sensors"),
    ("protocols", Search::Main, "protocols"),
    ("top_ports", Search::Main, "ports"),
    ("countries", Search::Main, "countries"),
    ("asns", Search::Main, "asns"),
    ("providers", Search::Main, "providers"),
    ("top_ips", Search::Main, "top_ips"),
    ("top_paths", Search::Main, "paths"),
    ("logins", Search::Main, "logins"),
    ("heatmap", Search::Main, "heatmap"),
    ("map_points", Search::Main, "points"),
    ("top_creds", Search::Behavior, "creds"),
    ("top_commands", Search::Behavior, "commands"),
    ("clients", Search::Behavior, "clients"),
    ("fingerprints", Search::Behavior, "fingerprints"),
    ("alerts", Search::Behavior, "alerts"),
    ("alert_cats", Search::Behavior, "alert_cats"),
    ("payloads", Search::Behavior, "payloads"),
];

/// Resolve `?parts=` into the aggregation keys each search may run.
fn allowed_aggs(parts: Option<&str>) -> (HashSet<&'static str>, HashSet<&'static str>) {
    let requested: Vec<&str> = parts
        .map(|value| value.split(',').map(str::trim).filter(|name| !name.is_empty()).collect())
        .unwrap_or_default();
    let wants = |field: &str| requested.is_empty() || requested.contains(&field);
    let mut main = HashSet::new();
    let mut behavior = HashSet::new();
    for &(field, search, agg) in SLICES {
        if !wants(field) {
            continue;
        }
        match search {
            Search::Main => {
                main.insert(agg);
            }
            Search::Behavior => {
                behavior.insert(agg);
            }
        }
    }
    (main, behavior)
}

/// Strip every aggregation the caller didn't ask for, so Elasticsearch
/// never computes a slice the response won't carry. An empty allow-set
/// leaves `"aggs": {}` behind, which is fine: the handler skips that
/// search entirely when nothing in it was requested.
fn limit_aggs(mut body: Value, allowed: &HashSet<&str>) -> Value {
    if let Some(aggs) = body.get_mut("aggs").and_then(Value::as_object_mut) {
        aggs.retain(|name, _| allowed.contains(name.as_str()));
    }
    body
}

const WINDOW: &str = "now-48h";

/// The WireGuard tunnel endpoint. Never an attacker: it is what a sensor
/// records when the via_port join could not recover the real client.
const TUNNEL_PEER_IP: &str = "10.8.0.1";

/// Addresses that belong to this fleet, and so can never be an attacker in
/// its own data.
///
/// #1677: `source.ip` on suricata-v2-* is whichever end Suricata saw as the
/// source, and for the honeypot's own machines that is *both* halves of an
/// attacker's session and the host's own outbound traffic. Measured live,
/// the VPS's own public address was the second-highest "attacker" on the
/// dashboard at 607,288 events over 48h -- reply packets to the real top
/// attacker, plus things like the host's own `apt update` to a Debian
/// mirror, which Suricata alerts on. Every one of those also contributed a
/// phantom entry to `countries`, `asns` and `map_points`, attributed to our
/// own hosting provider.
///
/// Configured rather than hardcoded: which addresses the fleet answers on
/// is a property of a deployment, not of this code. The tunnel peer is
/// always included, which preserves the exclusion this handler has always
/// had.
pub(crate) fn self_addresses() -> Vec<String> {
    let mut addresses: Vec<String> = std::env::var("HONEYPOT_SELF_IPS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(String::from)
        .collect();
    if !addresses.iter().any(|value| value == TUNNEL_PEER_IP) {
        addresses.push(TUNNEL_PEER_IP.to_string());
    }
    addresses
}

#[derive(Serialize)]
pub struct Kv {
    pub key: String,
    pub count: u64,
    /// Investigate link, same pivot targets as the Go "tbl" template.
    pub link: String,
}

#[derive(Serialize)]
pub struct HeatCell {
    pub label: String,
    pub count: u64,
    /// 0-100 intensity relative to the row's own max.
    pub pct: u8,
}

#[derive(Serialize)]
pub struct HeatRow {
    pub sensor: String,
    pub cells: Vec<HeatCell>,
}

#[derive(Serialize)]
pub struct MapPoint {
    pub city: String,
    pub country: String,
    pub lat: f64,
    pub lon: f64,
    pub events: u64,
    pub ips: u64,
    /// Marker drill-down target (hp-app.js:519-533's events_url). The Go
    /// tier's mapPointEventsURL also carried the city; this events
    /// endpoint has no city filter yet, so country is the nearest
    /// supported scope.
    pub url: String,
}

/// One row of the overview "Captured payloads" card — aggregate.go's
/// payloadRow (shasum / attacker target path / seen count / lookup links).
#[derive(Serialize)]
pub struct PayloadRow {
    pub shasum: String,
    /// Where the attacker tried to write the payload (classify.go's
    /// ev.download: destfile/url/filename, whichever the sensor filled).
    pub download: String,
    pub count: u64,
    pub link: String,
    pub vt: String,
}

#[derive(Serialize)]
pub struct SensorFeed {
    pub name: String,
    pub count: u64,
    pub last_seen: String,
    pub state: String,
}

#[derive(Serialize)]
pub struct Dashboard {
    pub protocols: Vec<Kv>,
    pub top_ports: Vec<Kv>,
    pub countries: Vec<Kv>,
    pub asns: Vec<Kv>,
    /// ASNs' deliberate half/half sibling (#1565, overview.html:259).
    pub providers: Vec<Kv>,
    pub top_ips: Vec<Kv>,
    pub top_paths: Vec<Kv>,
    pub top_creds: Vec<Kv>,
    pub top_commands: Vec<Kv>,
    pub clients: Vec<Kv>,
    pub fingerprints: Vec<Kv>,
    pub alerts: Vec<Kv>,
    pub alert_cats: Vec<Kv>,
    pub payloads: Vec<PayloadRow>,
    pub logins: u64,
    pub heatmap: Vec<HeatRow>,
    pub map_points: Vec<MapPoint>,
    pub sensors: Vec<SensorFeed>,
}

fn key_string(bucket: &Value) -> String {
    let key = &bucket["key"];
    key.as_str()
        .map(String::from)
        .or_else(|| key.as_i64().map(|n| n.to_string()))
        .or_else(|| key.as_f64().map(|n| n.to_string()))
        .unwrap_or_default()
}

fn kv_rows(result: &Value, agg: &str, link: impl Fn(&str) -> String) -> Vec<Kv> {
    result["aggregations"][agg]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|bucket| {
            let key = key_string(bucket);
            Kv { link: link(&key), count: bucket["doc_count"].as_u64().unwrap_or(0), key }
        })
        .filter(|row| !row.key.is_empty())
        .collect()
}

/// Strip trailing NULs and control bytes attackers embed in telnet
/// credentials (the Go classify path trimmed these in-process).
fn clean(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect::<String>().replace("\\x00", "")
}

pub async fn dashboard(
    State(state): State<AppState>,
    Query(query): Query<DashboardQuery>,
) -> Result<Json<Dashboard>, (StatusCode, String)> {
    let (main_allowed, behavior_allowed) = allowed_aggs(query.parts.as_deref());
    let main_body = json!({
        "size": 0,
        // #1677: self-generated probe traffic is excluded from every figure on
        // this page, not just from top_ips. A Docker healthcheck connecting to
        // its own sensor is not an attack, and it was inflating sensor
        // rankings, event counts and -- because conpot's healthcheck events
        // arrive tagged T0886 -- the MITRE ICS technique tallies. 312,905 such
        // events in 24 hours, 13.5% of everything ingested.
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": WINDOW}}}],
            "must_not": [
                {"term": {"honeypot.internal_probe": true}},
                // #1677: and the fleet's own traffic -- see self_addresses().
                {"terms": {"source.ip": self_addresses()}}
            ]
        }},
        "aggs": {
            "sensors": {
                "terms": {"field": "event.sensor", "size": 50},
                "aggs": {"last_seen": {"max": {"field": "@timestamp"}}}
            },
            "protocols": {"terms": {"field": "network.protocol", "size": 30}},
            "ports": {"terms": {"field": "destination.port", "size": 15}},
            "countries": {"terms": {"field": "source.geo.country_iso_code", "size": 12}},
            "providers": {"terms": {"field": "source.as.type", "size": 12}},
            "asns": {
                "terms": {"field": "source.as.asn", "size": 12},
                "aggs": {"org": {"terms": {"field": "source.as.organization_name", "size": 1}}}
            },
            // #1677: no per-agg exclusion any more. Hiding an address here
            // only ever fixed this one list while `countries`, `asns` and
            // `map_points` -- which aggregate the same documents -- kept
            // counting them. Both classes of non-attacker are now filtered
            // by the query above instead: self-generated healthchecks by
            // their `internal_probe` mark, and the fleet's own addresses,
            // tunnel endpoint included, by self_addresses().
            "top_ips": {"terms": {"field": "source.ip", "size": 15}},
            "paths": {"terms": {"field": "url.path", "size": 15}},
            "logins": {"filter": logins_filter()},
            "heatmap": {
                "filter": {"range": {"@timestamp": {"gte": "now-24h"}}},
                "aggs": {"sensors": {
                    "terms": {"field": "event.sensor", "size": 50, "order": {"_count": "desc"}},
                    "aggs": {"hourly": {"date_histogram": {
                        "field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0,
                        "extended_bounds": {"min": "now-23h/h", "max": "now/h"}
                    }}}
                }}
            },
            "points": {
                "filter": {"exists": {"field": "source.geo.location"}},
                "aggs": {"by_place": {
                    "multi_terms": {
                        "terms": [{"field": "source.geo.city_name"}, {"field": "source.geo.country_iso_code"}],
                        "size": 500
                    },
                    "aggs": {
                        "centroid": {"geo_centroid": {"field": "source.geo.location"}},
                        "unique_ips": {"cardinality": {"field": "source.ip"}}
                    }
                }}
            }
        }
    });

    let behavior_body = json!({
        "size": 0,
        // #1677: self-generated probe traffic is excluded from every figure on
        // this page, not just from top_ips. A Docker healthcheck connecting to
        // its own sensor is not an attack, and it was inflating sensor
        // rankings, event counts and -- because conpot's healthcheck events
        // arrive tagged T0886 -- the MITRE ICS technique tallies. 312,905 such
        // events in 24 hours, 13.5% of everything ingested.
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": WINDOW}}}],
            "must_not": [
                {"term": {"honeypot.internal_probe": true}},
                // #1677: and the fleet's own traffic -- see self_addresses().
                {"terms": {"source.ip": self_addresses()}}
            ]
        }},
        "aggs": {
            "creds": {"multi_terms": {
                "terms": [{"field": "honeypot.username"}, {"field": "honeypot.password"}],
                "size": 15
            }},
            "commands": {"terms": {"field": "honeypot.canonical_command", "size": 15}},
            "clients": {"terms": {"field": "honeypot.version", "size": 15}},
            "fingerprints": {"terms": {"field": "honeypot.canonical_fingerprint", "size": 15}},
            "alerts": {"terms": {"field": "suricata.eve.alert.signature.keyword", "size": 15}},
            "alert_cats": {"terms": {"field": "suricata.eve.alert.category.keyword", "size": 15}},
            // aggregate.go's payload leaderboard keyed on ev.shasum;
            // canonical_shasum is that same promotion (and, per
            // ip_enrichment/canonical.rs, never set on cowrie.log.closed,
            // so TTY recordings don't count as payload deliveries — #1266).
            "payloads": {
                "terms": {"field": "honeypot.canonical_shasum", "size": 50},
                "aggs": {"latest": {"top_hits": {
                    "size": 1,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "_source": {"includes": ["honeypot.destfile", "honeypot.url", "honeypot.filename"]}
                }}}
            }
        }
    });

    // #1963: a tab asking only for its own slices skips the other search
    // entirely -- the evidence tab never needed the geo_centroid sweep,
    // and the live tab never needed the multi_terms credential pair.
    // try_join! keeps them concurrent when both do run, as before.
    let (main, behavior) = tokio::try_join!(
        async {
            if main_allowed.is_empty() {
                Ok(json!({}))
            } else {
                state
                    .es
                    .search(limit_aggs(main_body, &main_allowed))
                    .await
                    .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))
            }
        },
        async {
            if behavior_allowed.is_empty() {
                Ok(json!({}))
            } else {
                state
                    .es
                    .search(limit_aggs(behavior_body, &behavior_allowed))
                    .await
                    .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))
            }
        },
    )?;

    // ASN rows: "AS<number> <org>", same label shape as the Go tier.
    let asns = main["aggregations"]["asns"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|bucket| {
            let number = key_string(bucket);
            let org = bucket["org"]["buckets"]
                .as_array()
                .and_then(|orgs| orgs.first())
                .map(key_string)
                .unwrap_or_default();
            Kv {
                key: format!("AS{number} {org}").trim_end().to_string(),
                count: bucket["doc_count"].as_u64().unwrap_or(0),
                link: format!("/events?asn={number}"),
            }
        })
        .collect();

    // Credential pairs come back "user|pass" from multi_terms.
    let top_creds = behavior["aggregations"]["creds"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|bucket| {
            let parts: Vec<String> = bucket["key"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|part| clean(part.as_str().unwrap_or("")))
                .collect();
            Kv {
                key: parts.join(" / "),
                count: bucket["doc_count"].as_u64().unwrap_or(0),
                link: "/events?kind=login".to_string(),
            }
        })
        .filter(|row| !row.key.trim().is_empty() && row.key != " / ")
        .collect();

    // Payload rows: "seen | sha-256 | attacker target path | lookup",
    // ported from aggregate.go's payloadRows (overview.html:400-412).
    let payloads = behavior["aggregations"]["payloads"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|bucket| {
            let shasum = key_string(bucket);
            let hp = &bucket["latest"]["hits"]["hits"][0]["_source"]["honeypot"];
            let download = ["destfile", "url", "filename"]
                .iter()
                .map(|field| hp[*field].as_str().unwrap_or(""))
                .find(|value| !value.is_empty())
                .unwrap_or("")
                .to_string();
            PayloadRow {
                count: bucket["doc_count"].as_u64().unwrap_or(0),
                link: format!("/events?shasum={shasum}"),
                vt: format!("https://www.virustotal.com/gui/file/{shasum}"),
                shasum,
                download,
            }
        })
        .filter(|row| !row.shasum.is_empty())
        .collect();

    let heatmap = main["aggregations"]["heatmap"]["sensors"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|sensor| {
            let counts: Vec<(String, u64)> = sensor["hourly"]["buckets"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|bucket| {
                    (
                        bucket["key_as_string"].as_str().unwrap_or("").to_string(),
                        bucket["doc_count"].as_u64().unwrap_or(0),
                    )
                })
                .collect();
            let max = counts.iter().map(|(_, count)| *count).max().unwrap_or(0).max(1);
            HeatRow {
                sensor: sensor["key"].as_str().unwrap_or("").to_string(),
                cells: counts
                    .into_iter()
                    .map(|(label, count)| HeatCell { pct: ((count * 100) / max) as u8, label, count })
                    .collect(),
            }
        })
        .collect();

    let map_points = main["aggregations"]["points"]["by_place"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|bucket| {
            let key = bucket["key"].as_array()?;
            let country = key.get(1)?.as_str().unwrap_or("").to_string();
            Some(MapPoint {
                city: key.first()?.as_str().unwrap_or("").to_string(),
                url: format!("/events?country={country}"),
                country,
                lat: bucket["centroid"]["location"]["lat"].as_f64()?,
                lon: bucket["centroid"]["location"]["lon"].as_f64()?,
                events: bucket["doc_count"].as_u64().unwrap_or(0),
                ips: bucket["unique_ips"]["value"].as_u64().unwrap_or(0),
            })
        })
        .collect();

    let now_ms = chrono::Utc::now().timestamp_millis();
    let sensors = main["aggregations"]["sensors"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|bucket| {
            let last_seen = bucket["last_seen"]["value_as_string"].as_str().unwrap_or("").to_string();
            let last_ms = bucket["last_seen"]["value"].as_f64().unwrap_or(0.0) as i64;
            let age_s = ((now_ms - last_ms) / 1000).max(0);
            SensorFeed {
                name: bucket["key"].as_str().unwrap_or("").to_string(),
                count: bucket["doc_count"].as_u64().unwrap_or(0),
                last_seen,
                state: if age_s < 300 {
                    "active"
                } else if age_s < 3600 {
                    "quiet"
                } else {
                    "stale"
                }
                .to_string(),
            }
        })
        .collect();

    Ok(Json(Dashboard {
        protocols: kv_rows(&main, "protocols", |key| format!("/events?proto={key}")),
        top_ports: kv_rows(&main, "ports", |key| format!("/events?port={key}")),
        countries: kv_rows(&main, "countries", |key| format!("/events?country={key}")),
        asns,
        providers: kv_rows(&main, "providers", |key| format!("/events?provider={key}")),
        top_ips: kv_rows(&main, "top_ips", |key| format!("/events?ip={key}")),
        top_paths: kv_rows(&main, "paths", |key| format!("/events?path={key}")),
        top_creds,
        top_commands: kv_rows(&behavior, "commands", |_| "/commands".to_string()),
        clients: kv_rows(&behavior, "clients", |_| "/events".to_string()),
        fingerprints: kv_rows(&behavior, "fingerprints", |_| "/events".to_string()),
        alerts: kv_rows(&behavior, "alerts", |_| "/events".to_string()),
        alert_cats: kv_rows(&behavior, "alert_cats", |_| "/events".to_string()),
        payloads,
        logins: main["aggregations"]["logins"]["doc_count"].as_u64().unwrap_or(0),
        heatmap,
        map_points,
        sensors,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The env var is process-global, so these run as one test rather than
    /// racing each other through the same variable.
    #[test]
    fn self_addresses_reads_config_and_always_keeps_the_tunnel() {
        // Unset: the exclusion this handler has always had, and nothing else.
        unsafe { std::env::remove_var("HONEYPOT_SELF_IPS") };
        assert_eq!(self_addresses(), vec![TUNNEL_PEER_IP.to_string()]);

        // Configured: the deployment's own addresses, tunnel still included.
        unsafe { std::env::set_var("HONEYPOT_SELF_IPS", "203.0.113.7, 198.51.100.2") };
        assert_eq!(
            self_addresses(),
            vec!["203.0.113.7".to_string(), "198.51.100.2".to_string(), TUNNEL_PEER_IP.to_string()]
        );

        // Naming the tunnel explicitly must not list it twice -- a duplicated
        // term is harmless to Elasticsearch but the operator would have to
        // wonder whether it meant something.
        unsafe { std::env::set_var("HONEYPOT_SELF_IPS", "10.8.0.1,203.0.113.7") };
        assert_eq!(
            self_addresses(),
            vec![TUNNEL_PEER_IP.to_string(), "203.0.113.7".to_string()]
        );

        // Empty and whitespace-only entries are operator typos, not addresses.
        unsafe { std::env::set_var("HONEYPOT_SELF_IPS", " , ,203.0.113.7, ") };
        assert_eq!(
            self_addresses(),
            vec!["203.0.113.7".to_string(), TUNNEL_PEER_IP.to_string()]
        );
        unsafe { std::env::remove_var("HONEYPOT_SELF_IPS") };
    }

    #[test]
    fn parts_absent_or_empty_means_every_slice() {
        let main_count = SLICES.iter().filter(|(_, search, _)| *search == Search::Main).count();
        let behavior_count = SLICES.iter().filter(|(_, search, _)| *search == Search::Behavior).count();

        for parts in [None, Some(""), Some(", ")] {
            let (main, behavior) = allowed_aggs(parts);
            assert_eq!(main.len(), main_count, "parts={parts:?}");
            assert_eq!(behavior.len(), behavior_count, "parts={parts:?}");
        }
    }

    #[test]
    fn parts_pick_only_their_own_search() {
        // The overview live tab's three slices all come from the main
        // search, so a tick parked there never runs the behavior side at
        // all -- that is the whole point (#1963).
        let (main, behavior) = allowed_aggs(Some("sensors,heatmap,map_points"));
        assert_eq!(main, HashSet::from(["sensors", "heatmap", "points"]));
        assert!(behavior.is_empty());
    }

    #[test]
    fn parts_ignore_unknown_and_blank_names() {
        // A frontend older than a renamed slice must not lose the rest of
        // its payload for asking about it.
        let (_, behavior) = allowed_aggs(Some("payloads,retired_slice,, "));
        assert_eq!(behavior, HashSet::from(["payloads"]));
    }

    #[test]
    fn limit_aggs_drops_unrequested_aggregations_but_keeps_the_rest_of_the_body() {
        let (main_allowed, _) = allowed_aggs(Some("heatmap"));
        let body = limit_aggs(json!({"size": 0, "query": {"match_all": {}}, "aggs": {"heatmap": {}, "points": {}}}), &main_allowed);
        assert_eq!(body["size"], 0);
        assert!(body["aggs"].get("heatmap").is_some());
        assert!(body["aggs"].get("points").is_none());

        // Nothing requested from this search: aggs ends up empty rather
        // than absent -- harmless, because the handler skips the search.
        let (_, behavior_allowed) = allowed_aggs(Some("heatmap"));
        let body = limit_aggs(json!({"size": 0, "aggs": {"creds": {}}}), &behavior_allowed);
        assert!(body["aggs"].as_object().unwrap().is_empty());
    }
}
