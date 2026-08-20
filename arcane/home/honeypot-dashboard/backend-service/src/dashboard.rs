//! /api/v1/overview/dashboard — the whole overview page's panel data in
//! one call: every top-N leaderboard, the per-sensor hourly heatmap, the
//! geo map points, and sensor feed freshness. The main aggregation is
//! es_aggregate.go's esOverviewAggQuery ported field-for-field (same
//! window, sizes, exclusions); the attacker-behavior tables the Go tier
//! built in-process from its event cache are re-derived live from the
//! fields verified present in ES (multi_terms credential pairs,
//! honeypot.canonical_command, honeypot.version client banners,
//! honeypot.canonical_fingerprint, suricata alert signature/category).

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{es::logins_filter, AppState};

const WINDOW: &str = "now-48h";

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
    pub top_ips: Vec<Kv>,
    pub top_paths: Vec<Kv>,
    pub top_creds: Vec<Kv>,
    pub top_commands: Vec<Kv>,
    pub clients: Vec<Kv>,
    pub fingerprints: Vec<Kv>,
    pub alerts: Vec<Kv>,
    pub alert_cats: Vec<Kv>,
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

pub async fn dashboard(State(state): State<AppState>) -> Result<Json<Dashboard>, (StatusCode, String)> {
    let main_body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": WINDOW}}},
        "aggs": {
            "sensors": {
                "terms": {"field": "event.sensor", "size": 50},
                "aggs": {"last_seen": {"max": {"field": "@timestamp"}}}
            },
            "protocols": {"terms": {"field": "network.protocol", "size": 30}},
            "ports": {"terms": {"field": "destination.port", "size": 15}},
            "countries": {"terms": {"field": "source.geo.country_iso_code", "size": 12}},
            "asns": {
                "terms": {"field": "source.as.asn", "size": 12},
                "aggs": {"org": {"terms": {"field": "source.as.organization_name", "size": 1}}}
            },
            "top_ips": {"terms": {"field": "source.ip", "size": 15, "exclude": ["127.0.0.1", "::1", "10.8.0.1"]}},
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
        "query": {"range": {"@timestamp": {"gte": WINDOW}}},
        "aggs": {
            "creds": {"multi_terms": {
                "terms": [{"field": "honeypot.username"}, {"field": "honeypot.password"}],
                "size": 15
            }},
            "commands": {"terms": {"field": "honeypot.canonical_command", "size": 15}},
            "clients": {"terms": {"field": "honeypot.version", "size": 15}},
            "fingerprints": {"terms": {"field": "honeypot.canonical_fingerprint", "size": 15}},
            "alerts": {"terms": {"field": "suricata.eve.alert.signature.keyword", "size": 15}},
            "alert_cats": {"terms": {"field": "suricata.eve.alert.category.keyword", "size": 15}}
        }
    });

    let (main, behavior) = tokio::try_join!(state.es.search(main_body), state.es.search(behavior_body))
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

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
            Some(MapPoint {
                city: key.first()?.as_str().unwrap_or("").to_string(),
                country: key.get(1)?.as_str().unwrap_or("").to_string(),
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
        top_ips: kv_rows(&main, "top_ips", |key| format!("/events?ip={key}")),
        top_paths: kv_rows(&main, "paths", |key| format!("/events?path={key}")),
        top_creds,
        top_commands: kv_rows(&behavior, "commands", |_| "/commands".to_string()),
        clients: kv_rows(&behavior, "clients", |_| "/events".to_string()),
        fingerprints: kv_rows(&behavior, "fingerprints", |_| "/events".to_string()),
        alerts: kv_rows(&behavior, "alerts", |_| "/events".to_string()),
        alert_cats: kv_rows(&behavior, "alert_cats", |_| "/events".to_string()),
        logins: main["aggregations"]["logins"]["doc_count"].as_u64().unwrap_or(0),
        heatmap,
        map_points,
        sensors,
    }))
}
