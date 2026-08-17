//! Aggregation-backed list endpoints for the Investigate family. Query
//! shapes mirror the Go dashboard's es_aggregate.go semantics (same index
//! families, same field names); each returns page-shaped JSON the BFF
//! passes through to the routes.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::AppState;

fn text(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    pub offset: u64,
    #[serde(default = "default_size")]
    pub size: u64,
}

fn default_size() -> u64 {
    25
}

// ── Attack sources (/ips): top source IPs with activity window ───────────

#[derive(Serialize)]
pub struct SourceRow {
    pub ip: String,
    pub country: String,
    pub events: u64,
    pub logins: u64,
    pub sessions: u64,
    pub sensors: Vec<String>,
    pub first: String,
    pub last: String,
}

#[derive(Serialize)]
pub struct SourcesPage {
    pub total_unique: u64,
    pub rows: Vec<SourceRow>,
}

pub async fn sources(
    State(state): State<AppState>,
    Query(q): Query<PageQuery>,
) -> Result<Json<SourcesPage>, (StatusCode, String)> {
    let size = (q.offset + q.size).min(1000);
    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-10d"}}},
        "aggs": {
            "unique": {"cardinality": {"field": "source.ip"}},
            "ips": {
                "terms": {"field": "source.ip", "size": size, "order": {"_count": "desc"}},
                "aggs": {
                    "country": {"terms": {"field": "source.geo.country_iso_code", "size": 1}},
                    "sensors": {"terms": {"field": "event.sensor", "size": 30}},
                    "logins": {"filter": {"terms": {"honeypot.event": ["login.failed", "login.success", "auth_attempt"]}}},
                    "sessions": {"cardinality": {"field": "honeypot.session"}},
                    "first": {"min": {"field": "@timestamp"}},
                    "last": {"max": {"field": "@timestamp"}}
                }
            }
        }
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    let total_unique = result["aggregations"]["unique"]["value"].as_u64().unwrap_or(0);
    let rows = result["aggregations"]["ips"]["buckets"]
        .as_array()
        .map(|buckets| {
            buckets
                .iter()
                .skip(q.offset as usize)
                .map(|bucket| SourceRow {
                    ip: text(&bucket["key"]),
                    country: bucket["country"]["buckets"]
                        .as_array()
                        .and_then(|c| c.first())
                        .map(|c| text(&c["key"]))
                        .unwrap_or_default(),
                    events: bucket["doc_count"].as_u64().unwrap_or(0),
                    logins: bucket["logins"]["doc_count"].as_u64().unwrap_or(0),
                    sessions: bucket["sessions"]["value"].as_u64().unwrap_or(0),
                    sensors: bucket["sensors"]["buckets"]
                        .as_array()
                        .map(|s| s.iter().map(|b| text(&b["key"])).collect())
                        .unwrap_or_default(),
                    first: text(&bucket["first"]["value_as_string"]),
                    last: text(&bucket["last"]["value_as_string"]),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(SourcesPage { total_unique, rows }))
}

// ── Campaigns (/campaigns): /24 networks grouped over 7 days ─────────────

#[derive(Serialize)]
pub struct CampaignRow {
    pub network: String,
    pub events: u64,
    pub unique_ips: u64,
    pub sensors: Vec<String>,
    pub ports: Vec<String>,
    pub first: String,
    pub last: String,
}

#[derive(Serialize)]
pub struct CampaignsPage {
    pub rows: Vec<CampaignRow>,
}

pub async fn campaigns(
    State(state): State<AppState>,
    Query(q): Query<PageQuery>,
) -> Result<Json<CampaignsPage>, (StatusCode, String)> {
    let size = (q.offset + q.size).min(500);
    // /24 grouping via script would need runtime fields; the ECS docs carry
    // source.ip only, so group on the ip and roll /24s in this tier (the
    // Go correlator's own approach, minus its scoring model — scoring joins
    // with the worker port, #1610).
    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-7d"}}},
        "aggs": {
            "ips": {
                "terms": {"field": "source.ip", "size": 3000, "order": {"_count": "desc"}},
                "aggs": {
                    "sensors": {"terms": {"field": "event.sensor", "size": 30}},
                    "ports": {"terms": {"field": "destination.port", "size": 15}},
                    "first": {"min": {"field": "@timestamp"}},
                    "last": {"max": {"field": "@timestamp"}}
                }
            }
        }
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    use std::collections::BTreeMap;
    #[derive(Default)]
    struct Roll {
        events: u64,
        ips: u64,
        sensors: std::collections::BTreeSet<String>,
        ports: std::collections::BTreeSet<String>,
        first: String,
        last: String,
    }
    let mut nets: BTreeMap<String, Roll> = BTreeMap::new();
    if let Some(buckets) = result["aggregations"]["ips"]["buckets"].as_array() {
        for bucket in buckets {
            let ip = text(&bucket["key"]);
            let net = match ip.rsplit_once('.') {
                Some((prefix, _)) if ip.contains('.') => format!("{prefix}.0/24"),
                _ => continue, // v6 grouping joins with the worker port
            };
            let roll = nets.entry(net).or_default();
            roll.events += bucket["doc_count"].as_u64().unwrap_or(0);
            roll.ips += 1;
            if let Some(s) = bucket["sensors"]["buckets"].as_array() {
                for b in s {
                    roll.sensors.insert(text(&b["key"]));
                }
            }
            if let Some(p) = bucket["ports"]["buckets"].as_array() {
                for b in p {
                    let port = b["key"].as_u64().map(|v| v.to_string()).unwrap_or_else(|| text(&b["key"]));
                    roll.ports.insert(port);
                }
            }
            let first = text(&bucket["first"]["value_as_string"]);
            let last = text(&bucket["last"]["value_as_string"]);
            if roll.first.is_empty() || (!first.is_empty() && first < roll.first) {
                roll.first = first;
            }
            if last > roll.last {
                roll.last = last;
            }
        }
    }
    let mut rows: Vec<CampaignRow> = nets
        .into_iter()
        .map(|(network, roll)| CampaignRow {
            network,
            events: roll.events,
            unique_ips: roll.ips,
            sensors: roll.sensors.into_iter().collect(),
            ports: roll.ports.into_iter().collect(),
            first: roll.first,
            last: roll.last,
        })
        .collect();
    rows.sort_by(|a, b| b.events.cmp(&a.events));
    rows.truncate(size as usize);
    let rows = rows.into_iter().skip(q.offset as usize).collect();
    Ok(Json(CampaignsPage { rows }))
}

// ── Clusters (/clusters): shared fingerprints / providers across IPs ─────

#[derive(Serialize)]
pub struct ClusterRow {
    pub kind: String,
    pub value: String,
    pub sources: u64,
    pub events: u64,
    pub sensors: Vec<String>,
}

#[derive(Serialize)]
pub struct ClustersPage {
    pub rows: Vec<ClusterRow>,
}

pub async fn clusters(
    State(state): State<AppState>,
    Query(_q): Query<PageQuery>,
) -> Result<Json<ClustersPage>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": "now-7d"}}},
        "aggs": {
            "fingerprints": {
                "terms": {"field": "honeypot.fingerprint", "size": 60, "min_doc_count": 2},
                "aggs": {
                    "sources": {"cardinality": {"field": "source.ip"}},
                    "sensors": {"terms": {"field": "event.sensor", "size": 20}}
                }
            },
            "asns": {
                "terms": {"field": "source.as.organization.name", "size": 60, "min_doc_count": 2},
                "aggs": {
                    "sources": {"cardinality": {"field": "source.ip"}},
                    "sensors": {"terms": {"field": "event.sensor", "size": 20}}
                }
            }
        }
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    let mut rows = Vec::new();
    for (kind, agg) in [("Fingerprint", "fingerprints"), ("Autonomous system", "asns")] {
        if let Some(buckets) = result["aggregations"][agg]["buckets"].as_array() {
            for bucket in buckets {
                let sources = bucket["sources"]["value"].as_u64().unwrap_or(0);
                if sources < 2 {
                    continue; // a cluster is multi-source by definition
                }
                rows.push(ClusterRow {
                    kind: kind.to_string(),
                    value: text(&bucket["key"]),
                    sources,
                    events: bucket["doc_count"].as_u64().unwrap_or(0),
                    sensors: bucket["sensors"]["buckets"]
                        .as_array()
                        .map(|s| s.iter().map(|b| text(&b["key"])).collect())
                        .unwrap_or_default(),
                });
            }
        }
    }
    rows.sort_by(|a, b| b.events.cmp(&a.events));
    Ok(Json(ClustersPage { rows }))
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}
