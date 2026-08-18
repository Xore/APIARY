//! Kill-chain analytics (#1224) — the three chart endpoints, JSON shapes
//! identical to the Go tier's /api/kill-chain-sankey, /api/attck-coverage
//! and /api/campaign-timeline so the ported chart builders consume them
//! unchanged. One structural upgrade: instead of re-running
//! intelligence.go's per-event technique heuristics over an in-memory
//! cache, this tier aggregates the ATT&CK technique IDs
//! ip-enrichment-worker already promotes onto documents
//! (honeypot.canonical_attck_techniques, #1197/#1202). The worker
//! currently emits T1110/T1059(.x)/T1595/T1105 but not the Go page's
//! heuristic-only T1190 and ICS pair (T0886/T1692.001) — those three are
//! supplemented with filter aggregations here; aligning the worker to
//! emit the full set is on the ES-coverage round (#33).

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;

use crate::AppState;

const WINDOW: &str = "now-48h";
const GROUP_CAP: u64 = 1000;

pub const TACTICS: &[&str] = &[
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Credential Access",
    "Lateral Movement",
    "Command and Control",
    "Impair Process Control",
];

fn tactic_for(technique: &str) -> Option<&'static str> {
    Some(match technique {
        "T1595" => "Reconnaissance",
        "T1190" => "Initial Access",
        "T1059" | "T1059.001" | "T1059.003" | "T1059.004" => "Execution",
        "T1110" => "Credential Access",
        "T0886" => "Lateral Movement",
        "T1105" => "Command and Control",
        "T1692.001" => "Impair Process Control",
        _ => return None,
    })
}

fn technique_name(technique: &str) -> &'static str {
    match technique {
        "T1595" => "Active Scanning",
        "T1190" => "Exploit Public-Facing Application",
        "T1059" => "Command and Scripting Interpreter",
        "T1059.001" => "PowerShell",
        "T1059.003" => "Windows Command Shell",
        "T1059.004" => "Unix Shell",
        "T1110" => "Brute Force",
        "T0886" => "Remote Services",
        "T1105" => "Ingress Tool Transfer",
        "T1692.001" => "Unauthorized Message: Command Message",
        _ => "",
    }
}

fn tactic_index(tactic: &str) -> usize {
    TACTICS.iter().position(|candidate| *candidate == tactic).unwrap_or(usize::MAX)
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

/// The ICS filter mirrors intelligence.go's substring checks over
/// sensor/proto text; the write/command escalation approximates its
/// alert/command condition with the event kinds industrial sensors emit.
fn ics_filter() -> serde_json::Value {
    json!({"bool": {"should": [
        {"prefix": {"event.sensor": "conpot"}},
        {"terms": {"network.protocol": ["modbus", "s7comm", "iec104", "dnp3", "enip", "bacnet"]}},
        {"terms": {"honeypot.proto": ["modbus", "s7comm", "iec104", "dnp3", "enip", "bacnet"]}}
    ], "minimum_should_match": 1}})
}

/// Technique → count over the recent window: canonical technique terms
/// plus the three supplemental heuristic buckets.
async fn technique_counts(state: &AppState) -> anyhow::Result<HashMap<String, u64>> {
    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": WINDOW}}},
        "aggs": {
            "techs": {"terms": {"field": "honeypot.canonical_attck_techniques", "size": 40}},
            "ics": {"filter": ics_filter()},
            "ics_write": {"filter": {"bool": {"must": [ics_filter(),
                {"terms": {"honeypot.event": ["command", "write"]}}]}}},
            // honeypot.* is a flattened field — wildcard/substring queries
            // are unsupported on keyed flattened fields (they fail the
            // whole shard), so T1190 counts emulator detections and
            // query-string probes instead of the Go tier's path-substring
            // heuristics. Narrower than the legacy count; the ES-coverage
            // round (#33) promotes a real technique tag for this.
            "web_exploit": {"filter": {"bool": {
                "must": [{"exists": {"field": "honeypot.path"}}],
                "should": [
                    {"exists": {"field": "honeypot.response_msg.response.message.detection.name"}},
                    {"exists": {"field": "honeypot.query"}}
                ],
                "minimum_should_match": 1}}}
        }
    });
    let result = state.es.search(body).await?;
    let aggs = &result["aggregations"];
    let mut counts: HashMap<String, u64> = HashMap::new();
    for bucket in aggs["techs"]["buckets"].as_array().into_iter().flatten() {
        counts.insert(
            bucket["key"].as_str().unwrap_or("").to_string(),
            bucket["doc_count"].as_u64().unwrap_or(0),
        );
    }
    for (technique, agg_name) in [("T0886", "ics"), ("T1692.001", "ics_write"), ("T1190", "web_exploit")] {
        let count = aggs[agg_name]["doc_count"].as_u64().unwrap_or(0);
        if count > 0 {
            counts.insert(technique.to_string(), count);
        }
    }
    Ok(counts)
}

// --- ATT&CK coverage grid (Go: attckGrid) ---

#[derive(Serialize)]
pub struct AttckCell {
    pub tactic_idx: usize,
    pub technique_idx: usize,
    pub count: u64,
}

#[derive(Serialize)]
pub struct AttckGrid {
    pub tactics: Vec<&'static str>,
    pub techniques: Vec<String>,
    pub cells: Vec<AttckCell>,
}

pub async fn attck_coverage(State(state): State<AppState>) -> Result<Json<AttckGrid>, (StatusCode, String)> {
    let counts = technique_counts(&state).await.map_err(bad_gateway)?;
    let mut rows: Vec<(String, u64, usize)> = counts
        .into_iter()
        .filter_map(|(id, count)| tactic_for(&id).map(|tactic| (id, count, tactic_index(tactic))))
        .collect();
    rows.sort_by(|a, b| a.2.cmp(&b.2).then(a.0.cmp(&b.0)));
    let mut grid = AttckGrid { tactics: TACTICS.to_vec(), techniques: Vec::new(), cells: Vec::new() };
    for (id, count, tactic_idx) in rows {
        grid.techniques.push(format!("{} {}", id, technique_name(&id)));
        grid.cells.push(AttckCell { tactic_idx, technique_idx: grid.techniques.len() - 1, count });
    }
    Ok(Json(grid))
}

// --- Kill-chain sankey (Go: sankeyData) ---

#[derive(Serialize)]
pub struct SankeyNode {
    pub name: String,
}

#[derive(Serialize)]
pub struct SankeyLink {
    pub source: String,
    pub target: String,
    pub value: u64,
}

#[derive(Serialize)]
pub struct SankeyData {
    pub nodes: Vec<SankeyNode>,
    pub links: Vec<SankeyLink>,
}

pub async fn sankey(State(state): State<AppState>) -> Result<Json<SankeyData>, (StatusCode, String)> {
    // Per-session (or per-IP for sessionless sensors) technique sets, each
    // group flowing one unit between consecutive touched tactics — same
    // grouping fallback as buildKillChainSankey.
    let body = json!({
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": WINDOW}}},
        "aggs": {
            "sessions": {
                "terms": {"field": "honeypot.session", "size": GROUP_CAP},
                "aggs": {"techs": {"terms": {"field": "honeypot.canonical_attck_techniques", "size": 12}}}
            },
            "ips": {
                "terms": {"field": "source.ip", "size": GROUP_CAP},
                "aggs": {"techs": {"terms": {"field": "honeypot.canonical_attck_techniques", "size": 12}}}
            }
        }
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    let aggs = &result["aggregations"];
    let mut flows: HashMap<(String, String), u64> = HashMap::new();
    let mut touched: HashMap<String, bool> = HashMap::new();
    for group_agg in ["sessions", "ips"] {
        for bucket in aggs[group_agg]["buckets"].as_array().into_iter().flatten() {
            let mut tactics: Vec<&str> = bucket["techs"]["buckets"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|tech| tactic_for(tech["key"].as_str().unwrap_or("")))
                .collect();
            tactics.sort_by_key(|tactic| tactic_index(tactic));
            tactics.dedup();
            for tactic in &tactics {
                touched.insert(tactic.to_string(), true);
            }
            for pair in tactics.windows(2) {
                *flows.entry((pair[0].to_string(), pair[1].to_string())).or_insert(0) += 1;
            }
        }
    }
    let nodes: Vec<SankeyNode> = TACTICS
        .iter()
        .filter(|tactic| touched.contains_key(**tactic))
        .map(|tactic| SankeyNode { name: tactic.to_string() })
        .collect();
    let mut links: Vec<SankeyLink> = flows
        .into_iter()
        .map(|((source, target), value)| SankeyLink { source, target, value })
        .collect();
    links.sort_by_key(|link| (tactic_index(&link.source), tactic_index(&link.target)));
    Ok(Json(SankeyData { nodes, links }))
}

// --- Campaign timeline (Go: timelineRow) ---

#[derive(Serialize)]
pub struct TimelineRow {
    pub cidr: String,
    pub start_ms: i64,
    pub end_ms: i64,
    pub score: f64,
    pub events: u64,
}

pub async fn campaign_timeline(
    State(state): State<AppState>,
) -> Result<Json<Vec<TimelineRow>>, (StatusCode, String)> {
    let campaigns = state
        .es
        .search_index(
            &["campaigns-v1"],
            json!({"size": 200, "sort": [{"first": {"order": "asc", "unmapped_type": "date"}}],
                   "query": {"match_all": {}}}),
        )
        .await
        .map_err(bad_gateway)?;
    let rows: Vec<TimelineRow> = campaigns["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|hit| {
            let source = &hit["_source"];
            let start = chrono::DateTime::parse_from_rfc3339(source["first"].as_str()?).ok()?;
            let end = chrono::DateTime::parse_from_rfc3339(source["last"].as_str()?).ok()?;
            Some(TimelineRow {
                cidr: source["cidr"].as_str().unwrap_or("").to_string(),
                start_ms: start.timestamp_millis(),
                end_ms: end.timestamp_millis(),
                score: source["score"].as_f64().unwrap_or(0.0),
                events: source["events"].as_u64().unwrap_or(0),
            })
        })
        .collect();
    Ok(Json(rows))
}
