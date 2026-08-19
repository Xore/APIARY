//! Server-side bulk exports, ported from investigate.go's CSV exports and
//! elastic.go's history()'s attachment mode: the full filtered scope, not
//! whatever happens to be paginated into the browser (#513's own reasoning
//! in investigate.go — an export exists precisely for the rows that don't
//! fit on screen).
//!
//! Two deliberate departures from Go, both because this port already made
//! them elsewhere before this file existed and an export should match the
//! page it exports, not silently reintroduce a scope the page itself
//! doesn't show (Go's own #513 rule, applied to the port's own state):
//!   - commands.csv exports the same `events?kind=command` view
//!     commands.tsx renders (raw per-event rows), not Go's
//!     (sensor,command)-grouped aggregate with counts/first/last.
//!   - events.csv omits Go's "provider" column (a classification this tier
//!     has no confirmed source field for) — every other column present.

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
};
use serde_json::{json, Value};

use crate::events::{build_filters, row_from_source, suricata_noise_exclusion, EventsQuery};
use crate::AppState;

/// Well above anything the UI paginates (100-row store pages, 25-row list
/// pages) but still a real ES query bound — Go's own exports iterate an
/// in-memory event slice with no cap at all, which this tier has no
/// equivalent of; this is the practical stand-in.
const EXPORT_MAX_ROWS: u64 = 10_000;

/// Neutralizes a leading =, +, -, or @ (CSV/spreadsheet-formula injection:
/// a cell starting with one of those is evaluated as a formula by Excel/
/// Sheets/LibreOffice, letting attacker-controlled honeypot text execute
/// arbitrary spreadsheet formulas or DDE commands on the analyst's
/// machine). Prefixing a single quote is the standard mitigation — every
/// spreadsheet app treats a leading quote as "this is text". Ports
/// investigate.go's sanitizeCSVField exactly.
fn sanitize_csv_field(value: &str) -> String {
    match value.chars().next() {
        Some('=' | '+' | '-' | '@') => format!("'{value}"),
        _ => value.to_string(),
    }
}

fn csv_row(fields: &[String]) -> String {
    fields
        .iter()
        .map(|field| {
            let field = sanitize_csv_field(field);
            if field.contains(['"', ',', '\n', '\r']) {
                format!("\"{}\"", field.replace('"', "\"\""))
            } else {
                field
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn csv_body(header_row: &[&str], rows: &[Vec<String>]) -> String {
    let header: Vec<String> = header_row.iter().map(|value| value.to_string()).collect();
    let mut body = csv_row(&header);
    body.push_str("\r\n");
    for row in rows {
        body.push_str(&csv_row(row));
        body.push_str("\r\n");
    }
    body
}

fn csv_response(filename: &'static str, body: String) -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
        ],
        body,
    )
}

fn bad_gateway(error: anyhow::Error) -> (StatusCode, String) {
    (StatusCode::BAD_GATEWAY, error.to_string())
}

fn text(value: &Value) -> String {
    value.as_str().unwrap_or("").to_string()
}

fn number(value: &Value) -> String {
    value.as_i64().map(|n| n.to_string()).unwrap_or_default()
}

fn joined(value: &Value) -> String {
    value.as_array().into_iter().flatten().filter_map(|item| item.as_str()).collect::<Vec<_>>().join(" ")
}

/// GET /api/v1/export/events.csv
pub async fn events_csv(
    State(state): State<AppState>,
    Query(q): Query<EventsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let filters = build_filters(&q);
    let body = json!({
        "size": EXPORT_MAX_ROWS,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}}
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    let rows: Vec<Vec<String>> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| {
            let row = row_from_source(&hit["_source"]);
            let hp = &row.record["honeypot"];
            vec![
                row.time,
                row.sensor,
                row.src_ip,
                row.country,
                text(&row.record["source"]["geo"]["city_name"]),
                number(&row.record["source"]["as"]["number"]),
                text(&row.record["source"]["as"]["organization"]["name"]),
                row.proto,
                row.port,
                text(&hp["username"]),
                text(&hp["password"]),
                text(&hp["command"]),
                text(&hp["path"]),
                text(&row.record["suricata"]["eve"]["alert"]["signature"]),
                row.session,
                text(&hp["shasum"]),
                row.detail,
            ]
        })
        .collect();
    Ok(csv_response(
        "honeypot-events.csv",
        csv_body(
            &[
                "time",
                "sensor",
                "source_ip",
                "country",
                "city",
                "asn",
                "organization",
                "protocol",
                "port",
                "username",
                "password",
                "command",
                "path",
                "alert",
                "session",
                "payload_hash",
                "detail",
            ],
            &rows,
        ),
    ))
}

/// GET /api/v1/export/commands.csv — see module doc: exports the same
/// `events?kind=command` scope commands.tsx itself renders.
pub async fn commands_csv(
    State(state): State<AppState>,
    Query(mut q): Query<EventsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    q.kind = Some("command".to_string());
    let filters = build_filters(&q);
    let body = json!({
        "size": EXPORT_MAX_ROWS,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}}
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    let rows: Vec<Vec<String>> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| {
            let row = row_from_source(&hit["_source"]);
            let hp = &row.record["honeypot"];
            let command = ["input", "command", "data", "message"]
                .into_iter()
                .find_map(|field| hp[field].as_str().filter(|value| !value.is_empty()))
                .map(str::to_string)
                .unwrap_or(row.detail);
            vec![row.time, row.sensor, row.src_ip, command, row.session]
        })
        .collect();
    Ok(csv_response("honeypot-commands.csv", csv_body(&["time", "sensor", "source_ip", "command", "session"], &rows)))
}

/// GET /api/v1/export/ips.csv — same aggregation aggregates::sources
/// backs /ips with, just a higher cap (that endpoint's own 1000-row cap,
/// already well above the page's 25-row pagination).
pub async fn ips_csv(State(state): State<AppState>) -> Result<impl IntoResponse, (StatusCode, String)> {
    let page = crate::aggregates::sources(
        State(state),
        Query(crate::aggregates::PageQuery { offset: 0, size: 1000 }),
    )
    .await?
    .0;
    let rows: Vec<Vec<String>> = page
        .rows
        .iter()
        .map(|row| {
            vec![
                row.ip.clone(),
                row.country.clone(),
                row.events.to_string(),
                row.logins.to_string(),
                row.sessions.to_string(),
                row.sensors.join(" "),
                row.first.clone(),
                row.last.clone(),
            ]
        })
        .collect();
    Ok(csv_response(
        "honeypot-attack-sources.csv",
        csv_body(&["ip", "country", "events", "logins", "sessions", "sensors", "first", "last"], &rows),
    ))
}

/// GET /api/v1/export/campaigns.csv
pub async fn campaigns_csv(State(state): State<AppState>) -> Result<impl IntoResponse, (StatusCode, String)> {
    let result = state
        .es
        .search_index(&["campaigns-v1"], json!({"size": EXPORT_MAX_ROWS, "sort": [{"score": {"order": "desc"}}]}))
        .await
        .map_err(bad_gateway)?;
    let rows: Vec<Vec<String>> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| {
            let src = &hit["_source"];
            vec![
                number(&src["score"]),
                text(&src["cidr"]),
                number(&src["events"]),
                number(&src["unique_ips"]),
                joined(&src["sensors"]),
                joined(&src["ports"]),
                number(&src["creds"]),
                number(&src["payloads"]),
                number(&src["alerts"]),
                joined(&src["providers"]),
                number(&src["fingerprints"]),
                text(&src["explanation"]),
                text(&src["first"]),
                text(&src["last"]),
            ]
        })
        .collect();
    Ok(csv_response(
        "honeypot-campaigns.csv",
        csv_body(
            &[
                "score",
                "network",
                "events",
                "unique_ips",
                "sensors",
                "ports",
                "creds",
                "payloads",
                "alerts",
                "providers",
                "fingerprints",
                "why_correlated",
                "first",
                "last",
            ],
            &rows,
        ),
    ))
}

#[derive(serde::Deserialize)]
pub struct ClustersExportQuery {
    #[serde(default)]
    kind: String,
}

/// GET /api/v1/export/clusters.csv — same ?kind= post-aggregation
/// narrowing the /clusters page itself applies client-side, applied here
/// server-side over the full result set.
pub async fn clusters_csv(
    State(state): State<AppState>,
    Query(query): Query<ClustersExportQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let kind_filter = query.kind;
    let result = state
        .es
        .search_index(&["attacker-clusters-v1"], json!({"size": EXPORT_MAX_ROWS, "sort": [{"events": {"order": "desc"}}]}))
        .await
        .map_err(bad_gateway)?;
    let rows: Vec<Vec<String>> = result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|hit| kind_filter.is_empty() || text(&hit["_source"]["kind"]) == kind_filter)
        .map(|hit| {
            let src = &hit["_source"];
            vec![text(&src["kind"]), text(&src["value"]), number(&src["sources"]), number(&src["events"]), joined(&src["sensors"])]
        })
        .collect();
    Ok(csv_response("honeypot-clusters.csv", csv_body(&["kind", "value", "sources", "events", "sensors"], &rows)))
}

/// GET /api/v1/export/history.json — the same honeypot-v2-*/suricata-v2-*
/// query events::list serves, just forced to the export cap and marked as
/// a download. Mirrors elastic.go's history(attachment=true).
pub async fn history_json(
    State(state): State<AppState>,
    Query(mut q): Query<EventsQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    q.size = 500;
    let filters = build_filters(&q);
    let body = json!({
        "size": 500,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": filters, "must_not": suricata_noise_exclusion()}}
    });
    let result = state.es.search(body).await.map_err(bad_gateway)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"honeypot-history.json\"".to_string()),
        ],
        result.to_string(),
    ))
}
