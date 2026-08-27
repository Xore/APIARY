//! Report telemetry dataset, ported from report_pdf.go's reportDataFor —
//! Go filters an in-memory, already-loaded event slice (s.getEvents());
//! this crate has no such cache (every read endpoint queries Elasticsearch
//! directly, see events.rs/aggregates.rs/dashboard.rs), so the same
//! summary/top-N/findings dataset is rebuilt as ES aggregations instead of
//! in-memory map-counting. Field names match the ones already established
//! by those modules (source.ip, event.sensor, destination.port,
//! source.geo.country_iso_code, source.as.asn/organization_name,
//! suricata.eve.alert.signature.keyword, honeypot.event).

use serde_json::{json, Value};

use crate::report_pdf::{AlertRecord, Kv, ReportData, ReportEventRow, ReportSummary};
use crate::reports_store::{report_window_duration, ReportScope};
use crate::es::logins_filter;
use crate::AppState;

fn text(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn key_string(bucket: &Value) -> String {
    let key = &bucket["key"];
    key.as_str().map(String::from).unwrap_or_else(|| {
        key.as_i64()
            .map(|n| n.to_string())
            .or_else(|| key.as_f64().map(|n| n.to_string()))
            .unwrap_or_default()
    })
}

/// One human-readable filter description per set scope field, in the same
/// order report_pdf.go's filter.describe() lists them — used for the cover
/// page's "REPORT SCOPE" line and the parameters section's "Applied
/// filters".
fn describe_filters(scope: &ReportScope) -> Vec<String> {
    let mut out = Vec::new();
    if !scope.ip.is_empty() {
        out.push(format!("source IP = {}", scope.ip));
    }
    if !scope.network.is_empty() {
        out.push(format!("network = {}", scope.network));
    }
    if !scope.sensor.is_empty() {
        out.push(format!("sensor = {}", scope.sensor));
    }
    if !scope.port.is_empty() {
        out.push(format!("port = {}", scope.port));
    }
    if !scope.signature.is_empty() {
        out.push(format!("signature = {}", scope.signature));
    }
    if !scope.country.is_empty() {
        out.push(format!("country = {}", scope.country));
    }
    if !scope.asn.is_empty() {
        out.push(format!("ASN = {}", scope.asn));
    }
    if !scope.text.is_empty() {
        out.push(format!("text = {}", scope.text));
    }
    if !scope.kind.is_empty() {
        out.push(format!("type = {}", scope.kind));
    }
    if !scope.session.is_empty() {
        out.push(format!("session = {}", scope.session));
    }
    if !scope.window.is_empty() {
        out.push(format!("window = {}", scope.window));
    }
    out
}

/// Builds the ES bool/filter clauses for a report's scope — the same
/// fields the Event Explorer filter bar understands (events.rs/
/// aggregates.rs), plus the report-specific window.
fn scope_filters(scope: &ReportScope) -> Vec<Value> {
    let mut filters = Vec::new();
    let since = if scope.window.is_empty() {
        // No window restriction: Go's "full observation window" is bounded
        // by whatever the in-memory cache happened to retain; there's no
        // equivalent unbounded query here, so default to a generous 30d
        // rather than scanning every document ever indexed.
        "now-30d".to_string()
    } else if report_window_duration(&scope.window).is_some() {
        format!("now-{}", scope.window)
    } else {
        "now-30d".to_string()
    };
    filters.push(json!({"range": {"@timestamp": {"gte": since}}}));
    if !scope.ip.is_empty() {
        filters.push(json!({"term": {"source.ip": scope.ip}}));
    }
    if !scope.network.is_empty() {
        // ES `ip`-mapped fields accept CIDR notation directly in a term query.
        filters.push(json!({"term": {"source.ip": scope.network}}));
    }
    if !scope.sensor.is_empty() {
        filters.push(json!({"term": {"event.sensor": scope.sensor}}));
    }
    if !scope.port.is_empty() {
        filters.push(json!({"term": {"destination.port": scope.port}}));
    }
    if !scope.signature.is_empty() {
        filters.push(json!({"term": {"suricata.eve.alert.signature.keyword": scope.signature}}));
    }
    if !scope.country.is_empty() {
        filters.push(json!({"term": {"source.geo.country_iso_code": scope.country}}));
    }
    if !scope.asn.is_empty() {
        filters.push(json!({"term": {"source.as.asn": scope.asn}}));
    }
    if !scope.kind.is_empty() {
        filters.push(json!({"term": {"honeypot.event": scope.kind}}));
    }
    if !scope.session.is_empty() {
        // The crate-wide session vocabulary, shared with events.rs and the
        // session pane (#2119): this clause used to match only two of the
        // three id fields, so a report scoped to a mailoney/tanner session
        // — whose events carry honeypot.session_id — silently came back
        // with zero matching telemetry.
        filters.push(crate::events::any_of(crate::events::SESSION_FIELDS, &scope.session));
    }
    if !scope.text.is_empty() {
        filters.push(json!({"query_string": {"query": scope.text, "lenient": true}}));
    }
    filters
}

/// Mirrors dashboard/payload_analysis.go's riskLevel — the one canonical
/// risk scale this dashboard reuses across sandbox/payload/report scoring
/// (report_pdf.go's reportDataFor calls the very same function). Any
/// divergence here would make a ported report show a different risk word
/// for the same score than the Go tier does/did. pub(crate) so
/// payload_static_analysis's deterministic-analyzer scoring reuses this
/// same canonical scale rather than a second copy of the same four bands.
pub(crate) fn risk_level(score: i64) -> &'static str {
    match score {
        s if s >= 75 => "critical",
        s if s >= 50 => "high",
        s if s >= 25 => "medium",
        _ => "low",
    }
}

/// reportAlertMatches ported: every non-empty scope needle (ip/network/
/// sensor/signature/country/asn — the only fields reportScope.filter()
/// actually populates on the shared `filter` type Go's version checks)
/// must substring-match the alert's Key+Message, case-insensitive.
fn alert_matches(key: &str, message: &str, scope: &ReportScope) -> bool {
    let blob = format!("{key} {message}").to_lowercase();
    let needles = [
        &scope.ip,
        &scope.network,
        &scope.sensor,
        &scope.signature,
        &scope.country,
        &scope.asn,
    ];
    needles
        .iter()
        .all(|needle| needle.is_empty() || blob.contains(&needle.to_lowercase()))
}

async fn operational_alerts(
    state: &AppState,
    scope: &ReportScope,
) -> anyhow::Result<(Vec<AlertRecord>, i64)> {
    let result = state
        .es
        .search_index(&["dashboard-alert-state-v1"], json!({"size": 500}))
        .await?;
    let mut open = 0i64;
    let mut alerts = Vec::new();
    for hit in result["hits"]["hits"].as_array().into_iter().flatten() {
        let source = &hit["_source"];
        let key = text(&source["Key"]);
        let message = text(&source["Message"]);
        if !alert_matches(&key, &message, scope) {
            continue;
        }
        let acknowledged = source["Acknowledged"].as_bool().unwrap_or(false);
        if !acknowledged {
            open += 1;
        }
        alerts.push(AlertRecord {
            message,
            count: source["Count"].as_i64().unwrap_or(0),
            acknowledged,
        });
    }
    Ok((alerts, open))
}

async fn event_appendix_rows(
    state: &AppState,
    filters: &[Value],
    limit: i64,
) -> anyhow::Result<Vec<ReportEventRow>> {
    if limit <= 0 {
        return Ok(Vec::new());
    }
    let body = json!({
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        // #2145: both the appendix rows and the summary aggregations are
        // attacker-facing report content; a sensor-scoped report would
        // otherwise count the sensor's own healthchecks in every section
        // (unlike events.rs's list, reports_data had no noise exclusion).
        "query": {"bool": {
            "filter": filters,
            "must_not": [crate::es::internal_probe_exclusion()]
        }}
    });
    let result = state.es.search(body).await?;
    Ok(result["hits"]["hits"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|hit| {
            let src = &hit["_source"];
            let alert = text(&src["suricata"]["eve"]["alert"]["signature"]);
            let command = text(&src["honeypot"]["canonical_command"]);
            let detail = {
                let d = text(&src["honeypot"]["event"]);
                if d.is_empty() {
                    text(&src["message"])
                } else {
                    d
                }
            };
            ReportEventRow {
                time: text(&src["@timestamp"]),
                sensor: text(&src["event"]["sensor"]),
                src_ip: text(&src["source"]["ip"]),
                port: src["destination"]["port"]
                    .as_u64()
                    .map(|p| p.to_string())
                    .unwrap_or_default(),
                alert,
                detail,
                command,
                path: text(&src["url"]["path"]),
            }
        })
        .collect())
}

fn findings(summary: &ReportSummary) -> Vec<String> {
    let mut out = vec![format!(
        "{} matching events from {} unique source addresses reached {} sensors.",
        summary.events, summary.unique_sources, summary.sensors
    )];
    if summary.alerts > 0 {
        out.push(format!(
            "{} IDS or honeypot alert signatures were observed; {} records carried high-severity classifications.",
            summary.alerts, summary.high_severity
        ));
    }
    if summary.logins > 0 {
        out.push(format!(
            "{} authentication attempts were recorded across the selected scope.",
            summary.logins
        ));
    }
    if summary.payloads > 0 {
        out.push(format!(
            "{} payload observations require static and isolated sandbox triage.",
            summary.payloads
        ));
    }
    if summary.commands > 0 {
        out.push(format!(
            "{} command-execution records provide behavioral evidence.",
            summary.commands
        ));
    }
    if summary.open_operational > 0 {
        out.push(format!(
            "{} operational dashboard alerts remain open or unacknowledged.",
            summary.open_operational
        ));
    }
    if summary.events == 0 {
        out.push(
            "No telemetry matched the selected report filters in the queried window.".to_string(),
        );
    }
    out
}

fn recommendations(summary: &ReportSummary) -> Vec<String> {
    let mut out = Vec::new();
    if summary.high_severity > 0 || summary.alerts > 20 {
        out.push("Prioritize the highest-volume signatures and pivot to EveBox and Arkime for packet and session confirmation.".to_string());
    }
    if summary.payloads > 0 {
        out.push("Complete static analysis and disposable-VM sandbox runs for every unique payload hash before handling samples elsewhere.".to_string());
    }
    if summary.logins > 0 {
        out.push("Review repeated credentials, source reuse, and cross-sensor authentication patterns for campaign correlation.".to_string());
    }
    if summary.unique_sources > 0 {
        out.push("Use ASN, provider, country, fingerprint, and network pivots before considering network-level blocking.".to_string());
    }
    if summary.open_operational > 0 {
        out.push("Resolve collection or correlation problems represented by open operational alerts, then acknowledge them with an audit note.".to_string());
    }
    out.push("Treat all attribution and GeoIP results as contextual leads, not proof of actor identity or physical location.".to_string());
    out
}

/// Ports reportDataFor: builds the full telemetry dataset for a scope, via
/// two round trips (one packed aggregation request for every summary count
/// and top-N ranking, one bounded query for the event appendix rows) plus
/// one small query against the alert-state index.
pub async fn report_data_for(
    state: &AppState,
    scope: &ReportScope,
    title: String,
    appendix_limit: i64,
) -> anyhow::Result<ReportData> {
    let filters = scope_filters(scope);
    let filter_descriptions = describe_filters(scope);

    let agg_body = json!({
        "size": 0,
        "track_total_hits": true,
        "query": {"bool": {
            "filter": filters,
            "must_not": [crate::es::internal_probe_exclusion()]
        }},
        "aggs": {
            "sensors": {"terms": {"field": "event.sensor", "size": 10, "order": [{"_count": "desc"}, {"_key": "asc"}]}},
            "unique_sources": {"cardinality": {"field": "source.ip"}},
            "top_sources": {"terms": {"field": "source.ip", "size": 12, "order": [{"_count": "desc"}, {"_key": "asc"}]}},
            "top_signatures": {"terms": {"field": "suricata.eve.alert.signature.keyword", "size": 12, "order": [{"_count": "desc"}, {"_key": "asc"}]}},
            "top_asns": {
                "terms": {"field": "source.as.asn", "size": 10, "order": [{"_count": "desc"}]},
                "aggs": {"org": {"terms": {"field": "source.as.organization_name", "size": 1}}}
            },
            "top_countries": {"terms": {"field": "source.geo.country_iso_code", "size": 10, "order": [{"_count": "desc"}, {"_key": "asc"}]}},
            "top_ports": {"terms": {"field": "destination.port", "size": 10, "order": [{"_count": "desc"}]}},
            "alerts": {"filter": {"exists": {"field": "suricata.eve.alert.signature"}}},
            "high_severity": {"filter": {"bool": {"filter": [
                {"exists": {"field": "suricata.eve.alert.severity"}},
                {"range": {"suricata.eve.alert.severity": {"lte": 2}}}
            ]}}},
            "logins": {"filter": logins_filter()},
            "payloads": {"filter": {"exists": {"field": "honeypot.shasum"}}},
            "commands": {"filter": {"exists": {"field": "honeypot.canonical_command"}}},
            "sessions": {"cardinality": {"field": "honeypot.session"}},
            "first_seen": {"min": {"field": "@timestamp"}},
            "last_seen": {"max": {"field": "@timestamp"}}
        }
    });

    let (agg_result, (operational_alerts_rows, open_operational), events) = tokio::try_join!(
        async { state.es.search(agg_body).await },
        async { operational_alerts(state, scope).await },
        async { event_appendix_rows(state, &filters, appendix_limit.max(1)).await },
    )?;

    let aggs = &agg_result["aggregations"];
    let kv_rows = |agg: &str, size: usize| -> Vec<Kv> {
        aggs[agg]["buckets"]
            .as_array()
            .into_iter()
            .flatten()
            .take(size)
            .map(|bucket| Kv {
                key: key_string(bucket),
                count: bucket["doc_count"].as_i64().unwrap_or(0),
                link: String::new(),
                title: String::new(),
            })
            .collect()
    };
    let top_asns = aggs["top_asns"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|bucket| {
            let number = key_string(bucket);
            let org = bucket["org"]["buckets"]
                .as_array()
                .and_then(|o| o.first())
                .map(key_string)
                .unwrap_or_default();
            Kv {
                key: format!("AS{number} {org}").trim_end().to_string(),
                count: bucket["doc_count"].as_i64().unwrap_or(0),
                link: String::new(),
                title: String::new(),
            }
        })
        .collect();

    let events_count = agg_result["hits"]["total"]["value"].as_i64().unwrap_or(0);
    let mut summary = ReportSummary {
        events: events_count,
        alerts: aggs["alerts"]["doc_count"].as_i64().unwrap_or(0),
        high_severity: aggs["high_severity"]["doc_count"].as_i64().unwrap_or(0),
        unique_sources: aggs["unique_sources"]["value"].as_i64().unwrap_or(0),
        logins: aggs["logins"]["doc_count"].as_i64().unwrap_or(0),
        payloads: aggs["payloads"]["doc_count"].as_i64().unwrap_or(0),
        sessions: aggs["sessions"]["value"].as_i64().unwrap_or(0),
        commands: aggs["commands"]["doc_count"].as_i64().unwrap_or(0),
        sensors: aggs["sensors"]["buckets"]
            .as_array()
            .map(|b| b.len() as i64)
            .unwrap_or(0),
        open_operational,
        first_seen: text(&aggs["first_seen"]["value_as_string"]),
        last_seen: text(&aggs["last_seen"]["value_as_string"]),
        risk_score: 0,
        risk_level: String::new(),
    };

    let mut score: i64 = 5;
    score += (summary.alerts / 5).min(30);
    score += (summary.high_severity * 5).min(25);
    score += (summary.payloads * 3).min(15);
    score += ((summary.sensors - 1).max(0) * 2).min(10);
    score += (summary.open_operational * 2).min(10);
    score += summary.commands.min(5);
    summary.risk_score = score.min(100);
    summary.risk_level = risk_level(summary.risk_score).to_string();

    let scope_description = if filter_descriptions.is_empty() {
        "All normalized telemetry in the queried window".to_string()
    } else {
        filter_descriptions.join(" AND ")
    };

    let data = ReportData {
        generated: chrono::Utc::now(),
        title,
        scope: scope_description,
        filters: filter_descriptions,
        findings: findings(&summary),
        recommendations: recommendations(&summary),
        summary,
        events,
        top_sensors: kv_rows("sensors", 10),
        top_sources: kv_rows("top_sources", 12),
        top_signatures: kv_rows("top_signatures", 12),
        top_asns,
        top_countries: kv_rows("top_countries", 10),
        top_ports: kv_rows("top_ports", 10),
        operational_alerts: operational_alerts_rows,
    };
    Ok(data)
}
