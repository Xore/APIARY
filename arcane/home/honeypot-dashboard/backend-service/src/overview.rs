//! /api/v1/overview/kpis — the overview KPI strip, mirroring the fields the
//! Go dashboard's esOverview aggregation produces (es_aggregate.go): total
//! events in the 48h window, last-24h count with the vs-previous-24h delta,
//! unique source IPs. #1963 adds login attempts: the strip renders on every
//! overview tab, and reading that one integer from /overview/dashboard used
//! to force that endpoint's whole eighteen-slice aggregation on ticks that
//! needed none of it. (Captured payloads stay on the store listing the
//! frontend already reads; their count is a doc count over captured
//! artifacts, not an event aggregation.)

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::json;

use crate::{es::logins_filter, AppState};

#[derive(Serialize)]
pub struct OverviewKpis {
    pub total: u64,
    pub last24h: u64,
    pub previous24h: u64,
    /// Percent change of last24h vs previous24h, e.g. "+41%"; empty while
    /// the previous window is empty (mirrors the Go hero's guard).
    pub change24h: String,
    pub unique_ips: u64,
    /// Per-hour event counts for the last 24 hours, oldest first — the
    /// "Events in 24 hours" KPI sparkline (overview.html:65-68 /
    /// page_hero.go's hourlySpark, which summed the heatmap's columns;
    /// here the same series comes straight from a date_histogram).
    pub hourly: Vec<u64>,
    /// Login attempts in the 48h window (#1963). Same logins_filter() as
    /// /overview/dashboard's slice was; this is where the KPI strip reads
    /// it now.
    pub logins: u64,
    pub ready: bool,
}

pub async fn kpis(State(state): State<AppState>) -> Result<Json<OverviewKpis>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "track_total_hits": true,
        "query": {"range": {"@timestamp": {"gte": "now-48h"}}},
        "aggs": {
            "last24h": {
                "filter": {"range": {"@timestamp": {"gte": "now-24h"}}},
                "aggs": {"hourly": {"date_histogram": {
                    "field": "@timestamp", "fixed_interval": "1h", "min_doc_count": 0,
                    "extended_bounds": {"min": "now-23h/h", "max": "now/h"}
                }}}
            },
            "previous24h": {"filter": {"range": {"@timestamp": {"gte": "now-48h", "lt": "now-24h"}}}},
            "unique_ips": {"cardinality": {"field": "source.ip"}},
            "logins": {"filter": logins_filter()}
        }
    });
    let result = state
        .es
        .search(body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

    let total = result["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let last24h = result["aggregations"]["last24h"]["doc_count"].as_u64().unwrap_or(0);
    let previous24h = result["aggregations"]["previous24h"]["doc_count"].as_u64().unwrap_or(0);
    let unique_ips = result["aggregations"]["unique_ips"]["value"].as_u64().unwrap_or(0);
    let logins = result["aggregations"]["logins"]["doc_count"].as_u64().unwrap_or(0);
    let hourly: Vec<u64> = result["aggregations"]["last24h"]["hourly"]["buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|bucket| bucket["doc_count"].as_u64().unwrap_or(0))
        .collect();

    let change24h = if previous24h > 0 {
        let delta = (last24h as i64 - previous24h as i64) * 100 / previous24h as i64;
        format!("{}{}%", if delta >= 0 { "+" } else { "" }, delta)
    } else {
        String::new()
    };

    Ok(Json(OverviewKpis {
        total,
        last24h,
        previous24h,
        change24h,
        unique_ips,
        hourly,
        logins,
        ready: true,
    }))
}
