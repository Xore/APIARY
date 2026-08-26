//! /api/v1/overview/kpis — the overview KPI strip, mirroring the fields the
//! Go dashboard's esOverview aggregation produces (es_aggregate.go): total
//! events in the 48h window, last-24h count with the vs-previous-24h delta,
//! unique source IPs. #1963 adds login attempts: the strip renders on every
//! overview tab, and reading that one integer from /overview/dashboard used
//! to force that endpoint's whole eighteen-slice aggregation on ticks that
//! needed none of it. (Captured payloads stay on the store listing the
//! frontend already reads; their count is a doc count over captured
//! artifacts, not an event aggregation.)
//!
//! #2046: everything except `unique_ips` reads the hourly fleet rollup
//! when its 48 buckets are covered — one ≤49-doc read instead of a full
//! EVENT_INDICES aggregation per visitor tick. Two deliberate divergences
//! from the live path, both inherent to a precomputed hourly shape:
//!   * the 24h splits align to the hour rather than a second-exact rolling
//!     cutoff (drift bounded by the current partial hour);
//!   * unique_ips still needs true cross-hour uniqueness — summing hourly
//!     cardinalities would over-count, and HLL++ sketches aren't carried by
//!     the plain long docs — so that single query stays computed-on-read.

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::json;

use crate::{
    es::logins_filter,
    rollups::{self},
    AppState,
};

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

/// KPI values pulled out of rolled `_all` hour docs: totals summed over the
/// window, 24h splits aligned to the current hour boundary, and the
/// always-length-24 oldest-first sparkline.
fn kpis_from_rollup(
    now: chrono::DateTime<chrono::Utc>,
    docs: Vec<(chrono::DateTime<chrono::Utc>, serde_json::Value)>,
) -> Option<(u64, u64, u64, Vec<u64>, u64)> {
    let current_hour = rollups::hour_floor(now);
    let day_start = current_hour - chrono::Duration::hours(23);
    let prev_end = current_hour - chrono::Duration::hours(24);
    let mut total = 0u64;
    let mut last24h = 0u64;
    let mut previous24h = 0u64;
    let mut logins = 0u64;
    let mut by_hour: std::collections::HashMap<chrono::DateTime<chrono::Utc>, u64> =
        std::collections::HashMap::new();
    for (hour, doc) in &docs {
        let events = doc["events"].as_u64().unwrap_or(0);
        total += events;
        logins += doc["logins"].as_u64().unwrap_or(0);
        if *hour >= day_start {
            last24h += events;
        } else if *hour >= prev_end {
            previous24h += events;
        }
        by_hour.insert(*hour, events);
    }
    if !rollups::covered(docs.len(), 48) {
        return None;
    }
    let hourly: Vec<u64> = (0..24)
        .map(|offset| by_hour.get(&(day_start + chrono::Duration::hours(offset))).copied().unwrap_or(0))
        .collect();
    Some((total, last24h, previous24h, hourly, logins))
}

fn change24h_str(previous24h: u64, last24h: u64) -> String {
    if previous24h > 0 {
        let delta = (last24h as i64 - previous24h as i64) * 100 / previous24h as i64;
        format!("{}{}%", if delta >= 0 { "+" } else { "" }, delta)
    } else {
        String::new()
    }
}

/// The one value no hourly doc can carry: true cross-hour source-IP
/// uniqueness over the 48h window.
async fn unique_ips_live(state: &AppState) -> Result<u64, (StatusCode, String)> {
    let result = state
        .es
        .search(json!({
            "size": 0,
            "track_total_hits": false,
            "query": {"range": {"@timestamp": {"gte": "now-48h"}}},
            "aggs": {"unique_ips": {"cardinality": {"field": "source.ip"}}}
        }))
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    Ok(result["aggregations"]["unique_ips"]["value"].as_u64().unwrap_or(0))
}

pub async fn kpis(State(state): State<AppState>) -> Result<Json<OverviewKpis>, (StatusCode, String)> {
    // #2046: the rolled fleet hours are the primary path; the aggregation
    // below runs only while the worker hasn't covered the window yet (fresh
    // deploy, disabled loop) or the rollup read itself errors.
    if let Ok(docs) = rollups::fleet_hours(&state, 48).await {
        if let Some((total, last24h, previous24h, hourly, logins)) =
            kpis_from_rollup(chrono::Utc::now(), docs)
        {
            let unique_ips = unique_ips_live(&state).await?;
            return Ok(Json(OverviewKpis {
                total,
                last24h,
                previous24h,
                change24h: change24h_str(previous24h, last24h),
                unique_ips,
                hourly,
                logins,
                ready: true,
            }));
        }
    }

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

    let change24h = change24h_str(previous24h, last24h);

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
