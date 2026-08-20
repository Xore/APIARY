//! /api/v1/overview/kpis — the overview KPI strip, mirroring the fields the
//! Go dashboard's esOverview aggregation produces (es_aggregate.go): total
//! events in the 48h window, last-24h count with the vs-previous-24h delta,
//! unique source IPs. Login/payload counts join in a later slice once
//! their query shapes are ported.

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::json;

use crate::AppState;

#[derive(Serialize)]
pub struct OverviewKpis {
    pub total: u64,
    pub last24h: u64,
    pub previous24h: u64,
    /// Percent change of last24h vs previous24h, e.g. "+41%"; empty while
    /// the previous window is empty (mirrors the Go hero's guard).
    pub change24h: String,
    pub unique_ips: u64,
    pub ready: bool,
}

pub async fn kpis(State(state): State<AppState>) -> Result<Json<OverviewKpis>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "track_total_hits": true,
        "query": {"range": {"@timestamp": {"gte": "now-48h"}}},
        "aggs": {
            "last24h": {"filter": {"range": {"@timestamp": {"gte": "now-24h"}}}},
            "previous24h": {"filter": {"range": {"@timestamp": {"gte": "now-48h", "lt": "now-24h"}}}},
            "unique_ips": {"cardinality": {"field": "source.ip"}}
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
        ready: true,
    }))
}
