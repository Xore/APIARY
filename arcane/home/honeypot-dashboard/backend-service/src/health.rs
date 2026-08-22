//! /api/v1/source-health — per-sensor ingestion freshness + ES cluster
//! state, the port's version of the Go source-health page's ES half. (The
//! filebeat/log-tail half joins with the worker port #1610, which owns
//! host-local observability.)

use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use serde_json::json;

use crate::AppState;

#[derive(Serialize)]
pub struct SensorHealth {
    pub sensor: String,
    pub documents: u64,
    pub last_seen: String,
    /// ACTIVE (<5m), QUIET (<1h), STALE otherwise — same thresholds the Go
    /// page communicates.
    pub state: String,
}

#[derive(Serialize)]
pub struct Storage {
    pub cluster_status: String,
    pub index_count: u64,
    pub doc_count: u64,
    pub store_bytes: u64,
}

/// /api/v1/settings/storage — the ES storage summary the legacy settings
/// modal's storage pane shows.
pub async fn storage(State(state): State<AppState>) -> Result<Json<Storage>, (StatusCode, String)> {
    let (index_count, doc_count, store_bytes) = state
        .es
        .storage_summary()
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;
    Ok(Json(Storage {
        cluster_status: state.es.cluster_status().await,
        index_count,
        doc_count,
        store_bytes,
    }))
}

/// YARA scanner card (ui/source_health.html "YARA scanner",
/// dashboard/yara.go yaraSummary) — aggregated from the yara-analysis-v1
/// ES mirror, the same read-only path the Go page used.
#[derive(Serialize)]
pub struct YaraHealth {
    /// false when the yara-analysis-v1 search failed — the Go card's
    /// Enabled bit (loadYaraSamplesES' ok).
    pub enabled: bool,
    pub last_scan: String,
    pub rules_sha256: String,
    pub samples: u64,
    pub matched: u64,
    pub errors: u64,
}

/// "Dashboard runtime" card, ported honestly: this is the Rust backend
/// service, so Go heap/goroutines have no equivalent — /proc/self uptime
/// and memory stand in.
#[derive(Serialize)]
pub struct RuntimeHealth {
    pub uptime_seconds: u64,
    pub rss_bytes: u64,
    pub vm_bytes: u64,
}

/// "Ingestion freshness" card — dashboard/elastic.go refresh()'s verdict:
/// healthy, delayed (>2m), stale (>15m) on the newest indexed event.
#[derive(Serialize)]
pub struct IngestFreshness {
    pub state: String,
    pub last_ingest: String,
    pub age_seconds: i64,
    pub recent_dead_letters: u64,
}

#[derive(Serialize)]
pub struct SourceHealth {
    pub cluster_status: String,
    pub total_documents: u64,
    pub sensors: Vec<SensorHealth>,
    pub yara: YaraHealth,
    pub runtime: RuntimeHealth,
    pub ingest: IngestFreshness,
    pub dead_letters: u64,
}

/// Uptime + memory from /proc/self — zeroes off Linux or on parse failure
/// rather than failing the whole endpoint.
fn runtime_health() -> RuntimeHealth {
    let mut health = RuntimeHealth { uptime_seconds: 0, rss_bytes: 0, vm_bytes: 0 };
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            let kb = |line: &str| {
                line.split_whitespace().nth(1).and_then(|value| value.parse::<u64>().ok()).unwrap_or(0) * 1024
            };
            if line.starts_with("VmRSS:") {
                health.rss_bytes = kb(line);
            } else if line.starts_with("VmSize:") {
                health.vm_bytes = kb(line);
            }
        }
    }
    // starttime is stat field 22, counted from after the ")" closing the
    // comm field (comm itself may contain spaces). Ticks are _SC_CLK_TCK,
    // which is 100 on every Linux this deploys to (no libc dep to ask).
    if let (Ok(stat), Ok(uptime)) =
        (std::fs::read_to_string("/proc/self/stat"), std::fs::read_to_string("/proc/uptime"))
    {
        let boot_seconds = uptime.split_whitespace().next().and_then(|v| v.parse::<f64>().ok());
        let start_ticks = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(19))
            .and_then(|v| v.parse::<f64>().ok());
        if let (Some(boot), Some(start)) = (boot_seconds, start_ticks) {
            health.uptime_seconds = (boot - start / 100.0).max(0.0) as u64;
        }
    }
    health
}

async fn yara_health(state: &AppState) -> YaraHealth {
    let body = json!({
        "size": 1,
        "track_total_hits": true,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {"exists": {"field": "yara.sha256"}},
        "aggs": {
            // matched/errors mirror yaraSummary's len(Matches)>0 /
            // Error != "" counts; an empty array has no value in ES, so
            // exists alone matches Go's len>0.
            "matched": {"filter": {"exists": {"field": "yara.matches"}}},
            "errors": {"filter": {"bool": {
                "filter": [{"exists": {"field": "yara.error"}}],
                "must_not": [{"term": {"yara.error": ""}}]
            }}}
        }
    });
    let Ok(result) = state.es.search_index(&["yara-analysis-v1"], body).await else {
        return YaraHealth {
            enabled: false,
            last_scan: String::new(),
            rules_sha256: String::new(),
            samples: 0,
            matched: 0,
            errors: 0,
        };
    };
    let newest = &result["hits"]["hits"][0]["_source"];
    // report.updated_at is scanner.py's whole-corpus results.json stamp;
    // yara.scanned_at the per-sample one. Newest doc first, prefer the
    // corpus stamp like yaraSummary's max-of-both.
    let last_scan = [&newest["report"]["updated_at"], &newest["yara"]["report_updated_at"], &newest["yara"]["scanned_at"]]
        .iter()
        .filter_map(|value| value.as_str())
        .max()
        .unwrap_or("")
        .to_string();
    YaraHealth {
        enabled: true,
        last_scan,
        rules_sha256: newest["report"]["rules_sha256"].as_str().unwrap_or("").to_string(),
        samples: result["hits"]["total"]["value"].as_u64().unwrap_or(0),
        matched: result["aggregations"]["matched"]["doc_count"].as_u64().unwrap_or(0),
        errors: result["aggregations"]["errors"]["doc_count"].as_u64().unwrap_or(0),
    }
}

/// Total + last-24h dead letters (elastic.go refresh()'s DeadLetters /
/// RecentDeadLetters counts). ignore_unavailable makes a missing index 0.
async fn dead_letter_counts(state: &AppState) -> (u64, u64) {
    let body = json!({
        "size": 0,
        "track_total_hits": true,
        "aggs": {"recent": {"filter": {"range": {"@timestamp": {"gte": "now-24h"}}}}}
    });
    match state.es.search_index(&["dead-letter-honeypot"], body).await {
        Ok(result) => (
            result["hits"]["total"]["value"].as_u64().unwrap_or(0),
            result["aggregations"]["recent"]["doc_count"].as_u64().unwrap_or(0),
        ),
        Err(_) => (0, 0),
    }
}

pub async fn source_health(State(state): State<AppState>) -> Result<Json<SourceHealth>, (StatusCode, String)> {
    let body = json!({
        "size": 0,
        "track_total_hits": true,
        "aggs": {
            "sensors": {
                "terms": {"field": "event.sensor", "size": 60, "order": {"last": "desc"}},
                "aggs": {"last": {"max": {"field": "@timestamp"}}}
            },
            "newest": {"max": {"field": "@timestamp"}}
        }
    });
    let result = state
        .es
        .search(body)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?;

    let cluster_status = state.es.cluster_status().await;
    let total_documents = result["hits"]["total"]["value"].as_u64().unwrap_or(0);
    let now_ms = chrono::Utc::now().timestamp_millis();

    let newest_ms = result["aggregations"]["newest"]["value"].as_f64().map(|value| value as i64);
    let ingest_age_s = newest_ms.map(|ms| ((now_ms - ms) / 1000).max(0));
    let (dead_letters, recent_dead_letters) = dead_letter_counts(&state).await;
    let ingest = IngestFreshness {
        // elastic.go refresh(): healthy, delayed over 2 minutes, stale
        // over 15.
        state: match ingest_age_s {
            None => "unknown",
            Some(age) if age > 15 * 60 => "stale",
            Some(age) if age > 2 * 60 => "delayed",
            Some(_) => "healthy",
        }
        .to_string(),
        last_ingest: result["aggregations"]["newest"]["value_as_string"].as_str().unwrap_or("").to_string(),
        age_seconds: ingest_age_s.unwrap_or(-1),
        recent_dead_letters,
    };
    let yara = yara_health(&state).await;
    let sensors = result["aggregations"]["sensors"]["buckets"]
        .as_array()
        .map(|buckets| {
            buckets
                .iter()
                .map(|bucket| {
                    let last_ms = bucket["last"]["value"].as_f64().unwrap_or(0.0) as i64;
                    let age_s = ((now_ms - last_ms) / 1000).max(0);
                    SensorHealth {
                        sensor: bucket["key"].as_str().unwrap_or("").to_string(),
                        documents: bucket["doc_count"].as_u64().unwrap_or(0),
                        last_seen: bucket["last"]["value_as_string"].as_str().unwrap_or("").to_string(),
                        state: if age_s < 300 {
                            "ACTIVE"
                        } else if age_s < 3600 {
                            "QUIET"
                        } else {
                            "STALE"
                        }
                        .to_string(),
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(Json(SourceHealth {
        cluster_status,
        total_documents,
        sensors,
        yara,
        runtime: runtime_health(),
        ingest,
        dead_letters,
    }))
}
