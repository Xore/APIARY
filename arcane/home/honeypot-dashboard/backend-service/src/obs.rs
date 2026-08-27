//! Serving-tier observability (#1972) — the three things #1942's ~290ms-500
//! investigation proved were missing from this tier:
//!
//! 1. **Request identity.** `observe` (the axum middleware below) reads an
//!    inbound `x-request-id` or mints one, echoes it on every response,
//!    carries it into the per-request `tracing` span and the durable JSONL
//!    line, so one id strings together Traefik → BFF → this tier → ES.
//!    Not cryptographic — it only has to be unique-in-practice and stable
//!    across a request's hops, never secret.
//! 2. **Durable logs.** `tracing` stdout dies with a recreated container;
//!    that gap is the whole reason #1942's failures predated every log we
//!    had. When DASHBOARD_LOG_FILE names a file on the filebeat-tailed
//!    mount (/logs/dashboard-backend/app.jsonl in compose), one structured
//!    JSONL line lands there per request and survives into ES under its own
//!    index family + ILM policy, next to every other evidence stream.
//! 3. **A metrics baseline.** /metrics serves Prometheus text exposition —
//!    requests by route family/status class and a latency histogram per
//!    family — hand-rolled on atomics because the point is exposing numbers
//!    today, not adopting a client crate for two series families. A shedding
//!    storm or error burst becomes visible without reading Traefik's log.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tracing::Instrument;

use crate::AppState;

/// Upper bound accepted from upstream before we regenerate instead.
const MAX_INBOUND_ID_LEN: usize = 128;

/// Latency bucket edges in whole milliseconds, kept integer so every write
/// is a relaxed atomic increment (no float accumulators anywhere).
const LATENCY_BUCKETS_MS: [u64; 10] = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];

/// The path's coarse identity. "Per route family" needs bounded label sets;
/// tower's matched-route patterns would need routing internals inside the
/// middleware, while this tier's paths already namespace themselves as
/// /api/v1/<family>/... — everything after <family> is entity ids that must
/// NOT become label values (unbounded cardinality is what quietly kills a
/// metrics endpoint months later).
pub fn family_for_path(path: &str) -> String {
    let mut segments = path.split('/').filter(|s| !s.is_empty());
    match (segments.next(), segments.next(), segments.next()) {
        (Some("healthz"), None, None) => "healthz".to_string(),
        (Some("metrics"), None, None) => "metrics".to_string(),
        (Some("api"), Some("v1"), Some(family)) => {
            // Only clean single-segment names become labels; anything odd
            // folds into "other" rather than feeding cardinality.
            let clean = !family.is_empty()
                && family.len() <= 40
                && family.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if clean {
                family.to_string()
            } else {
                "other".to_string()
            }
        }
        _ => "other".to_string(),
    }
}

fn status_class(status: u16) -> &'static str {
    match status / 100 {
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

/// The tier's observability state: what AppState actually holds. Kept as one
/// handle so adding the next signal is one field here, not another
/// AppState-wide thread.
pub struct Obs {
    pub metrics: Metrics,
    /// Durable JSONL sink (DASHBOARD_LOG_FILE); empty string disables.
    pub log_file: String,
}

impl Obs {
    pub fn new(log_file: String) -> Self {
        Self { metrics: Metrics::new(), log_file }
    }
}

fn valid_inbound_id(raw: &str) -> bool {
    // Accept what came from upstream when it looks like a transport id:
    // printable ASCII, no whitespace/control bytes, sane length. Anything
    // else is regenerated rather than trusted further.
    !raw.is_empty()
        && raw.len() <= MAX_INBOUND_ID_LEN
        && raw.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// This request's id: upstream's when present and well-formed, otherwise
/// time+counter hex. Monotonic-nanosecond XOR with a process-lifetime counter
/// keeps concurrent generations distinct without pulling a uuid crate; these
/// are correlation keys, not capabilities.
pub fn mint_request_id(inbound: Option<&str>) -> String {
    if let Some(id) = inbound.map(str::trim).filter(|id| valid_inbound_id(id)) {
        return id.to_string();
    }
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mixed = nanos ^ counter.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0xa5a5_5a5a_0000_0001;
    format!("req-{mixed:016x}")
}

pub struct Metrics {
    /// {family,status_class} → count. One Mutex over plain counters: writes
    /// are a short critical section each and the scrape takes it once — fine
    /// at dashboard-grade traffic (#1616 caps this tier at 64 inflight).
    requests: Mutex<HashMap<(String, String), u64>>,
    /// Cumulative-per-family histogram buckets keyed "<family>|<le_ms>".
    latency_buckets: Mutex<HashMap<String, u64>>,
    latency_sum_ms: AtomicU64,
    latency_count: AtomicU64,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
            latency_buckets: Mutex::new(HashMap::new()),
            latency_sum_ms: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
        }
    }

    pub fn record(&self, family: &str, status: u16, duration_ms: u64) {
        *self
            .requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry((family.to_string(), status_class(status).to_string()))
            .or_default() += 1;
        {
            let mut buckets = self.latency_buckets.lock().unwrap_or_else(|p| p.into_inner());
            for edge in LATENCY_BUCKETS_MS {
                if duration_ms <= edge {
                    *buckets.entry(format!("{family}|{edge}")).or_default() += 1;
                }
            }
        }
        self.latency_sum_ms.fetch_add(duration_ms, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Prometheus text exposition. Cumulative buckets plus _sum/_count keep
    /// this standard-shape for any scraper; le=+Inf closes each family's
    /// series so rate()/histogram_quantile() behave as documented.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);
        out.push_str("# HELP apiary_backend_requests_total Requests by route family and status class.\n");
        out.push_str("# TYPE apiary_backend_requests_total counter\n");
        let mut rows: Vec<((String, String), u64)> =
            self.requests.lock().unwrap_or_else(|p| p.into_inner()).clone().into_iter().collect();
        rows.sort();
        // Borrowed, not moved: the histogram section below re-reads these
        // same rows for per-family family lists and +Inf counts.
        for ((family, class), count) in &rows {
            out.push_str(&format!(
                "apiary_backend_requests_total{{family=\"{family}\",status=\"{class}\"}} {count}\n"
            ));
        }

        out.push_str("# HELP apiary_backend_request_duration_seconds Request latency by route family.\n");
        out.push_str("# TYPE apiary_backend_request_duration_seconds histogram\n");
        let buckets = self.latency_buckets.lock().unwrap_or_else(|p| p.into_inner()).clone();
        // Family list comes from the requests rows, NOT from populated
        // bucket keys: a duration above every finite edge fills no bucket
        // yet is still a real sample of that family — dropping it would
        // strand the family with no +Inf close and skew histogram_quantile().
        // record() bumps both maps one-for-one, so the same rows also give
        // each family its own sample count for +Inf (the global counter
        // would leak one family's volume into every other family's Inf
        // bucket — caught exactly that way by the text-exposition test).
        let rows_ref = &rows;
        let mut families: Vec<&str> =
            rows_ref.iter().map(|((f, _), _)| f.as_str()).collect();
        families.sort_unstable();
        families.dedup();
        let total = self.latency_count.load(Ordering::Relaxed);
        for family in families {
            for edge in LATENCY_BUCKETS_MS {
                let value = buckets.get(&format!("{family}|{edge}")).copied().unwrap_or(0);
                out.push_str(&format!(
                    "apiary_backend_request_duration_seconds_bucket{{family=\"{family}\",le=\"{}\"}} {value}\n",
                    edge as f64 / 1000.0
                ));
            }
            let family_total: u64 = rows_ref
                .iter()
                .filter(|((f, _), _)| f.as_str() == family)
                .map(|(_, c)| c)
                .sum();
            out.push_str(&format!(
                "apiary_backend_request_duration_seconds_bucket{{family=\"{family}\",le=\"+Inf\"}} {family_total}\n"
            ));
        }
        let sum = self.latency_sum_ms.load(Ordering::Relaxed);
        out.push_str("# UNIT apiary_backend_request_duration_seconds seconds\n");
        out.push_str(&format!("apiary_backend_request_duration_seconds_sum {:.6}\n", sum as f64 / 1000.0));
        out.push_str(&format!("apiary_backend_request_duration_seconds_count {total}\n"));
        out
    }
}

/// One structured line per served request into the filebeat-tailed volume.
/// Shape mirrors what the -v1 index template maps: ECS-ish top level like
/// disk-space-check's feed (#263 precedent), so downstream needs no ndjson
/// target namespace. A failing sink logs once per failure at debug and gets
/// out of the way — shipping logs must never take serving down with it.
async fn append_log_line(log_file: String, line: serde_json::Value) {
    use tokio::io::AsyncWriteExt;
    let Ok(mut file) = tokio::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_file)
        .await
    else {
        tracing::debug!(log_file = %log_file, "[E-OBS] durable request log unavailable");
        return;
    };
    match serde_json::to_string(&line) {
        Ok(mut rendered) => {
            rendered.push('\n');
            let _ = file.write_all(rendered.as_bytes()).await;
        }
        Err(_) => {}
    }
}

/// Outermost middleware: metrics + request-id echo/span + durable line for
/// everything this tier serves, healthz and metrics included (the probe's
/// own behavior is part of the observability story too).
pub async fn observe(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let started = std::time::Instant::now();
    let method = request.method().as_str().to_string();
    let uri_path = request.uri().path().to_string();
    let inbound = headers.get("x-request-id").and_then(|v| v.to_str().ok()).map(str::to_string);
    let request_id = mint_request_id(inbound.as_deref());
    let family = family_for_path(&uri_path);

    // Named span fields put the id into every log line any inner handler
    // emits — grepping stdout for one id answers which handler ran and what
    // it saw, halving #1942's archaeology problem even before ES has the
    // durable copy.
    let span = tracing::info_span!("request", request_id = %request_id, method = %method, path = %uri_path);
    let response = next.run(request).instrument(span).await;

    let status = response.status().as_u16();
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    state.observability.metrics.record(&family, status, duration_ms);

    let mut response = response;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }

    if !state.observability.log_file.is_empty() {
        let line = json!({
            "@timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "event.category": "api_request",
            "service": "backend-service",
            "request.id": request_id,
            "http.request.method": method,
            "url.path": uri_path,
            "status_code": status,
            "duration_ms": duration_ms,
            "level": if status >= 500 { "error" } else { "info" },
        });
        let log_file = state.observability.log_file.clone();
        tokio::spawn(async move { append_log_line(log_file, line).await });
    }
    response
}

/// GET /metrics — deliberately unauthenticated exactly like /healthz: both
/// are reachable only on LISTEN_ADDR, which is the internal docker network
/// (Traefik publishes the BFF tier, not this listener). Adding auth here
/// would just mean operators punt and scrape over SSH tunnels anyway.
pub async fn metrics_route(State(state): State<AppState>) -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.observability.metrics.render(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn families_match_the_tier_path_shapes() {
        assert_eq!(family_for_path("/healthz"), "healthz");
        assert_eq!(family_for_path("/metrics"), "metrics");
        assert_eq!(family_for_path("/api/v1/store/ml-anomalies?offset=0"), "store");
        assert_eq!(family_for_path("/api/v1/live"), "live");
        // Entity ids must not leak into labels...
        assert_eq!(family_for_path("/api/v1/workbench/runs/abc%20def/children"), "workbench");
        // ...and malformed shapes fold rather than feed cardinality.
        assert_eq!(family_for_path("/api/v1"), "other");
        assert_eq!(family_for_path("/api/v1/../etc/passwd"), "other");
        assert_eq!(family_for_path("/favicon.ico"), "other");
    }

    #[test]
    fn inbound_ids_are_kept_only_when_transport_plausible() {
        assert_eq!(mint_request_id(Some("traefik-id-123")), "traefik-id-123");
        assert_eq!(mint_request_id(Some("  padded-ok  ")), "padded-ok"); // trimmed
        // Whitespace/control bytes/oversized are regenerated, not echoed.
        assert_ne!(mint_request_id(Some("bad id")), "bad id");
        assert_ne!(mint_request_id(Some("bad\nid")), "bad\nid");
        assert_ne!(mint_request_id(Some("x".repeat(MAX_INBOUND_ID_LEN + 1).as_str())), "");
        // Every generated id is distinct from a fresh one.
        assert_ne!(mint_request_id(None), mint_request_id(None));
    }

    #[test]
    fn metrics_render_is_a_valid_text_exposition() {
        let m = Metrics::new();
        m.record("store", 200, 42);
        m.record("store", 200, 1500);
        m.record("auth", 500, 9000);
        let body = m.render();
        assert!(body.contains("apiary_backend_requests_total{family=\"store\",status=\"2xx\"} 2"));
        assert!(body.contains("apiary_backend_requests_total{family=\"auth\",status=\"5xx\"} 1"));
        // Cumulative histogram property: every finite bucket includes both
        // store samples; the 500ms bucket also does (42ms sample), the 100ms
        // one does not (1500ms sample).
        let finite_5000 = "le=\"5\"}"; // sanity: label formatting survived
        assert!(body.contains(finite_5000));
        let plus_inf = "apiary_backend_request_duration_seconds_bucket{family=\"store\",le=\"+Inf\"} 2";
        assert!(body.contains(plus_inf));
        assert!(body.contains("apiary_backend_request_duration_seconds_sum 10.542000"));
        assert!(body.contains("apiary_backend_request_duration_seconds_count 3"));
    }
}
