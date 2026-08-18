//! apiary-backend — Rust service tier of the modernization port (#1608).
//!
//! Serves /api/v1 JSON to the Nitro BFF. This is the foundation slice:
//! health, build info, and the first ES-backed endpoint (overview KPIs).
//! Auth model: the BFF is the only caller and authenticates with a shared
//! service token (SERVICE_TOKEN env; empty disables the check for local
//! dev), mirroring how the Go dashboard introspects today. Browsers never
//! reach this service directly.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::{net::SocketAddr, sync::Arc};

mod aggregates;
mod charts;
mod dashboard;
mod es;
mod events;
mod fusion;
mod health;
mod kill_chain;
mod live;
mod overview;
mod replay;
mod reports;
mod sensors;
mod search;
mod session;
mod stores;

#[derive(Clone)]
pub struct AppState {
    pub es: Arc<es::Es>,
    pub service_token: Arc<Option<String>>,
}

#[derive(Serialize)]
struct Health {
    ok: bool,
    es: bool,
}

async fn healthz(State(state): State<AppState>) -> Json<Health> {
    let es_ok = state.es.ping().await;
    Json(Health { ok: true, es: es_ok })
}

/// Every /api/v1 route requires the BFF's service token (constant-time
/// comparison; header X-Service-Token). /healthz stays open for the
/// container healthcheck, same as the Go dashboard's -healthcheck probe.
async fn require_service_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if let Some(expected) = state.service_token.as_ref() {
        let presented = headers
            .get("x-service-token")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let expected = expected.as_bytes();
        let presented = presented.as_bytes();
        let mut diff = expected.len() ^ presented.len();
        for i in 0..expected.len().min(presented.len()) {
            diff |= (expected[i] ^ presented[i]) as usize;
        }
        if diff != 0 {
            return (StatusCode::UNAUTHORIZED, "service token required").into_response();
        }
    }
    next.run(request).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,apiary_backend=debug".into()),
        )
        .init();

    let es_url = std::env::var("ELASTICSEARCH_URL").unwrap_or_else(|_| "http://127.0.0.1:9200".into());
    let listen = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".into());
    let service_token = std::env::var("SERVICE_TOKEN").ok().filter(|t| !t.is_empty());

    let state = AppState {
        es: Arc::new(es::Es::connect(&es_url)?),
        service_token: Arc::new(service_token),
    };

    let api = Router::new()
        .route("/api/v1/overview/kpis", get(overview::kpis))
        .route("/api/v1/overview/dashboard", get(dashboard::dashboard))
        .route("/api/v1/events", get(events::list))
        .route("/api/v1/live", get(live::stream))
        .route("/api/v1/sources", get(aggregates::sources))
        .route("/api/v1/source-health", get(health::source_health))
        .route("/api/v1/sensors", get(sensors::detail))
        .route("/api/v1/sessions/{id}", get(session::detail))
        .route("/api/v1/search", get(search::search))
        .route("/api/v1/settings/storage", get(health::storage))
        .route("/api/v1/reports/{id}/pdf", get(reports::pdf))
        .route("/api/v1/charts/kill-chain-sankey", get(kill_chain::sankey))
        .route("/api/v1/charts/attck-coverage", get(kill_chain::attck_coverage))
        .route("/api/v1/charts/campaign-timeline", get(kill_chain::campaign_timeline))
        .route("/api/v1/charts/ml-backlog", get(charts::ml_backlog))
        .route("/api/v1/charts/netflow-bytes", get(charts::netflow_bytes))
        .route("/api/v1/charts/netflow-packets", get(charts::netflow_packets))
        .route("/api/v1/charts/anomaly-trend", get(charts::anomaly_trend))
        .route("/api/v1/charts/dionaea-cves", get(charts::dionaea_cves))
        .route("/api/v1/charts/os-distribution", get(charts::os_distribution))
        .route("/api/v1/charts/tls-fingerprints", get(charts::tls_fingerprints))
        .route("/api/v1/charts/ssh-fingerprints", get(charts::ssh_fingerprints))
        .route("/api/v1/charts/endlessh-held-histogram", get(charts::endlessh_histogram))
        .route("/api/v1/charts/ml-anomaly-scores", get(charts::ml_anomaly_scores))
        .route("/api/v1/charts/attacker-fusion", get(fusion::fusion))
        .route("/api/v1/campaigns", get(stores::campaigns))
        .route("/api/v1/clusters", get(stores::clusters))
        .route("/api/v1/attackers", get(stores::attackers))
        .route("/api/v1/recordings", get(stores::recordings))
        .route("/api/v1/recordings/{shasum}", get(replay::replay))
        .route("/api/v1/alerts", get(stores::alerts))
        .route("/api/v1/payloads", get(stores::payloads))
        .route("/api/v1/store/{name}", get(stores::generic))
        .layer(middleware::from_fn_with_state(state.clone(), require_service_token));

    let app = Router::new()
        .route("/healthz", get(healthz))
        .merge(api)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = listen.parse()?;
    tracing::info!(%addr, %es_url, "apiary-backend listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
