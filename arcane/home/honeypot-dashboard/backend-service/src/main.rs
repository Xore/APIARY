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
    routing::{delete, get, patch, post},
    Json, Router,
};
use serde::Serialize;
use std::{net::SocketAddr, sync::Arc};

mod aggregates;
mod artifacts;
mod attacker_identity;
mod audit;
mod canarytokens;
mod charts;
mod config;
mod config_history;
mod agent_intrusion;
mod campaign_correlator;
mod correlator;
mod credentials;
mod criticality_rules;
mod dashboard;
mod decode_correlate;
mod detail;
mod es;
mod event_detail;
mod es_importer;
mod events;
mod exports;
mod fusion;
mod ghidra_submit;
mod github_analysis_submit;
mod gpu_queue;
mod health;
mod honeyfs_implant;
mod investigate;
mod ip_block;
mod ip_enrichment;
mod kill_chain;
mod live;
mod llm_search;
mod mail;
mod ml_health;
mod overview;
mod payload_bytes;
mod payload_detail;
mod payload_inventory;
mod payload_kind;
mod payload_paths;
mod payload_static_analysis;
mod preferences;
mod problem_reports;
mod replay;
mod report_pdf;
mod reports;
mod reports_api;
mod reports_data;
mod reports_store;
mod reporter_stats;
mod sandbox_submit;
mod sensors;
mod search;
mod services_control;
mod session;
mod stores;
mod ics_severity;
mod ioc_correlation;
mod threat_intel;
mod zeek_proxy_attribution;
mod worker;
mod workbench_api;
mod workbench_domain;
mod workbench_es;
mod workbench_orchestrator;

#[derive(Clone)]
pub struct AppState {
    pub es: Arc<es::Es>,
    pub service_token: Arc<Option<String>>,
    pub audit: Arc<audit::AuditLogger>,
    pub config_history: Arc<config_history::ConfigHistory>,
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


/// When this binary was compiled, as RFC 3339.
///
/// Set by build.rs. Falls back to the raw value if it is ever not a number,
/// so a broken stamp degrades to something visible rather than to a lie.
pub fn build_stamp() -> String {
    let raw = env!("APIARY_BUILD_EPOCH");
    match raw.parse::<i64>() {
        Ok(epoch) => chrono::DateTime::from_timestamp(epoch, 0)
            .map(|when| when.to_rfc3339())
            .unwrap_or_else(|| raw.to_string()),
        Err(_) => raw.to_string(),
    }
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
    let audit_path =
        std::env::var("DASHBOARD_AUDIT_FILE").unwrap_or_else(|_| "/state/dashboard-audit.jsonl".into());
    let config_history_path = std::env::var("DASHBOARD_CONFIG_HISTORY_FILE")
        .unwrap_or_else(|_| "/state/dashboard-config-history.jsonl".into());

    let state = AppState {
        es: Arc::new(es::Es::connect(&es_url)?),
        service_token: Arc::new(service_token),
        audit: Arc::new(audit::AuditLogger::new(audit_path)),
        config_history: Arc::new(config_history::ConfigHistory::new(config_history_path)),
    };

    // Worker loops (#1610): same image, role by WORKER_LOOPS env.
    worker::spawn_enabled(state.clone());

    let api = Router::new()
        .route("/api/v1/overview/kpis", get(overview::kpis))
        .route("/api/v1/overview/dashboard", get(dashboard::dashboard))
        .route("/api/v1/events", get(events::list))
        .route("/api/v1/export/events.csv", get(exports::events_csv))
        .route("/api/v1/export/commands.csv", get(exports::commands_csv))
        .route("/api/v1/export/ips.csv", get(exports::ips_csv))
        .route("/api/v1/export/campaigns.csv", get(exports::campaigns_csv))
        .route("/api/v1/export/clusters.csv", get(exports::clusters_csv))
        .route("/api/v1/export/history.json", get(exports::history_json))
        .route("/api/v1/live", get(live::stream))
        .route("/api/v1/mail/{session_id}", get(mail::get))
        .route("/api/v1/ml-health", get(ml_health::list))
        .route("/api/v1/gpu-queue", get(gpu_queue::list))
        .route("/api/v1/gpu-queue/{job_id}/abort", post(gpu_queue::abort))
        .route("/api/v1/sources", get(aggregates::sources))
        .route("/api/v1/filter-values", get(aggregates::filter_values))
        .route("/api/v1/investigate/ip/{ip}", get(investigate::ip))
        .route("/api/v1/investigate/cidr/{cidr}", get(investigate::cidr))
        .route("/api/v1/investigate/cluster", get(investigate::cluster))
        .route("/api/v1/source-health", get(health::source_health))
        .route("/api/v1/sensors", get(sensors::detail))
        .route("/api/v1/sessions/{id}", get(session::detail))
        .route("/api/v1/search", get(search::search))
        .route("/api/v1/settings/storage", get(health::storage))
        .route("/api/v1/config", get(config::get_config))
        .route(
            "/api/v1/config/presentation",
            axum::routing::put(config::put_presentation),
        )
        .route(
            "/api/v1/config/{section}",
            axum::routing::put(config::put_config_section),
        )
        .route("/api/v1/config/history", get(config::history))
        .route("/api/v1/config/rollback", post(config::rollback))
        .route("/api/v1/config/validate", post(config::validate))
        .route("/api/v1/users", get(config::users))
        .route("/api/v1/audit", get(audit::list))
        .route(
            "/api/v1/preferences",
            get(preferences::get).put(preferences::put),
        )
        .route("/api/v1/preferences/reset", post(preferences::reset))
        .route("/api/v1/reporter-stats", get(reporter_stats::stats))
        .route("/api/v1/services", get(services_control::list))
        .route("/api/v1/services/{name}/logs", get(services_control::logs))
        .route("/api/v1/services/{name}/{action}", post(services_control::action))
        .route("/api/v1/llm-search", get(llm_search::search))
        .route("/api/v1/ip-block", post(ip_block::set_block))
        .route("/api/v1/ip-block/{ip}", get(ip_block::get_block))
        .route("/api/v1/ip-block-export", get(ip_block::export))
        .route("/api/v1/sandbox/{job}", get(detail::sandbox_run))
        .route("/api/v1/ghidra/{sha}", get(detail::ghidra_run))
        .route("/api/v1/ghidra-callgraph/{sha}", get(detail::ghidra_callgraph))
        .route("/api/v1/revdeck/{sha}", get(detail::revdeck_run))
        .route("/api/v1/cape/{sha}", get(detail::cape_run))
        .route("/api/v1/cape/{sha}/raw", get(detail::cape_raw))
        .route("/api/v1/github-analysis/{sha}", get(detail::github_analysis_run))
        .route("/api/v1/attackers-graph", get(detail::attackers_graph))
        .route("/api/v1/attack-vectors", get(detail::attack_vectors))
        .route("/api/v1/ml-anomalies/ack", post(detail::ml_anomaly_ack))
        .route("/api/v1/ml-anomalies/ack-all", post(detail::ml_anomaly_ack_all))
        .route("/api/v1/ml-anomalies/acks", get(detail::ml_anomaly_acks))
        .route("/api/v1/reports/{id}/pdf", get(reports::pdf))
        // #1612 phase 4: Reports studio — template/element catalog,
        // definitions CRUD, and on-demand generate. See reports_store.rs's
        // module doc comment for the sandbox/payload/ghidra scope decision.
        .route("/api/v1/reports/templates", get(reports_api::templates))
        .route(
            "/api/v1/reports/definitions",
            get(reports_api::list_definitions).post(reports_api::create_definition),
        )
        .route(
            "/api/v1/reports/definitions/{id}",
            get(reports_api::get_definition)
                .put(reports_api::replace_definition)
                .delete(reports_api::delete_definition),
        )
        .route("/api/v1/reports/definitions/{id}/generate", post(reports_api::generate))
        .route("/api/v1/reports/generated/{id}", delete(reports_api::delete_generated))
        .route("/api/v1/artifacts/{kind}/{key}", get(artifacts::list))
        .route("/api/v1/artifacts/{kind}/{key}/{filename}", get(artifacts::download))
        .route("/api/v1/charts/kill-chain-sankey", get(kill_chain::sankey))
        .route("/api/v1/charts/attck-coverage", get(kill_chain::attck_coverage))
        .route("/api/v1/charts/campaign-timeline", get(kill_chain::campaign_timeline))
        .route("/api/v1/charts/ml-backlog", get(charts::ml_backlog))
        .route("/api/v1/charts/netflow-bytes", get(charts::netflow_bytes))
        .route("/api/v1/charts/netflow-packets", get(charts::netflow_packets))
        .route("/api/v1/charts/anomaly-trend", get(charts::anomaly_trend))
        .route("/api/v1/charts/dionaea-cves", get(charts::dionaea_cves))
        .route("/api/v1/charts/os-distribution", get(charts::os_distribution))
        // #1727 §7: JA4T stack clusters, the successor to the p0f OS chart above.
        .route("/api/v1/charts/tcp-stack-clusters", get(charts::tcp_stack_clusters))
        // #1736/#1739: two surfaces for data that currently has no view at all.
        .route("/api/v1/charts/ics-functions", get(charts::ics_functions))
        .route("/api/v1/charts/decoy-requests", get(charts::decoy_requests))
        // #1765: the wire-tuple join in use -- Traefik requests meeting the
        // ClientHello fingerprints only the passive sniffer can see.
        .route("/api/v1/charts/decoy-client-fingerprints", get(charts::decoy_client_fingerprints))
        // #1729: the rest of the JA4+ family Zeek produces.
        .route("/api/v1/charts/ja4h-fingerprints", get(charts::ja4h_fingerprints))
        .route("/api/v1/charts/ja4x-fingerprints", get(charts::ja4x_fingerprints))
        .route("/api/v1/charts/ja4l-fingerprints", get(charts::ja4l_fingerprints))
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
        // #1711: the two download forms the Go tier served at
        // /tty/<shasum>.cast and .raw, which the port dropped.
        .route("/api/v1/recordings/{shasum}/cast", get(replay::replay_cast))
        .route("/api/v1/recordings/{shasum}/raw", get(replay::replay_raw))
        .route("/api/v1/alerts", get(stores::alerts))
        .route("/api/v1/alerts/{key}/ack", post(stores::acknowledge))
        .route("/api/v1/canarytokens/types", get(canarytokens::types))
        .route("/api/v1/canarytokens", get(canarytokens::list).post(canarytokens::create))
        .route("/api/v1/canarytokens/{id}/download", get(canarytokens::download))
        // #1612 misc write paths: honeyfs-implant credential provisioning/
        // rotation (credentials_manager.go/credentials_api.go). Plain HTTP
        // to a WireGuard-reachable URL, no host mount — same tier as
        // canarytokens.rs above, not the mounted-worker-role service.
        .route(
            "/api/v1/credentials",
            get(credentials::list).post(credentials::create),
        )
        .route("/api/v1/credentials/{id}/rotate", post(credentials::rotate))
        .route("/api/v1/credentials/{id}/link-token", post(credentials::link_token))
        .route("/api/v1/payloads", get(stores::payloads))
        .route("/api/v1/payloads/{hash}", get(payload_detail::detail))
        .route("/api/v1/payloads/{hash}/raw", get(payload_detail::raw))
        // #474 one-click payload PDF (hp-payload-report.js): ephemeral
        // payload-scoped report into the generated store, no saved
        // definition. See reports_api::generate_payload_report.
        .route("/api/v1/payloads/{hash}/report", post(reports_api::generate_payload_report))
        .route("/api/v1/store/{name}", get(stores::generic).delete(stores::generic_delete))
        .route("/api/v1/problem-reports", post(problem_reports::submit))
        .route("/api/v1/problem-reports/{id}", patch(problem_reports::patch_status))
        // #1612 mounted worker role (phase 3a): sandbox/ghidra/github-
        // analysis submission + golden-image status. Registered in the
        // same shared route table as everything else — which container
        // these are actually reachable/useful on depends entirely on
        // which compose service has the spool-dir mounts (backend-service-
        // mounted), not on route registration here.
        .route("/api/v1/sandbox/submit", post(sandbox_submit::submit))
        .route("/api/v1/sandbox/golden-image-status", get(sandbox_submit::golden_image_status))
        .route("/api/v1/sandbox/vnc", get(sandbox_submit::vnc_status))
        .route("/api/v1/ghidra/submit", post(ghidra_submit::submit))
        .route("/api/v1/github-analysis/submit", post(github_analysis_submit::submit))
        // #1612 phase 3b: Payload Workbench orchestrator (recipes, run
        // creation/reconciliation, child cancel/retry). Same
        // shared-route-table posture as phase 3a — only useful on
        // backend-service-mounted, which has the write-capable spool mounts.
        .route("/api/v1/workbench/analyzers", get(workbench_api::analyzers))
        .route(
            "/api/v1/workbench/runs",
            get(workbench_api::list_runs).post(workbench_api::create_run),
        )
        .route("/api/v1/workbench/runs/{id}", get(workbench_api::get_run))
        .route(
            "/api/v1/workbench/runs/{id}/children/{analyzer_id}/{action}",
            post(workbench_api::child_action),
        )
        .route(
            "/api/v1/workbench/recipes",
            get(workbench_api::list_recipes).post(workbench_api::save_recipe),
        )
        .layer(middleware::from_fn_with_state(state.clone(), require_service_token));

    let app = Router::new()
        .route("/healthz", get(healthz))
        .merge(api)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = listen.parse()?;
    // `built` is the one thing that makes a deploy verifiable from outside.
    // Compare it against the merge time; anything else -- a fresh image id, a
    // recreated container, `{"done":true}` -- says the machinery ran, not
    // that this code is what is running. See build.rs.
    tracing::info!(%addr, %es_url, built = %build_stamp(), "apiary-backend listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod build_stamp_tests {
    use super::build_stamp;

    #[test]
    fn build_stamp_is_a_real_recent_timestamp() {
        // The stamp exists to answer "is the running binary newer than the
        // merge", so a value that does not parse, or that sits in 1970,
        // would be worse than none: it reads as an answer.
        let stamp = build_stamp();
        let parsed = chrono::DateTime::parse_from_rfc3339(&stamp)
            .unwrap_or_else(|error| panic!("build stamp {stamp:?} is not RFC 3339: {error}"));

        let now = chrono::Utc::now();
        let age = now.signed_duration_since(parsed.with_timezone(&chrono::Utc));
        assert!(
            age.num_days() < 3650 && age.num_seconds() > -3600,
            "build stamp {stamp} is not a plausible build time (age {age})",
        );
    }
}
