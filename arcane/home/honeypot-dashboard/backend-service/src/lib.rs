//! The library half of the crate: the handler modules, the shared state,
//! the /api route table, and the machine-readable /api contract (#3325).
//!
//! # Why the service is a library
//!
//! This used to be the other way round. Every handler module was declared
//! from `main.rs`, on the reasoning that a service does not need to be a
//! library and making it one would be a large refactor with no payoff. The
//! refactor arrived anyway, for a reason the earlier note did not foresee:
//! to generate the #3325 contract with `utoipa`/`utoipa-axum` the
//! annotations have to sit on the handlers, and a second binary -- the
//! `openapi` generator -- cannot see a first binary's modules. So the
//! modules moved here, and the move is what turned the contract from a
//! hand-transcribed parallel table into a description of the router that
//! actually serves.
//!
//! The move is deliberately mechanical: no module was renamed, split or
//! reorganized, and the 300-odd `crate::` references the handlers make
//! resolve to exactly the same items they did when the crate root was
//! `main.rs`. What `main.rs` keeps is the part that is genuinely a
//! process: reading the environment, refusing to boot without a service
//! token (#2183), constructing the state, and binding the listener.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use serde::Serialize;
use std::sync::Arc;

pub mod aggregates;
pub mod artifacts;
pub mod attacker_identity;
pub mod audit;
pub mod canarytokens;
pub mod charts;
pub mod config;
pub mod config_history;
pub mod agent_intrusion;
pub mod campaign_correlator;
pub mod correlator;
pub mod correlations;
pub mod credentials;
pub mod criticality_rules;
pub mod dashboard;
pub mod decode_correlate;
pub mod detail;
pub mod es;
pub mod event_detail;
pub mod obs;
pub mod event_page;
pub mod es_importer;
pub mod events;
pub mod exports;
pub mod fusion;
pub mod ghidra_submit;
pub mod github_analysis_submit;
pub mod gpu_queue;
pub mod health;
pub mod isolate;
pub mod honeyfs_implant;
pub mod investigate;
pub mod ip_block;
pub mod ip_enrichment;
pub mod kill_chain;
pub mod live;
pub mod llm_search;
pub mod mail;
pub mod ml_health;
pub mod overview;
pub mod payload_bytes;
pub mod payload_detail;
pub mod payload_inventory;
pub mod payload_kind;
pub mod payload_paths;
pub mod payload_static_analysis;
pub mod preferences;
pub mod problem_reports;
pub mod replay;
pub mod report_pdf;
pub mod reports;
pub mod reports_api;
pub mod reports_data;
pub mod reports_store;
pub mod reporter_stats;
pub mod rollups;
pub mod sandbox_submit;
pub mod sensors;
pub mod search;
pub mod services_control;
pub mod session;
pub mod stores;
pub mod ics_severity;
pub mod ioc_correlation;
pub mod threat_intel;
pub mod topology;
pub mod webhook_delivery;
pub mod zeek_proxy_attribution;
pub mod worker;
pub mod vault_rag;
pub mod workbench_api;
pub mod workbench_domain;
pub mod workbench_es;
pub mod workbench_orchestrator;
pub mod openapi;

#[derive(Clone)]
pub struct AppState {
    pub es: Arc<es::Es>,
    pub service_token: Arc<Option<String>>,
    pub audit: Arc<audit::AuditLogger>,
    pub config_history: Arc<config_history::ConfigHistory>,
    /// #1972: request metrics + where durable JSONL request lines land
    /// (empty = durable shipping disabled; stdout tracing unaffected).
    pub observability: Arc<obs::Obs>,
}

/// /livez — the process is up and its HTTP stack is answering. Says nothing
/// about Elasticsearch, and must never ask it.
///
/// This is the endpoint the container HEALTHCHECK curls on an interval, and
/// the reason it stays dependency-free is the whole point of #3317: a probe
/// that can block on Elasticsearch turns that dependency's outage into a
/// restart loop of a container which was never the thing that broke. The
/// old /healthz answered `{"ok": true, "es": <bool>}` from inside this
/// handler, so an ES outage showed up here as a slow or failed probe
/// instead of as an ES outage.
#[derive(Serialize)]
struct Liveness {
    live: bool,
    /// build.rs's compile stamp, so a probe can answer "is the running
    /// binary newer than the merge" without a second round trip. Same
    /// field main logs at boot.
    built: String,
    /// #3315: which revision of the repository this binary was compiled from,
    /// or "unknown". Unauthenticated and deliberately so — this is the field
    /// that turns "is the running binary newer than the merge?" from a manual
    /// inference into a curl, and /livez is already the one open probe on this
    /// service (the token middleware covers /api/v1 only, see
    /// require_service_token). A git revision names no secret: it is the same
    /// string the image carries in org.opencontainers.image.revision and that
    /// ghcr shows on the tag.
    ///
    /// This is the *answer* where `built` is the *inference*: `built` can only
    /// be compared against a time, and a rebuilt-from-old-commit image passes
    /// that comparison while running month-old code. `revision` is an object
    /// name, so it can be looked up — which is what
    /// scripts/verify-deploy.sh does, and why it reads this field rather than
    /// `built`. Both are here because both have a consumer, and neither is
    /// derivable from the other after the fact.
    revision: String,
}

/// /readyz — Elasticsearch is reachable and this tier's own write targets
/// are not write-blocked, i.e. the backend can actually do its job rather
/// than merely be running. 503 plus a `reason` when it cannot.
///
/// Unlike liveness this endpoint is allowed to fail, so it is the one
/// diagnostics and the #3315 deploy verifier probe: "the process is up" is
/// the wrong question during an ingest outage, and it is the only question
/// the old endpoint could ask.
#[derive(Serialize)]
struct Readiness {
    ready: bool,
    /// Present exactly when `ready` is false, and specific enough to act
    /// on — "Elasticsearch is unreachable" and "these four indices are
    /// write-blocked" send an operator to different pages.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    /// green / yellow / red / unreachable. Reported even when ready, since
    /// yellow is the ordinary shape of a replicated cluster and a probe
    /// that only ever printed green would be no better than the constant
    /// it replaces.
    cluster: String,
    /// The write-blocked members of `es::WRITE_TARGET_FAMILIES`. Always
    /// present so a consumer can read one shape; named rather than counted,
    /// because the point is to be able to act on which ones.
    write_blocked: Vec<String>,
}

/// /readyz's own deadline, independent of the shared client's.
///
/// es::connect gives the transport 30s, sized for real multi-second queries
/// rather than for a probe — and es.rs's own comment on that budget records
/// a /healthz that stopped responding because a worker loop's aggregation
/// saturated the search queue. A readiness answer somebody is waiting on
/// should arrive in seconds, and a probe that blocks for 30 is
/// indistinguishable from the outage it exists to report.
const READINESS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The one place readiness is decided, kept pure so its truth table is
/// testable without an Elasticsearch to ask — the same discipline as
/// `resolve_service_token` below, and for the same reason: the interesting
/// cases are the ones where two independent probes disagree about how bad
/// things are, and a test that needs a live cluster to reach them is a test
/// that does not get run.
///
/// `cluster` and `write_blocked` are two Results rather than one tuple of
/// plain values so a partial failure is a case this function has to answer
/// for, instead of one a caller has to.
fn readiness_verdict(
    cluster: anyhow::Result<String>,
    write_blocked: anyhow::Result<Vec<String>>,
) -> Readiness {
    // Unreachable outranks everything else. A write-block reading against a
    // cluster we could not reach is not a fact, it is the absence of one,
    // and reporting it as the cause would be a guess.
    let cluster = match cluster {
        Ok(status) => status,
        Err(error) => {
            return Readiness {
                ready: false,
                reason: Some(format!("elasticsearch is unreachable: {error}")),
                cluster: "unreachable".to_string(),
                write_blocked: Vec::new(),
            }
        }
    };
    let blocked = match write_blocked {
        Ok(blocked) => blocked,
        Err(error) => {
            return Readiness {
                ready: false,
                reason: Some(format!("elasticsearch refused the readiness probe: {error}")),
                cluster,
                write_blocked: Vec::new(),
            }
        }
    };
    // Red means unassigned primaries, against which both reads and writes
    // fail. Yellow means unassigned *replicas*, which is the ordinary shape
    // of a replicated cluster during a rolling restart and costs this tier
    // nothing — a red-only gate would go not-ready on every deploy.
    if cluster == "red" {
        return Readiness {
            ready: false,
            reason: Some("elasticsearch cluster health is red (unassigned primaries)".to_string()),
            cluster,
            write_blocked: blocked,
        };
    }
    if !blocked.is_empty() {
        return Readiness {
            ready: false,
            reason: Some(format!(
                "elasticsearch has index.blocks.write set on: {}. The flood-stage disk \
                 watermark sets this on every index at once, and so does an operator's \
                 `PUT /<index>/_block/write`; this endpoint cannot tell those apart, so \
                 check _cat/allocation free space before concluding which one it is.",
                blocked.join(", ")
            )),
            cluster,
            write_blocked: blocked,
        };
    }
    Readiness { ready: true, reason: None, cluster, write_blocked: blocked }
}

/// GET /livez, and GET /healthz — the same handler under two names. See
/// `Liveness` for why the response carries no Elasticsearch signal.
async fn livez() -> Json<Liveness> {
    Json(Liveness { live: true, built: build_stamp(), revision: git_revision() })
}

/// `/healthz` is the name the image's HEALTHCHECK, the port-test harness
/// and the ops scripts already use, so it stays as an alias rather than
/// being broken (killing a 2024-era name in a health-probe rename is how a
/// stack ends up reporting permanently unhealthy with nothing wrong). It
/// used to answer `{"ok": true, "es": <bool>}` where `ok` was the constant
/// #3317 is about; the `es` half of that answer now lives on /readyz, which
/// can say no.
async fn healthz() -> Json<Liveness> {
    livez().await
}

/// GET /readyz — see `Readiness`. Unauthenticated exactly like the liveness
/// probes and /metrics, because the callers are infrastructure: the deploy
/// verifier, diagnostics, and an operator on a jump host. Authentication
/// would not make it safer here, only less answerable.
async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<Readiness>) {
    // Both probes in flight together: they are independent round trips and
    // the endpoint's whole value is being quick to answer. The async block
    // is what makes the pair a single future the deadline can wrap --
    // `join!` on its own expands to the values, not to something awaitable.
    let probes = tokio::time::timeout(READINESS_TIMEOUT, async {
        tokio::join!(
            state.es.cluster_health_status(),
            state.es.write_blocked(es::WRITE_TARGET_FAMILIES),
        )
    })
    .await;
    let (cluster, write_blocked) = match probes {
        Ok(probes) => probes,
        Err(_elapsed) => {
            // Both halves report the deadline, because a probe pair that
            // timed out established nothing about either question. The
            // verdict resolves the cluster half as unreachable; this one
            // exists so the pair stays a pair of Results rather than a
            // Result of a pair, and its text is never what gets reported.
            let expired = || anyhow::anyhow!("no answer within {}s", READINESS_TIMEOUT.as_secs());
            (Err(expired()), Err(expired()))
        }
    };
    let readiness = readiness_verdict(cluster, write_blocked);
    let status = if readiness.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    tracing::debug!(ready = readiness.ready, cluster = %readiness.cluster, "readyz");
    (status, Json(readiness))
}

/// A boot refusal carries the code the cutover doc and dashboards grep
/// for, plus the exact remedy — the whole point of #2183 is that a
/// misconfigured instance explains itself instead of silently opening
/// every route. `std::fmt::Display` rather than deriving Debug on an enum:
/// anyhow prints this through `Error: {}` at exit, one line, no nesting.
#[derive(Debug)]
pub struct ServiceTokenRefusal {
    message: String,
}

impl ServiceTokenRefusal {
    fn new() -> Self {
        Self {
            message: concat!(
                "[E-SERVICE-TOKEN] refusing to start: SERVICE_TOKEN is unset or empty, ",
                "which would leave every /api/v1 route open to unauthenticated requests ",
                "(the BFF proxy tier mirrors this check). ",
                "Set SERVICE_TOKEN to a shared secret — see docs/DASHBOARD-CUTOVER.md step 2 — ",
                "or, for local development only, set APIARY_ALLOW_UNAUTH_DEV=1 explicitly (#2183).",
            )
            .to_string(),
        }
    }
}

impl std::fmt::Display for ServiceTokenRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ServiceTokenRefusal {}

/// The single decision behind #2183's boot gate, kept pure so tests can pin
/// its truth table without env-var races between parallel test threads.
///
/// - Ok(Some(token)) — a real token is configured; require_service_token
///   enforces it below.
/// - Ok(None) — SERVICE_TOKEN unset/empty AND APIARY_ALLOW_UNAUTH_DEV=1:
///   an explicitly opted-in unauthenticated dev instance, announced loudly.
/// - Err — otherwise: main refuses before binding, replacing #2044's
///   warn-only posture (a warning sat next to a listen socket that silently
///   accepted everything).
///
/// The override never weakens a configured token: with both set, the token
/// wins and the middleware enforces it as usual.
pub fn resolve_service_token(
    service_token: Option<&str>,
    allow_unauth_dev: bool,
) -> Result<Option<&str>, ServiceTokenRefusal> {
    match service_token.filter(|token| !token.is_empty()) {
        Some(token) => Ok(Some(token)),
        None if allow_unauth_dev => Ok(None),
        None => Err(ServiceTokenRefusal::new()),
    }
}

/// Exactly "1" enables the override — no truthiness zoo where someone's
/// `APIARY_ALLOW_UNAUTH_DEV=0` or `=false` quietly reads as consent.
pub fn allow_unauth_dev_from_env(raw: Option<&str>) -> bool {
    raw == Some("1")
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


/// When this binary was compiled, as RFC 3339, or "unknown".
///
/// Set by build.rs. `option_env!` rather than `env!` on purpose: the first
/// attempt at this used `env!` and broke the image build outright, because
/// the Dockerfile copies Cargo.toml and src but did not copy build.rs, so
/// cargo never ran it. That is fixed, but the failure mode should not be a
/// dead build for a diagnostic field -- and it must not be a lie either, so
/// an absent stamp reads as "unknown" rather than as a plausible time.
pub fn build_stamp() -> String {
    let Some(raw) = option_env!("APIARY_BUILD_EPOCH") else {
        return "unknown".to_string();
    };
    match raw.parse::<i64>() {
        Ok(epoch) => chrono::DateTime::from_timestamp(epoch, 0)
            .map(|when| when.to_rfc3339())
            .unwrap_or_else(|| raw.to_string()),
        Err(_) => raw.to_string(),
    }
}

/// The honest answer when no revision was baked in. Same word build_stamp
/// uses, deliberately: a value that reads as a plausible time or a plausible
/// object name is worse than one that says nothing.
pub const REVISION_UNKNOWN: &str = "unknown";

/// A git object name is 7-64 hex characters, optionally `sha256:`-prefixed
/// (git's own object-format naming) — anything else is not a revision.
///
/// This is a filter, not a format preference. `APIARY_GIT_SHA` arrives from a
/// `docker build --build-arg`, and a value that is not an object name is
/// either a mistake or something injected; either way it must not be echoed
/// back out of /healthz verbatim and read as "this is the deployed commit".
/// Case is normalized because GitHub, `git rev-parse` and the OCI label
/// convention each spell it differently, and a spelling difference must not
/// read as a deployed-revision mismatch.
pub fn normalize_revision(raw: &str) -> String {
    let candidate = raw.strip_prefix("sha256:").unwrap_or(raw);
    if (7..=64).contains(&candidate.len()) && candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
        candidate.to_ascii_lowercase()
    } else {
        REVISION_UNKNOWN.to_string()
    }
}

/// The revision this binary was compiled from, as the image build supplied it.
///
/// `option_env!` for the same reason build_stamp() uses it: a missing stamp is
/// a diagnostic field, not a reason to fail a build. It is set unconditionally
/// by build.rs (an absent GIT_SHA becomes the empty string), so the None arm
/// only fires for a crate built by some path that skipped build.rs entirely —
/// which must read as "unknown", never as a guess.
pub fn git_revision() -> String {
    match option_env!("APIARY_GIT_SHA") {
        Some(raw) => normalize_revision(raw),
        None => REVISION_UNKNOWN.to_string(),
    }
}

// The route table lives here rather than in `main.rs` for the same reason
// the modules do: `utoipa-axum` derives the OpenAPI document from the very
// same `Router` the service serves, so a second binary cannot reach a
// route table that only `main.rs` can see. `main.rs` still owns state
// construction and the listener.

/// The /api/v1 surface: every route behind the BFF's service token.
///
/// `state` is not a parameter because nothing here needs it: the token
/// middleware is layered on by [`router`] below, so the same table serves
/// the process and the contract generator.
pub fn api_router() -> Router<AppState> {
    Router::new()
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
        // #3330: the alert fan-out's own delivery outcomes. Also a field on
        // /api/v1/source-health; this route is what the Settings card
        // reads, so the operations page's one-snapshot design is not the
        // only way to get at it.
        .route("/api/v1/webhook-delivery", get(webhook_delivery::health))
        .route("/api/v1/event/{id}", get(event_page::get))
        // #2047: materialized cross-sensor correlations — the event page's
        // same-flow summary and the re-used-wordlist edges.
        .route("/api/v1/event/{id}/connections", get(correlations::event_connections))
        .route("/api/v1/connections/{community_id}", get(correlations::flow_by_id))
        .route("/api/v1/cred-reuse", get(correlations::cred_reuse))
        .route("/api/v1/sensors", get(sensors::detail))
        // #1856: /catalog is registered before /{sensor} so the literal
        // segment is not swallowed by the capture. A sensor genuinely
        // named "catalog" would be shadowed; none is, and the alternative
        // is a query parameter that reads worse for the common case.
        .route("/api/v1/sensors/catalog", get(sensors::catalog))
        .route("/api/v1/sensors/{sensor}/events", get(sensors::events))
        .route("/api/v1/sensors/{sensor}/overview", get(sensors::overview))
        .route("/api/v1/sessions/{id}", get(session::detail))
        .route("/api/v1/search", get(search::search))
        .route("/api/v1/topology", get(topology::topology))
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
        .route("/api/v1/vault-rag", get(vault_rag::ask))
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
        .route("/api/v1/ml-anomalies/stats", get(detail::ml_anomaly_stats))
        .route("/api/v1/ml-anomalies/disposition", post(detail::ml_anomaly_disposition))
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
        // #2045: the raw evidence behind an attacker entity.
        .route("/api/v1/attackers/{id}/events", get(attacker_identity::entity_events))
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
}

/// The unauthenticated routes: the two liveness names, readiness, and the
/// #1972 metrics scrape. They are a separate builder from [`api_router`]
/// because they are the only routes the token middleware does not cover.
pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/livez", get(livez))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        // #1972: same listener, same internal-network posture as /healthz.
        .route("/metrics", get(obs::metrics_route))
}

/// The whole service surface: the public routes, the token-gated /api
/// table, and the observability wrapper. This is what `main.rs` serves,
/// and its shape is unchanged from the one binary had before the move.
pub fn router(state: AppState) -> Router {
    let api = api_router()
        .layer(middleware::from_fn_with_state(state.clone(), require_service_token));

    let app = Router::new()
        // The public routes are declared first, exactly as `main.rs`
        // declared them before the move; the token-gated /api table is
        // merged in behind them.
        .merge(public_router())
        .merge(api)
        // #1972 observability wraps EVERYTHING above it — health probe,
        // metrics scrape, and every /api/v1 route get a request id echoed
        // in x-request-id, metrics recorded per family/status/latency, and
        // one durable JSONL line when DASHBOARD_LOG_FILE is set. observe()
        // reads its Obs handle via State<AppState>, so this must be the
        // _with_state form (plain from_fn builds FromFn<(), ..> whose
        // Service bound never matches a state-taking extractor).
        .layer(middleware::from_fn_with_state(state.clone(), obs::observe))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);
    app
}

#[cfg(test)]
mod build_stamp_tests {
    use super::{build_stamp, git_revision, normalize_revision, REVISION_UNKNOWN};

    #[test]
    fn build_stamp_is_a_real_recent_timestamp() {
        // The stamp exists to answer "is the running binary newer than the
        // merge", so a value that does not parse, or that sits in 1970,
        // would be worse than none: it reads as an answer.
        let stamp = build_stamp();
        // "unknown" is an acceptable answer -- it is the honest one when the
        // build script did not run. Anything else has to be a real time.
        if stamp == "unknown" {
            return;
        }
        let parsed = chrono::DateTime::parse_from_rfc3339(&stamp)
            .unwrap_or_else(|error| panic!("build stamp {stamp:?} is not RFC 3339: {error}"));

        let now = chrono::Utc::now();
        let age = now.signed_duration_since(parsed.with_timezone(&chrono::Utc));
        assert!(
            age.num_days() < 3650 && age.num_seconds() > -3600,
            "build stamp {stamp} is not a plausible build time (age {age})",
        );
    }

    // ---- #3315: the revision /healthz reports (lib.rs's `revision` field) ----

    #[test]
    fn a_full_object_name_survives_verbatim() {
        assert_eq!(normalize_revision("3dca4457f1b2c0d4e5a69788796a5b4c3d2e1f0ab"),
                   "3dca4457f1b2c0d4e5a69788796a5b4c3d2e1f0ab");
    }

    /// The table is a file rather than a literal list so that the other
    /// implementation of this rule -- dashboard-next's normalizeRevision, in
    /// JavaScript, in a different CI lane -- can be driven from exactly the
    /// same cases. `scripts/tests/test_3315_image_revision.py` runs both.
    /// Written inline, the two lists would drift the first time either gained
    /// a case, and the failure would be a deploy disagreement that is not one:
    /// two tiers stamping different strings for the same build, which
    /// scripts/verify-deploy.sh would report as a mismatch.
    #[test]
    fn the_shared_corpus_normalizes_as_the_other_tier_does() {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("revision-corpus.json")).expect("corpus is valid JSON");
        let unknown = corpus["unknown"].as_str().expect("corpus names its unknown value");
        let cases = corpus["cases"].as_array().expect("corpus carries a cases array");
        assert!(!cases.is_empty(), "the corpus is empty, so this test proves nothing");
        for case in cases {
            let pair = case.as_array().expect("each case is a [input, expected] pair");
            let (raw, expected) = (
                pair[0].as_str().expect("case input is a string"),
                pair[1].as_str().expect("case expectation is a string"),
            );
            assert_eq!(
                &normalize_revision(raw),
                expected,
                "normalize_revision({raw:?}) disagrees with the shared corpus"
            );
        }
        // The one value the whole design turns on: a build with no revision
        // says so rather than reporting something that reads as an answer.
        assert_eq!(normalize_revision(""), unknown);
    }

    #[test]
    fn this_test_binary_reports_a_revision_or_says_unknown() {
        // A `cargo test` run has GIT_SHA unset unless the caller exported it,
        // so the honest value here is "unknown" -- and both are acceptable.
        // What must never happen is a third thing: a revision that does not
        // look like an object name coming out of the real accessor.
        let revision = git_revision();
        assert!(!revision.is_empty(), "the revision field must never be empty");
        if revision != REVISION_UNKNOWN {
            assert_eq!(
                revision,
                normalize_revision(&revision),
                "git_revision() returned {revision:?}, which its own normalizer would not accept"
            );
        }
    }
}

#[cfg(test)]
mod service_token_tests {
    use super::{allow_unauth_dev_from_env, resolve_service_token};

    #[test]
    fn unset_token_without_override_refuses() {
        // #2183's whole point: the default posture for a copied/partial
        // compose or a bare `cargo run` used to be "open, quietly". It must
        // be a refusal carrying the code and the remedy instead.
        let err = resolve_service_token(None, false).expect_err("unset token must refuse");
        assert!(err.to_string().contains("E-SERVICE-TOKEN"), "{err}");
        assert!(err.to_string().contains("SERVICE_TOKEN"), "{err}");
        assert!(
            err.to_string().contains("APIARY_ALLOW_UNAUTH_DEV=1"),
            "{err}"
        );
    }

    #[test]
    fn empty_token_counts_as_unset() {
        // compose ships `${DASHBOARD_SERVICE_TOKEN:-}`; a copied/partial
        // env produces exactly this empty string, not an absent variable.
        // The filter lives inside the decision, so that state can't slip
        // past it if main()'s own pre-filter ever moves.
        let err = resolve_service_token(Some(""), false).expect_err("empty token must refuse");
        assert!(err.to_string().contains("E-SERVICE-TOKEN"), "{err}");
    }

    #[test]
    fn override_with_unset_token_is_sanctioned_dev() {
        let resolved = resolve_service_token(None, true).expect("override must boot");
        assert_eq!(resolved, None);
    }

    #[test]
    fn override_accepts_the_bare_literal_one_only() {
        // "1", not a truthiness zoo: a future `APIARY_ALLOW_UNAUTH_DEV=0`
        // must read as refusal, and `=true` as a typo to fix, not consent.
        assert!(!allow_unauth_dev_from_env(Some("")));
        assert!(!allow_unauth_dev_from_env(Some("0")));
        assert!(!allow_unauth_dev_from_env(Some("true")));
        assert!(!allow_unauth_dev_from_env(Some("yes")));
        assert!(allow_unauth_dev_from_env(Some("1")));
    }

    #[test]
    fn present_token_boots_without_override() {
        let resolved = resolve_service_token(Some("s3cret"), false).expect("token must boot");
        assert_eq!(resolved, Some("s3cret"));
    }

    #[test]
    fn override_never_weakens_a_present_token() {
        // Both set: the middleware enforces the real token. The override
        // exists only to sanction the token's absence, never to disable
        // enforcement alongside it.
        let resolved = resolve_service_token(Some("s3cret"), true).expect("must boot");
        assert_eq!(resolved, Some("s3cret"));
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::readiness_verdict;

    fn blocked(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    #[test]
    fn a_reachable_unblocked_cluster_is_ready() {
        let readiness = readiness_verdict(Ok("green".into()), Ok(vec![]));
        assert!(readiness.ready);
        assert_eq!(readiness.reason, None, "a ready verdict carries no reason");
        // Still reported when ready: yellow is the ordinary shape of a
        // replicated cluster, and a probe that only ever printed green
        // would be no better than the constant #3317 replaced.
        assert_eq!(readiness.cluster, "green");
        assert!(readiness.write_blocked.is_empty());
    }

    #[test]
    fn yellow_stays_ready() {
        // Yellow is unassigned *replicas*, which costs this tier nothing.
        // Gating on it would take the backend not-ready on every rolling
        // restart and every replica relocation.
        assert!(readiness_verdict(Ok("yellow".into()), Ok(vec![])).ready);
    }

    #[test]
    fn an_unreachable_cluster_is_not_ready_and_says_why() {
        // The bug in #3317's report, in the shape it took there: a backend
        // that cannot reach Elasticsearch still answering healthy.
        let readiness = readiness_verdict(Err(anyhow::anyhow!("connection refused")), Ok(vec![]));
        assert!(!readiness.ready);
        assert_eq!(readiness.cluster, "unreachable");
        let reason = readiness.reason.expect("not-ready must carry a reason");
        assert!(reason.contains("unreachable"), "{reason}");
        assert!(reason.contains("connection refused"), "{reason}");
    }

    #[test]
    fn unreachable_outranks_a_write_block_report() {
        // A block reading taken against a cluster we could not reach is not
        // a fact about that cluster. Reporting it as the cause would be a
        // guess, and it would be the wrong one to send an operator after.
        let readiness = readiness_verdict(
            Err(anyhow::anyhow!("no route to host")),
            Ok(blocked(&["dashboard-config-v1"])),
        );
        assert!(!readiness.ready);
        assert!(
            readiness.write_blocked.is_empty(),
            "an unreachable cluster has no block state to report, got {:?}",
            readiness.write_blocked
        );
        assert!(readiness.reason.unwrap().contains("unreachable"));
    }

    #[test]
    fn a_write_block_is_not_ready_and_names_the_indices() {
        // The disk-flood-stage / operator-block case: ES answers health
        // fine and the block is the only evidence there is. Names rather
        // than counts, because the point is to be actionable.
        let readiness = readiness_verdict(
            Ok("green".into()),
            Ok(blocked(&["dashboard-config-v1", "dashboard-users-v1"])),
        );
        assert!(!readiness.ready, "a green cluster is not the same as a writable one");
        assert_eq!(readiness.cluster, "green");
        assert_eq!(readiness.write_blocked, blocked(&["dashboard-config-v1", "dashboard-users-v1"]));
        let reason = readiness.reason.expect("not-ready must carry a reason");
        assert!(reason.contains("dashboard-config-v1"), "{reason}");
        assert!(reason.contains("dashboard-users-v1"), "{reason}");
        assert!(
            reason.contains("_cat/allocation"),
            "the reason has to point at the two causes it cannot tell apart: {reason}"
        );
    }

    #[test]
    fn red_is_not_ready_even_with_nothing_blocked() {
        let readiness = readiness_verdict(Ok("red".into()), Ok(vec![]));
        assert!(!readiness.ready);
        assert!(readiness.reason.unwrap().contains("red"));
    }

    #[test]
    fn a_probe_refused_itself_is_not_ready() {
        // Reachable enough to answer health, but the settings call itself
        // failed. "Ready" would be an answer this endpoint has no basis
        // for -- it asked whether writes are permitted and was not told.
        let readiness =
            readiness_verdict(Ok("green".into()), Err(anyhow::anyhow!("403 forbidden")));
        assert!(!readiness.ready);
        assert!(readiness.reason.unwrap().contains("refused the readiness probe"));
    }

    #[test]
    fn an_unknown_color_is_not_treated_as_red_or_green() {
        // Neither branch claims it. The verdict is ready because no
        // condition was met -- but `cluster` carries the honest "unknown"
        // for the reader, rather than the endpoint inventing a color it
        // was not told.
        let readiness = readiness_verdict(Ok("unknown".into()), Ok(vec![]));
        assert!(readiness.ready);
        assert_eq!(readiness.cluster, "unknown");
    }
}
