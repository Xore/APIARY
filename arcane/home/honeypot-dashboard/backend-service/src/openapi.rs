//! The machine-readable contract for this service's HTTP surface (#3325).
//!
//! # Why this is hand-maintained rather than derived
//!
//! #3325 offered two ways to get an OpenAPI document: derive it from the
//! Axum handlers with `utoipa`, or hand-maintain one. This is the second
//! one, deliberately. The handlers almost all return `Json<Value>` or a
//! typed struct with a field per surface concern, and the one thing the
//! issue wants the document to pin -- the auth tier and the request shape
//! -- lives in the *route table* and the *extractor signatures*, not in
//! the response bodies. Deriving would mean adding `#[utoipa::path]` to
//! 138 handlers to learn that `GET /api/v1/events` takes a `Query<EventsQuery>`
//! and answers 401 without a service token; a table plus the two drift
//! tests below states the same thing in one readable place.
//!
//! # Why it cannot drift
//!
//! Two tests in `tests` below, both of which run inside `cargo test` (so in
//! both of quality.yml's backend-service twins):
//!
//! 1. `checked_in_contract_is_current` -- the committed `openapi.json` must
//!    equal what this module renders. Regenerate with
//!    `cargo run --bin openapi > openapi.json` after any edit here.
//! 2. `contract_covers_every_router_route` -- the (path, method) set this
//!    module publishes must equal the (path, method) set `main.rs`
//!    registers. A route added to the router without a row here fails the
//!    build, which is the direction that actually rots.
//!
//! # What the document deliberately does NOT claim
//!
//! **Every** success body is free-form (an empty schema, which accepts any
//! JSON value) -- including `/healthz`'s two-field struct. Hand-transcribing
//! 138 response shapes would be 138 chances to assert something the code
//! does not enforce, and a contract that lies about a response is worse
//! than one that admits it is open. The empty schema is the truthful
//! statement: it is also what keeps `response_schema_conformance` from
//! failing the fuzz job on correct behaviour, which is why this document
//! reports service findings like "API accepted schema-violating request"
//! and treats them as a standing record rather than as a verdict.
//!
//! What the document *does* pin is the part that has been wrong before:
//! the auth tier per operation, the request parameters (including the
//! enum-shaped ones the handlers actually validate), the declared status
//! codes, and the media type of every response. That is what
//! `.github/workflows/weekly-schemathesis.yml` checks, and the auth tier
//! is the property #3325 was filed for.
//!
//! # Statuses that no row has to remember
//!
//! Three come from axum's extractors, before any handler runs, and the
//! builders add them so a row cannot forget: `body()` adds 415 and 422 for
//! `Json<T>`, and `with_query()` adds 400 for `Query<T>`. Running the fuzz
//! job against a booted service is what found all three -- they are
//! unreachable from the router's source, since nothing in `main.rs`
//! mentions them, and every one of them was reported "undocumented" on
//! routes whose rows looked complete.
//!
//! One status carries two media types on the routes where the extractor's
//! answer and the handler's own answer share a code: the Workbench's 400
//! is `text/plain` when `Query<T>` refuses the query string and
//! `application/json` when the handler rejects the value. `render_operation`
//! merges content types for a repeated status rather than overwriting.

use serde_json::{json, Map, Value};

/// Which gate an operation sits behind. The names say what the *caller*
/// must present, because that is the only part of the auth model an
/// operator has to get right (the BFF is the only legitimate caller --
/// see the crate doc in main.rs).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// No service token: `/healthz` for the container healthcheck and
    /// `/metrics` for the #1972 scrape. Both stay open on purpose and are
    /// the only two routes in the binary that do.
    Public,
    /// `require_service_token` (main.rs). 401 is `text/plain`: the
    /// middleware returns a bare `(StatusCode, String)`.
    ServiceToken,
    /// `require_service_token` *plus* the Workbench's own
    /// `require_actor` (workbench_api.rs), which wants a forwarded
    /// `X-Actor-Username` and answers a `Json<Value>` 401. Both media
    /// types are declared on the one 401, because both are reachable:
    /// no token gets the middleware's, a token without an actor gets the
    /// Workbench's.
    ServiceTokenAndActor,
}

/// A query or header parameter. `in` is filled in by the renderer from
/// where the entry sits in the table, so a row cannot put a query
/// parameter in the header block.
pub struct Param {
    pub name: &'static str,
    pub description: &'static str,
    pub schema: Value,
    pub required: bool,
}

/// A path parameter. Kept apart from [`Param`] because `in: path` is
/// mandatory and always required -- a mistake there is a spec error, and
/// mixing the two makes it easy to write.
pub struct PathParam {
    pub name: &'static str,
    pub description: &'static str,
    pub schema: Value,
}

pub struct Response {
    pub status: u16,
    pub description: &'static str,
    /// One entry per media type under `content`; empty for a bodiless
    /// status. A list rather than a single media type because the
    /// Workbench's one 401 is reachable as both `text/plain` and
    /// `application/json` (see [`Tier::ServiceTokenAndActor`]).
    pub schemas: Vec<(&'static str, Value)>,
}

pub struct Op {
    pub method: &'static str,
    pub path: &'static str,
    pub summary: &'static str,
    pub tier: Tier,
    pub query: Vec<Param>,
    pub headers: Vec<Param>,
    pub path_params: Vec<PathParam>,
    pub body: Option<Body>,
    pub responses: Vec<Response>,
    /// Not free-form: for SSE (`/api/v1/live`) the success body is an
    /// endless stream, so the media type is the whole contract.
    pub success_media: Option<&'static str>,
}

/// A JSON request body. The shape is left open -- see the module doc --
/// but the description names the handler struct, so a reader can jump
/// straight to the fields the service actually deserializes.
pub struct Body {
    pub handler_struct: &'static str,
    pub required: bool,
}

// ---------------------------------------------------------------------
// Small constructors. Every response body the service produces is JSON
// unless the table says otherwise, so `json` is the default and the
// error helpers are the ones that carry a media type.
// ---------------------------------------------------------------------

fn free_form() -> Value {
    // `type` is deliberately omitted rather than "object": most handlers
    // answer an object, but several (sources, ml-health, gpu-queue, the
    // chart family) answer a bare array, and a wrong `type` here would
    // make schemathesis's response_schema_conformance fail on correct
    // behaviour. An empty schema accepts any JSON value, which is the
    // truthful statement.
    json!({})
}

fn str_schema() -> Value {
    json!({"type": "string"})
}

fn u64_schema() -> Value {
    json!({"type": "integer", "format": "int64", "minimum": 0})
}

fn query(name: &'static str, description: &'static str, schema: Value) -> Param {
    Param { name, description, schema, required: false }
}

fn opt_query(
    name: &'static str,
    description: &'static str,
    schema: Value,
) -> Param {
    query(name, description, schema)
}

fn path_param(name: &'static str, description: &'static str, schema: Value) -> PathParam {
    PathParam { name, description, schema }
}

fn op(method: &'static str, path: &'static str, summary: &'static str) -> Op {
    Op {
        method,
        path,
        summary,
        tier: Tier::ServiceToken,
        query: Vec::new(),
        headers: Vec::new(),
        path_params: Vec::new(),
        body: None,
        responses: Vec::new(),
        success_media: None,
    }
}

impl Op {
    fn public(mut self) -> Self {
        self.tier = Tier::Public;
        self
    }

    /// Marks the route as also requiring the BFF's forwarded actor
    /// identity, with a required `X-Actor-Username` header so the fuzzer
    /// exercises the route the way the BFF actually calls it.
    fn actor(mut self) -> Self {
        self.tier = Tier::ServiceTokenAndActor;
        self.headers.push(Param {
            name: "X-Actor-Username",
            description: "Operator identity the BFF forwards; workbench_api.rs's \
                          require_actor rejects a missing or blank value with a \
                          JSON 401.",
            schema: str_schema(),
            required: true,
        });
        self
    }

    /// A 200 whose body is `application/json` of unconstrained shape.
    fn ok(mut self) -> Self {
        self.responses.push(Response {
            status: 200,
            description: "Success.",
            schemas: vec![("application/json", free_form())],
        });
        self
    }

    /// A 200 with a specific media type -- CSV, PDF, octet-stream, an
    /// SSE stream, Prometheus text.
    fn ok_media(mut self, media: &'static str, description: &'static str) -> Self {
        self.success_media = Some(media);
        self.responses.push(Response {
            status: 200,
            description,
            schemas: vec![(media, free_form())],
        });
        self
    }

    /// A bodiless success (`204 No Content`, and the `200` some submit
    /// routes answer with an empty object).
    fn ok_status(mut self, status: u16, description: &'static str) -> Self {
        self.responses.push(Response {
            status,
            description,
            schemas: Vec::new(),
        });
        self
    }

    /// A `text/plain` error status -- the shape of every
    /// `Err((StatusCode, String))` in the crate, which is most of them.
    fn err(mut self, status: u16) -> Self {
        self.responses.push(Response {
            status,
            description: error_description(status),
            schemas: vec![("text/plain", str_schema())],
        });
        self
    }

    /// A `application/json` error status -- the Workbench's
    /// `Err((StatusCode, Json<Value>))` family.
    fn err_json(mut self, status: u16) -> Self {
        self.responses.push(Response {
            status,
            description: error_description(status),
            schemas: vec![("application/json", free_form())],
        });
        self
    }

    /// Declares this operation's query parameters, and the 400 that
    /// axum's `Query<T>` extractor raises when the query string will not
    /// deserialize -- a required field missing, or a value of the wrong
    /// type (`?limit=false` on a `limit: usize`). It is `text/plain` and
    /// it happens before the handler runs.
    ///
    /// Added here rather than per row because forgetting it is invisible:
    /// an operation that lists query parameters and declares no 400 looks
    /// complete, and only a fuzzer sending `?limit=false` finds out. On
    /// a row that already declares a `text/plain` 400 this is a no-op
    /// (the render merges same-key content), and on one whose handler
    /// answers 400 in JSON the status ends up carrying both media types,
    /// which is the truth.
    fn with_query(mut self, params: Vec<Param>) -> Self {
        self.query = params;
        self = self.err(400);
        self
    }

    fn with_path(mut self, params: Vec<PathParam>) -> Self {
        self.path_params = params;
        self
    }

    /// A JSON request body the handler deserializes into `handler_struct`
    /// (axum's `Json<T>` extractor). `required` is false for the
    /// `Option<Json<T>>` handlers, which accept a missing body.
    fn body(mut self, handler_struct: &'static str, required: bool) -> Self {
        self.body = Some(Body { handler_struct, required });
        // Two rejections happen in the extractor, before the handler is
        // entered, so no row can be forgotten and no handler's own error
        // list has to remember them: axum's `Json<T>` answers 415 for a
        // wrong `Content-Type` and 422 for a body that does not
        // deserialize into `handler_struct`. Both are `text/plain`.
        // Found by running the weekly fuzz job against a booted
        // service, which called them undocumented on all 25 body routes
        // -- #3325's job earning its keep on the contract it ships with.
        // `err` takes self by value, so hand it back and keep going.
        self = self.err(415).err(422);
        self
    }

    /// An optional `If-Match` carrying the revision the caller believes it
    /// is editing (config.rs's `expected_revision`, a weak ETag whose
    /// numeric body is the revision). Optional because a missing header
    /// means "no expectation", not "reject".
    fn if_match(mut self) -> Self {
        self.headers.push(Param {
            name: "If-Match",
            description: "Optional optimistic-concurrency revision, as a weak ETag \
                          (`W/\"7\"`). A mismatch answers 409.",
            schema: str_schema(),
            required: false,
        });
        self
    }
}

fn error_description(status: u16) -> &'static str {
    match status {
        400 => "Rejected: the request was understood but its input is not acceptable.",
        401 => "No valid service token (or, on the Workbench, no actor identity).",
        404 => "No such record, store, or route for the values given.",
        405 => "The store exists but exposes no delete side (only dead-letters does).",
        409 => "The record changed since the revision the caller presented.",
        413 => "The stored artifact is larger than this endpoint will serve.",
        415 => "The `Content-Type` is not `application/json`; the extractor refused the body before the handler ran.",
        422 => "Well-formed but unprocessable. Two causes, both text/plain: the Json<T> \
                extractor refused the body before the handler ran, or the route's own domain \
                check rejected the reference it was asked to resolve (the reports store \
                answers this for an unresolvable scope or an unexpected storage failure).",
        500 => "The handler failed in a way it does not model as a 4xx.",
        501 => "The saved definition's template is not implemented by the renderer yet.",
        502 => "Elasticsearch (or a sibling it proxies) refused or failed the query.",
        503 => "A dependency this route needs is not configured or not reachable.",
        _ => "Error.",
    }
}

// ---------------------------------------------------------------------
// Shared query shapes, transcribed from the handler structs they mirror.
// Each `fn` names the Rust type it tracks so a reader can check it
// against that struct in one jump; a drift test does not cover these
// field-by-field (nothing in the crate can), which is why each carries
// the type name.
// ---------------------------------------------------------------------

/// `events::EventsQuery` -- the filter set /events and four of the CSV
/// exports share.
fn events_query() -> Vec<Param> {
    let filters: [(&'static str, &'static str); 24] = [
        ("ip", "Single source address."),
        ("ips", "Comma-separated source addresses."),
        ("sensor", "Sensor name (honeypot.dionaea, suricata, ...)."),
        ("country", "ISO country code."),
        ("city", "City name, as bucketed on the overview map."),
        ("port", "Destination port."),
        ("proto", "Transport protocol."),
        ("kind", "honeypot.event kind (command, login, ...)."),
        ("shasum", "Captured-payload hash."),
        ("community_id", "One flow across every sensor that saw it."),
        ("q", "Free-text query_string, passed to Elasticsearch as-is."),
        ("since", "Go-style relative window (24h, 7d)."),
        ("persona", "Decoy persona id."),
        ("site", "Decoy site id."),
        ("asset", "Decoy asset id."),
        ("fingerprint", "Client fingerprint, matched across every field sensors record one in."),
        ("cmd", "Exact command text."),
        ("cred", "\"user / pass\" pair."),
        ("path", "Request path."),
        ("session", "Session id."),
        ("asn", "Source AS number."),
        ("org", "Source network organization."),
        ("provider", "Provider class."),
        ("sig", "IDS alert signature."),
    ];
    let mut params = vec![
        query("offset", "Result window start.", u64_schema()),
        opt_query("size", "Page size, clamped to 100 by the handler.", json!({"type": "integer", "format": "int64", "minimum": 1, "maximum": 100})),
    ];
    params.extend(filters.iter().map(|(name, description)| opt_query(name, description, str_schema())));
    params.push(opt_query("cat", "Detection category (Suricata alert category or honeypot.category).", str_schema()));
    params
}

/// `stores::StoreQuery` -- the generic store family's paging, shared by
/// the fixed store endpoints and `/api/v1/store/{name}`.
fn store_query() -> Vec<Param> {
    vec![
        query("offset", "Result window start.", u64_schema()),
        opt_query("size", "Page size.", json!({"type": "integer", "format": "int64", "minimum": 1})),
        opt_query("q", "Free-text Lucene query string.", str_schema()),
        opt_query("ip", "Narrow to one source address.", str_schema()),
        opt_query("aggs", "`sources` adds the payload-inventory source buckets; anything else is ignored.", str_schema()),
    ]
}

/// `aggregates::PageQuery`.
fn page_query() -> Vec<Param> {
    vec![
        query("offset", "Result window start.", u64_schema()),
        opt_query("size", "Page size.", json!({"type": "integer", "format": "int64", "minimum": 1})),
    ]
}

/// `config::ActorQuery` -- the audit attribution the write paths take.
fn actor_query() -> Vec<Param> {
    vec![
        opt_query("actor_subject", "OIDC subject recorded on the audit/history entry.", str_schema()),
        opt_query("actor_username", "Operator name recorded on the audit/history entry.", str_schema()),
    ]
}

fn q(name: &'static str, description: &'static str) -> Param {
    opt_query(name, description, str_schema())
}

fn enum_schema(values: &[&str]) -> Value {
    json!({"type": "string", "enum": values})
}

// ---------------------------------------------------------------------
// The surface itself. Grouped and ordered the way main.rs registers it,
// so the two read side by side.
// ---------------------------------------------------------------------

fn operations() -> Vec<Op> {
    vec![
        // The /api surface, in main.rs's registration order. Every row is
        // a route the router really registers -- `contract_covers_every_router_route`
        // below fails the build if these two lists stop being the same list.
        op("GET", "/api/v1/overview/kpis", "KPI counters behind the overview tiles.")
            .ok()
            .err(502),
        op("GET", "/api/v1/overview/dashboard", "The one aggregation the overview page renders, sliced by ?parts=.")
            .ok()
            .err(502)
            .with_query(vec![q("parts", "Comma-separated subset of slice names; absent or empty means every slice.")]),
        op("GET", "/api/v1/events", "Event explorer page: the shared filter set, windowed.")
            .ok()
            .err(502)
            .with_query(events_query()),
        op("GET", "/api/v1/export/events.csv", "The event explorer as CSV, same filters as /events.")
            .ok_media("text/csv", "CSV of the matching events.")
            .err(502)
            .with_query(events_query()),
        op("GET", "/api/v1/export/commands.csv", "Matching commands as CSV.")
            .ok_media("text/csv", "CSV of matching commands.")
            .err(502)
            .with_query(events_query()),
        op("GET", "/api/v1/export/ips.csv", "Every source address in the window as CSV.")
            .ok_media("text/csv", "CSV of source addresses.")
            .err(502)
            .with_query(page_query()),
        op("GET", "/api/v1/export/campaigns.csv", "Campaigns as CSV.")
            .ok_media("text/csv", "CSV of campaigns.")
            .err(502)
            .with_query(page_query()),
        op("GET", "/api/v1/export/clusters.csv", "Attacker clusters as CSV, by cluster kind.")
            .ok_media("text/csv", "CSV of attacker clusters.")
            .err(502)
            .with_query(vec![opt_query("kind", "Cluster kind to export.", enum_schema(&["fingerprint", "payload", "asn", "provider"]))]),
        op("GET", "/api/v1/export/history.json", "The behaviour-search slice as JSON.")
            .ok_media("application/json", "Behaviour-search rows as JSON.")
            .err(502)
            .with_query(events_query()),
        op("GET", "/api/v1/live", "Server-sent event source: the explorer tailing contract.")
            .ok_media("text/event-stream", "An endless text/event-stream of event documents. Never terminates, which is why the fuzz job excludes this path."),
        op("GET", "/api/v1/mail/{session_id}", "Mail the SMTP honeypot captured for one session.")
            .with_path(vec![path_param("session_id", "Session whose captured mail is wanted.", str_schema())])
            .ok()
            .err(400)
            .err(404)
            .err(502),
        op("GET", "/api/v1/ml-health", "Per-model ml-worker health.")
            .ok()
            .err(502),
        op("GET", "/api/v1/gpu-queue", "The GPU analysis queue as it stands.")
            .ok()
            .err(502),
        op("POST", "/api/v1/gpu-queue/{job_id}/abort", "Abort a queued or running GPU job.")
            .with_path(vec![path_param("job_id", "GPU job to abort.", str_schema())])
            .ok()
            .err(502),
        op("GET", "/api/v1/sources", "Known source addresses with their event counts.")
            .ok()
            .err(502)
            .with_query(page_query()),
        op("GET", "/api/v1/filter-values", "Distinct values behind every explorer filter dropdown.")
            .ok()
            .err(502),
        op("GET", "/api/v1/investigate/ip/{ip}", "Everything one source address did, across sensors.")
            .with_path(vec![path_param("ip", "Source address to profile. A non-address is a 400.", json!({"type": "string"}))])
            .ok()
            .err(400)
            .err(404)
            .err(502),
        op("GET", "/api/v1/investigate/cidr/{cidr}", "Correlation across one CIDR block.")
            .with_path(vec![path_param("cidr", "CIDR block to correlate. A malformed block is a 400.", str_schema())])
            .ok()
            .err(400)
            .err(502),
        op("GET", "/api/v1/investigate/cluster", "The members of one attacker cluster.")
            .ok()
            .err(400)
            .err(404)
            .err(502)
            .with_query(vec![opt_query("kind", "Cluster kind.", enum_schema(&["fingerprint", "payload", "asn", "provider"])), q("value", "The cluster's value, as /api/v1/clusters reports it.")]),
        op("GET", "/api/v1/source-health", "Per-source ingestion health, the page behind \"Source & pipeline health\".")
            .ok()
            .err(502),
        // The one ES-backed read in the API that does *not* 502. Every
        // other row with a `.err(502)` gets there because the extractor
        // turns a dead cluster into a status code; this handler catches
        // the error and answers 200 with `available: false` and the
        // reason in the body, because a delivery card that states why it
        // has nothing is worth more than an operations page that fails to
        // render. Declaring 502 here would be the exact kind of guess the
        // rest of this file refuses to make.
        op("GET", "/api/v1/webhook-delivery", "Delivery outcomes for the configured alert webhook.")
            .ok(),
        op("GET", "/api/v1/event/{id}", "One event, with the pivot groups its detail pane needs.")
            .with_path(vec![path_param("id", "Event document id.", str_schema())])
            .ok()
            .err(400)
            .err(404)
            .err(502),
        op("GET", "/api/v1/event/{id}/connections", "The same-flow summary and re-used-wordlist edges for one event.")
            .with_path(vec![path_param("id", "Event document id.", str_schema())])
            .ok()
            .err(400)
            .err(404)
            .err(502),
        op("GET", "/api/v1/connections/{community_id}", "Every record that shares one community_id flow hash.")
            .with_path(vec![path_param("community_id", "network.community_id flow hash, as computed independently by each sensor.", str_schema())])
            .ok()
            .err(404)
            .err(502),
        op("GET", "/api/v1/cred-reuse", "Credential pairs reused across more than one address.")
            .ok()
            .err(502),
        op("GET", "/api/v1/sensors", "Per-sensor counts, last-seen, and state.")
            .ok()
            .err(502),
        op("GET", "/api/v1/sensors/catalog", "The sensor catalog the setup pages read.")
            .ok()
            .err(502),
        op("GET", "/api/v1/sensors/{sensor}/events", "Recent events from one sensor.")
            .with_path(vec![path_param("sensor", "Sensor name; the handler rejects an empty value or one over 128 characters.", json!({"type": "string", "maxLength": 128}))])
            .ok()
            .err(400)
            .err(502)
            .with_query(vec![q("limit", "How many events to return; clamped by the handler.")]),
        op("GET", "/api/v1/sensors/{sensor}/overview", "Protocols, ports and fingerprints for one sensor.")
            .with_path(vec![path_param("sensor", "Sensor name; the handler rejects an empty value or one over 128 characters.", json!({"type": "string", "maxLength": 128}))])
            .ok()
            .err(400)
            .err(502),
        op("GET", "/api/v1/sessions/{id}", "One session: its events, commands and credentials.")
            .with_path(vec![path_param("id", "Session id.", str_schema())])
            .ok()
            .err(400)
            .err(404)
            .err(502),
        op("GET", "/api/v1/search", "Cross-surface search for the omnibox.")
            .ok()
            .err(502)
            .with_query(vec![q("q", "What to search for.")]),
        op("GET", "/api/v1/topology", "Decoy topology graph.")
            .ok(),
        op("GET", "/api/v1/settings/storage", "Index sizes and document counts.")
            .ok()
            .err(502),
        op("GET", "/api/v1/config", "The whole operator-authored dashboard configuration.")
            .ok()
            .err(502),
        op("PUT", "/api/v1/config/presentation", "Replace the presentation block (branding, theme, landing copy).")
            .ok_status(200, "The stored presentation block and its new revision.")
            .err(400)
            .err(404)
            .err(409)
            .err(502)
            .body("serde_json::Value", true)
            .if_match()
            .with_query(actor_query()),
        op("PUT", "/api/v1/config/{section}", "Replace one settings section.")
            .with_path(vec![path_param("section", "Settings section to replace.", enum_schema(&["honeypot", "behavior", "report-presets"]))])
            .ok_status(200, "The stored section and its new revision.")
            .err(400)
            .err(404)
            .err(409)
            .err(502)
            .body("serde_json::Value", true)
            .if_match()
            .with_query(actor_query()),
        op("GET", "/api/v1/config/history", "The revision history the rollback picker reads (payloads excluded).")
            .ok(),
        op("POST", "/api/v1/config/rollback", "Restore a past configuration revision.")
            .ok_status(200, "The restored configuration and its new revision.")
            .err(400)
            .err(404)
            .err(409)
            .err(502)
            .body("RollbackBody", true)
            .if_match(),
        op("POST", "/api/v1/config/validate", "Check a candidate configuration without storing it.")
            .ok()
            .err(400)
            .body("serde_json::Value", true),
        op("GET", "/api/v1/users", "Dashboard users, as the ES-side user store reports them.")
            .ok()
            .err(502),
        op("GET", "/api/v1/audit", "The audit trail, newest first.")
            .ok()
            .with_query(vec![opt_query("limit", "How many entries; clamped to [1, 500] by the handler, default 100.", json!({"type": "integer", "minimum": 1, "maximum": 500})), q("action", "Only entries with this action.")]),
        op("GET", "/api/v1/preferences", "One user's saved preferences.")
            .ok()
            .err(400)
            .err(502)
            .with_query(vec![q("subject", "OIDC subject. Required -- an empty value is a 400."), q("username", "Operator name."), q("role", "Operator role.")]),
        op("PUT", "/api/v1/preferences", "Replace one user's saved preferences.")
            .ok()
            .err(400)
            .err(404)
            .err(502)
            .body("PreferencesWriteBody", true),
        op("POST", "/api/v1/preferences/reset", "Drop one user's saved preferences back to the defaults.")
            .ok()
            .err(400)
            .err(404)
            .err(502)
            .body("PreferencesResetBody", true),
        op("GET", "/api/v1/reporter-stats", "What the reporting loops produced and when.")
            .ok()
            .err(500)
            .err_json(502),
        op("GET", "/api/v1/services", "The compose services the operator can act on.")
            .ok()
            .err_json(503),
        op("GET", "/api/v1/services/{name}/logs", "Recent log lines for one service, via the services adapter.")
            .with_path(vec![path_param("name", "compose service name.", str_schema())])
            .ok()
            .err_json(400)
            .err_json(503)
            .with_query(vec![opt_query("lines", "How many lines; the handler defaults to 200.", json!({"type": "integer", "format": "int32", "minimum": 1}))]),
        op("POST", "/api/v1/services/{name}/{action}", "Start, stop or restart one service.")
            .with_path(vec![path_param("name", "compose service name.", str_schema()), path_param("action", "Lifecycle action the services adapter accepts.", enum_schema(&["start", "stop", "restart"]))])
            .ok()
            .err_json(400)
            .err_json(503)
            .with_query(actor_query()),
        op("GET", "/api/v1/llm-search", "Natural-language search over the corpus, answered by the local model.")
            .ok()
            .with_query(vec![q("q", "The question."), opt_query("limit", "How many hits to summarise.", json!({"type": "integer", "minimum": 1})), q("source", "\"session\", \"vault\" or \"vault-note\"; an unknown value falls back to session.")]),
        op("GET", "/api/v1/vault-rag", "Answer a question from the Vault corpus through the local model.")
            .ok()
            .with_query(vec![q("q", "The question.")]),
        op("POST", "/api/v1/ip-block", "Block or unblock an address.")
            .ok()
            .err(400)
            .err(502)
            .body("BlockBody", true),
        op("GET", "/api/v1/ip-block/{ip}", "One address's block state.")
            .with_path(vec![path_param("ip", "Address whose block state is wanted.", str_schema())])
            .ok()
            .err(400)
            .err(502),
        op("GET", "/api/v1/ip-block-export", "The whole block list, for backup or review.")
            // Not JSON: ip_block::export answers the newline-joined IP
            // list as text/plain, which is what makes it paste-able into a
            // block list. The fuzzer called the declared application/json
            // undocumented.
            .ok_media("text/plain", "The blocked addresses, one per line.")
            .err(502),
        op("GET", "/api/v1/sandbox/{job}", "One sandbox run.")
            .with_path(vec![path_param("job", "Sandbox job id.", str_schema())])
            .ok()
            .err(404)
            .err(502),
        op("GET", "/api/v1/ghidra/{sha}", "One Ghidra analysis run.")
            .with_path(vec![path_param("sha", "Payload/analysis subject id, lower-case hex.", json!({"type": "string", "pattern": "^[0-9a-fA-F]{8,64}$"}))])
            .ok()
            .err(404)
            .err(502),
        op("GET", "/api/v1/ghidra-callgraph/{sha}", "The call graph one Ghidra run produced.")
            .with_path(vec![path_param("sha", "Payload/analysis subject id, lower-case hex.", json!({"type": "string", "pattern": "^[0-9a-fA-F]{8,64}$"}))])
            .ok()
            .err(404)
            .err(502),
        op("GET", "/api/v1/revdeck/{sha}", "One RevDeck analysis run.")
            .with_path(vec![path_param("sha", "Payload/analysis subject id, lower-case hex.", json!({"type": "string", "pattern": "^[0-9a-fA-F]{8,64}$"}))])
            .ok()
            .err(404)
            .err(502),
        op("GET", "/api/v1/cape/{sha}", "One CAPE analysis run.")
            .with_path(vec![path_param("sha", "Payload/analysis subject id, lower-case hex.", json!({"type": "string", "pattern": "^[0-9a-fA-F]{8,64}$"}))])
            .ok()
            .err(404)
            .err(502),
        op("GET", "/api/v1/cape/{sha}/raw", "The raw CAPE report JSON for one run.")
            .with_path(vec![path_param("sha", "Payload/analysis subject id, lower-case hex.", json!({"type": "string", "pattern": "^[0-9a-fA-F]{8,64}$"}))])
            .ok_media("application/json", "The stored report, verbatim.")
            .err(404)
            .err(502),
        op("GET", "/api/v1/github-analysis/{sha}", "One GitHub analysis run.")
            .with_path(vec![path_param("sha", "Payload/analysis subject id, lower-case hex.", json!({"type": "string", "pattern": "^[0-9a-fA-F]{8,64}$"}))])
            .ok()
            .err(404)
            .err(502),
        op("GET", "/api/v1/attackers-graph", "The node/edge graph around one attacker entity.")
            .ok()
            .err(400)
            .err(404)
            .err(502)
            .with_query(vec![q("id", "Attacker entity id.")]),
        op("GET", "/api/v1/attack-vectors", "Attack vectors for one sensor.")
            .ok()
            .err(400)
            .err(502)
            .with_query(vec![q("sensor", "A specific sensor. Empty, suricata and portbridge are all rejected: those ship to their own index families.")]),
        op("POST", "/api/v1/ml-anomalies/ack", "Acknowledge one ML anomaly.")
            .ok()
            .err(400)
            .err(502)
            .body("MlAckBody", true),
        op("POST", "/api/v1/ml-anomalies/ack-all", "Acknowledge every open ML anomaly.")
            .ok()
            .err(502)
            .body("MlAckAllBody", true),
        op("GET", "/api/v1/ml-anomalies/acks", "The ack ledger.")
            .ok()
            .err(502),
        op("GET", "/api/v1/ml-anomalies/stats", "Ack statistics.")
            .ok()
            .err(502),
        op("POST", "/api/v1/ml-anomalies/disposition", "Record an analyst disposition for anomalies.")
            .ok()
            .err(400)
            .err(502)
            .body("MlDispositionBody", true),
        op("GET", "/api/v1/reports/{id}/pdf", "One generated report, rendered to PDF.")
            .with_path(vec![path_param("id", "Generated report id.", str_schema())])
            .ok_media("application/pdf", "The rendered PDF.")
            .err(404)
            .err(502),
        op("GET", "/api/v1/reports/templates", "The report template and element catalog.")
            .ok(),
        op("GET", "/api/v1/reports/definitions", "Saved report definitions.")
            .ok()
            .err(502),
        op("POST", "/api/v1/reports/definitions", "Save a new report definition.")
            .ok_status(201, "The stored definition.")
            .err(400)
            .err(409)
            .err(422)
            .err(502)
            .body("ReportDefinition", true),
        op("GET", "/api/v1/reports/definitions/{id}", "One saved report definition.")
            .with_path(vec![path_param("id", "Saved report-definition id.", str_schema())])
            .ok()
            .err(404)
            .err(502),
        op("PUT", "/api/v1/reports/definitions/{id}", "Replace one saved report definition.")
            .with_path(vec![path_param("id", "Saved report-definition id.", str_schema())])
            .ok()
            .err(400)
            .err(404)
            .err(409)
            .err(422)
            .err(502)
            .body("ReportDefinition", true),
        op("DELETE", "/api/v1/reports/definitions/{id}", "Delete one saved report definition.")
            .with_path(vec![path_param("id", "Saved report-definition id.", str_schema())])
            .ok()
            .err(404)
            .err(422)
            .err(502),
        op("POST", "/api/v1/reports/definitions/{id}/generate", "Run a saved definition now and store the result.")
            .with_path(vec![path_param("id", "Saved report-definition id.", str_schema())])
            .ok_status(201, "The queued run.")
            .err(400)
            .err(404)
            .err(409)
            .err(502)
            .body("GenerateBody", false),
        op("DELETE", "/api/v1/reports/generated/{id}", "Delete one generated report.")
            .with_path(vec![path_param("id", "Generated report id.", str_schema())])
            .ok()
            .err(404)
            .err(502),
        op("GET", "/api/v1/artifacts/{kind}/{key}", "Artifacts a run produced, one row per filename.")
            .with_path(vec![path_param("kind", "Artifact family.", enum_schema(&["ghidra", "sandbox"])), path_param("key", "Run id the artifacts belong to (a sha256 for ghidra, a job id for sandbox).", str_schema())])
            .ok()
            .err(404)
            .err(502),
        op("GET", "/api/v1/artifacts/{kind}/{key}/{filename}", "Download one artifact of a run.")
            .with_path(vec![path_param("kind", "Artifact family.", enum_schema(&["ghidra", "sandbox"])), path_param("key", "Run id the artifacts belong to.", str_schema()), path_param("filename", "Exact stored filename; the handler refuses a path separator or a name outside this key.", str_schema())])
            .ok_media("application/octet-stream", "The stored artifact bytes.")
            .err(400)
            .err(404)
            .err(413)
            .err(502)
            .err(503),
        op("GET", "/api/v1/charts/kill-chain-sankey", "Kill-chain stages as a sankey.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/attck-coverage", "ATT&CK technique coverage as a grid.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/campaign-timeline", "Campaigns over time.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/ml-backlog", "ML anomaly backlog over time.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/netflow-bytes", "Netflow bytes over time.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/netflow-packets", "Netflow packets over time.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/anomaly-trend", "Anomaly counts over time.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/dionaea-cves", "Dionaea exploit attempts by CVE.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/os-distribution", "Fingerprint-derived OS distribution.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/tcp-stack-clusters", "JA4T stack clusters.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/ics-functions", "ICS function codes seen.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/decoy-requests", "Requests per decoy.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/decoy-client-fingerprints", "Decoy requests joined against ClientHello fingerprints.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/ja4h-fingerprints", "JA4H fingerprint distribution.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/ja4x-fingerprints", "JA4X fingerprint distribution.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/ja4l-fingerprints", "JA4L fingerprint distribution.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/tls-fingerprints", "TLS fingerprint distribution.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/ssh-fingerprints", "SSH fingerprint distribution.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/endlessh-held-histogram", "How long endlessh held each connection.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/ml-anomaly-scores", "ML anomaly scores over time.")
            .ok()
            .err(502),
        op("GET", "/api/v1/charts/attacker-fusion", "How one attacker's signals fuse across sources.")
            .ok()
            .err(400)
            .err(404)
            .err(502)
            .with_query(vec![q("id", "Attacker entity id.")]),
        op("GET", "/api/v1/campaigns", "Campaign store.")
            .ok()
            .err(502)
            .with_query(store_query()),
        op("GET", "/api/v1/clusters", "Attacker-cluster store.")
            .ok()
            .err(502)
            .with_query(store_query()),
        op("GET", "/api/v1/attackers", "Attacker-entity store.")
            .ok()
            .err(502)
            .with_query(store_query()),
        op("GET", "/api/v1/attackers/{id}/events", "The raw evidence behind one attacker entity.")
            .with_path(vec![path_param("id", "Attacker entity id from /api/v1/attackers.", str_schema())])
            .ok()
            .err(404)
            .err(500)
            .err(502)
            .with_query(page_query()),
        op("GET", "/api/v1/recordings", "TTY recording store.")
            .ok()
            .err(502)
            .with_query(store_query()),
        op("GET", "/api/v1/recordings/{shasum}", "One TTY recording.")
            .with_path(vec![path_param("shasum", "Recording shasum to replay.", str_schema())])
            .ok()
            .err(404)
            .err(502),
        op("GET", "/api/v1/recordings/{shasum}/cast", "One TTY recording as asciicast.")
            .with_path(vec![path_param("shasum", "Recording shasum to replay.", str_schema())])
            .ok_media("text/plain", "The asciicast body.")
            .err(404)
            .err(502),
        op("GET", "/api/v1/recordings/{shasum}/raw", "One TTY recording as raw bytes.")
            .with_path(vec![path_param("shasum", "Recording shasum to replay.", str_schema())])
            .ok_media("application/octet-stream", "The raw log bytes.")
            .err(404)
            .err(413)
            .err(502),
        op("GET", "/api/v1/alerts", "Alert-state store.")
            .ok()
            .err(502)
            .with_query(store_query()),
        op("POST", "/api/v1/alerts/{key}/ack", "Acknowledge one alert.")
            .with_path(vec![path_param("key", "Alert-state document key (the hashified signature triple).", str_schema())])
            .ok()
            .err(502)
            .body("AckBody", true),
        op("GET", "/api/v1/canarytokens/types", "The canarytoken types this build can mint.")
            .ok(),
        op("GET", "/api/v1/canarytokens", "Minted canarytokens, with their management token redacted.")
            .ok()
            .err(502),
        op("POST", "/api/v1/canarytokens", "Mint a canarytoken.")
            .ok()
            .err(400)
            .err(500)
            .err(502)
            .err(503)
            .body("CreateBody", true),
        op("GET", "/api/v1/canarytokens/{id}/download", "The canarytoken's landing URL, as a redirect.")
            .with_path(vec![path_param("id", "Canarytoken id.", str_schema())])
            .ok_status(302, "Redirect to the token's landing URL.")
            .err(400)
            .err(404)
            .err(500)
            .err(502)
            .err(503),
        op("GET", "/api/v1/credentials", "HoneyFS implant credentials, with secrets redacted.")
            .ok(),
        op("POST", "/api/v1/credentials", "Provision a honeyfs-implant credential.")
            .ok()
            .err(400)
            .err(500)
            .err(502)
            .err(503)
            .body("CreateBody", true),
        op("POST", "/api/v1/credentials/{id}/rotate", "Rotate a honeyfs-implant credential's secret.")
            .with_path(vec![path_param("id", "HoneyFS implant credential id.", str_schema())])
            .ok()
            .err(404)
            .err(500)
            .err(502)
            .err(503)
            .body("RotateBody", false),
        op("POST", "/api/v1/credentials/{id}/link-token", "Mint a link token for a honeyfs-implant credential.")
            .with_path(vec![path_param("id", "HoneyFS implant credential id.", str_schema())])
            .ok()
            .err(400)
            .err(404)
            .err(500)
            .body("LinkTokenBody", true),
        op("GET", "/api/v1/payloads", "Captured-payload store.")
            .ok()
            .err(502)
            .with_query(store_query()),
        op("GET", "/api/v1/payloads/{hash}", "One captured payload and its analysis.")
            .with_path(vec![path_param("hash", "Payload id: 32 or 64 lower-case hex characters.", json!({"type": "string", "pattern": "^[0-9a-fA-F]{32}([0-9a-fA-F]{32})?$"}))])
            .ok()
            .err(404)
            .err(502),
        op("GET", "/api/v1/payloads/{hash}/raw", "One captured payload's bytes.")
            .with_path(vec![path_param("hash", "Payload id: 32 or 64 lower-case hex characters.", json!({"type": "string", "pattern": "^[0-9a-fA-F]{32}([0-9a-fA-F]{32})?$"}))])
            .ok_media("application/octet-stream", "The payload bytes.")
            .err(400)
            .err(404)
            .err(413)
            .err(502),
        op("POST", "/api/v1/payloads/{hash}/report", "One-click payload PDF into the generated store.")
            .with_path(vec![path_param("hash", "Payload id: 32 or 64 lower-case hex characters.", json!({"type": "string", "pattern": "^[0-9a-fA-F]{32}([0-9a-fA-F]{32})?$"}))])
            .ok_status(201, "The queued report run.")
            .err(400)
            .err(404)
            .err(422)
            .err(501)
            .err(502),
        op("GET", "/api/v1/store/{name}", "One allowlisted store, through the generic passthrough.")
            .with_path(vec![path_param("name", "Allowlisted generic store. Anything else is a 404 -- this route is not an arbitrary index read.", enum_schema(STORE_NAMES))])
            .ok()
            .err(404)
            .err(502)
            .with_query(store_query()),
        op("DELETE", "/api/v1/store/{name}", "Purge dead letters matching ?q= (dead-letters only).")
            .with_path(vec![path_param("name", "Allowlisted generic store. Anything else is a 404 -- this route is not an arbitrary index read.", enum_schema(STORE_NAMES))])
            .ok()
            .err(405)
            .err(502)
            .with_query(vec![q("q", "Lucene query string; absent or empty purges every retained dead letter.")]),
        op("POST", "/api/v1/problem-reports", "File a problem report from the dashboard UI.")
            .ok_status(201, "The stored report.")
            .err(400)
            .err(404)
            .err(409)
            .err(502)
            .body("Submission", true)
            .with_query(actor_query()),
        op("PATCH", "/api/v1/problem-reports/{id}", "Move a problem report through open/triaged/closed.")
            .with_path(vec![path_param("id", "Problem-report id.", str_schema())])
            .ok_status(204, "No content; the status was stored.")
            .err(400)
            .err(404)
            .err(409)
            .err(502)
            .body("StatusPatch", true),
        op("POST", "/api/v1/sandbox/submit", "Queue a sandbox detonation.")
            .ok()
            .err(400)
            .err(404)
            .err(503)
            .body("SubmitBody", true),
        op("GET", "/api/v1/sandbox/golden-image-status", "Whether the sandbox golden image is built.")
            .ok(),
        op("GET", "/api/v1/sandbox/vnc", "The VNC port the sandbox advertises, if any.")
            .ok()
            .err(404),
        op("POST", "/api/v1/ghidra/submit", "Queue a Ghidra analysis.")
            .ok()
            .err(400)
            .err(404)
            .err(503)
            .body("SubmitBody", true),
        op("POST", "/api/v1/github-analysis/submit", "Queue a GitHub analysis.")
            .ok()
            .err(400)
            .err(404)
            .err(503)
            .body("SubmitBody", true),
        op("GET", "/api/v1/workbench/analyzers", "Analyzers available for one payload.")
            .ok()
            .err_json(400)
            .err_json(404)
            .with_query(vec![q("hash", "Payload id.")]),
        op("GET", "/api/v1/workbench/runs", "Payload Workbench runs owned by the calling operator.")
            .ok()
            .err_json(502)
            .actor()
            .with_query(vec![q("hash", "Narrow to one payload id."), opt_query("limit", "How many runs to return.", json!({"type": "integer", "minimum": 1}))]),
        op("POST", "/api/v1/workbench/runs", "Start a Workbench run over one payload.")
            .ok()
            .err_json(400)
            .err_json(404)
            .err_json(502)
            .actor()
            .body("CreateRunBody", true),
        op("GET", "/api/v1/workbench/runs/{id}", "One Workbench run, with its children.")
            .with_path(vec![path_param("id", "Workbench run id.", str_schema())])
            .ok()
            .err_json(404)
            .err_json(502)
            .actor(),
        op("POST", "/api/v1/workbench/runs/{id}/children/{analyzer_id}/{action}", "Cancel or retry one child of a run.")
            .with_path(vec![path_param("id", "Workbench run id.", str_schema()), path_param("analyzer_id", "Analyzer entry on this run; the orchestrator looks the child up by it.", str_schema()), path_param("action", "Child lifecycle action.", enum_schema(&["cancel", "retry"]))])
            .ok()
            .err_json(400)
            .err_json(404)
            .err_json(502)
            .actor(),
        op("GET", "/api/v1/workbench/recipes", "Saved Workbench recipes owned by the calling operator.")
            .ok()
            .err_json(502)
            .actor(),
        op("POST", "/api/v1/workbench/recipes", "Save a Workbench recipe.")
            .ok()
            .err_json(400)
            .err_json(404)
            .err_json(409)
            .err_json(502)
            .actor()
            .body("SaveRecipeBody", true),
        op("GET", "/healthz", "Liveness plus an Elasticsearch reachability flag. Public on purpose: the container healthcheck is the caller.")
            .public()
            .ok()
            .err(502),
        op("GET", "/metrics", "Prometheus exposition for the #1972 request metrics. Public on purpose, like /healthz.")
            .public()
            .ok_media("text/plain", "Prometheus text exposition format."),
    ]
}

/// The tag an operation is filed under. Derived from the path so the
/// grouping is reviewable in one place rather than repeated 138 times.
fn tag_for(path: &str) -> &'static str {
    let rest = path.strip_prefix("/api/v1/").unwrap_or(path);
    // Group by the *first* segment, not the whole remainder. Matching
    // the remainder reads `workbench/runs` as an unknown route and
    // dumps every multi-segment path into `other` -- which is most of
    // the API, and a tag that covers most of the API is not a tag. The
    // leading `/` has to come off first, or the first segment of
    // `/healthz` is the empty string and the two public routes read as
    // ungrouped.
    let head = rest.trim_start_matches('/');
    match head.split('/').next().unwrap_or(head) {
        "healthz" | "metrics" | "sources" | "filter-values" | "source-health" | "settings"
        | "reporter-stats" | "ml-health" | "gpu-queue" | "overview" | "webhook-delivery" => "platform",
        "events" | "live" | "event" => "events",
        "mail" | "sessions" | "search" | "topology" | "attackers-graph" | "attack-vectors"
        | "cred-reuse" | "connections" | "investigate" | "sensors" => "investigate",
        "llm-search" | "vault-rag" => "ai",
        "ip-block" | "ip-block-export" | "services" | "problem-reports" | "canarytokens"
        | "credentials" => "operations",
        "config" | "preferences" | "users" | "audit" => "configuration",
        "attackers" | "campaigns" | "clusters" | "alerts" | "recordings" | "payloads"
        | "ml-anomalies" | "store" => "stores",
        "reports" | "workbench" => "reports",
        "sandbox" | "ghidra" | "ghidra-callgraph" | "revdeck" | "cape" | "github-analysis"
        | "artifacts" => "analysis",
        "export" => "export",
        "charts" => "charts",
        _ => "other",
    }
}

/// What a tag covers, for the document's top-level `tags` list. OpenAPI
/// wants a Tag Object per entry rather than a bare string, and a reader
/// landing on a 500-operation group deserves to know what is in it.
fn tag_description(tag: &str) -> &'static str {
    match tag {
        "platform" => "The dashboard's own view of the service: landing overview and KPIs, health, source and pipeline health, and platform settings.",
        "events" => "The event corpus itself: browse, search, and the live event stream.",
        "investigate" => "Read paths that turn one event or sensor into something a human reads.",
        "ai" => "Model-backed triage: LLM search over the corpus and the vault-backed RAG endpoint.",
        "operations" => "Operator housekeeping: block lists, service accounts, canary tokens, problem reports.",
        "configuration" => "Dashboard configuration, user preferences, and the audit trail.",
        "stores" => "The generated Elasticsearch stores the alert, campaign and identity views are built from.",
        "reports" => "Saved report definitions, generated reports, and the Payload Workbench.",
        "analysis" => "Submission and polling for the out-of-band analysers (sandbox, Ghidra, CAPE, RevDeck).",
        "export" => "Bulk CSV/JSON exports of the views an operator hands to someone else.",
        "charts" => "Precomputed chart series, one route per widget.",
        _ => "Routes this service exposes that do not fit the groups above; grouped so nothing is unrouted.",
    }
}

/// The allowlisted store names, mirroring `stores.rs`'s `store_config`
/// match. A copy rather than a reference because the contract is a
/// document, not a view of the binary -- but it is a copy with teeth:
/// anything outside this list is a 404 at runtime, so widening the
/// contract's enum without widening the allowlist would advertise a
/// route that cannot work.
const STORE_NAMES: &[&str] = &[
    "agent-campaigns",
    "auth-events",
    "canarytokens",
    "cape",
    "dead-letters",
    "generated-reports",
    "ghidra-runs",
    "github-analysis",
    "intelligence",
    "llm-analysis",
    "ml-anomalies",
    "problem-reports",
    "report-definitions",
    "revdeck",
    "sandbox-runs",
    "static-analysis",
    "workbench-runs",
    "yara",
];

/// Renders the OpenAPI 3.1 document. Deterministic: operations are
/// emitted in sorted (path, method) order and every map is built with
/// sorted keys, so regenerating an unchanged table produces a
/// byte-identical file and a reviewer can read a real diff.
pub fn document() -> Value {
    let mut ops = operations();
    ops.sort_by(|a, b| (a.path, a.method).cmp(&(b.path, b.method)));

    let mut paths: Map<String, Value> = Map::new();
    for op in &ops {
        let item = paths.entry(op.path.to_string()).or_insert_with(|| json!({}));
        let object = item
            .as_object_mut()
            .expect("path items are always built as objects");
        assert!(
            !object.contains_key(op.method),
            "two operations claim {} {}",
            op.method,
            op.path,
        );
        // A Path Item's method fields are lowercase in OpenAPI
        // (`get:`, not `GET:`) -- the table above keeps the uppercase
        // spelling because that is how the methods read in the source
        // and in the drift test, so the case is folded here rather than
        // in all 138 rows.
        object.insert(op.method.to_ascii_lowercase(), render_operation(op));
    }

    let mut tag_names: Vec<&str> = ops.iter().map(|op| tag_for(op.path)).collect();
    tag_names.sort_unstable();
    tag_names.dedup();
    let tags: Vec<Value> = tag_names
        .iter()
        .map(|tag| json!({"name": tag, "description": tag_description(tag)}))
        .collect();

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "APIARY dashboard backend-service",
            "version": env!("CARGO_PKG_VERSION"),
            "summary": "The dashboard's Rust service tier: Elasticsearch-backed \
                        read APIs over the honeypot event corpus.",
            "description": INFO_DESCRIPTION
        },
        "servers": [
            {"url": "http://127.0.0.1:8081", "description":
                "The default LISTEN_ADDR. In compose this service is reachable \
                only over the internal honeynet, and only by the dashboard BFF."}
        ],
        "tags": Value::Array(tags),
        "paths": Value::Object(paths),
        "components": {
            "securitySchemes": {
                "serviceToken": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-Service-Token",
                    "description": "The shared secret the Nitro BFF presents on \
                                    every /api/v1 call (SERVICE_TOKEN; main.rs's \
                                    require_service_token, #2183). Compared in \
                                    constant time, and a wrong or missing value \
                                    is a 401 before the route is even resolved. \
                                    Browsers never reach this service directly."
                }
            }
        }
    })
}

const INFO_DESCRIPTION: &str = "\
The /api surface of `backend-service/` (`apiary-backend`), the Rust service \
tier of the APIARY dashboard's modernization port (#1608). It is not a \
public API: the Nitro BFF in `frontend-next/` is the only intended caller \
and presents a shared service token on every /api/v1 route. /healthz and \
/metrics are the two exceptions, open on purpose for the container \
healthcheck and the #1972 metrics scrape.

Response bodies are deliberately left unconstrained here. The handlers \
return `Json<Value>` or a per-surface struct that nothing in this crate \
enforces, so restating 138 shapes would be 138 chances to publish \
something the code does not promise -- and a contract that lies about a \
response is worse than one that admits the gap. What this document does \
pin is the part that has been wrong before: the auth tier, the request \
parameters (including the enum-valued ones the handlers actually \
validate), the declared status codes, and the media type of every \
response. That is what `.github/workflows/weekly-schemathesis.yml` \
checks.

`arcane/home/honeypot-dashboard/backend-service/src/openapi.rs` is the \
source of truth. Regenerate the committed copy with \
`cargo run --bin openapi > openapi.json`; the drift tests in that module \
and a diff step in `quality.yml` both fail if you forget.";

fn render_operation(op: &Op) -> Value {
    let mut parameters: Vec<Value> = Vec::new();
    for param in &op.path_params {
        parameters.push(json!({
            "name": param.name,
            "in": "path",
            "required": true,
            "description": param.description,
            "schema": param.schema,
        }));
    }
    for param in &op.query {
        parameters.push(json!({
            "name": param.name,
            "in": "query",
            "required": false,
            "description": param.description,
            "schema": param.schema,
        }));
    }
    for param in &op.headers {
        parameters.push(json!({
            "name": param.name,
            "in": "header",
            "required": param.required,
            "description": param.description,
            "schema": param.schema,
        }));
    }

    let mut responses: Map<String, Value> = Map::new();
    for response in &op.responses {
        let mut content = Map::new();
        for (name, schema) in &response.schemas {
            content.insert((*name).to_string(), json!({"schema": schema}));
        }
        let key = response.status.to_string();
        // Merge, do not overwrite. One status can be reachable with two
        // media types on this API -- the Workbench's 400 is text/plain
        // when axum's `Query<T>` extractor refuses the query string and
        // application/json when the handler rejects the value itself --
        // and an overwrite here would quietly publish only whichever was
        // declared last, which is how the fuzzer ends up reporting a
        // documented-but-unreachable media type.
        match responses.get_mut(&key) {
            Some(existing) => {
                let existing = existing
                    .as_object_mut()
                    .expect("a rendered response is always an object");
                if let Some(existing_content) = existing.get_mut("content").and_then(Value::as_object_mut)
                {
                    for (name, schema) in content {
                        existing_content.insert(name, schema);
                    }
                } else {
                    existing.insert("content".to_string(), Value::Object(content));
                }
            }
            None => {
                let mut rendered = Map::new();
                rendered.insert("description".to_string(), json!(response.description));
                if !content.is_empty() {
                    rendered.insert("content".to_string(), Value::Object(content));
                }
                responses.insert(key, Value::Object(rendered));
            }
        }
    }
    // The auth tier belongs in every operation, not in a note above the
    // table: it is the property the fuzzer is pointed at, and an
    // operation that quietly lost its `security` block would otherwise
    // still validate.
    match op.tier {
        Tier::Public => {}
        Tier::ServiceToken => {
            responses.insert(
                "401".to_string(),
                json!({
                    "description": error_description(401),
                    "content": {"text/plain": {"schema": str_schema()}}
                }),
            );
        }
        Tier::ServiceTokenAndActor => {
            // Both media types are reachable on one status: no token gets
            // the middleware's text/plain 401, a valid token without a
            // forwarded actor gets the Workbench's JSON one.
            responses.insert(
                "401".to_string(),
                json!({
                    "description": error_description(401),
                    "content": {
                        "text/plain": {"schema": str_schema()},
                        "application/json": {"schema": free_form()}
                    }
                }),
            );
        }
    }

    let mut rendered = Map::new();
    rendered.insert("tags".to_string(), json!([tag_for(op.path)]));
    rendered.insert("summary".to_string(), json!(op.summary));
    rendered.insert("operationId".to_string(), json!(operation_id(op)));
    rendered.insert("parameters".to_string(), Value::Array(parameters));
    if op.method != "GET" {
        if let Some(body) = &op.body {
            rendered.insert(
                "requestBody".to_string(),
                json!({
                    "required": body.required,
                    "description": format!(
                        "Deserialized by the handler into `{}`. The shape is \
                         left open here on purpose -- see the module doc.",
                        body.handler_struct
                    ),
                    "content": {"application/json": {"schema": free_form()}}
                }),
            );
        }
    }
    rendered.insert("responses".to_string(), Value::Object(responses));
    if op.tier != Tier::Public {
        rendered.insert("security".to_string(), json!([{"serviceToken": []}]));
    }
    if op.success_media == Some("text/event-stream") {
        // Not part of OpenAPI, and present on exactly one operation: a
        // fuzzer that reads the document has to be able to find the
        // route whose body never ends without hardcoding a path. The
        // other non-JSON routes (CSV, PDF, octet-stream) terminate and
        // need no marker -- a response too big to assert on is a
        // finding, not a hang.
        rendered.insert("x-endless-stream".to_string(), json!(true));
    }
    Value::Object(rendered)
}

/// A stable, greppable operation id: the method, then the path with `/`
/// and `{}` folded away. Unique by construction, because `document()`
/// has already refused a repeated (path, method).
fn operation_id(op: &Op) -> String {
    let path: String = op
        .path
        .trim_start_matches('/')
        .chars()
        .map(|c| match c {
            '{' | '}' | '.' | '-' | '/' => '_',
            other => other,
        })
        .collect();
    format!("{}_{}", op.method.to_lowercase(), path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn crate_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    /// #3325's drift gate, direction one: the committed document has to
    /// be what this module renders. Compared parsed rather than
    /// byte-wise, so a reformat of the JSON is not a red build while a
    /// changed status code, parameter or tag is.
    #[test]
    fn checked_in_contract_is_current() {
        let path = crate_dir().join("openapi.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} unreadable: {error}", path.display()));
        let committed: Value = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()));
        let generated = document();
        assert!(
            committed == generated,
            "openapi.json is stale -- regenerate with\n    \
             cargo run --bin openapi > openapi.json\n\nfirst difference: {}",
            first_difference(&committed, &generated),
        );
    }

    /// #3325's drift gate, direction two: every `.route(...)` main.rs
    /// registers is in the contract, and nothing in the contract is
    /// missing from the router. The direction that matters is
    /// router -> contract -- a new route with no contract row is how a
    /// fuzz target quietly stops covering the thing it was added for.
    /// The other direction catches a contract path that no longer routes,
    /// which is how a fuzzer ends up measuring a 404.
    #[test]
    fn contract_covers_every_router_route() {
        let main_rs =
            std::fs::read_to_string(crate_dir().join("src/main.rs")).expect("src/main.rs is readable");
        let registered: BTreeSet<(String, String)> = router_routes(&main_rs)
            .into_iter()
            .collect();
        assert!(
            registered.len() > 100,
            "the route scan found only {} registrations -- the parser is broken, \
             not the router",
            registered.len(),
        );

        let published: BTreeSet<(String, String)> = operations()
            .iter()
            .map(|op| (op.path.to_string(), op.method.to_string()))
            .collect();

        let missing: Vec<_> = registered.difference(&published).collect();
        let extra: Vec<_> = published.difference(&registered).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "the contract and src/main.rs disagree about the /api surface (#3325).\n\
             registered but not in openapi.json: {missing:#?}\n\
             in openapi.json but not registered: {extra:#?}\n\
             add the row to operations() in src/openapi.rs, then run \
             `cargo run --bin openapi > openapi.json`.",
        );
    }

    /// The document has to be loadable, not merely equal to itself. A
    /// path template whose parameter was never declared, an operation
    /// with no responses, or a secured operation that forgot its 401 all
    /// pass the two gates above -- and then leave a fuzzer doing nothing
    /// useful against it.
    #[test]
    fn document_is_well_formed() {
        let document = document();
        assert_eq!(document["openapi"], json!("3.1.0"));
        assert!(document["info"]["title"].is_string());
        assert!(document["info"]["version"].is_string());
        assert_eq!(
            document["components"]["securitySchemes"]["serviceToken"]["name"],
            json!("X-Service-Token"),
        );

        let paths = document["paths"].as_object().expect("paths is an object");
        assert!(paths.len() > 100, "only {} paths", paths.len());

        let mut operations_seen = 0usize;
        for (path, item) in paths {
            let captures = capture_names(path);
            for (method, operation) in item.as_object().expect("path item is an object") {
                operations_seen += 1;
                assert!(
                    operation["summary"].is_string(),
                    "{method} {path} has no summary"
                );

                let responses = operation["responses"]
                    .as_object()
                    .unwrap_or_else(|| panic!("{method} {path} declares no responses"));
                assert!(!responses.is_empty(), "{method} {path} declares no response");

                let secured = operation.get("security").is_some();
                assert_eq!(
                    secured,
                    responses.contains_key("401"),
                    "{method} {path}: a secured operation must declare its 401, or \
                     the auth tier is not actually in the contract"
                );
                assert_eq!(
                    secured,
                    !(path.starts_with("/healthz") || path.starts_with("/metrics")),
                    "{method} {path}: /healthz and /metrics are the only routes outside \
                     the service-token tier (main.rs)"
                );

                // Every `Json<T>` body can be refused by the extractor
                // before the handler runs, and the fuzzer sends exactly
                // the bodies that trip it. `body()` adds these, so this
                // only fires if a row starts declaring a body some other
                // way.
                if operation.get("requestBody").is_some() {
                    for status in ["415", "422"] {
                        assert!(
                            responses.contains_key(status),
                            "{method} {path} takes a JSON body but does not declare {status} \
                             (axum's Json<T> rejection)"
                        );
                    }
                }

                // Same for a `Query<T>` extractor, which answers 400 as
                // text/plain. `with_query` adds it. One direction only:
                // a row may declare 400 for its handler's own reasons
                // with no query parameters at all (the artifact download
                // refuses a path separator that way).
                let takes_query = operation
                    .get("parameters")
                    .and_then(Value::as_array)
                    .is_some_and(|parameters| {
                        parameters
                            .iter()
                            .any(|parameter| parameter["in"] == json!("query"))
                    });
                assert!(
                    !takes_query || responses.contains_key("400"),
                    "{method} {path}: an operation with query parameters must declare the \
                     400 that axum's Query<T> rejection raises"
                );

                let parameters = operation["parameters"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let declared: BTreeSet<String> = parameters
                    .iter()
                    .filter(|p| p["in"] == json!("path"))
                    .map(|p| p["name"].as_str().unwrap_or_default().to_string())
                    .collect();
                assert_eq!(
                    declared, captures,
                    "{method} {path}: the declared path parameters must match the \
                     template's {{captures}} exactly"
                );
                for parameter in &parameters {
                    assert!(
                        matches!(
                            parameter["in"].as_str(),
                            Some("query") | Some("path") | Some("header")
                        ),
                        "{method} {path}: parameter {} has no location",
                        parameter["name"],
                    );
                }

                if method != "get" {
                    if let Some(body) = operation.get("requestBody") {
                        assert!(
                            body["content"]["application/json"]["schema"].is_object(),
                            "{method} {path}: its request body has no schema"
                        );
                    }
                }
            }
        }
        assert!(operations_seen > 130, "only {operations_seen} operations");
    }

    /// The enum the contract advertises for `/api/v1/store/{name}` has
    /// to be the allowlist the handler enforces, or the fuzzer is being
    /// told a route exists that answers 404 for every value it generates.
    /// The list is copied from `stores.rs`, so this test is what keeps
    /// the copy honest.
    #[test]
    fn the_store_enum_matches_the_handside_allowlist() {
        let stores_rs =
            std::fs::read_to_string(crate_dir().join("src/stores.rs")).expect("src/stores.rs");
        let allowlist_start = stores_rs
            .find("fn store_config")
            .expect("store_config is still the allowlist");
        let allowlist_end = allowlist_start
            + stores_rs[allowlist_start..]
                .find("\n}\n")
                .expect("store_config has a closing brace");
        let allowlist = &stores_rs[allowlist_start..allowlist_end];

        let mut from_code: Vec<&str> = allowlist
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                let rest = trimmed.strip_prefix('"')?;
                let end = rest.find('"')?;
                let name = &rest[..end];
                (trimmed.contains("=>")
                    && name.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
                .then_some(name)
            })
            .collect();
        from_code.sort_unstable();

        let mut from_contract: Vec<&str> = STORE_NAMES.to_vec();
        from_contract.sort_unstable();
        assert_eq!(
            from_contract, from_code,
            "the contract's store enum has drifted from stores.rs's store_config \
             allowlist (#3325)"
        );
    }

    fn capture_names(path: &str) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        let mut rest = path;
        while let Some(open) = rest.find('{') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('}') else { break };
            names.insert(after[..close].to_string());
            rest = &after[close + 1..];
        }
        names
    }

    /// The `(path, method)` pairs main.rs registers, read out of the
    /// source rather than a hand-kept list. A third list would be a
    /// third thing to update, and the point of the gate is that the
    /// router stays the thing that decides what exists.
    ///
    /// The scan tracks paren depth, so a method name is only read where
    /// it sits in the route's own argument list. That is what keeps
    /// `get(preferences::get).put(preferences::put)` from reading as
    /// four methods instead of two, and `axum::routing::put(...)` --
    /// where the name arrives after `::` -- from reading as none.
    fn router_routes(source: &str) -> Vec<(String, String)> {
        const METHODS: [&str; 5] = ["get", "post", "put", "delete", "patch"];
        let bytes = source.as_bytes();
        let mut found: Vec<(String, String)> = Vec::new();
        let mut cursor = 0usize;

        while let Some(offset) = source[cursor..].find(".route(") {
            let open = cursor + offset + ".route(".len();
            let mut depth = 1i32;
            let mut end = open;
            while depth > 0 {
                match bytes[end] {
                    b'(' => depth += 1,
                    b')' => depth -= 1,
                    _ => {}
                }
                end += 1;
            }
            let body = &source[open..end - 1];
            cursor = end;

            let Some(first_quote) = body.find('"') else { continue };
            let after = &body[first_quote + 1..];
            let Some(closing) = after.find('"') else { continue };
            let path = &after[..closing];

            for method in methods_in(&after[closing + 1..], &METHODS) {
                // axum spells these lowercase (`get(handler)`); the
                // contract spells them the way OpenAPI does (`GET`).
                // Normalize here so the comparison below is two
                // vocabularies rather than a wall of case mismatches.
                found.push((path.to_string(), method.to_ascii_uppercase()));
            }
        }
        found
    }

    fn methods_in<'a>(arguments: &str, methods: &'a [&'a str]) -> Vec<&'a str> {
        let bytes = arguments.as_bytes();
        let mut found: Vec<&'a str> = Vec::new();
        let mut depth = 0i32;
        let mut index = 0usize;
        while index < bytes.len() {
            match bytes[index] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
            if depth == 0 {
                for method in methods.iter().copied() {
                    if !arguments[index..].starts_with(method) {
                        continue;
                    }
                    // A method name is a whole token: the character in
                    // front of it is not part of a longer identifier.
                    let before = if index == 0 { b' ' } else { bytes[index - 1] };
                    if before.is_ascii_alphanumeric() || before == b'_' {
                        continue;
                    }
                    let after = &arguments[index + method.len()..];
                    let call = after.trim_start();
                    if call.starts_with('(') {
                        found.push(method);
                        // Step over the call so its arguments -- and any
                        // identifier inside them that merely ends in a
                        // method name -- are not rescanned. `call` is a
                        // slice of `arguments` offset by the leading
                        // whitespace, so the `(` is this far in; the
                        // balance starts at zero and the `(` itself is
                        // counted, which stops the walk exactly after
                        // this method's own closing paren. That is what
                        // leaves a chained `.post(...)` to be read.
                        let open = index + method.len() + (after.len() - call.len());
                        let mut inner = 0i32;
                        let mut scan = open;
                        // `open` is the `(`, so the balance only returns
                        // to zero once this method's own call is
                        // closed -- leaving a chained `.post(...)` at
                        // depth zero for the outer loop to read. An
                        // unbalanced tail stops on the end of the input
                        // rather than looping forever.
                        while scan < bytes.len() {
                            match bytes[scan] {
                                b'(' => inner += 1,
                                b')' => inner -= 1,
                                _ => {}
                            }
                            scan += 1;
                            if inner == 0 {
                                break;
                            }
                        }
                        index = scan;
                    }
                    break;
                }
            }
            index += 1;
        }
        found
    }

    /// "Here is where they stop matching", so a stale contract names the
    /// operation that moved instead of dumping both documents.
    fn first_difference(left: &Value, right: &Value) -> String {
        fn walk(left: &Value, right: &Value, at: &str) -> Option<String> {
            if left == right {
                return None;
            }
            match (left, right) {
                (Value::Object(l), Value::Object(r)) => {
                    for (key, value) in l {
                        match r.get(key) {
                            None => return Some(format!("{at}/{key}: only in openapi.json")),
                            Some(other) => {
                                if let Some(found) = walk(value, other, &format!("{at}/{key}")) {
                                    return Some(found);
                                }
                            }
                        }
                    }
                    for key in r.keys() {
                        if !l.contains_key(key) {
                            return Some(format!("{at}/{key}: missing from openapi.json"));
                        }
                    }
                    None
                }
                _ => Some(format!("{at}: openapi.json has {left}, the generator has {right}")),
            }
        }
        walk(left, right, "").unwrap_or_else(|| "no obvious difference".to_string())
    }
}
