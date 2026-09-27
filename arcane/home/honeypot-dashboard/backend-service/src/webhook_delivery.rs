//! Alert-webhook delivery outcomes (#3330).
//!
//! `alert-notifier` posts every newly notified alert to the single
//! `ALERT_WEBHOOK_URL` the worker is configured with. That call used to be
//! fire-and-forget: transport errors produced one `tracing::warn!` line and
//! a response that arrived with a 4xx or 5xx was never looked at, so a
//! webhook that had stopped accepting alerts was indistinguishable from a
//! healthy one. The only place the failure existed was the worker's
//! container log, which nothing in this dashboard reads.
//!
//! Three changes, all deliberately small:
//!
//!   * **A non-2xx is a failure.** `error_for_status` decides it, not a
//!     hand-rolled range check, so a 3xx that reqwest declined to follow
//!     counts too. The response body is not read — a rejecting receiver's
//!     body is untrusted input, and nothing here needs it.
//!
//!   * **A bounded retry on the failures that can clear themselves.**
//!     A timeout, a refused connect, 408, 429, 5xx. A 400/401/403/404 is
//!     a verdict on this exact request and is not repeated: the receiver
//!     has already said the request itself is wrong, so trying again
//!     verbatim only triples the load on a webhook that is refusing us.
//!
//!   * **The outcome is recorded**, in one small Elasticsearch document per
//!     target: `{status, http_code, latency_ms, tries, error, at}` for the
//!     last success and the last failure, plus the failure streak. Never
//!     the payload. An alert body quotes attacker-controlled strings by
//!     construction, and the target is third-party infrastructure; neither
//!     belongs in a document this dashboard then serves to every operator.
//!     For the same reason the recorded `target` is the URL's origin only
//!     — a webhook URL's path and query is where Slack- and Discord-style
//!     bots keep the secret token in the first place.
//!
//! Settings and the diagnostics page both read this back:
//! `GET /api/v1/webhook-delivery`, plus the `webhook` field on
//! `GET /api/v1/source-health`.

use std::time::{Duration, Instant};

use axum::{extract::State, Json};
use serde::Serialize;
use serde_json::{json, Value};

use crate::es::{Es, WriteError};
use crate::AppState;

/// One document per webhook target. The name says what the index is for;
/// the id says which target.
const INDEX: &str = "dashboard-webhook-delivery-v1";

/// Record id for the one webhook a deployment configures. ALERT_WEBHOOK_URL
/// is a single URL, so the alert fan-out needs exactly one record — and a
/// second id would only ever be a second way to read the same streak.
pub const ALERT_ID: &str = "alert";

/// Tries per delivery, including the first. Three is the smallest count
/// that clears a single restarting receiver without turning a dead endpoint
/// into a sustained request flood: the pass interval is 60s and
/// `MissedTickBehavior::Delay` already means a slow pass delays the next
/// one rather than stacking a second copy of it.
const WEBHOOK_TRIES: u32 = 3;

/// Per-request timeout, set on the request rather than inherited from the
/// shared client so it cannot be loosened by a sibling probe's config.
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

/// Linear backoff between tries: 250ms, then 500ms. Worst case for one
/// message is therefore 3x5s + 750ms ≈ 15.8s, which is the deliberate
/// price of a fan-out that can report its own failure.
const WEBHOOK_RETRY_BASE: Duration = Duration::from_millis(250);

/// Consecutive failures before the diagnostics surface calls it broken
/// rather than merely degraded. Not 1: a single refused connect during a
/// receiver's own restart is noise, and a warning that fires on noise is a
/// warning operators learn to skip. Not 10 either — a receiver that has
/// refused five deliveries in a row, against a 6h per-alert cooldown, is
/// not coming back on its own.
const FAILURE_STREAK_THRESHOLD: u64 = 5;

/// Cap on a stored error string. The text is read in a table cell, and an
/// unbounded hyper/reqwest message is a field that grows without limit in a
/// document every operator can open.
const MAX_ERROR_CHARS: usize = 480;

/// Read-modify-write attempts before an outcome record gives up. Same
/// primitive and the same reasoning as worker.rs's OBSERVE_CAS_ATTEMPTS
/// (#2044): two workers can both be delivering, and an un-fenced
/// get→index would let the loser's read resurrect a streak the winner had
/// already cleared.
const RECORD_CAS_ATTEMPTS: usize = 3;

/// The outcome of one delivery attempt (all tries of one message).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub ok: bool,
    /// None when no response ever arrived — a timeout or a refused connect.
    pub http_code: Option<u16>,
    /// Wall clock across every try, not just the last, because that is the
    /// latency the notifier actually paid.
    pub latency_ms: u64,
    pub tries: u32,
    pub error: Option<String>,
}

impl Attempt {
    /// The recorded shape. The payload is absent by construction — see the
    /// module comment.
    fn to_doc(&self, at: &str) -> Value {
        json!({
            "at": at,
            "status": if self.ok { "delivered" } else { "failed" },
            "http_code": self.http_code,
            "latency_ms": self.latency_ms,
            "tries": self.tries,
            "error": self.error,
        })
    }
}

/// Statuses worth another try. 408 and 429 are the receiver saying "not
/// now"; 5xx is "not me". The rest of the 4xx range is a judgement on this
/// request, and repeating it cannot change the answer.
fn retryable_status(code: u16) -> bool {
    code == 408 || code == 429 || (500..600).contains(&code)
}

/// Transport failures worth another try. A timeout and a refused connect
/// are the shape a restarting webhook actually presents. Everything else
/// (an unparseable URL, a redirect chain reqwest refused to follow) is
/// misconfiguration, and retrying it would re-send the same doomed request
/// on every notification forever.
fn retryable_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect()
}

/// The stored text for a rejected response. Composed from the status rather
/// than from `reqwest::Error`'s own Display, which embeds the request URL —
/// and that URL's path and query are exactly where a bot's secret lives.
fn status_error(status: reqwest::StatusCode) -> String {
    let reason = status.canonical_reason().unwrap_or("unknown status");
    format!("HTTP {} {}", status.as_u16(), reason)
}

/// The stored text for a transport failure. `Error::source` is the innermost
/// cause, which unlike reqwest's Display carries no URL.
fn transport_error(error: &reqwest::Error) -> String {
    let text = std::error::Error::source(error)
        .map(ToString::to_string)
        .unwrap_or_else(|| "request failed without a reported cause".to_string());
    truncate(&text)
}

fn truncate(text: &str) -> String {
    if text.chars().count() <= MAX_ERROR_CHARS {
        return text.to_string();
    }
    let kept: String = text.chars().take(MAX_ERROR_CHARS).collect();
    format!("{kept}…")
}

/// scheme://host[:port] and nothing else — the part an operator needs to
/// tell "pointed at the wrong host" from "the right host is refusing us",
/// with the credential-bearing tail dropped. Falls back to the same
/// redaction for an unparseable URL rather than echoing the raw string.
pub fn origin_of(url: &str) -> String {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return "<unparseable url>".to_string();
    };
    match (parsed.host_str(), parsed.port_or_known_default()) {
        (Some(host), Some(port)) => format!("{}://{host}:{port}", parsed.scheme()),
        (Some(host), None) => format!("{}://{host}", parsed.scheme()),
        // A URL that parsed but carries no host (`file:`, `data:`) names
        // no endpoint a webhook could be delivered to.
        _ => "<unparseable url>".to_string(),
    }
}

/// Post one message, retrying only what a retry can fix, and report what
/// happened. Never records anything itself and never returns Err: a
/// delivery failure is the caller's to record, not this function's to hide.
pub async fn deliver(client: &reqwest::Client, url: &str, body: &Value) -> Attempt {
    let started = Instant::now();
    let mut attempt = Attempt { ok: false, http_code: None, latency_ms: 0, tries: 0, error: None };
    for index in 0..WEBHOOK_TRIES {
        attempt.tries = index + 1;
        match client.post(url).timeout(WEBHOOK_TIMEOUT).json(body).send().await {
            Ok(response) => {
                let status = response.status();
                attempt.http_code = Some(status.as_u16());
                // The boundary is 2xx-or-bust, and that is `is_success()`
                // rather than reqwest's `error_for_status` even though
                // `error_for_status` is the obvious spelling of the same
                // idea. It is defined to fail on 4xx/5xx *only*, because
                // reqwest follows redirects transparently and a 3xx on
                // its way to a real handler is not an error. A 3xx that
                // reaches this line is therefore one reqwest could not
                // follow — no Location to follow — so nothing was
                // accepted at the address the alert was sent to, which
                // is precisely the silence this change exists to end.
                // `a_3xx_that_was_not_followed_is_a_failure` pins it.
                //
                // The body is deliberately not read either way: a
                // rejecting receiver's body is untrusted input, and
                // nothing here needs it.
                if status.is_success() {
                    attempt.error = None;
                    attempt.ok = true;
                    break;
                }
                attempt.error = Some(status_error(status));
                if !retryable_status(status.as_u16()) {
                    break;
                }
            }
            Err(error) => {
                attempt.http_code = None;
                attempt.error = Some(transport_error(&error));
                if !retryable_error(&error) {
                    break;
                }
            }
        }
        if index + 1 < WEBHOOK_TRIES {
            tokio::time::sleep(WEBHOOK_RETRY_BASE * (index + 1)).await;
        }
    }
    attempt.latency_ms = started.elapsed().as_millis() as u64;
    attempt
}

/// Write one outcome into the target's record: bump the message count, move
/// the streak, and keep the last success and last failure as separate
/// values so a receiver that is broken *right now* does not erase the proof
/// that it worked an hour ago.
///
/// Best-effort by design. This runs inside the notifier's own pass, where a
/// record-write failure must cost the operator a log line, not the alerts
/// that pass was collecting.
pub async fn record(es: &Es, id: &str, target: &str, attempt: &Attempt) {
    let at = chrono::Utc::now().to_rfc3339();
    for _ in 0..RECORD_CAS_ATTEMPTS {
        let current = match es.get_doc_meta(INDEX, id).await {
            Ok(found) => found,
            Err(error) => {
                tracing::warn!(%error, id, "webhook delivery record read failed");
                return;
            }
        };
        let existed = current.is_some();
        let (mut doc, seq_no, primary_term) = current.unwrap_or_else(|| {
            (
                json!({
                    "kind": "webhook-delivery",
                    "id": id,
                    "target": target,
                    "messages": 0,
                    "consecutive_failures": 0,
                    "last_success": null,
                    "last_failure": null,
                    "updated_at": null,
                }),
                0,
                0,
            )
        });
        doc["target"] = json!(target);
        doc["updated_at"] = json!(at);
        doc["messages"] = json!(doc["messages"].as_u64().unwrap_or(0) + 1);
        if attempt.ok {
            doc["consecutive_failures"] = json!(0);
            doc["last_success"] = attempt.to_doc(&at);
        } else {
            doc["consecutive_failures"] =
                json!(doc["consecutive_failures"].as_u64().unwrap_or(0).saturating_add(1));
            doc["last_failure"] = attempt.to_doc(&at);
        }
        let result = if existed {
            es.index_doc_cas(INDEX, id, doc, seq_no, primary_term).await
        } else {
            // op_type=create, so two workers racing on the first-ever
            // record resolve deterministically instead of one clobbering
            // the other's first streak.
            es.index_doc_create(INDEX, id, doc).await
        };
        match result {
            Ok(()) => return,
            Err(WriteError::Conflict) => continue,
            Err(WriteError::Other(error)) => {
                tracing::warn!(%error, id, "webhook delivery record write failed");
                return;
            }
        }
    }
    tracing::warn!(id, "webhook delivery record kept losing races; outcome not recorded");
}

/// What Settings and the diagnostics page read back. `available: false`
/// means the *record* could not be read — the same envelope
/// reporter_stats.rs uses, so one card pattern covers both.
#[derive(Serialize)]
pub struct DeliveryHealth {
    pub available: bool,
    pub reason: String,
    /// disabled / idle / healthy / degraded / failing / unknown — see
    /// `delivery_state`.
    pub state: String,
    /// The URL's origin, never its path or query.
    pub target: String,
    pub messages: u64,
    pub consecutive_failures: u64,
    pub failure_threshold: u64,
    pub last_success: Value,
    pub last_failure: Value,
    pub updated_at: String,
}

/// The record's absence is genuinely ambiguous and says so, rather than
/// guessing: either no delivery has happened because nothing has notified
/// since, or because ALERT_WEBHOOK_URL is unset. Both read as "disabled"
/// here, which is the honest reading of "this worker has never delivered
/// anything to a webhook" — and the note on the surface spells out the two
/// possibilities so nobody debugs the wrong one.
fn delivery_state(has_record: bool, consecutive_failures: u64) -> &'static str {
    if !has_record {
        return "disabled";
    }
    if consecutive_failures == 0 {
        return "healthy";
    }
    if consecutive_failures < FAILURE_STREAK_THRESHOLD {
        return "degraded";
    }
    "failing"
}

/// The one snapshot both surfaces read. `pub` because health.rs folds it
/// into `/api/v1/source-health` rather than the page making a second call.
pub async fn summary(es: &Es) -> DeliveryHealth {
    let doc = match es.get_doc(INDEX, ALERT_ID).await {
        Ok(doc) => doc,
        Err(error) => {
            // Not a hard failure of the page: the rest of source-health is
            // still worth rendering, and a missing delivery card with a
            // stated reason is better than a blank operations page.
            return DeliveryHealth {
                available: false,
                reason: error.to_string(),
                state: "unknown".to_string(),
                target: String::new(),
                messages: 0,
                consecutive_failures: 0,
                failure_threshold: FAILURE_STREAK_THRESHOLD,
                last_success: Value::Null,
                last_failure: Value::Null,
                updated_at: String::new(),
            };
        }
    };
    let failures = doc.as_ref().map(|doc| doc["consecutive_failures"].as_u64().unwrap_or(0)).unwrap_or(0);
    DeliveryHealth {
        available: true,
        reason: String::new(),
        state: delivery_state(doc.is_some(), failures).to_string(),
        target: doc.as_ref().map(|doc| doc["target"].as_str().unwrap_or("").to_string()).unwrap_or_default(),
        messages: doc.as_ref().map(|doc| doc["messages"].as_u64().unwrap_or(0)).unwrap_or(0),
        consecutive_failures: failures,
        failure_threshold: FAILURE_STREAK_THRESHOLD,
        last_success: doc.as_ref().map(|doc| doc["last_success"].clone()).unwrap_or(Value::Null),
        last_failure: doc.as_ref().map(|doc| doc["last_failure"].clone()).unwrap_or(Value::Null),
        updated_at: doc
            .as_ref()
            .map(|doc| doc["updated_at"].as_str().unwrap_or("").to_string())
            .unwrap_or_default(),
    }
}

/// `GET /api/v1/webhook-delivery` — the alert fan-out's own card, for
/// Settings. The diagnostics page reads the same value as a field on
/// `/api/v1/source-health` rather than making a second round trip.
pub async fn health(State(state): State<AppState>) -> Json<DeliveryHealth> {
    Json(summary(&state.es).await)
}

// ---------------------------------------------------------------------------
// Contract tests
//
// A local stub server, one canned response per test, and an assertion on
// both the returned outcome and the number of requests the stub actually
// received. The request count is the half that matters: it is what proves
// a permanent rejection is not retried and a 5xx is, which is the whole
// content of the retry policy.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct Stub {
        url: String,
        hits: Arc<AtomicUsize>,
    }

    impl Stub {
        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    /// Byte-level HTTP/1.1 on a loopback port. No dev-dependency for a
    /// mock server: the responses these tests need are lines of text, and a
    /// mock crate would be a second HTTP stack to keep honest.
    ///
    /// `response_for(n)` picks the raw response for the n-th request, so a
    /// stub can answer a redirect first and the real thing second.
    /// `delay` holds every response back, which is what makes a
    /// client-side timeout the thing under test.
    async fn stub_responding<F>(delay: Option<Duration>, response_for: F) -> Stub
    where
        F: Fn(usize) -> String + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stub");
        let addr = listener.local_addr().expect("stub addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let counted = hits.clone();
        // Arc'd so each connection task can own a handle; the accept loop
        // keeps the only other one alive.
        let responses = Arc::new(response_for);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let counted = counted.clone();
                let response = responses.clone();
                tokio::spawn(async move {
                    // Read the whole request — headers *and* the
                    // Content-Length body — before answering. Replying
                    // mid-upload races the client's write and shows up as
                    // a transport error instead of the status under test.
                    let mut buf: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        if request_complete(&buf) {
                            break;
                        }
                        match tokio::time::timeout(Duration::from_millis(500), stream.read(&mut chunk)).await
                        {
                            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                            Ok(Ok(read)) => buf.extend_from_slice(&chunk[..read]),
                        }
                    }
                    let nth = counted.fetch_add(1, Ordering::SeqCst);
                    if let Some(delay) = delay {
                        tokio::time::sleep(delay).await;
                    }
                    let _ = stream.write_all(response(nth).as_bytes()).await;                    let _ = stream.flush().await;
                });
            }
        });
        // A path carrying a secret, because the recorded target and the
        // recorded error are both asserted to have dropped it.
        Stub { url: format!("http://{addr}/hooks/secret-token"), hits }
    }

    /// One canned response for every request.
    async fn stub(status_line: &'static str, delay: Option<Duration>) -> Stub {
        stub_responding(delay, move |_| {
            format!("{status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        })
        .await
    }

    /// Headers terminated by a blank line, plus however many body bytes
    /// Content-Length promises.
    fn request_complete(buf: &[u8]) -> bool {
        let Some(header_end) = buf.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let headers = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
        let body_len: usize = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0);
        buf.len() >= header_end + 4 + body_len
    }

    /// A client with a timeout short enough to keep the timeout test to
    /// well under a second. The per-request WEBHOOK_TIMEOUT is 5s, which
    /// would make this test take fifteen.
    fn fast_client(timeout: Duration) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("reqwest client")
    }

    fn body() -> Value {
        json!({"content": "ingest stalled: suricata-v2-dns-*", "text": "ingest stalled: suricata-v2-dns-*"})
    }

    #[tokio::test]
    async fn a_2xx_is_delivered_on_the_first_try() {
        let stub = stub("HTTP/1.1 200 OK", None).await;
        let attempt = deliver(&fast_client(Duration::from_secs(2)), &stub.url, &body()).await;
        assert!(attempt.ok, "2xx must count as delivered: {attempt:?}");
        assert_eq!(attempt.http_code, Some(200));
        assert_eq!(attempt.tries, 1, "a success is never retried");
        assert_eq!(attempt.error, None);
        assert_eq!(stub.hits(), 1, "one request for a healthy webhook");
    }

    #[tokio::test]
    async fn a_3xx_that_was_not_followed_is_a_failure() {
        // reqwest follows redirects by default, so a 302 that reaches the
        // caller had no Location for it to follow and the receiver
        // accepted nothing. Its own `error_for_status` deliberately lets
        // 3xx through (redirects are transparent to it), which is exactly
        // why the boundary here is `status.is_success()`.
        let stub = stub("HTTP/1.1 302 Found", None).await;
        let attempt = deliver(&fast_client(Duration::from_secs(2)), &stub.url, &body()).await;
        assert!(!attempt.ok, "an unfollowed 3xx is not a delivery: {attempt:?}");
        assert_eq!(attempt.http_code, Some(302));
        let error = attempt.error.clone().expect("a 3xx records why");
        assert!(error.contains("302"), "the recorded error names the status: {error}");
    }

    #[tokio::test]
    async fn a_redirect_reqwest_could_follow_is_still_a_delivery() {
        // The other half of the 3xx rule, and the reason the boundary sits
        // on the *final* status rather than on "no 3xx anywhere": a
        // receiver that redirects to a real handler (http -> https, or a
        // service behind a proxy) did accept the alert, and tightening the
        // check to reject every 3xx would start calling those deliveries
        // failures.
        //
        // Two stubs, because a Location header needs a URL that exists:
        // the source answers 307 at whatever the destination is, and the
        // destination answers 200.
        let destination = stub("HTTP/1.1 200 OK", None).await;
        let location = format!("{}/moved", destination.url);
        let source = stub_responding(None, move |_| {
            format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        })
        .await;
        let attempt = deliver(&fast_client(Duration::from_secs(2)), &source.url, &body()).await;
        assert!(attempt.ok, "a followed redirect delivered the alert: {attempt:?}");
        assert_eq!(attempt.http_code, Some(200), "the verdict is on the final response");
        assert_eq!(attempt.tries, 1, "following a redirect is not a retry");
        assert_eq!(source.hits(), 1, "one POST, not one POST per hop");
        assert_eq!(destination.hits(), 1, "the redirect target received it");
    }

    #[tokio::test]
    async fn a_4xx_is_a_failure_and_is_not_retried() {
        let stub = stub("HTTP/1.1 404 Not Found", None).await;
        let attempt = deliver(&fast_client(Duration::from_secs(2)), &stub.url, &body()).await;
        assert!(!attempt.ok, "a 4xx must not read as delivered: {attempt:?}");
        assert_eq!(attempt.http_code, Some(404));
        assert_eq!(attempt.tries, 1, "a permanent rejection is not repeated");
        assert_eq!(stub.hits(), 1, "the stub must see exactly one request");
        // The operator needs to know which status, without the URL — this
        // document is served to every dashboard user.
        let error = attempt.error.expect("a 4xx records why");
        assert!(error.contains("404"), "recorded error names the status: {error}");
        assert!(!error.contains("secret-token"), "recorded error must not carry the URL: {error}");
    }

    #[tokio::test]
    async fn a_5xx_is_a_failure_and_is_retried_to_the_bound() {
        let stub = stub("HTTP/1.1 503 Service Unavailable", None).await;
        let attempt = deliver(&fast_client(Duration::from_secs(2)), &stub.url, &body()).await;
        assert!(!attempt.ok, "a 5xx must not read as delivered: {attempt:?}");
        assert_eq!(attempt.http_code, Some(503));
        assert_eq!(attempt.tries, WEBHOOK_TRIES, "retries stop at the bound");
        assert_eq!(stub.hits(), WEBHOOK_TRIES as usize, "one request per try, and no more");
        assert!(attempt.latency_ms > 0, "a delivery records what it cost: {attempt:?}");
    }

    #[tokio::test]
    async fn a_timeout_is_a_failure_with_no_status_and_is_retried() {
        // Held for far longer than the client's own budget, so every try
        // ends the same way: no response, no status code.
        let stub = stub("HTTP/1.1 200 OK", Some(Duration::from_secs(30))).await;
        let attempt = deliver(&fast_client(Duration::from_millis(120)), &stub.url, &body()).await;
        assert!(!attempt.ok, "a timeout is not a delivery: {attempt:?}");
        assert_eq!(attempt.http_code, None, "no response means no status to report");
        assert_eq!(attempt.tries, WEBHOOK_TRIES, "a timeout is the retryable case");
        let error = attempt.error.clone().expect("a timeout records why");
        assert!(!error.is_empty(), "the recorded error is not an empty placeholder");
        assert!(!error.contains("secret-token"), "recorded error must not carry the URL: {error}");
    }

    #[tokio::test]
    async fn an_unreachable_endpoint_fails_without_a_status() {
        // Port 1 on loopback: reserved, nothing listening. The transport
        // failure half of the same contract, with no stub needed.
        let attempt =
            deliver(&fast_client(Duration::from_millis(500)), "http://127.0.0.1:1/hook", &body()).await;
        assert!(!attempt.ok, "an unreachable endpoint is not a delivery: {attempt:?}");
        assert_eq!(attempt.http_code, None);
        assert!(attempt.error.is_some(), "a refused connect records why: {attempt:?}");
    }

    #[test]
    fn the_recorded_target_drops_the_path_a_bots_secret_lives_in() {
        assert_eq!(origin_of("https://hooks.slack.com/services/T000/B111/XXXX"), "https://hooks.slack.com:443");
        assert_eq!(origin_of("http://alerts.internal:8080/hook?token=abcd1234"), "http://alerts.internal:8080");
        // Not a URL at all: say so rather than echo whatever was in the env
        // var into a document every operator can read.
        assert_eq!(origin_of("not a url"), "<unparseable url>");
    }

    #[test]
    fn an_oversized_error_is_capped_rather_than_stored_whole() {
        let long = "x".repeat(MAX_ERROR_CHARS * 3);
        let capped = truncate(&long);
        assert_eq!(capped.chars().count(), MAX_ERROR_CHARS + 1, "cap plus the ellipsis");
        assert!(capped.ends_with('…'));
        assert_eq!(truncate("short"), "short");
    }

    #[test]
    fn a_permanent_rejection_and_a_transient_one_are_told_apart() {
        // The retry policy, stated as data so a later edit to either half
        // has to come here and change the expectation.
        assert!(!retryable_status(400), "a rejected request stays rejected");
        assert!(!retryable_status(401), "a bad token stays bad");
        assert!(!retryable_status(403));
        assert!(!retryable_status(404));
        assert!(retryable_status(408), "a receiver saying 'not now' is worth another go");
        assert!(retryable_status(429));
        assert!(retryable_status(500));
        assert!(retryable_status(503));
        assert!(!retryable_status(200));
        assert!(!retryable_status(302));
    }

    #[test]
    fn the_diagnostics_warning_waits_for_the_streak_it_promises() {
        // No record at all: nothing has been delivered, ever.
        assert_eq!(delivery_state(false, 0), "disabled");
        // Delivered, then a failure or two: visible, not yet alarming.
        assert_eq!(delivery_state(true, 0), "healthy");
        assert_eq!(delivery_state(true, 1), "degraded");
        assert_eq!(delivery_state(true, FAILURE_STREAK_THRESHOLD - 1), "degraded");
        // At the threshold the page warns.
        assert_eq!(delivery_state(true, FAILURE_STREAK_THRESHOLD), "failing");
        assert_eq!(delivery_state(true, FAILURE_STREAK_THRESHOLD + 40), "failing");
    }

    #[test]
    fn a_record_never_carries_the_message_it_delivered() {
        // The record is written from the outcome only. If a payload field
        // ever appears here, the doc stops being safe to serve to every
        // operator.
        let attempt = Attempt {
            ok: false,
            http_code: Some(500),
            latency_ms: 12,
            tries: 3,
            error: Some("HTTP 500 Internal Server Error".to_string()),
        };
        let doc = attempt.to_doc("2026-09-27T00:00:00Z");
        let fields: Vec<&String> = doc.as_object().expect("object").keys().collect();
        assert_eq!(
            fields,
            vec!["at", "error", "http_code", "latency_ms", "status", "tries"],
            "exactly the outcome, in the documented shape"
        );
        assert_eq!(doc["status"], "failed");
        assert_eq!(doc["http_code"], 500);
        assert!(doc.get("content").is_none(), "no payload field");
        assert!(doc.get("text").is_none(), "no payload field");
    }

    #[test]
    fn a_delivered_attempt_reads_as_delivered() {
        let attempt = Attempt { ok: true, http_code: Some(204), latency_ms: 41, tries: 1, error: None };
        let doc = attempt.to_doc("2026-09-27T00:00:00Z");
        assert_eq!(doc["status"], "delivered");
        assert_eq!(doc["http_code"], 204);
        assert_eq!(doc["error"], Value::Null);
    }
}
