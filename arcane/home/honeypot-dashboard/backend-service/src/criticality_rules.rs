//! agent-intrusion-worker port (#1610), criticality_rules.py half:
//! deterministic, stateless detection rules over raw sensor-shaped event
//! structure — never an LLM verdict. Each rule is independent;
//! evaluate_event() returns every rule that matched, not just the first —
//! an event tripping multiple trust-boundary categories at once is itself
//! part of the signal (see campaign_severity, which counts distinct rule
//! categories across a campaign).

use crate::decode_correlate::{self, DecodeStep};
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::LazyLock;

const SENSITIVE_PATHS: &[&str] = &[
    "/proc/self/environ",
    "/proc/1/environ",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
];

/// (transform name, decoder) — the candidate exfil-encoding attempts tried
/// in the DNS/HTTP-label decode loop below.
type DecodeAttempt = (&'static str, Box<dyn Fn(&str) -> Option<Vec<u8>>>);

const NAMED_ACTORS: &[&str] = &[
    "admin",
    "system",
    "hp-autoheal",
    "dependabot[bot]",
    "github-actions[bot]",
];

pub const METADATA_SERVICE_IP: &str = "169.254.169.254";

/// Planted breadcrumb hostnames mapped to the real sensor each one's real,
/// portbridge-forwarded port actually reaches.
pub static BREADCRUMB_TARGETS: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| {
        HashMap::from([
            ("bastion02", "beelzebub"),
            ("dc01", "beelzebub"),
            ("agent-gateway-01", "beelzebub"),
            ("cms-legacy-01", "beelzebub"),
            ("analytics-es-04", "elasticpot"),
        ])
    });

#[derive(Debug, Clone, PartialEq)]
pub struct RuleMatch {
    pub rule: String,
    pub reason: String,
    pub decode_chain: Vec<DecodeStep>,
}

impl RuleMatch {
    fn new(rule: &str, reason: impl Into<String>) -> Self {
        Self {
            rule: rule.to_string(),
            reason: reason.into(),
            decode_chain: Vec::new(),
        }
    }

    fn with_chain(rule: &str, reason: impl Into<String>, chain: Vec<DecodeStep>) -> Self {
        Self {
            rule: rule.to_string(),
            reason: reason.into(),
            decode_chain: chain,
        }
    }
}

fn s<'a>(raw: &'a serde_json::Value, field: &str) -> &'a str {
    raw.get(field).and_then(|v| v.as_str()).unwrap_or("")
}

fn cowrie_input(raw: &serde_json::Value) -> &str {
    if s(raw, "eventid").starts_with("cowrie.") {
        s(raw, "input")
    } else {
        ""
    }
}

pub fn rule_sensitive_path_read(raw: &serde_json::Value) -> Option<RuleMatch> {
    let text = cowrie_input(raw);
    for path in SENSITIVE_PATHS {
        if text.contains(path) {
            return Some(RuleMatch::new(
                "sensitive-path-read",
                format!("command references {path}"),
            ));
        }
    }
    None
}

pub fn rule_chunked_c2_protocol(raw: &serde_json::Value) -> Option<RuleMatch> {
    let text = {
        let input = s(raw, "input");
        if !input.is_empty() {
            input
        } else {
            s(raw, "payload_printable")
        }
    };
    let msg = decode_correlate::parse_chunk_message(text)?;
    Some(RuleMatch::new(
        "chunked-c2-protocol",
        format!(
            "type={} channel={} seq={}",
            msg.msg_type, msg.channel, msg.seq
        ),
    ))
}

static EXEC_EVAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bexec\s*\(|\beval\s*\(").unwrap());

pub fn rule_encoded_execution(raw: &serde_json::Value) -> Option<RuleMatch> {
    let text = cowrie_input(raw);
    if text.is_empty() || !EXEC_EVAL_RE.is_match(text) {
        return None;
    }
    let blob = decode_correlate::extract_candidate_blob(text)?;
    let result = decode_correlate::bounded_decode(
        blob.as_bytes(),
        decode_correlate::MAX_DEPTH,
        decode_correlate::MAX_OUTPUT_BYTES,
    );
    if result.ok {
        let preview: String = String::from_utf8_lossy(&result.output)
            .chars()
            .take(60)
            .collect();
        return Some(RuleMatch::with_chain(
            "encoded-execution",
            format!("verified decode: {preview:?}"),
            result.chain,
        ));
    }
    None
}

/// Deliberately *relative* (same /24 as the source), not an absolute
/// RFC1918-membership check — RFC1918-only misreads RFC5737 TEST-NET
/// traffic (this corpus's own safety constraint) as external even when
/// both addresses are on the same segment. A same-/24 check sidesteps the
/// whole problem, see the Python source's own extended rationale.
fn same_segment(src: &str, dest: &str) -> bool {
    let (Ok(src_addr), Ok(dest_addr)) = (src.parse::<IpAddr>(), dest.parse::<IpAddr>()) else {
        return false;
    };
    if dest_addr.is_loopback() {
        return true;
    }
    if let IpAddr::V4(dest_v4) = dest_addr {
        if dest_v4.is_link_local() {
            return true;
        }
    }
    if src_addr == dest_addr {
        return true;
    }
    match (src_addr, dest_addr) {
        (IpAddr::V4(s), IpAddr::V4(d)) => s.octets()[..3] == d.octets()[..3],
        _ => false,
    }
}

pub fn rule_encoded_egress_external(raw: &serde_json::Value) -> Option<RuleMatch> {
    let src = raw.get("src_ip").and_then(|v| v.as_str())?;
    let dest = raw.get("dest_ip").and_then(|v| v.as_str())?;
    if same_segment(src, dest) {
        return None;
    }

    let mut candidates: Vec<String> = Vec::new();
    if let Some(payload) = raw.get("payload_printable").and_then(|v| v.as_str()) {
        if let Some(blob) = decode_correlate::extract_candidate_blob(payload) {
            candidates.push(blob);
        }
    }
    if let Some(rrname) = raw
        .get("dns")
        .and_then(|d| d.get("rrname"))
        .and_then(|v| v.as_str())
    {
        if let Some(label) = rrname.split('.').next() {
            candidates.push(label.to_string());
        }
    }

    for blob in candidates {
        // "raw": the HTTP-payload candidate is checked as already-plaintext
        // bytes (no decode applied) — an interchangeable exfil transport
        // alongside DNS-label base32, not a placeholder.
        let attempts: [DecodeAttempt; 2] = [
            ("raw", Box::new(|b: &str| Some(b.as_bytes().to_vec()))),
            (
                "base32",
                Box::new(|b: &str| {
                    let padded =
                        format!("{}{}", b.to_uppercase(), "=".repeat((8 - b.len() % 8) % 8));
                    data_encoding::BASE32.decode(padded.as_bytes()).ok()
                }),
            ),
        ];
        for (transform, decoder) in attempts {
            let Some(data) = decoder(&blob) else { continue };
            if !data.is_empty() && decode_correlate::looks_like_text(&data) {
                use sha2::{Digest, Sha256};
                let hex = |b: &[u8]| -> String {
                    let mut h = Sha256::new();
                    h.update(b);
                    h.finalize().iter().map(|x| format!("{x:02x}")).collect()
                };
                let step = DecodeStep {
                    transform: transform.to_string(),
                    input_sha256: hex(blob.as_bytes()),
                    output_sha256: hex(&data),
                    output_len: data.len(),
                };
                let dest = dest.to_string();
                return Some(RuleMatch::with_chain(
                    "encoded-egress-external",
                    format!("decodable payload toward external {dest}"),
                    vec![step],
                ));
            }
        }
    }
    None
}

pub fn rule_metadata_service_probe(raw: &serde_json::Value) -> Option<RuleMatch> {
    if raw.get("dest_ip").and_then(|v| v.as_str()) == Some(METADATA_SERVICE_IP) {
        return Some(RuleMatch::new(
            "metadata-service-probe",
            "destination is the cloud metadata link-local address",
        ));
    }
    None
}

pub fn rule_privileged_container_create(raw: &serde_json::Value) -> Option<RuleMatch> {
    if raw.get("event").and_then(|v| v.as_str()) != Some("container_create") {
        return None;
    }
    let flags: Vec<&str> = raw
        .get("flags")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .collect();
    if flags.contains(&"--privileged") {
        return Some(RuleMatch::new(
            "privileged-container-create",
            format!("flags={flags:?}"),
        ));
    }
    None
}

pub fn rule_broad_scope_identity_token(raw: &serde_json::Value) -> Option<RuleMatch> {
    let event = raw.get("event").and_then(|v| v.as_str());
    if !matches!(event, Some("token_mint") | Some("token_mint_attempt")) {
        return None;
    }
    let scope = raw
        .get("requested_scope")
        .map(|v| v.to_string())
        .unwrap_or_default();
    let scope_str = raw
        .get("requested_scope")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let ttl = raw
        .get("requested_ttl_hours")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let actor = raw.get("actor").and_then(|v| v.as_str());
    let suspicious_scope = scope_str.to_lowercase().contains("admin");
    let long_lived = ttl > 4.0;
    let unnamed_actor = actor.map(|a| !NAMED_ACTORS.contains(&a)).unwrap_or(true);
    if (suspicious_scope || long_lived) && unnamed_actor {
        return Some(RuleMatch::new(
            "broad-scope-identity-token",
            format!("scope={scope:?} ttl={ttl}h actor={actor:?}"),
        ));
    }
    None
}

pub fn rule_covert_mesh_enrollment(raw: &serde_json::Value) -> Option<RuleMatch> {
    let args: Vec<&str> = raw
        .get("process_args")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str())
        .collect();
    let joined = args.join(" ");
    if joined.contains("--no-logs") || joined.contains("state=mem") {
        return Some(RuleMatch::new(
            "covert-mesh-enrollment",
            format!("process_args={args:?}"),
        ));
    }
    let signature = raw
        .get("alert")
        .and_then(|a| a.get("signature"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let lower = signature.to_lowercase();
    if lower.contains("mesh") && lower.contains("vpn") {
        return Some(RuleMatch::new(
            "covert-mesh-enrollment",
            format!("alert signature: {signature:?}"),
        ));
    }
    None
}

pub fn rule_internal_connector_enumeration(raw: &serde_json::Value) -> Option<RuleMatch> {
    if raw.get("event").and_then(|v| v.as_str()) != Some("api_request") {
        return None;
    }
    let endpoint = s(raw, "endpoint");
    let actor = raw.get("actor").and_then(|v| v.as_str());
    let unnamed = actor.map(|a| !NAMED_ACTORS.contains(&a)).unwrap_or(true);
    if endpoint.contains("connector") && unnamed {
        return Some(RuleMatch::new(
            "internal-connector-enumeration",
            format!("endpoint={endpoint:?} actor={actor:?}"),
        ));
    }
    None
}

pub fn rule_scm_write_unexpected_actor(raw: &serde_json::Value) -> Option<RuleMatch> {
    let event = raw.get("event").and_then(|v| v.as_str());
    let actor = raw.get("actor").and_then(|v| v.as_str());
    let unnamed = actor.map(|a| !NAMED_ACTORS.contains(&a)).unwrap_or(true);
    if event == Some("github_app_token_mint") && unnamed {
        return Some(RuleMatch::new(
            "scm-write-unexpected-actor",
            format!("github_app_token_mint by actor={actor:?}"),
        ));
    }
    let triggers = raw
        .get("triggers_workflow")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if event == Some("pull_request_opened") && triggers && unnamed {
        return Some(RuleMatch::new(
            "scm-write-unexpected-actor",
            format!("pull_request_opened by actor={actor:?}, triggers CI"),
        ));
    }
    None
}

pub fn rule_staged_payload_reference(raw: &serde_json::Value) -> Option<RuleMatch> {
    let text = cowrie_input(raw);
    if text.contains("/tmp/staged") {
        return Some(RuleMatch::new(
            "staged-payload-reference",
            "command references a known staging-directory path",
        ));
    }
    None
}

pub fn rule_breadcrumb_reference(raw: &serde_json::Value) -> Option<RuleMatch> {
    let text = cowrie_input(raw);
    for name in BREADCRUMB_TARGETS.keys() {
        if text.contains(name) {
            return Some(RuleMatch::new(
                "breadcrumb-reference",
                format!("command references planted breadcrumb {name:?}"),
            ));
        }
    }
    None
}

/// Dispatch order matches criticality_rules.py's own ALL_RULES tuple
/// exactly (12 entries — campaign_breadcrumb_followed is a distinct,
/// campaign-level check applied separately, not part of this per-event
/// list).
pub const ALL_RULES: &[fn(&serde_json::Value) -> Option<RuleMatch>] = &[
    rule_sensitive_path_read,
    rule_chunked_c2_protocol,
    rule_encoded_execution,
    rule_encoded_egress_external,
    rule_metadata_service_probe,
    rule_privileged_container_create,
    rule_broad_scope_identity_token,
    rule_covert_mesh_enrollment,
    rule_internal_connector_enumeration,
    rule_scm_write_unexpected_actor,
    rule_staged_payload_reference,
    rule_breadcrumb_reference,
];

pub fn evaluate_event(raw: &serde_json::Value) -> Vec<RuleMatch> {
    ALL_RULES.iter().filter_map(|rule| rule(raw)).collect()
}

/// The trust boundary crossed — a property of which rule matched, not of
/// any one event's own data.
pub static TRUST_BOUNDARIES: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        (
            "sensitive-path-read",
            "process/container -> host secret material",
        ),
        (
            "chunked-c2-protocol",
            "honeypot session -> external C2 channel",
        ),
        (
            "encoded-execution",
            "honeypot session -> local code execution",
        ),
        (
            "encoded-egress-external",
            "internal workload -> external network segment",
        ),
        (
            "metadata-service-probe",
            "workload -> cloud identity/metadata service",
        ),
        (
            "privileged-container-create",
            "workload -> host (root-equivalent)",
        ),
        (
            "broad-scope-identity-token",
            "workload -> orchestrator identity",
        ),
        ("covert-mesh-enrollment", "workload -> internal mesh/VPN"),
        (
            "internal-connector-enumeration",
            "mesh identity -> internal service catalog",
        ),
        (
            "scm-write-unexpected-actor",
            "workload/mesh identity -> source control",
        ),
        (
            "staged-payload-reference",
            "honeypot session -> local filesystem (staged artifacts)",
        ),
        (
            "breadcrumb-reference",
            "honeypot session -> named internal decoy asset (unconfirmed)",
        ),
        (
            "breadcrumb-followed",
            "honeypot session -> named internal decoy asset -> real target sensor (confirmed)",
        ),
    ])
});

/// Counts the *distinct* rule categories that fired anywhere in a
/// campaign (not the raw match count) and derives an overall severity.
pub fn campaign_severity(
    matched_rules_per_event: &HashMap<String, Vec<RuleMatch>>,
) -> (&'static str, std::collections::HashSet<String>) {
    let mut categories = std::collections::HashSet::new();
    for matches in matched_rules_per_event.values() {
        for m in matches {
            categories.insert(m.rule.clone());
        }
    }
    let severity = if categories.len() >= 3 {
        "critical"
    } else if !categories.is_empty() {
        "high"
    } else {
        "low"
    };
    (severity, categories)
}

/// The real "followed the breadcrumb" claim: requires BOTH, in order —
/// some event in this campaign matched breadcrumb-reference naming an
/// asset, AND a chronologically *later* event in the same campaign was
/// actually served by that asset's real target sensor.
/// `campaign_event_ids` must already be timestamp-sorted.
pub fn campaign_breadcrumb_followed(
    campaign_event_ids: &[String],
    events_by_id: &HashMap<String, serde_json::Value>,
    matches_per_event: &HashMap<String, Vec<RuleMatch>>,
) -> Option<(String, RuleMatch)> {
    let mut referenced_targets: std::collections::HashSet<&'static str> =
        std::collections::HashSet::new();
    for eid in campaign_event_ids {
        if let Some(matches) = matches_per_event.get(eid) {
            for m in matches {
                if m.rule == "breadcrumb-reference" {
                    for (name, target) in BREADCRUMB_TARGETS.iter() {
                        if m.reason.contains(name) {
                            referenced_targets.insert(target);
                        }
                    }
                }
            }
        }
        let sensor = events_by_id
            .get(eid)
            .and_then(|raw| raw.get("sensor"))
            .and_then(|v| v.as_str());
        if let Some(sensor) = sensor {
            if referenced_targets.contains(sensor) {
                return Some((
                    eid.clone(),
                    RuleMatch::new(
                        "breadcrumb-followed",
                        format!("referenced a breadcrumb pointing at {sensor:?}, then {sensor:?} was actually reached"),
                    ),
                ));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sensitive_path_read_matches_proc_environ() {
        let raw = json!({"eventid": "cowrie.command.input", "input": "cat /proc/self/environ"});
        assert!(rule_sensitive_path_read(&raw).is_some());
    }

    #[test]
    fn sensitive_path_read_ignores_unrelated_command() {
        let raw = json!({"eventid": "cowrie.command.input", "input": "ls -la /tmp"});
        assert!(rule_sensitive_path_read(&raw).is_none());
    }

    #[test]
    fn sensitive_path_read_ignores_non_cowrie_sensor() {
        let raw = json!({"event": "note", "input": "/proc/self/environ"});
        assert!(rule_sensitive_path_read(&raw).is_none());
    }

    #[test]
    fn chunked_c2_protocol_matches() {
        let raw = json!({"input": "curl -d 'type=stage&channel=ab12&seq=1&chk=x&data=AAAAAAAA'"});
        let m = rule_chunked_c2_protocol(&raw).unwrap();
        assert!(m.reason.contains("channel=ab12"));
    }

    fn gz_b64(payload: &[u8]) -> String {
        use base64::Engine;
        use std::io::Write;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(payload).unwrap();
        let compressed = enc.finish().unwrap();
        base64::engine::general_purpose::STANDARD.encode(compressed)
    }

    #[test]
    fn encoded_execution_requires_both_exec_and_verified_decode() {
        let blob = gz_b64(b"id");
        let raw = json!({"eventid": "cowrie.command.input", "input": format!("python3 -c \"exec(gzip.decompress(base64.b64decode('{blob}')))\"")});
        assert!(rule_encoded_execution(&raw).is_some());
    }

    #[test]
    fn encoded_execution_ignores_exec_without_decodable_payload() {
        let raw = json!({"eventid": "cowrie.command.input", "input": "exec('id')"});
        assert!(rule_encoded_execution(&raw).is_none());
    }

    #[test]
    fn encoded_execution_populates_decode_chain() {
        let blob = gz_b64(b"id");
        let raw = json!({"eventid": "cowrie.command.input", "input": format!("python3 -c \"exec(gzip.decompress(base64.b64decode('{blob}')))\"")});
        let m = rule_encoded_execution(&raw).unwrap();
        assert!(!m.decode_chain.is_empty());
        assert_eq!(m.decode_chain[0].transform, "base64");
        assert!(m.decode_chain.iter().any(|step| step.transform == "gzip"));
        assert_eq!(m.decode_chain.last().unwrap().output_sha256.len(), 64);
    }

    #[test]
    fn encoded_egress_external_populates_decode_chain() {
        let raw = json!({"src_ip": "10.0.0.5", "dest_ip": "8.8.8.8", "payload_printable": "GET /x?data=aGVsbG93b3JsZA== HTTP/1.1"});
        let m = rule_encoded_egress_external(&raw).unwrap();
        assert_eq!(m.decode_chain.len(), 1);
        assert_eq!(m.decode_chain[0].transform, "raw");
        assert_eq!(m.decode_chain[0].output_sha256.len(), 64);
    }

    #[test]
    fn metadata_service_probe_matches_link_local_address() {
        let raw = json!({"dest_ip": "169.254.169.254"});
        assert!(rule_metadata_service_probe(&raw).is_some());
    }

    #[test]
    fn privileged_container_create_matches() {
        let raw = json!({"event": "container_create", "flags": ["--privileged", "-v", "/:/host"]});
        assert!(rule_privileged_container_create(&raw).is_some());
    }

    #[test]
    fn privileged_container_create_ignores_unprivileged() {
        let raw = json!({"event": "container_create", "flags": ["--rm"]});
        assert!(rule_privileged_container_create(&raw).is_none());
    }

    #[test]
    fn broad_scope_identity_token_matches_admin_scope_unnamed_actor() {
        let raw = json!({"event": "token_mint_attempt", "requested_scope": "cluster-admin", "requested_ttl_hours": 24, "actor": "unknown"});
        assert!(rule_broad_scope_identity_token(&raw).is_some());
    }

    #[test]
    fn broad_scope_identity_token_ignores_narrow_named_request() {
        let raw = json!({"event": "token_mint", "requested_scope": "introspection", "requested_ttl_hours": 1, "actor": "admin"});
        assert!(rule_broad_scope_identity_token(&raw).is_none());
    }

    #[test]
    fn broad_scope_identity_token_ignores_admin_scope_from_named_actor() {
        let raw = json!({"event": "token_mint", "requested_scope": "admin", "requested_ttl_hours": 1, "actor": "admin"});
        assert!(rule_broad_scope_identity_token(&raw).is_none());
    }

    #[test]
    fn covert_mesh_enrollment_matches_process_args() {
        let raw = json!({"process_args": ["--state=mem:", "--no-logs-no-support"]});
        assert!(rule_covert_mesh_enrollment(&raw).is_some());
    }

    #[test]
    fn covert_mesh_enrollment_matches_alert_signature() {
        let raw =
            json!({"alert": {"signature": "LOCAL Mesh-VPN Client Enrollment (unexpected source)"}});
        assert!(rule_covert_mesh_enrollment(&raw).is_some());
    }

    #[test]
    fn internal_connector_enumeration_matches_unnamed_actor() {
        let raw = json!({"event": "api_request", "endpoint": "/internal/connectors/catalog", "actor": "unknown"});
        assert!(rule_internal_connector_enumeration(&raw).is_some());
    }

    #[test]
    fn scm_write_unexpected_actor_matches_token_mint() {
        let raw = json!({"event": "github_app_token_mint", "actor": "unknown"});
        assert!(rule_scm_write_unexpected_actor(&raw).is_some());
    }

    #[test]
    fn scm_write_unexpected_actor_ignores_dependabot() {
        let raw = json!({"event": "pull_request_opened", "actor": "dependabot[bot]", "triggers_workflow": true});
        assert!(rule_scm_write_unexpected_actor(&raw).is_none());
    }

    #[test]
    fn staged_payload_reference_matches() {
        let raw =
            json!({"eventid": "cowrie.command.input", "input": "ls -la /tmp/staged; hostname"});
        assert!(rule_staged_payload_reference(&raw).is_some());
    }

    #[test]
    fn evaluate_event_returns_every_match_not_just_first() {
        let raw = json!({"eventid": "cowrie.command.input", "input": "cat /proc/self/environ > /tmp/staged/out"});
        let matches = evaluate_event(&raw);
        let names: std::collections::HashSet<&str> =
            matches.iter().map(|m| m.rule.as_str()).collect();
        assert!(names.contains("sensitive-path-read"));
        assert!(names.contains("staged-payload-reference"));
    }

    #[test]
    fn same_24_is_internal() {
        assert!(same_segment("192.0.2.60", "192.0.2.61"));
    }

    #[test]
    fn different_24_is_external() {
        assert!(!same_segment("192.0.2.50", "198.51.100.53"));
    }

    #[test]
    fn real_rfc1918_same_segment_still_works() {
        assert!(same_segment("10.1.2.3", "10.1.2.4"));
    }

    #[test]
    fn loopback_destination_is_always_internal() {
        assert!(same_segment("192.0.2.50", "127.0.0.1"));
    }

    #[test]
    fn link_local_destination_is_always_internal() {
        assert!(same_segment("192.0.2.50", "169.254.1.1"));
    }

    #[test]
    fn low_severity_for_pure_recon() {
        let matches = HashMap::from([("e1".to_string(), vec![]), ("e2".to_string(), vec![])]);
        assert_eq!(campaign_severity(&matches).0, "low");
    }

    #[test]
    fn high_severity_for_one_category() {
        let matches = HashMap::from([(
            "e1".to_string(),
            vec![RuleMatch::new("sensitive-path-read", "x")],
        )]);
        assert_eq!(campaign_severity(&matches).0, "high");
    }

    #[test]
    fn critical_severity_for_three_or_more_categories() {
        let matches = HashMap::from([
            (
                "e1".to_string(),
                vec![RuleMatch::new("sensitive-path-read", "x")],
            ),
            (
                "e2".to_string(),
                vec![RuleMatch::new("metadata-service-probe", "x")],
            ),
            (
                "e3".to_string(),
                vec![RuleMatch::new("covert-mesh-enrollment", "x")],
            ),
        ]);
        assert_eq!(campaign_severity(&matches).0, "critical");
    }

    #[test]
    fn repeated_category_does_not_inflate_severity() {
        let matches = HashMap::from([
            (
                "e1".to_string(),
                vec![RuleMatch::new("sensitive-path-read", "x")],
            ),
            (
                "e2".to_string(),
                vec![RuleMatch::new("sensitive-path-read", "y")],
            ),
        ]);
        let (severity, categories) = campaign_severity(&matches);
        assert_eq!(severity, "high");
        assert_eq!(
            categories,
            std::collections::HashSet::from(["sensitive-path-read".to_string()])
        );
    }

    #[test]
    fn breadcrumb_reference_alone_does_not_match_followed() {
        let events_by_id = HashMap::from([(
            "e1".to_string(),
            json!({"eventid": "cowrie.command.input", "input": "cat internal-services.txt", "sensor": "cowrie"}),
        )]);
        let matches = HashMap::from([("e1".to_string(), evaluate_event(&events_by_id["e1"]))]);
        assert!(
            campaign_breadcrumb_followed(&["e1".to_string()], &events_by_id, &matches).is_none()
        );
    }

    #[test]
    fn breadcrumb_reference_then_reaching_target_sensor_matches() {
        let events_by_id = HashMap::from([
            (
                "e1".to_string(),
                json!({"eventid": "cowrie.command.input", "input": "ssh bastion02", "sensor": "cowrie"}),
            ),
            (
                "e2".to_string(),
                json!({"sensor": "beelzebub", "src_ip": "203.0.113.9"}),
            ),
        ]);
        let ids = vec!["e1".to_string(), "e2".to_string()];
        let matches: HashMap<String, Vec<RuleMatch>> = ids
            .iter()
            .map(|eid| (eid.clone(), evaluate_event(&events_by_id[eid])))
            .collect();
        let (eid, m) = campaign_breadcrumb_followed(&ids, &events_by_id, &matches).unwrap();
        assert_eq!(eid, "e2");
        assert_eq!(m.rule, "breadcrumb-followed");
    }

    #[test]
    fn breadcrumb_reaching_target_before_reference_does_not_match() {
        let events_by_id = HashMap::from([
            (
                "e1".to_string(),
                json!({"sensor": "beelzebub", "src_ip": "203.0.113.9"}),
            ),
            (
                "e2".to_string(),
                json!({"eventid": "cowrie.command.input", "input": "ssh bastion02", "sensor": "cowrie"}),
            ),
        ]);
        let ids = vec!["e1".to_string(), "e2".to_string()];
        let matches: HashMap<String, Vec<RuleMatch>> = ids
            .iter()
            .map(|eid| (eid.clone(), evaluate_event(&events_by_id[eid])))
            .collect();
        assert!(campaign_breadcrumb_followed(&ids, &events_by_id, &matches).is_none());
    }

    #[test]
    fn breadcrumb_wrong_target_sensor_does_not_match() {
        let events_by_id = HashMap::from([
            (
                "e1".to_string(),
                json!({"eventid": "cowrie.command.input", "input": "cat /etc/hosts | grep dc01", "sensor": "cowrie"}),
            ),
            (
                "e2".to_string(),
                json!({"sensor": "elasticpot", "src_ip": "203.0.113.9"}),
            ),
        ]);
        let ids = vec!["e1".to_string(), "e2".to_string()];
        let matches: HashMap<String, Vec<RuleMatch>> = ids
            .iter()
            .map(|eid| (eid.clone(), evaluate_event(&events_by_id[eid])))
            .collect();
        assert!(campaign_breadcrumb_followed(&ids, &events_by_id, &matches).is_none());
    }
}
