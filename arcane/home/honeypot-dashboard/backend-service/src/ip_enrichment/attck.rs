//! Ported from ip-enrichment-worker/attck.go, then widened per #1611
//! workstream D: writes canonical_attck_techniques after canonical-field
//! promotion has already set canonical_command/canonical_user/
//! canonical_pass/canonical_fingerprint/canonical_shasum for this event.
//! attck.go's own header deliberately deferred T1190 and the ICS pair
//! (T0886/T1692.001) to "the ES-coverage round" — this is that round: they
//! now promote here too, reading raw per-persona fields directly (path,
//! proto, app_function, request, event-kind) since not every sensor these
//! techniques apply to goes through canonical-field promotion at all
//! (conpot/dnp3 have no promote_*_fields case — see canonical.rs — and
//! several bespoke sensors only promote a subset of fields).
//! kill_chain.rs's supplemental filter-aggregations for these three
//! techniques are removed in the same change that lands this, now that a
//! real canonical_attck_techniques tag covers them.

use serde_json::Value;

fn str(e: &Value, key: &str) -> String {
    e.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

const ICS_PROTOCOLS: &[&str] = &["modbus", "s7comm", "iec104", "dnp3", "enip", "bacnet"];

/// Must run after canonical-field promotion — reads its output for the
/// techniques that depend on it, but also reads raw per-persona fields
/// directly for T0886/T1692.001/T1190, which apply to personas (conpot,
/// dnp3, several web-facing bespoke sensors) that canonical promotion
/// never covers.
pub fn promote_attck_technique_fields(persona: &str, e: &mut Value) -> bool {
    let mut ids: Vec<String> = Vec::new();

    let user = str(e, "canonical_user");
    let pass = str(e, "canonical_pass");
    let has_creds = !user.is_empty() || !pass.is_empty();
    // #1611 workstream D: the legacy dashboard heuristic tags T1110 on
    // IsLogin || HasCredential, not credential-presence alone — an empty-
    // password login *attempt* (the overwhelming majority of cowrie's own
    // login.failed traffic) is exactly the brute-force signal this
    // technique names, and was previously invisible here whenever the
    // password happened to be blank.
    if has_creds || is_login_attempt(persona, e) {
        ids.push("T1110".to_string());
    }

    let command = str(e, "canonical_command");
    if !command.is_empty() {
        ids.push(attck_command_technique(&command).to_string());
    }

    let lower_command = command.to_lowercase();
    let shasum = str(e, "canonical_shasum");
    if !shasum.is_empty()
        || lower_command.contains("wget")
        || lower_command.contains("curl")
        || lower_command.contains("invoke-webrequest")
        || lower_command.contains("downloadstring")
    {
        ids.push("T1105".to_string());
    }

    let fingerprint = str(e, "canonical_fingerprint");
    if !fingerprint.is_empty() && command.is_empty() && !has_creds {
        ids.push("T1595".to_string());
    }

    // #1611 workstream D: ICS interaction (T0886) + a write/command
    // escalation on top of it (T1692.001) — mirrors kill_chain.rs's
    // now-removed ics_filter()/ics_write supplemental aggs, moved to
    // promotion time so every downstream consumer (kill-chain sankey,
    // ATT&CK coverage grid, campaign timeline, attacker-identity-worker's
    // own Techniques field) sees a real tag instead of a query-time
    // approximation.
    if is_ics_interaction(persona, e) {
        ids.push("T0886".to_string());
        if is_ics_write(persona, e) {
            ids.push("T1692.001".to_string());
        }
    }

    // #1611 workstream D: web-exploit probe (T1190) — mirrors
    // kill_chain.rs's now-removed web_exploit supplemental agg (itself
    // already an ES-query adaptation of dashboard/intelligence.go's own
    // path-substring heuristic, since honeypot.* is flattened and can't
    // run wildcard queries) — promoted here with the same substring checks
    // now that we're working against the raw JSON line, not a query DSL.
    if is_web_exploit(persona, e) {
        ids.push("T1190".to_string());
    }

    if ids.is_empty() {
        return false;
    }
    e["canonical_attck_techniques"] = Value::from(unique_attck_ids(ids));
    true
}

/// True for a login event/attempt regardless of whether credentials ended
/// up non-empty — matches the legacy dashboard's IsLogin || HasCredential
/// gate for T1110, which credential-presence alone under-counts (cowrie
/// logs login.failed with an empty password far more often than a
/// populated one).
fn is_login_attempt(persona: &str, e: &Value) -> bool {
    let eventid = str(e, "eventid");
    if eventid.starts_with("cowrie.login.") || eventid == "cowrie.telnet.exploit_success" {
        return true;
    }
    if str(e, "event") == "login" || str(e, "event") == "auth_attempt" {
        return true;
    }
    // rdp-honeypot's auth rides on a plain "connect" with a non-empty
    // username (mstshash) — no dedicated login/auth_attempt kind of its
    // own, matching workstream C's own logins_filter() precedent.
    persona == "rdp-honeypot" && str(e, "event") == "connect" && e.get("username").and_then(Value::as_str).is_some_and(|u| !u.is_empty())
}

/// True for any event this worker already knows is an ICS protocol
/// interaction: every conpot persona and dnp3 tail this worker watches
/// directly, or any other persona whose event names an ICS protocol
/// (matches kill_chain.rs's now-removed ics_filter()).
fn is_ics_interaction(persona: &str, e: &Value) -> bool {
    if persona.starts_with("conpot") || persona == "dnp3" {
        return true;
    }
    let proto = {
        let p = str(e, "proto");
        if !p.is_empty() { p } else { str(e, "protocol") }
    };
    ICS_PROTOCOLS.contains(&proto.to_lowercase().as_str())
}

/// True when an ICS interaction (already confirmed by is_ics_interaction)
/// is a write/command, not just a read/probe — dnp3's own app_function
/// (e.g. direct_operate) being present, a conpot request that isn't empty
/// (the decoy only ever populates "request" for an actual protocol
/// request, not a bare connection), or an explicit command/write event
/// kind on any other ICS-tagged persona (multipot's own ICS protocol
/// handlers included).
fn is_ics_write(persona: &str, e: &Value) -> bool {
    if persona == "dnp3" {
        return !str(e, "app_function").is_empty();
    }
    if persona.starts_with("conpot") {
        return !str(e, "request").is_empty();
    }
    let kind = str(e, "event");
    kind == "command" || kind == "write"
}

/// True for a web-exploit probe — mirrors kill_chain.rs's now-removed
/// web_exploit supplemental agg: a request path present, combined with
/// either a query string, a path-traversal/PHP/wp- marker, or an explicit
/// exploit-tagged event this pipeline already names outright (CVE payload
/// captures, cisco's method_pri, elasticpot's own attack event, or a
/// tanner emulator detection that isn't the bare "index" default).
fn is_web_exploit(persona: &str, e: &Value) -> bool {
    if e.get("cve_2019_19781_payload").is_some()
        || e.get("cve_2018_0101_payload").is_some()
        || e.get("cve_2017_0144_payload").is_some()
    {
        return true;
    }
    let eventid = str(e, "eventid");
    let kind = str(e, "event");
    if kind == "method_pri" || eventid == "elasticpot.attack" {
        return true;
    }
    if persona == "tanner" {
        if let Some(name) = e
            .get("response_msg")
            .and_then(|r| r.get("response"))
            .and_then(|r| r.get("message"))
            .and_then(|m| m.get("detection"))
            .and_then(|d| d.get("name"))
            .and_then(Value::as_str)
        {
            if !name.is_empty() && name != "index" {
                return true;
            }
        }
    }

    let path = str(e, "path");
    if path.is_empty() {
        return false;
    }
    if e.get("query").is_some() {
        return true;
    }
    let lower = path.to_lowercase();
    lower.contains('?') || lower.contains('%') || lower.contains("../") || lower.contains("wp-") || lower.ends_with(".php") || lower.contains(".php?")
}

/// Mirrors techniquesForEvent's own command sub-classification exactly.
fn attck_command_technique(command: &str) -> &'static str {
    let text = command.to_lowercase();
    if text.contains("powershell") || text.contains("pwsh") {
        "T1059.001"
    } else if text.contains("cmd.exe") || text.contains("cmd /c") {
        "T1059.003"
    } else if text.contains("/bin/sh") || text.contains("bash") || text.contains("wget") || text.contains("curl") {
        "T1059.004"
    } else {
        "T1059"
    }
}

fn unique_attck_ids(ids: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    ids.into_iter().filter(|id| seen.insert(id.clone())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn credentials_promote_t1110() {
        let mut e = json!({"canonical_user": "root", "canonical_pass": "toor"});
        assert!(promote_attck_technique_fields("cowrie", &mut e));
        assert_eq!(e["canonical_attck_techniques"], json!(["T1110"]));
    }

    #[test]
    fn empty_password_login_attempt_still_promotes_t1110() {
        let mut e = json!({"eventid": "cowrie.login.failed", "username": "root", "password": ""});
        assert!(promote_attck_technique_fields("cowrie", &mut e));
        assert_eq!(e["canonical_attck_techniques"], json!(["T1110"]));
    }

    #[test]
    fn rdp_connect_with_username_promotes_t1110() {
        let mut e = json!({"event": "connect", "username": "mstshash-abc"});
        assert!(promote_attck_technique_fields("rdp-honeypot", &mut e));
        assert_eq!(e["canonical_attck_techniques"], json!(["T1110"]));
    }

    #[test]
    fn powershell_command_promotes_t1059_001_and_t1105_via_downloadstring() {
        let mut e = json!({"canonical_command": "powershell -c IEX (New-Object Net.WebClient).DownloadString(...)"});
        assert!(promote_attck_technique_fields("cowrie", &mut e));
        let ids = e["canonical_attck_techniques"].as_array().unwrap();
        assert!(ids.iter().any(|v| v == "T1059.001"));
        assert!(ids.iter().any(|v| v == "T1105"));
    }

    #[test]
    fn bare_fingerprint_with_no_command_or_creds_promotes_t1595() {
        let mut e = json!({"canonical_fingerprint": "aa:bb"});
        assert!(promote_attck_technique_fields("cowrie", &mut e));
        assert_eq!(e["canonical_attck_techniques"], json!(["T1595"]));
    }

    #[test]
    fn nothing_promoted_is_not_a_change() {
        let mut e = json!({});
        assert!(!promote_attck_technique_fields("cowrie", &mut e));
    }

    #[test]
    fn conpot_persona_promotes_t0886() {
        let mut e = json!({"event_type": "NEW_CONNECTION"});
        assert!(promote_attck_technique_fields("conpot-s7-1200", &mut e));
        assert_eq!(e["canonical_attck_techniques"], json!(["T0886"]));
    }

    #[test]
    fn conpot_with_nonempty_request_promotes_t1692_001_too() {
        let mut e = json!({"data_type": "modbus", "request": "write_coil"});
        assert!(promote_attck_technique_fields("conpot", &mut e));
        let ids = e["canonical_attck_techniques"].as_array().unwrap();
        assert!(ids.iter().any(|v| v == "T0886"));
        assert!(ids.iter().any(|v| v == "T1692.001"));
    }

    #[test]
    fn dnp3_with_app_function_promotes_both_ics_techniques() {
        let mut e = json!({"function": "link", "app_function": "direct_operate"});
        assert!(promote_attck_technique_fields("dnp3", &mut e));
        let ids = e["canonical_attck_techniques"].as_array().unwrap();
        assert!(ids.iter().any(|v| v == "T0886"));
        assert!(ids.iter().any(|v| v == "T1692.001"));
    }

    #[test]
    fn dnp3_without_app_function_is_ics_read_only() {
        let mut e = json!({"function": "link"});
        assert!(promote_attck_technique_fields("dnp3", &mut e));
        assert_eq!(e["canonical_attck_techniques"], json!(["T0886"]));
    }

    #[test]
    fn path_traversal_promotes_t1190() {
        let mut e = json!({"path": "/../../../../etc/passwd"});
        assert!(promote_attck_technique_fields("citrix-honeypot", &mut e));
        assert_eq!(e["canonical_attck_techniques"], json!(["T1190"]));
    }

    #[test]
    fn plain_path_with_no_markers_does_not_promote_t1190() {
        let mut e = json!({"path": "/"});
        assert!(!promote_attck_technique_fields("hellpot", &mut e));
    }

    #[test]
    fn explicit_cve_payload_event_promotes_t1190() {
        let mut e = json!({"cve_2019_19781_payload": {"raw": "..."}});
        assert!(promote_attck_technique_fields("citrix-honeypot", &mut e));
        assert_eq!(e["canonical_attck_techniques"], json!(["T1190"]));
    }

    #[test]
    fn tanner_real_detection_promotes_t1190_but_index_default_does_not() {
        let mut real = json!({"response_msg": {"response": {"message": {"detection": {"name": "sqli"}}}}});
        assert!(promote_attck_technique_fields("tanner", &mut real));
        assert_eq!(real["canonical_attck_techniques"], json!(["T1190"]));

        let mut default = json!({"response_msg": {"response": {"message": {"detection": {"name": "index"}}}}});
        assert!(!promote_attck_technique_fields("tanner", &mut default));
    }
}
