//! Ported from ip-enrichment-worker/canonical.go: mirrors
//! dashboard/classify.go's per-sensor field mapping (TopCreds, TopCommands,
//! fingerprints, client version, payload hash), promoting them as flat
//! canonical_* top-level keys at ingest time so a live Elasticsearch terms
//! aggregation can eventually replace the dashboard's own in-process
//! per-cycle recomputation. This only makes the data available.
//!
//! Scope: cowrie, dionaea (+ dionaea_incident.json), and cisco-asa-honeypot
//! — the sensor families this worker watches for IP resolution that also
//! have a creds/command/fingerprint/client-version field in classify.go —
//! plus multipot/tanner/http-honeypot/citrix-honeypot/rdp-honeypot,
//! watched purely for field normalization. dns-honeypot and every conpot
//! persona are also watched but classify.go sets none of these fields for
//! them, so there is nothing to promote for those two.

use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

static HASH_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{32,64}$").unwrap());

/// Returns whether `e` was mutated.
pub fn promote_canonical_fields(persona: &str, e: &mut Value) -> bool {
    match persona {
        "cowrie" => promote_cowrie_fields(e),
        "dionaea" => promote_dionaea_fields(e),
        "dionaea-incident" => promote_dionaea_incident_fields(e),
        "multipot" => promote_multipot_fields(e),
        "mailoney" => promote_mailoney_fields(e),
        "beelzebub" => promote_beelzebub_fields(e),
        "citrix-honeypot" => promote_citrix_fields(e),
        "rdp-honeypot" => promote_rdp_fields(e),
        "tanner" | "http-honeypot" => promote_web_request_fields(persona, e),
        "cisco-asa-honeypot" => promote_cisco_asa_fields(e),
        _ => false,
    }
}

/// Ported verbatim from dashboard/links.go so canonical_user/canonical_pass
/// are only ever promoted when they'd actually count toward TopCreds today.
pub fn valid_credential_pair(user: &str, pass: &str) -> bool {
    if (user.is_empty() && pass.is_empty()) || user.len() > 128 || pass.len() > 512 {
        return false;
    }
    for value in [user, pass] {
        let lower = value.to_lowercase();
        if value.contains(['\0', '\r', '\n']) || lower.contains("\\x00") || lower.contains("\\u0000") {
            return false;
        }
    }
    if user.contains([' ', '\t', '/', ';', '|', '&', '<', '>']) {
        return false;
    }
    let lower_pass = pass.trim().to_lowercase();
    for marker in ["/bin/", "busybox", "linuxshell", "powershell", "cmd.exe"] {
        if lower_pass.contains(marker) {
            return false;
        }
    }
    true
}

fn str(e: &Value, key: &str) -> String {
    e.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// #1611 workstream G: telnet attackers embed NUL/control bytes in
/// credentials; stripped here (at ingest, before the enriched line is
/// written) rather than only display-side so every downstream consumer —
/// ES terms aggs, attackers-v1 `credentials`, search grouping — sees one
/// clean bucket instead of "root" and "root\0\0\0" splitting into two.
/// Mirrors dashboard.rs's `clean()`, kept there unchanged for historical
/// documents written before this fix landed.
fn strip_nul_and_control(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect::<String>().replace("\\x00", "")
}

fn first_non_empty(vals: &[&str]) -> String {
    vals.iter().find(|v| !v.is_empty()).map(|v| v.to_string()).unwrap_or_default()
}

/// Writes canonical_user/canonical_pass only when they'd pass
/// valid_credential_pair — matching TopCreds' exact semantics rather than
/// promoting every raw username/password field regardless of shape.
pub fn set_creds(e: &mut Value, user: &str, pass: &str) -> bool {
    if !valid_credential_pair(user, pass) {
        return false;
    }
    e["canonical_user"] = Value::from(user);
    e["canonical_pass"] = Value::from(pass);
    true
}

pub fn set_fingerprint(e: &mut Value, fingerprint: &str, kind: &str) -> bool {
    if fingerprint.is_empty() {
        return false;
    }
    e["canonical_fingerprint"] = Value::from(fingerprint);
    e["canonical_fingerprint_kind"] = Value::from(kind);
    true
}

/// Mirrors classify.go's cowrie branch: username/password on a login event
/// (plus a pubkey fingerprint riding along on the same event), command
/// text, SSH client version, HASSH/JA4/JA4H/pubkey fingerprints, and a
/// download's payload hash.
///
/// #1266: cowrie.log.closed is deliberately excluded — its own "shasum" is
/// the TTY log recording's own hash, not a downloaded file's hash, even
/// though cowrie reuses the same JSON key for both.
fn promote_cowrie_fields(e: &mut Value) -> bool {
    let eid = str(e, "eventid");
    if !eid.starts_with("cowrie.") {
        return false;
    }
    let mut changed = false;
    match eid.as_str() {
        "cowrie.login.success" | "cowrie.login.failed" => {
            let raw_user = str(e, "username");
            let raw_pass = str(e, "password");
            let user = strip_nul_and_control(&raw_user);
            let pass = strip_nul_and_control(&raw_pass);
            if user != raw_user {
                e["username"] = Value::from(user.clone());
                changed = true;
            }
            if pass != raw_pass {
                e["password"] = Value::from(pass.clone());
                changed = true;
            }
            if set_creds(e, &user, &pass) {
                changed = true;
            }
            let fp = str(e, "fingerprint");
            if !fp.is_empty() && set_fingerprint(e, &fp, "SSH pubkey") {
                changed = true;
            }
        }
        "cowrie.command.input" | "cowrie.command.failed" | "cowrie.command.success" | "cowrie.session.input" => {
            let cmd = str(e, "input");
            if !cmd.is_empty() {
                e["canonical_command"] = Value::from(cmd);
                changed = true;
            }
        }
        "cowrie.client.version" => {
            let v = str(e, "version");
            if !v.is_empty() {
                // set_fingerprint's own return is redundant here — the
                // unconditional assignment below already covers it,
                // matching the Go source's own (equally redundant) shape.
                set_fingerprint(e, &v, "SSH client");
                e["canonical_client_version"] = Value::from(v);
                changed = true;
            }
        }
        "cowrie.client.kex" => {
            if set_fingerprint(e, &str(e, "hassh"), "HASSH") {
                changed = true;
            }
        }
        "cowrie.direct-tcpip.ja4" => {
            if set_fingerprint(e, &str(e, "ja4"), "JA4") {
                changed = true;
            }
        }
        "cowrie.direct-tcpip.ja4h" => {
            if set_fingerprint(e, &str(e, "ja4h"), "JA4H") {
                changed = true;
            }
        }
        "cowrie.client.fingerprint" => {
            if set_fingerprint(e, &str(e, "fingerprint"), "SSH pubkey") {
                changed = true;
            }
        }
        "cowrie.session.file_download" | "cowrie.session.file_upload" => {
            let sha = str(e, "shasum");
            if !sha.is_empty() {
                e["canonical_shasum"] = Value::from(sha);
                changed = true;
            }
        }
        _ => {}
    }
    changed
}

/// Mirrors classify.go's flat dionaea (log_json) branch: credentials[0],
/// when present, is the only field that feeds TopCreds for this shape.
fn promote_dionaea_fields(e: &mut Value) -> bool {
    let Some(first) = e.get("credentials").and_then(Value::as_array).and_then(|a| a.first()) else { return false };
    let (user, pass) = (str(first, "username"), str(first, "password"));
    set_creds(e, &user, &pass)
}

/// Mirrors classify.go's dionaea_incident.json branch: user/pass (gated on
/// the incident kind mentioning login/auth) and a payload hash, read
/// straight from any {sha256,sha1,md5,...}/download-basename shape under
/// "data".
fn promote_dionaea_incident_fields(e: &mut Value) -> bool {
    let origin = str(e, "origin");
    if !origin.starts_with("dionaea.") {
        return false;
    }
    let kind = origin.trim_start_matches("dionaea.").to_string();
    let Some(data) = e.get("data").cloned().filter(Value::is_object) else { return false };
    let mut changed = false;

    let user = first_non_empty(&[&str(&data, "username"), &str(&data, "user"), &str(&data, "login")]);
    let pass = first_non_empty(&[&str(&data, "password"), &str(&data, "pass")]);
    if (!user.is_empty() || !pass.is_empty()) && (kind.contains("login") || kind.contains("auth")) {
        if set_creds(e, &user, &pass) {
            changed = true;
        }
    }

    let mut shasum = first_non_empty(&[
        &str(&data, "sha256"),
        &str(&data, "sha256hash"),
        &str(&data, "sha1"),
        &str(&data, "md5"),
        &str(&data, "md5hash"),
    ]);
    if shasum.is_empty() {
        let download = first_non_empty(&[&str(&data, "url"), &str(&data, "path"), &str(&data, "file"), &str(&data, "filename")]);
        if !download.is_empty() {
            let base = download.rsplit('/').next().unwrap_or(&download);
            if HASH_NAME.is_match(base) {
                shasum = base.to_string();
            }
        }
    }
    if !shasum.is_empty() {
        e["canonical_shasum"] = Value::from(shasum);
        changed = true;
    }
    changed
}

/// Coerces a JSON headers object into a lowercased-key string map — used
/// for JA3/JA4/User-Agent fingerprint extraction.
fn header_map(v: Option<&Value>) -> std::collections::HashMap<String, String> {
    let mut m = std::collections::HashMap::new();
    if let Some(Value::Object(obj)) = v {
        for (k, val) in obj {
            m.insert(k.to_lowercase(), val.as_str().unwrap_or("").to_string());
        }
    }
    m
}

fn header_val(m: &std::collections::HashMap<String, String>, key: &str) -> String {
    m.get(&key.to_lowercase()).cloned().unwrap_or_default()
}

/// Mirrors classify.go's cisco-asa-honeypot branch: the CVE-2018-0101/
/// generic POST payload as canonical_command, and a JA4/JA3/User-Agent
/// fingerprint from the request's own headers.
fn promote_cisco_asa_fields(e: &mut Value) -> bool {
    let mut changed = false;
    let kind = str(e, "event");
    if kind == "cve_2018_0101_payload" || kind == "post" {
        let body = str(e, "data");
        if !body.is_empty() {
            e["canonical_command"] = Value::from(body);
            changed = true;
        }
    }
    let hdr = header_map(e.get("headers"));
    if !hdr.is_empty() {
        let ja4 = header_val(&hdr, "x-ja4");
        let ja3 = header_val(&hdr, "x-ja3");
        let ua = header_val(&hdr, "user-agent");
        if !ja4.is_empty() {
            changed |= set_fingerprint(e, &ja4, "JA4");
        } else if !ja3.is_empty() {
            changed |= set_fingerprint(e, &ja3, "JA3");
        } else if !ua.is_empty() {
            changed |= set_fingerprint(e, &ua, "User-Agent");
        }
    }
    changed
}

/// Mirrors classify.go's multipot branch: per-protocol login credentials,
/// a "command" field carried by every handler except http_request (whose
/// own "command" is an HTTP request line, not an attacker command), and
/// the client banner as a fingerprint.
fn promote_multipot_fields(e: &mut Value) -> bool {
    if e.get("sensor").and_then(Value::as_str) != Some("multipot") {
        return false;
    }
    let kind = str(e, "event");
    if matches!(kind.as_str(), "listening" | "multipot_started" | "listen_error") {
        return false;
    }
    let mut changed = false;
    if kind == "login" && set_creds(e, &str(e, "username"), &str(e, "password")) {
        changed = true;
    }
    if kind != "http_request" {
        let cmd = str(e, "command");
        if !cmd.is_empty() {
            e["canonical_command"] = Value::from(cmd);
            changed = true;
        }
    }
    let client = str(e, "client");
    if !client.is_empty() && set_fingerprint(e, &client, "client banner") {
        changed = true;
    }
    changed
}

/// Mailoney's own "login" events — same validCredentialPair-gated
/// promotion every other credential-capturing sensor gets.
fn promote_mailoney_fields(e: &mut Value) -> bool {
    if str(e, "event") != "login" {
        return false;
    }
    set_creds(e, &str(e, "username"), &str(e, "password"))
}

/// beelzebub.go's own field-mirror step already flattens username/password
/// before this runs, so no event-type gate is needed here.
fn promote_beelzebub_fields(e: &mut Value) -> bool {
    set_creds(e, &str(e, "username"), &str(e, "password"))
}

/// Mirrors classify.go's citrix-honeypot branch: the CVE-2019-19781
/// payload as canonical_command, and a JA4/JA3/User-Agent fingerprint —
/// the same shape promote_cisco_asa_fields already promotes.
fn promote_citrix_fields(e: &mut Value) -> bool {
    let mut changed = false;
    if str(e, "event") == "cve_2019_19781_payload" {
        let body = str(e, "data");
        if !body.is_empty() {
            e["canonical_command"] = Value::from(body);
            changed = true;
        }
    }
    let hdr = header_map(e.get("headers"));
    if !hdr.is_empty() {
        let ja4 = header_val(&hdr, "x-ja4");
        let ja3 = header_val(&hdr, "x-ja3");
        let ua = header_val(&hdr, "user-agent");
        if !ja4.is_empty() {
            changed |= set_fingerprint(e, &ja4, "JA4");
        } else if !ja3.is_empty() {
            changed |= set_fingerprint(e, &ja3, "JA3");
        } else if !ua.is_empty() {
            changed |= set_fingerprint(e, &ua, "User-Agent");
        }
    }
    changed
}

/// rdp-honeypot's own "mstshash" offered username as canonical_user — no
/// separate password field exists for RDP's pre-auth handshake.
fn promote_rdp_fields(e: &mut Value) -> bool {
    if str(e, "event") == "listening" {
        return false;
    }
    let user = str(e, "username");
    if user.is_empty() {
        return false;
    }
    set_creds(e, &user, "")
}

/// Mirrors classify.go's shared tanner_report.json/http-honeypot branch:
/// username/password on any request that carries them, a JA4/JA3/
/// User-Agent fingerprint from headers, and (tanner only) tanner's own
/// emulator-matched post_data as canonical_command.
fn promote_web_request_fields(persona: &str, e: &mut Value) -> bool {
    if str(e, "method").is_empty() && str(e, "category").is_empty() {
        return false;
    }
    if str(e, "category") == "startup" {
        return false;
    }
    let mut changed = false;
    if set_creds(e, &str(e, "username"), &str(e, "password")) {
        changed = true;
    }
    let hdr = header_map(e.get("headers"));
    let ja4 = header_val(&hdr, "x-ja4");
    let ja3 = header_val(&hdr, "x-ja3");
    let ua = header_val(&hdr, "user-agent");
    if !ja4.is_empty() {
        changed |= set_fingerprint(e, &ja4, "JA4");
    } else if !ja3.is_empty() {
        changed |= set_fingerprint(e, &ja3, "JA3");
    } else if !ua.is_empty() {
        changed |= set_fingerprint(e, &ua, "User-Agent");
    }
    if persona == "tanner" {
        if let Some(Value::Object(post_data)) = e.get("post_data") {
            if !post_data.is_empty() {
                let mut parts: Vec<String> =
                    post_data.iter().map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or_default())).collect();
                parts.sort(); // deterministic field order
                e["canonical_command"] = Value::from(parts.join("&"));
                changed = true;
            }
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cowrie_login_promotes_creds_and_fingerprint() {
        let mut e = json!({"eventid": "cowrie.login.success", "username": "root", "password": "toor", "fingerprint": "aa:bb"});
        assert!(promote_canonical_fields("cowrie", &mut e));
        assert_eq!(e["canonical_user"], "root");
        assert_eq!(e["canonical_pass"], "toor");
        assert_eq!(e["canonical_fingerprint"], "aa:bb");
    }

    #[test]
    fn cowrie_login_strips_nul_and_control_bytes_from_raw_and_canonical_creds() {
        // Real telnet-attacker shape: trailing NULs on the username,
        // embedded literal "\x00" text (not an actual NUL byte) on the
        // password -- both forms dashboard.rs's own display-side clean()
        // already defends against.
        let mut e = json!({
            "eventid": "cowrie.login.failed",
            "username": "root\u{0}\u{0}\u{0}",
            "password": "toor\\x00"
        });
        assert!(promote_canonical_fields("cowrie", &mut e));
        assert_eq!(e["username"], "root");
        assert_eq!(e["password"], "toor");
        assert_eq!(e["canonical_user"], "root");
        assert_eq!(e["canonical_pass"], "toor");
    }

    #[test]
    fn cowrie_log_closed_never_promotes_ttylog_hash_as_shasum() {
        let mut e = json!({"eventid": "cowrie.log.closed", "shasum": "deadbeef"});
        assert!(!promote_canonical_fields("cowrie", &mut e));
        assert!(e.get("canonical_shasum").is_none());
    }

    #[test]
    fn invalid_credential_pair_is_never_promoted() {
        let mut e = Value::Null;
        assert!(!set_creds(&mut e, "", ""));
        assert!(!set_creds(&mut e, "root", "cmd.exe /c whoami"));
    }

    #[test]
    fn conpot_and_dns_honeypot_have_no_promotion_case() {
        let mut e = json!({"username": "x", "password": "y"});
        assert!(!promote_canonical_fields("conpot", &mut e));
        assert!(!promote_canonical_fields("dns-honeypot", &mut e));
    }

    #[test]
    fn tanner_post_data_becomes_deterministic_canonical_command() {
        let mut e = json!({"category": "emulator", "post_data": {"b": "2", "a": "1"}});
        assert!(promote_canonical_fields("tanner", &mut e));
        assert_eq!(e["canonical_command"], "a=1&b=2");
    }
}
