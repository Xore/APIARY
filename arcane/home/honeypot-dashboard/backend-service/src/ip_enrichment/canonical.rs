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
            // #1565: trailing whitespace/CRLF in the raw terminal input
            // (present on some capture paths, not others, for what's
            // otherwise the same command) split one command into two
            // identical-looking terms-agg buckets with matching counts —
            // trim so "enable" and "enable " collapse into one bucket.
            let cmd = str(e, "input").trim().to_string();
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
    if (!user.is_empty() || !pass.is_empty())
        && (kind.contains("login") || kind.contains("auth"))
        && set_creds(e, &user, &pass)
    {
        changed = true;
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
        let body = str(e, "data").trim().to_string();
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
        let cmd = str(e, "command").trim().to_string();
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
        let body = str(e, "data").trim().to_string();
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
    fn cowrie_command_input_trims_trailing_whitespace() {
        // #1565: "enable" and "enable " (trailing space from some capture
        // paths) were bucketing as two distinct top-commands terms with
        // identical counts -- trim so they collapse into one value.
        let mut e = json!({"eventid": "cowrie.command.input", "input": "enable \r\n"});
        assert!(promote_canonical_fields("cowrie", &mut e));
        assert_eq!(e["canonical_command"], "enable");
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

    // ---- ported from the Go worker's canonical_test.go before that tree
    // ---- was retired (#1890). It covered 34 cases here against 7, and the
    // ---- difference was not redundancy: every per-sensor promotion below
    // ---- had no Rust test at all, so a field silently landing in the
    // ---- wrong place would have gone unnoticed. Field shapes come from
    // ---- real records (#1217), not from invention.

    #[test]
    fn cowrie_rejects_a_command_shaped_password() {
        // The same gate the dashboard applies before a pair reaches
        // TopCreds -- a password that is really a shell fragment is a
        // command, not a credential.
        let mut e = json!({"eventid": "cowrie.login.failed", "username": "root", "password": "; /bin/busybox"});
        assert!(!promote_cowrie_fields(&mut e));
        assert!(e.get("canonical_user").is_none());
    }

    #[test]
    fn cowrie_pubkey_login_records_the_fingerprint() {
        let mut e = json!({
            "eventid": "cowrie.login.success", "username": "root", "password": "",
            "fingerprint": "aa:bb:cc",
        });
        assert!(promote_cowrie_fields(&mut e));
        assert_eq!(e["canonical_fingerprint"], json!("aa:bb:cc"));
        assert_eq!(e["canonical_fingerprint_kind"], json!("SSH pubkey"));
        // An empty password is legitimate for a key-only attempt, so the
        // username still promotes.
        assert_eq!(e["canonical_user"], json!("root"));
    }

    #[test]
    fn cowrie_client_version_and_kex_are_both_fingerprints() {
        let mut e = json!({"eventid": "cowrie.client.version", "version": "SSH-2.0-libssh2"});
        assert!(promote_cowrie_fields(&mut e));
        assert_eq!(e["canonical_client_version"], json!("SSH-2.0-libssh2"));
        assert_eq!(e["canonical_fingerprint"], json!("SSH-2.0-libssh2"));
        assert_eq!(e["canonical_fingerprint_kind"], json!("SSH client"));

        let mut kex = json!({"eventid": "cowrie.client.kex", "hassh": "deadbeef"});
        assert!(promote_cowrie_fields(&mut kex));
        assert_eq!(kex["canonical_fingerprint"], json!("deadbeef"));
        assert_eq!(kex["canonical_fingerprint_kind"], json!("HASSH"));
    }

    #[test]
    fn cowrie_file_download_promotes_its_shasum() {
        let mut e = json!({"eventid": "cowrie.session.file_download", "shasum": "abc123"});
        assert!(promote_cowrie_fields(&mut e));
        assert_eq!(e["canonical_shasum"], json!("abc123"));
    }

    #[test]
    fn cowrie_leaves_alone_what_it_has_no_case_for() {
        let mut other = json!({"eventid": "dionaea.connection.tcp.accept"});
        assert!(!promote_cowrie_fields(&mut other));
        let mut connect = json!({"eventid": "cowrie.session.connect"});
        assert!(!promote_cowrie_fields(&mut connect));
    }

    #[test]
    fn dionaea_promotes_the_first_credential_pair() {
        let mut e = json!({"credentials": [{"username": "admin", "password": "admin"}]});
        assert!(promote_dionaea_fields(&mut e));
        assert_eq!(e["canonical_user"], json!("admin"));
        assert_eq!(e["canonical_pass"], json!("admin"));
    }

    #[test]
    fn dionaea_without_credentials_changes_nothing() {
        let mut e = json!({"connection": {"protocol": "smbd"}});
        assert!(!promote_dionaea_fields(&mut e));
    }

    #[test]
    fn dionaea_incident_login_promotes_creds() {
        let mut e = json!({
            "origin": "dionaea.ftp.login",
            "data": {"username": "anon", "password": "guest"},
        });
        assert!(promote_dionaea_incident_fields(&mut e));
        assert_eq!(e["canonical_user"], json!("anon"));
        assert_eq!(e["canonical_pass"], json!("guest"));
    }

    #[test]
    fn dionaea_incident_only_treats_a_login_origin_as_credentials() {
        // Identical shape, but an origin that is neither a login nor an
        // auth event -- the fields happen to be named username/password
        // and mean something else.
        let mut e = json!({
            "origin": "dionaea.connection.tcp.accept",
            "data": {"username": "anon", "password": "guest"},
        });
        assert!(!promote_dionaea_incident_fields(&mut e));
    }

    #[test]
    fn dionaea_incident_takes_a_direct_sha256() {
        let mut e = json!({
            "origin": "dionaea.download.complete.unique",
            "data": {"sha256": "deadbeef"},
        });
        assert!(promote_dionaea_incident_fields(&mut e));
        assert_eq!(e["canonical_shasum"], json!("deadbeef"));
    }

    #[test]
    fn dionaea_incident_recovers_a_hash_from_the_download_url() {
        let hash = "0123456789abcdef0123456789abcdef01234567";
        let mut e = json!({
            "origin": "dionaea.download.complete.unique",
            "data": {"url": format!("http://x/{hash}")},
        });
        assert!(promote_dionaea_incident_fields(&mut e));
        assert_eq!(e["canonical_shasum"], json!(hash));
    }

    #[test]
    fn dionaea_incident_ignores_a_foreign_origin() {
        let mut e = json!({"origin": "other.thing", "data": {"sha256": "deadbeef"}});
        assert!(!promote_dionaea_incident_fields(&mut e));
    }

    #[test]
    fn cisco_asa_prefers_ja4_over_the_user_agent() {
        let mut e = json!({
            "event": "post",
            "data": "user=admin&pass=admin",
            "headers": {"User-Agent": "curl/8.0", "X-JA4": "t13d..."},
        });
        assert!(promote_cisco_asa_fields(&mut e));
        assert_eq!(e["canonical_command"], json!("user=admin&pass=admin"));
        assert_eq!(e["canonical_fingerprint"], json!("t13d..."));
        assert_eq!(e["canonical_fingerprint_kind"], json!("JA4"));
    }

    #[test]
    fn cisco_asa_falls_back_to_the_user_agent() {
        let mut e = json!({"event": "get", "headers": {"User-Agent": "curl/8.0"}});
        assert!(promote_cisco_asa_fields(&mut e));
        assert_eq!(e["canonical_fingerprint"], json!("curl/8.0"));
        assert_eq!(e["canonical_fingerprint_kind"], json!("User-Agent"));
    }

    #[test]
    fn cisco_asa_with_nothing_to_promote_changes_nothing() {
        let mut e = json!({"event": "https_listening"});
        assert!(!promote_cisco_asa_fields(&mut e));
    }

    #[test]
    fn multipot_login_promotes_creds() {
        let mut e = json!({
            "sensor": "multipot", "proto": "smtp", "event": "login",
            "username": "dvr@mail01.nexusai.local", "password": "123456789",
        });
        assert!(promote_multipot_fields(&mut e));
        assert_eq!(e["canonical_user"], json!("dvr@mail01.nexusai.local"));
        assert_eq!(e["canonical_pass"], json!("123456789"));
    }

    #[test]
    fn multipot_ignores_a_record_from_another_sensor() {
        let mut e = json!({"sensor": "dns-honeypot", "event": "login", "username": "a", "password": "b"});
        assert!(!promote_multipot_fields(&mut e));
    }

    #[test]
    fn multipot_command_promotes() {
        let mut e = json!({
            "sensor": "multipot", "proto": "socks5", "event": "command",
            "command": "CONNECT 10.0.0.1:80",
        });
        assert!(promote_multipot_fields(&mut e));
        assert_eq!(e["canonical_command"], json!("CONNECT 10.0.0.1:80"));
    }

    #[test]
    fn multipot_http_request_line_is_not_an_attacker_command() {
        // Its "command" is a request line, and promoting it would fill
        // TopCommands with "GET /..." instead of what attackers typed.
        let mut e = json!({
            "sensor": "multipot", "event": "http_request",
            "command": "GET /_search HTTP/1.1",
        });
        assert!(!promote_multipot_fields(&mut e));
    }

    #[test]
    fn multipot_client_banner_is_a_fingerprint() {
        let mut e = json!({"sensor": "multipot", "event": "connect", "client": "libssh2_1.0"});
        assert!(promote_multipot_fields(&mut e));
        assert_eq!(e["canonical_fingerprint"], json!("libssh2_1.0"));
        assert_eq!(e["canonical_fingerprint_kind"], json!("client banner"));
    }

    #[test]
    fn citrix_prefers_ja4_over_ja3_and_the_user_agent() {
        let mut e = json!({
            "sensor": "citrix-honeypot", "event": "get", "path": "/",
            "headers": {"User-Agent": "Mozilla/5.0 zgrab/0.x", "x-ja3": "cba7f3", "x-ja4": "t12i13"},
        });
        assert!(promote_citrix_fields(&mut e));
        assert_eq!(e["canonical_fingerprint"], json!("t12i13"));
        assert_eq!(e["canonical_fingerprint_kind"], json!("JA4"));
    }

    #[test]
    fn citrix_cve_payload_becomes_the_command() {
        let mut e = json!({"sensor": "citrix-honeypot", "event": "cve_2019_19781_payload", "data": "id"});
        assert!(promote_citrix_fields(&mut e));
        assert_eq!(e["canonical_command"], json!("id"));
    }

    #[test]
    fn rdp_promotes_a_username_with_no_password() {
        let mut e = json!({"sensor": "rdp-honeypot", "event": "connect", "username": "Test"});
        assert!(promote_rdp_fields(&mut e));
        assert_eq!(e["canonical_user"], json!("Test"));
        assert_eq!(e["canonical_pass"], json!(""));
    }

    #[test]
    fn rdp_without_a_username_changes_nothing() {
        let mut e = json!({"sensor": "rdp-honeypot", "event": "listening"});
        assert!(!promote_rdp_fields(&mut e));
    }

    #[test]
    fn web_request_promotes_creds_and_the_user_agent() {
        let mut e = json!({
            "sensor": "http-honeypot", "method": "GET", "path": "/admin",
            "username": "admin", "password": "admin123",
            "headers": {"User-Agent": "curl/8.0"},
        });
        assert!(promote_web_request_fields("http-honeypot", &mut e));
        assert_eq!(e["canonical_user"], json!("admin"));
        assert_eq!(e["canonical_pass"], json!("admin123"));
        assert_eq!(e["canonical_fingerprint"], json!("curl/8.0"));
        assert_eq!(e["canonical_fingerprint_kind"], json!("User-Agent"));
    }

    #[test]
    fn web_request_skips_a_startup_record() {
        let mut e = json!({"category": "startup"});
        assert!(!promote_web_request_fields("tanner", &mut e));
    }

    #[test]
    fn web_request_skips_the_legacy_peer_shape() {
        // No method and no category: tanner's old peer-shaped report,
        // which carries nothing promotable.
        let mut e = json!({"peer": {"ip": "10.8.0.2"}, "paths": []});
        assert!(!promote_web_request_fields("tanner", &mut e));
    }

    #[test]
    fn tanner_post_data_is_only_read_for_tanner() {
        // http-honeypot's own POST body was never promoted into
        // TopCommands, and reading it here would change what the dashboard
        // shows for a sensor that has always been quiet about it.
        let mut e = json!({"method": "POST", "path": "/login", "post_data": {"a": "b"}});
        assert!(!promote_web_request_fields("http-honeypot", &mut e));
    }

    #[test]
    fn canonical_dispatch_is_by_persona() {
        let cases: Vec<(&str, Value, bool)> = vec![
            ("cowrie", json!({"eventid": "cowrie.command.input", "input": "id"}), true),
            ("dionaea", json!({"credentials": [{"username": "a", "password": "b"}]}), true),
            (
                "dionaea-incident",
                json!({"origin": "dionaea.ftp.login", "data": {"username": "a", "password": "b"}}),
                true,
            ),
            ("cisco-asa-honeypot", json!({"event": "post", "data": "x"}), true),
            ("dns-honeypot", json!({"event": "query", "query": "example.com"}), false),
            ("conpot", json!({"data_type": "modbus", "request": "\u{0}\u{1}"}), false),
            // A persona with no case must not fall through to another
            // sensor's rules just because the record looks like one.
            (
                "unknown-sensor",
                json!({"eventid": "cowrie.login.success", "username": "a", "password": "b"}),
                false,
            ),
        ];
        for (persona, event, want) in cases {
            let mut e = event.clone();
            assert_eq!(
                promote_canonical_fields(persona, &mut e),
                want,
                "promote_canonical_fields({persona:?}, {event})",
            );
        }
    }

    #[test]
    fn credential_pair_validation_matches_the_dashboard() {
        for (user, pass, want) in [
            ("", "", false),
            ("root", "toor", true),
            ("root", "; /bin/busybox", false),
            ("root ; rm -rf /", "x", false),
            ("root", "powershell -enc ...", false),
        ] {
            assert_eq!(valid_credential_pair(user, pass), want, "{user:?}/{pass:?}");
        }
    }
}
