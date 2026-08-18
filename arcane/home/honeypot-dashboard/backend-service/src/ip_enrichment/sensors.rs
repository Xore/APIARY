//! Ported from ip-enrichment-worker/enrich.go plus the bespoke per-sensor
//! files (beelzebub.go/hellpot.go/galah.go/sentrypeer.go/wordpot.go): the
//! generic tunnel-peer src_ip join, dionaea_incident.json's nested-shape
//! variant, and five sensors whose raw log line doesn't match the generic
//! src_ip/src_port shape at all.

use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

use super::canonical::promote_canonical_fields;
use super::tftp::is_tftp_relay_record;
use super::viamap::ViaMap;

pub const TUNNEL_PEER_IP: &str = "10.8.0.1";

fn str(e: &Value, key: &str) -> String {
    e.get(key).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Mirrors dashboard/classify.go's eventSrcPort: a top-level "src_port"
/// first, dionaea's older nested connection.remote_port shape as a
/// defensive fallback.
fn extract_src_port(e: &Value) -> i64 {
    if let Some(p) = e.get("src_port").and_then(Value::as_f64).filter(|p| *p != 0.0) {
        return p as i64;
    }
    if let Some(p) = e.get("connection").and_then(|c| c.get("remote_port")).and_then(Value::as_f64) {
        return p as i64;
    }
    0
}

/// Corrects "dst_port" for the two Siemens S7 personas whose
/// host-published Modbus/S7comm ports differ from the container-internal
/// port conpot itself binds and logs.
fn fix_conpot_dest_port(e: &mut Value, persona: &str) -> bool {
    let remap: &[(f64, f64)] = match persona {
        "conpot-s7-1200" => &[(502.0, 1502.0), (102.0, 1102.0)],
        "conpot-s7-1500" => &[(502.0, 2502.0), (102.0, 2102.0)],
        _ => return false,
    };
    let Some(p) = e.get("dst_port").and_then(Value::as_f64) else { return false };
    let Some((_, real)) = remap.iter().find(|(from, _)| *from == p) else { return false };
    e["dst_port"] = Value::from(*real);
    true
}

pub fn marshal_if_changed(line: &[u8], e: &Value, changed: bool) -> Vec<u8> {
    if !changed {
        return line.to_vec();
    }
    serde_json::to_vec(e).unwrap_or_else(|_| line.to_vec())
}

/// The generic case: fix conpot dest port, promote canonical fields
/// unconditionally on every attempt (including retries — cheap, idempotent
/// against the same original line), then resolve src_ip via the
/// tunnel-peer or TFTP-relay join. A src_ip miss still returns whatever
/// dst_port/canonical-field changes were made — pendingQueue.drain calls
/// this again on every retry and writes *this* return value once the line
/// either resolves or times out, so those changes must not be dropped.
pub fn enrich_line(line: &[u8], vm: &ViaMap, tftp_vm: &ViaMap, persona: &str) -> (Vec<u8>, bool) {
    let Ok(mut e) = serde_json::from_slice::<Value>(line) else {
        return (line.to_vec(), true); // unparseable: nothing to retry, pass through as-is
    };

    let port_fixed = fix_conpot_dest_port(&mut e, persona);
    let canonical_changed = promote_canonical_fields(persona, &mut e);
    let fields_changed = super::attck::promote_attck_technique_fields(&mut e) || canonical_changed || port_fixed;

    let ip = str(&e, "src_ip");
    let lookup = if ip == TUNNEL_PEER_IP {
        vm
    } else if is_tftp_relay_record(&e, persona) {
        tftp_vm
    } else {
        return (marshal_if_changed(line, &e, fields_changed), true); // already correct or genuinely unknown
    };

    let port = extract_src_port(&e);
    if port == 0 {
        return (marshal_if_changed(line, &e, fields_changed), true); // no src_port to join on
    }
    let Some(real) = lookup.get(&port) else {
        return (marshal_if_changed(line, &e, fields_changed), false); // via_port miss — retry later
    };
    e["src_ip"] = Value::from(real.clone());
    (marshal_if_changed(line, &e, true), true)
}

/// Recursively walks `v` (typically dionaea_incident.json's "data" field)
/// looking for every embedded connection-shape object — any map carrying
/// both "remote_ip" and "remote_port" — and rewrites remote_ip in place
/// wherever it's currently the tunnel peer and the port resolves. Matches
/// by shape, not a fixed key name, since the key varies by incident
/// origin ("connection" for most, "child"/"parent" for
/// dionaea.connection.link).
fn rewrite_dionaea_connections(v: &mut Value, vm: &ViaMap) -> (usize, bool) {
    let mut changed = 0usize;
    let mut all_resolved = true;
    match v {
        Value::Object(map) => {
            if let Some(Value::String(ip)) = map.get("remote_ip") {
                if ip == TUNNEL_PEER_IP {
                    if let Some(port) = map.get("remote_port").and_then(Value::as_f64) {
                        if let Some(real) = vm.get(&(port as i64)) {
                            map.insert("remote_ip".to_string(), Value::from(real.clone()));
                            changed += 1;
                        } else {
                            all_resolved = false;
                        }
                    }
                }
            }
            for child in map.values_mut() {
                let (c, r) = rewrite_dionaea_connections(child, vm);
                changed += c;
                all_resolved = all_resolved && r;
            }
        }
        Value::Array(arr) => {
            for child in arr {
                let (c, r) = rewrite_dionaea_connections(child, vm);
                changed += c;
                all_resolved = all_resolved && r;
            }
        }
        _ => {}
    }
    (changed, all_resolved)
}

/// dionaea_incident.json's own enrichLine: unlike the flat-log sensors, an
/// incident record carries no top-level src_ip at all — the real signal
/// is buried in "data". tftp_vm/persona are accepted only to match the
/// shared enrich-function signature and are unused here.
pub fn enrich_dionaea_incident_line(line: &[u8], vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
    let Ok(mut e) = serde_json::from_slice::<Value>(line) else {
        return (line.to_vec(), true);
    };
    let (changed, all_resolved) = match e.get_mut("data") {
        Some(data) => rewrite_dionaea_connections(data, vm),
        None => (0, true),
    };
    let canonicalized = promote_canonical_fields("dionaea-incident", &mut e);
    if changed == 0 && !canonicalized {
        return (line.to_vec(), all_resolved);
    }
    (serde_json::to_vec(&e).unwrap_or_else(|_| line.to_vec()), all_resolved)
}

// ---------------------------------------------------------------------------
// Bespoke per-sensor enrichers — each adapts one sensor's own non-standard
// raw log shape into the shared (line, resolved) enrich-function contract.
// ---------------------------------------------------------------------------

/// beelzebub.json: every standardOutStrategy line nests the actual
/// tracer.Event under a top-level "event" key. Three independent steps:
/// rewrite event.SourceIp when it's the tunnel peer and the port resolves;
/// mirror the (possibly just-rewritten) SourceIp/SourcePort as flat
/// top-level src_ip/src_port (the geoip ingest pipeline only ever promotes
/// h.src_ip at honeypot.* top level); mirror
/// User/Password/Command/RequestURI as flat lowercase fields. No
/// destination-port field: beelzebub's Event carries no listen-port of its
/// own.
pub fn enrich_beelzebub_line(line: &[u8], vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
    let Ok(mut e) = serde_json::from_slice::<Value>(line) else {
        return (line.to_vec(), true);
    };
    let Some(ev) = e.get("event").cloned().filter(Value::is_object) else {
        return (line.to_vec(), true); // not a "New Event" line (e.g. startup/error log)
    };

    let mut changed = false;
    if let Some(proto) = ev.get("Protocol").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        if e.get("sensor").and_then(Value::as_str) != Some("beelzebub") {
            e["sensor"] = Value::from("beelzebub");
            changed = true;
        }
        if e.get("protocol").and_then(Value::as_str) != Some(proto) {
            e["protocol"] = Value::from(proto);
            changed = true;
        }
    }
    for (src_key, dst_key) in [("User", "username"), ("Password", "password"), ("Command", "command"), ("RequestURI", "path")] {
        if let Some(v) = ev.get(src_key).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            if e.get(dst_key).and_then(Value::as_str) != Some(v) {
                e[dst_key] = Value::from(v);
                changed = true;
            }
        }
    }
    if promote_canonical_fields("beelzebub", &mut e) {
        changed = true;
    }

    let ip = ev.get("SourceIp").and_then(Value::as_str).unwrap_or("").to_string();
    if ip != TUNNEL_PEER_IP {
        if !ip.is_empty() && e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip.clone());
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), true);
    }

    let port: Option<i64> = ev.get("SourcePort").and_then(Value::as_str).and_then(|s| s.parse().ok());
    let Some(port) = port.filter(|p| *p != 0) else {
        if e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip);
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), true);
    };

    let Some(real) = vm.get(&port) else {
        if e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip);
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), false);
    };

    let mut ev = ev;
    ev["SourceIp"] = Value::from(real.clone());
    e["event"] = ev;
    e["src_ip"] = Value::from(real.clone());
    e["src_port"] = Value::from(port);
    (marshal_if_changed(line, &e, true), true)
}

/// hellpot.json: REMOTE_ADDR is a single "ip:port" string (fasthttp's
/// RemoteAddr()). No destination-port field; every event is HTTP by
/// definition (a single-protocol tarpit).
pub fn enrich_hellpot_line(line: &[u8], vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
    let Ok(mut e) = serde_json::from_slice::<Value>(line) else {
        return (line.to_vec(), true);
    };
    let Some(remote_addr) = e.get("REMOTE_ADDR").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) else {
        return (line.to_vec(), true); // not a per-request line
    };

    let mut changed = false;
    if e.get("sensor").and_then(Value::as_str) != Some("hellpot") {
        e["sensor"] = Value::from("hellpot");
        changed = true;
    }
    if e.get("protocol").and_then(Value::as_str) != Some("HTTP") {
        e["protocol"] = Value::from("HTTP");
        changed = true;
    }
    if let Some(url) = e.get("URL").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
        if e.get("path").and_then(Value::as_str) != Some(url.as_str()) {
            e["path"] = Value::from(url);
            changed = true;
        }
    }
    if let Some(ua) = e.get("USERAGENT").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
        if e.get("user_agent").and_then(Value::as_str) != Some(ua.as_str()) {
            e["user_agent"] = Value::from(ua);
            changed = true;
        }
    }

    let Some((ip, port_str)) = split_host_port(&remote_addr) else {
        return (marshal_if_changed(line, &e, changed), true); // malformed REMOTE_ADDR
    };

    if ip != TUNNEL_PEER_IP {
        if e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip);
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), true);
    }

    let Ok(port) = port_str.parse::<i64>().map_err(|_| ()).and_then(|p| if p != 0 { Ok(p) } else { Err(()) }) else {
        if e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip);
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), true);
    };

    let Some(real) = vm.get(&port) else {
        if e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip);
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), false);
    };

    e["REMOTE_ADDR"] = Value::from(join_host_port(real, &port_str));
    e["src_ip"] = Value::from(real.clone());
    e["src_port"] = Value::from(port);
    (marshal_if_changed(line, &e, true), true)
}

/// galah's event_log.json: flat srcIP/srcPort fields already. Promotes
/// body_sha256 from httpRequest.bodySha256 and dst_port from the server's
/// own "port" string. srcHost/tags (galah's own pre-join enrichment,
/// looked up against the tunnel peer address) are deliberately left
/// untouched, not deleted, not trusted.
pub fn enrich_galah_line(line: &[u8], vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
    let Ok(mut e) = serde_json::from_slice::<Value>(line) else {
        return (line.to_vec(), true);
    };
    if e.get("msg").and_then(Value::as_str) != Some("successfulResponse") {
        return (line.to_vec(), true); // not a per-request event line
    }

    let mut changed = false;
    if e.get("sensor").and_then(Value::as_str) != Some("galah") {
        e["sensor"] = Value::from("galah");
        changed = true;
    }
    if e.get("protocol").and_then(Value::as_str) != Some("HTTP") {
        e["protocol"] = Value::from("HTTP");
        changed = true;
    }
    if let Some(dst) = e.get("port").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
        if e.get("dst_port").and_then(Value::as_str) != Some(dst.as_str()) {
            e["dst_port"] = Value::from(dst);
            changed = true;
        }
    }
    if let Some(hr) = e.get("httpRequest").cloned().filter(Value::is_object) {
        if let Some(req) = hr.get("request").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
            if e.get("path").and_then(Value::as_str) != Some(req.as_str()) {
                e["path"] = Value::from(req);
                changed = true;
            }
        }
        if let Some(ua) = hr.get("userAgent").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
            if e.get("user_agent").and_then(Value::as_str) != Some(ua.as_str()) {
                e["user_agent"] = Value::from(ua);
                changed = true;
            }
        }
        if let Some(sha) = hr.get("bodySha256").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
            if e.get("body_sha256").and_then(Value::as_str) != Some(sha.as_str()) {
                e["body_sha256"] = Value::from(sha);
                changed = true;
            }
        }
    }

    let ip = e.get("srcIP").and_then(Value::as_str).unwrap_or("").to_string();
    if ip != TUNNEL_PEER_IP {
        if !ip.is_empty() && e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip.clone());
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), true);
    }

    let port: Option<i64> = e.get("srcPort").and_then(Value::as_str).and_then(|s| s.parse().ok());
    let Some(port) = port.filter(|p| *p != 0) else {
        if e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip);
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), true);
    };

    let Some(real) = vm.get(&port) else {
        if e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip);
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), false);
    };

    e["srcIP"] = Value::from(real.clone());
    e["src_ip"] = Value::from(real.clone());
    e["src_port"] = Value::from(port);
    (marshal_if_changed(line, &e, true), true)
}

/// sentrypeer.json: "source_ip" is a single "ip:port" string, same shape
/// as hellpot's REMOTE_ADDR. No destination-port field: "destination_ip"
/// is a fixed bind-address string, not the real per-request listen port.
pub fn enrich_sentrypeer_line(line: &[u8], vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
    let Ok(mut e) = serde_json::from_slice::<Value>(line) else {
        return (line.to_vec(), true);
    };
    let Some(source_addr) = e.get("source_ip").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) else {
        return (line.to_vec(), true);
    };

    let mut changed = false;
    if e.get("sensor").and_then(Value::as_str) != Some("sentrypeer") {
        e["sensor"] = Value::from("sentrypeer");
        changed = true;
    }
    if e.get("protocol").and_then(Value::as_str) != Some("SIP") {
        e["protocol"] = Value::from("SIP");
        changed = true;
    }
    if let Some(ua) = e.get("sip_user_agent").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
        if e.get("user_agent").and_then(Value::as_str) != Some(ua.as_str()) {
            e["user_agent"] = Value::from(ua);
            changed = true;
        }
    }

    let Some((ip, port_str)) = split_host_port(&source_addr) else {
        return (marshal_if_changed(line, &e, changed), true);
    };

    if ip != TUNNEL_PEER_IP {
        if e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip);
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), true);
    }

    let Ok(port) = port_str.parse::<i64>().map_err(|_| ()).and_then(|p| if p != 0 { Ok(p) } else { Err(()) }) else {
        if e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip);
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), true);
    };

    let Some(real) = vm.get(&port) else {
        if e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip);
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), false);
    };

    e["source_ip"] = Value::from(join_host_port(real, &port_str));
    e["src_ip"] = Value::from(real.clone());
    e["src_port"] = Value::from(port);
    (marshal_if_changed(line, &e, true), true)
}

// wordpot_patch.py's _JsonFormatter wraps every LOGGER call in
// {"time","level","message"}. wordpotMessageRE extracts the leading
// "ip:port" the port-preserving middleware adds; the per-template regexes
// below extract whatever structured fields that specific message carries.
static WORDPOT_MESSAGE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\S+):(\d+) (.+)$").unwrap());
static WORDPOT_LOGIN_ATTEMPT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^tried to login with username (.*) and password (.*)$").unwrap());
static WORDPOT_LOGIN_PROBE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^probed for the login page$").unwrap());
static WORDPOT_ADMIN_PROBE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^probed for the admin panel with path: (.*)$").unwrap());
static WORDPOT_PLUGIN_PROBE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^probed for plugin "(.*)" with path: (.*)$"#).unwrap());
static WORDPOT_THEME_PROBE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^probed for theme "(.*)" with path: (.*)$"#).unwrap());
static WORDPOT_COMMON_FILE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^probed for: (.*)$").unwrap());
static WORDPOT_TIMTHUMB_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^probed for timthumb: (.*)$").unwrap());
static WORDPOT_BACKUPS_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^probed for recent-backups: (.*)$").unwrap());
static WORDPOT_AUTHOR_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^probed author page for user: (.*)$").unwrap());

/// Sets structured fields on `e` from a known wordpot message template,
/// returning whether it actually changed anything.
fn classify_wordpot_message(e: &mut Value, msg: &str) -> bool {
    let mut set = |k: &str, v: String| -> bool {
        if e.get(k).and_then(Value::as_str) == Some(v.as_str()) {
            return false;
        }
        e[k] = Value::from(v);
        true
    };
    if WORDPOT_LOGIN_ATTEMPT_RE.is_match(msg) {
        let caps = WORDPOT_LOGIN_ATTEMPT_RE.captures(msg).unwrap();
        let c1 = set("path", "/wp-login.php".to_string());
        let c2 = set("username", caps[1].to_string());
        let c3 = set("password", caps[2].to_string());
        c1 || c2 || c3
    } else if WORDPOT_LOGIN_PROBE_RE.is_match(msg) {
        set("path", "/wp-login.php".to_string())
    } else if WORDPOT_ADMIN_PROBE_RE.is_match(msg) {
        let caps = WORDPOT_ADMIN_PROBE_RE.captures(msg).unwrap();
        set("path", format!("/wp-admin{}", &caps[1]))
    } else if WORDPOT_PLUGIN_PROBE_RE.is_match(msg) {
        let caps = WORDPOT_PLUGIN_PROBE_RE.captures(msg).unwrap();
        let c1 = set("plugin", caps[1].to_string());
        let c2 = set("path", format!("/wp-content/plugins/{}{}", &caps[1], &caps[2]));
        c1 || c2
    } else if WORDPOT_THEME_PROBE_RE.is_match(msg) {
        let caps = WORDPOT_THEME_PROBE_RE.captures(msg).unwrap();
        let c1 = set("theme", caps[1].to_string());
        let c2 = set("path", format!("/wp-content/themes/{}{}", &caps[1], &caps[2]));
        c1 || c2
    } else if WORDPOT_TIMTHUMB_RE.is_match(msg) {
        let caps = WORDPOT_TIMTHUMB_RE.captures(msg).unwrap();
        set("path", caps[1].to_string())
    } else if WORDPOT_BACKUPS_RE.is_match(msg) {
        let caps = WORDPOT_BACKUPS_RE.captures(msg).unwrap();
        set("path", caps[1].to_string())
    } else if WORDPOT_AUTHOR_RE.is_match(msg) {
        let caps = WORDPOT_AUTHOR_RE.captures(msg).unwrap();
        set("username", caps[1].to_string())
    } else if WORDPOT_COMMON_FILE_RE.is_match(msg) {
        let caps = WORDPOT_COMMON_FILE_RE.captures(msg).unwrap();
        set("path", format!("/{}", &caps[1]))
    } else {
        false
    }
}

/// wordpot.log: startup lines don't match WORDPOT_MESSAGE_RE (no leading
/// "ip:port") and pass through unresolved-but-unchanged. Every event is
/// HTTP by definition. No destination-port field.
pub fn enrich_wordpot_line(line: &[u8], vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
    let Ok(mut e) = serde_json::from_slice::<Value>(line) else {
        return (line.to_vec(), true);
    };
    let Some(msg) = e.get("message").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) else {
        return (line.to_vec(), true);
    };
    let Some(caps) = WORDPOT_MESSAGE_RE.captures(&msg) else {
        return (line.to_vec(), true); // a startup log — no ip:port prefix
    };
    let (ip, port_str, rest) = (caps[1].to_string(), caps[2].to_string(), caps[3].to_string());

    let mut changed = false;
    if e.get("sensor").and_then(Value::as_str) != Some("wordpot") {
        e["sensor"] = Value::from("wordpot");
        changed = true;
    }
    if e.get("protocol").and_then(Value::as_str) != Some("HTTP") {
        e["protocol"] = Value::from("HTTP");
        changed = true;
    }
    changed = classify_wordpot_message(&mut e, &rest) || changed;

    if ip != TUNNEL_PEER_IP {
        if e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip);
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), true);
    }

    let Ok(port) = port_str.parse::<i64>().map_err(|_| ()).and_then(|p| if p != 0 { Ok(p) } else { Err(()) }) else {
        if e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip);
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), true);
    };

    let Some(real) = vm.get(&port) else {
        if e.get("src_ip").and_then(Value::as_str) != Some(ip.as_str()) {
            e["src_ip"] = Value::from(ip);
            changed = true;
        }
        return (marshal_if_changed(line, &e, changed), false);
    };

    e["message"] = Value::from(format!("{} {}", join_host_port(real, &port_str), rest));
    e["src_ip"] = Value::from(real.clone());
    e["src_port"] = Value::from(port);
    (marshal_if_changed(line, &e, true), true)
}

/// net.SplitHostPort equivalent for the plain "ip:port" shape every
/// bespoke sensor here uses (no IPv6 brackets in any real captured line).
fn split_host_port(addr: &str) -> Option<(String, String)> {
    let (ip, port) = addr.rsplit_once(':')?;
    if ip.is_empty() || port.is_empty() {
        return None;
    }
    Some((ip.to_string(), port.to_string()))
}

fn join_host_port(ip: &str, port: &str) -> String {
    format!("{ip}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vm_with(port: i64, ip: &str) -> ViaMap {
        let mut m = ViaMap::new();
        m.insert(port, ip.to_string());
        m
    }

    #[test]
    fn generic_enrich_resolves_tunnel_peer_via_viamap() {
        let line = json!({"src_ip": TUNNEL_PEER_IP, "src_port": 4000, "sensor": "cowrie"}).to_string();
        let vm = vm_with(4000, "203.0.113.5");
        let (out, resolved) = enrich_line(line.as_bytes(), &vm, &ViaMap::new(), "cowrie");
        assert!(resolved);
        let out: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(out["src_ip"], "203.0.113.5");
    }

    #[test]
    fn generic_enrich_reports_unresolved_on_via_port_miss() {
        let line = json!({"src_ip": TUNNEL_PEER_IP, "src_port": 4000}).to_string();
        let (_out, resolved) = enrich_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "cowrie");
        assert!(!resolved);
    }

    #[test]
    fn already_correct_ip_passes_through_unresolved_flag_true() {
        let line = json!({"src_ip": "198.51.100.9"}).to_string();
        let (_out, resolved) = enrich_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "multipot");
        assert!(resolved);
    }

    #[test]
    fn dionaea_incident_rewrites_nested_remote_ip() {
        let line = json!({
            "origin": "dionaea.connection.tcp.accept",
            "data": {"connection": {"remote_ip": TUNNEL_PEER_IP, "remote_port": 5000}}
        })
        .to_string();
        let vm = vm_with(5000, "203.0.113.7");
        let (out, resolved) = enrich_dionaea_incident_line(line.as_bytes(), &vm, &ViaMap::new(), "dionaea-incident");
        assert!(resolved);
        let out: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(out["data"]["connection"]["remote_ip"], "203.0.113.7");
    }

    #[test]
    fn beelzebub_line_flattens_nested_event_and_joins_ip() {
        let line = json!({"event": {"Protocol": "ssh", "SourceIp": TUNNEL_PEER_IP, "SourcePort": "4000", "User": "root", "Password": "toor"}}).to_string();
        let vm = vm_with(4000, "203.0.113.11");
        let (out, resolved) = enrich_beelzebub_line(line.as_bytes(), &vm, &ViaMap::new(), "beelzebub");
        assert!(resolved);
        let out: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(out["src_ip"], "203.0.113.11");
        assert_eq!(out["canonical_user"], "root");
    }

    #[test]
    fn hellpot_line_splits_combined_remote_addr() {
        let line = json!({"REMOTE_ADDR": format!("{TUNNEL_PEER_IP}:4000"), "URL": "/", "USERAGENT": "curl/8"}).to_string();
        let vm = vm_with(4000, "203.0.113.12");
        let (out, resolved) = enrich_hellpot_line(line.as_bytes(), &vm, &ViaMap::new(), "hellpot");
        assert!(resolved);
        let out: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(out["src_ip"], "203.0.113.12");
        assert_eq!(out["REMOTE_ADDR"], "203.0.113.12:4000");
    }

    #[test]
    fn wordpot_line_extracts_login_attempt_fields() {
        let line = json!({"message": format!("{TUNNEL_PEER_IP}:4000 tried to login with username admin and password hunter2")}).to_string();
        let vm = vm_with(4000, "203.0.113.13");
        let (out, resolved) = enrich_wordpot_line(line.as_bytes(), &vm, &ViaMap::new(), "wordpot");
        assert!(resolved);
        let out: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(out["username"], "admin");
        assert_eq!(out["password"], "hunter2");
        assert_eq!(out["path"], "/wp-login.php");
        assert_eq!(out["src_ip"], "203.0.113.13");
    }

    #[test]
    fn wordpot_startup_line_passes_through_unchanged() {
        let line = b"{\"message\":\"Loading conf file...\"}";
        let (_out, resolved) = enrich_wordpot_line(line, &ViaMap::new(), &ViaMap::new(), "wordpot");
        assert!(resolved);
    }
}
