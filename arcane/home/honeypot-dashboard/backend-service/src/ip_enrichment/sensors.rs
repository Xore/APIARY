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

/// Loopback sources. A honeypot is reached from the network; nothing on this
/// fleet is legitimately attacked from inside its own container.
const LOOPBACK_IPS: [&str; 2] = ["127.0.0.1", "::1"];

/// #1677: mark self-generated probe traffic instead of counting it as an attack.
///
/// Every sensor here is fronted by a Docker healthcheck that connects to the
/// sensor's own listening port -- `nc -z 127.0.0.1 5060` for sentrypeer, an
/// HTTP GET for http-honeypot, `conpot-healthcheck.py` for the conpot
/// personas -- and the sensor logs that connection exactly as it logs a real
/// one. Measured live: 312,905 such events in 24 hours, 13.5% of everything
/// ingested.
///
/// This is not the tunnel case and must not be enriched like one. There is no
/// attacker address hiding behind a healthcheck; the container probed itself.
/// Rewriting the IP would produce a better-labelled fiction, and dropping the
/// event outright would destroy the evidence that a probe happened at all.
///
/// So the document is marked and kept. Attack-facing queries filter on this
/// field, which lets `dashboard.rs`'s `top_ips` stop hard-coding an exclusion
/// list -- the exclusion exists today only because the documents carry no way
/// to tell the two apart.
///
/// Worth being precise about the damage this was doing: conpot's healthcheck
/// events arrive tagged `canonical_attck_techniques: ["T0886"]`, so Docker
/// liveness probes were being recorded as MITRE ICS technique usage.
fn mark_internal_probe(e: &mut Value) -> bool {
    let ip = str(e, "src_ip");
    if !LOOPBACK_IPS.contains(&ip.as_str()) {
        return false;
    }
    if e.get("internal_probe").and_then(Value::as_bool) == Some(true) {
        return false;
    }
    e["internal_probe"] = Value::Bool(true);
    true
}

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

/// The public port the connection came in on, for cross-checking a via_port
/// entry against the service it was actually dialled for (#1771). 0 when the
/// line does not say.
fn extract_dest_port(e: &Value) -> i64 {
    if let Some(p) = e.get("dst_port").and_then(Value::as_f64).filter(|p| *p != 0.0) {
        return p as i64;
    }
    if let Some(p) = e.get("connection").and_then(|c| c.get("local_port")).and_then(Value::as_f64) {
        return p as i64;
    }
    0
}

/// When the sensor says the event happened, as epoch seconds; 0 when it says
/// nothing this can read.
///
/// #1771 needs this to tell a via_port entry that could have produced the
/// line from one dialled afterwards for a different connection. Every key
/// and shape below was read off the live enriched logs rather than guessed:
/// `timestamp` (conpot's six personas, cowrie, dionaea, elasticpot, mailoney,
/// tanner), `time` (cisco-asa, citrix, dns-honeypot, hellpot, http-honeypot,
/// multipot, rdp-honeypot, wordpot), `event_timestamp` (sentrypeer) and
/// `eventTime` (galah). beelzebub carries none, and gets the pre-#1771
/// behaviour.
///
/// Naive stamps are treated as UTC, which is what the sensors emit --
/// confirmed against wall clock on the live host.
fn extract_line_time(e: &Value) -> i64 {
    for key in ["timestamp", "time", "event_timestamp", "eventTime"] {
        let Some(raw) = e.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()) else { continue };
        if let Some(seconds) = parse_sensor_time(raw) {
            return seconds;
        }
    }
    0
}

fn parse_sensor_time(raw: &str) -> Option<i64> {
    let normalized = raw.replacen(' ', "T", 1);
    if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&normalized) {
        return Some(t.timestamp());
    }
    // galah: "2026-08-23T08:38:23.441305976 +0200" -- an offset, space-separated.
    if let Some((head, tail)) = normalized.rsplit_once(' ') {
        if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&format!("{head}{tail}")) {
            return Some(t.timestamp());
        }
    }
    for format in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(t) = chrono::NaiveDateTime::parse_from_str(&normalized, format) {
            return Some(t.and_utc().timestamp());
        }
    }
    None
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

/// Sets `e[key]` to `value` if it differs from the current string value,
/// returning whether it actually changed anything.
fn set_if_changed(e: &mut Value, key: &str, value: impl Into<String>) -> bool {
    let value = value.into();
    if e.get(key).and_then(Value::as_str) == Some(value.as_str()) {
        return false;
    }
    e[key] = Value::from(value);
    true
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
    let attck_changed = super::attck::promote_attck_technique_fields(persona, &mut e);
    let probe_marked = mark_internal_probe(&mut e);
    let fields_changed = attck_changed || canonical_changed || port_fixed || probe_marked;

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
    // #1771: the entry has to be one that could actually have produced this
    // line -- dialled before it, for the same service, and not so long before
    // that we are joining a replayed backlog against a live map.
    let line_at = extract_line_time(&e);
    let dest_port = extract_dest_port(&e);
    let Some(real) = super::viamap::lookup(lookup, port, line_at, dest_port) else {
        return (marshal_if_changed(line, &e, fields_changed), false); // via_port miss — retry later
    };
    e["src_ip"] = Value::from(real.to_string());
    (marshal_if_changed(line, &e, true), true)
}

/// Recursively walks `v` (typically dionaea_incident.json's "data" field)
/// looking for every embedded connection-shape object — any map carrying
/// both "remote_ip" and "remote_port" — and rewrites remote_ip in place
/// wherever it's currently the tunnel peer and the port resolves. Matches
/// by shape, not a fixed key name, since the key varies by incident
/// origin ("connection" for most, "child"/"parent" for
/// dionaea.connection.link).
fn rewrite_dionaea_connections(v: &mut Value, vm: &ViaMap, line_at: i64) -> (usize, bool) {
    let mut changed = 0usize;
    let mut all_resolved = true;
    match v {
        Value::Object(map) => {
            if let Some(Value::String(ip)) = map.get("remote_ip") {
                if ip == TUNNEL_PEER_IP {
                    if let Some(port) = map.get("remote_port").and_then(Value::as_f64) {
                        // local_port on the same embedded object is the service
                        // this connection reached, so the #1771 cross-check has
                        // both sides here too.
                        let dest = map.get("local_port").and_then(Value::as_f64).unwrap_or(0.0) as i64;
                        if let Some(real) = super::viamap::lookup(vm, port as i64, line_at, dest) {
                            map.insert("remote_ip".to_string(), Value::from(real.to_string()));
                            changed += 1;
                        } else {
                            all_resolved = false;
                        }
                    }
                }
            }
            for child in map.values_mut() {
                let (c, r) = rewrite_dionaea_connections(child, vm, line_at);
                changed += c;
                all_resolved = all_resolved && r;
            }
        }
        Value::Array(arr) => {
            for child in arr {
                let (c, r) = rewrite_dionaea_connections(child, vm, line_at);
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
    let line_at = extract_line_time(&e);
    let (changed, all_resolved) = match e.get_mut("data") {
        Some(data) => rewrite_dionaea_connections(data, vm, line_at),
        None => (0, true),
    };
    let canonicalized = promote_canonical_fields("dionaea-incident", &mut e);
    let attck_changed = super::attck::promote_attck_technique_fields("dionaea-incident", &mut e);
    if changed == 0 && !canonicalized && !attck_changed {
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
        changed |= set_if_changed(&mut e, "sensor", "beelzebub");
        changed |= set_if_changed(&mut e, "protocol", proto);
    }
    for (src_key, dst_key) in [("User", "username"), ("Password", "password"), ("Command", "command"), ("RequestURI", "path")] {
        if let Some(v) = ev.get(src_key).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            changed |= set_if_changed(&mut e, dst_key, v);
        }
    }
    changed |= promote_canonical_fields("beelzebub", &mut e);
    changed |= super::attck::promote_attck_technique_fields("beelzebub", &mut e);

    let ip = ev.get("SourceIp").and_then(Value::as_str).unwrap_or("").to_string();
    if ip != TUNNEL_PEER_IP {
        if !ip.is_empty() {
            changed |= set_if_changed(&mut e, "src_ip", ip);
        }
        return (marshal_if_changed(line, &e, changed), true);
    }

    let port: Option<i64> = ev.get("SourcePort").and_then(Value::as_str).and_then(|s| s.parse().ok());
    let Some(port) = port.filter(|p| *p != 0) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    };

    let Some(real) = super::viamap::lookup(vm, port, extract_line_time(&e), extract_dest_port(&e)) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), false);
    };
    let real = real.to_string();

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
    changed |= set_if_changed(&mut e, "sensor", "hellpot");
    changed |= set_if_changed(&mut e, "protocol", "HTTP");
    if let Some(url) = e.get("URL").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
        changed |= set_if_changed(&mut e, "path", url);
    }
    if let Some(ua) = e.get("USERAGENT").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
        changed |= set_if_changed(&mut e, "user_agent", ua);
    }
    changed |= super::attck::promote_attck_technique_fields("hellpot", &mut e);

    let Some((ip, port_str)) = split_host_port(&remote_addr) else {
        return (marshal_if_changed(line, &e, changed), true); // malformed REMOTE_ADDR
    };

    if ip != TUNNEL_PEER_IP {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    }

    let Ok(port) = port_str.parse::<i64>().map_err(|_| ()).and_then(|p| if p != 0 { Ok(p) } else { Err(()) }) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    };

    let Some(real) = super::viamap::lookup(vm, port, extract_line_time(&e), extract_dest_port(&e)) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), false);
    };
    let real = real.to_string();

    e["REMOTE_ADDR"] = Value::from(join_host_port(&real, &port_str));
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
    changed |= set_if_changed(&mut e, "sensor", "galah");
    changed |= set_if_changed(&mut e, "protocol", "HTTP");
    if let Some(dst) = e.get("port").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
        changed |= set_if_changed(&mut e, "dst_port", dst);
    }
    if let Some(hr) = e.get("httpRequest").cloned().filter(Value::is_object) {
        if let Some(req) = hr.get("request").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
            changed |= set_if_changed(&mut e, "path", req);
        }
        if let Some(ua) = hr.get("userAgent").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
            changed |= set_if_changed(&mut e, "user_agent", ua);
        }
        if let Some(sha) = hr.get("bodySha256").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
            changed |= set_if_changed(&mut e, "body_sha256", sha);
        }
    }
    changed |= super::attck::promote_attck_technique_fields("galah", &mut e);

    let ip = e.get("srcIP").and_then(Value::as_str).unwrap_or("").to_string();
    if ip != TUNNEL_PEER_IP {
        if !ip.is_empty() {
            changed |= set_if_changed(&mut e, "src_ip", ip);
        }
        return (marshal_if_changed(line, &e, changed), true);
    }

    let port: Option<i64> = e.get("srcPort").and_then(Value::as_str).and_then(|s| s.parse().ok());
    let Some(port) = port.filter(|p| *p != 0) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    };

    let Some(real) = super::viamap::lookup(vm, port, extract_line_time(&e), extract_dest_port(&e)) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), false);
    };
    let real = real.to_string();

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
    changed |= set_if_changed(&mut e, "sensor", "sentrypeer");
    changed |= set_if_changed(&mut e, "protocol", "SIP");
    if let Some(ua) = e.get("sip_user_agent").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string) {
        changed |= set_if_changed(&mut e, "user_agent", ua);
    }
    changed |= super::attck::promote_attck_technique_fields("sentrypeer", &mut e);

    let Some((ip, port_str)) = split_host_port(&source_addr) else {
        return (marshal_if_changed(line, &e, changed), true);
    };

    if ip != TUNNEL_PEER_IP {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    }

    let Ok(port) = port_str.parse::<i64>().map_err(|_| ()).and_then(|p| if p != 0 { Ok(p) } else { Err(()) }) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    };

    let Some(real) = super::viamap::lookup(vm, port, extract_line_time(&e), extract_dest_port(&e)) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), false);
    };
    let real = real.to_string();

    e["source_ip"] = Value::from(join_host_port(&real, &port_str));
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
    if WORDPOT_LOGIN_ATTEMPT_RE.is_match(msg) {
        let caps = WORDPOT_LOGIN_ATTEMPT_RE.captures(msg).unwrap();
        let c1 = set_if_changed(e, "path", "/wp-login.php");
        let c2 = set_if_changed(e, "username", caps[1].to_string());
        let c3 = set_if_changed(e, "password", caps[2].to_string());
        c1 || c2 || c3
    } else if WORDPOT_LOGIN_PROBE_RE.is_match(msg) {
        set_if_changed(e, "path", "/wp-login.php")
    } else if WORDPOT_ADMIN_PROBE_RE.is_match(msg) {
        let caps = WORDPOT_ADMIN_PROBE_RE.captures(msg).unwrap();
        set_if_changed(e, "path", format!("/wp-admin{}", &caps[1]))
    } else if WORDPOT_PLUGIN_PROBE_RE.is_match(msg) {
        let caps = WORDPOT_PLUGIN_PROBE_RE.captures(msg).unwrap();
        let c1 = set_if_changed(e, "plugin", caps[1].to_string());
        let c2 = set_if_changed(e, "path", format!("/wp-content/plugins/{}{}", &caps[1], &caps[2]));
        c1 || c2
    } else if WORDPOT_THEME_PROBE_RE.is_match(msg) {
        let caps = WORDPOT_THEME_PROBE_RE.captures(msg).unwrap();
        let c1 = set_if_changed(e, "theme", caps[1].to_string());
        let c2 = set_if_changed(e, "path", format!("/wp-content/themes/{}{}", &caps[1], &caps[2]));
        c1 || c2
    } else if WORDPOT_TIMTHUMB_RE.is_match(msg) {
        let caps = WORDPOT_TIMTHUMB_RE.captures(msg).unwrap();
        set_if_changed(e, "path", caps[1].to_string())
    } else if WORDPOT_BACKUPS_RE.is_match(msg) {
        let caps = WORDPOT_BACKUPS_RE.captures(msg).unwrap();
        set_if_changed(e, "path", caps[1].to_string())
    } else if WORDPOT_AUTHOR_RE.is_match(msg) {
        let caps = WORDPOT_AUTHOR_RE.captures(msg).unwrap();
        set_if_changed(e, "username", caps[1].to_string())
    } else if WORDPOT_COMMON_FILE_RE.is_match(msg) {
        let caps = WORDPOT_COMMON_FILE_RE.captures(msg).unwrap();
        set_if_changed(e, "path", format!("/{}", &caps[1]))
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
    changed |= set_if_changed(&mut e, "sensor", "wordpot");
    changed |= set_if_changed(&mut e, "protocol", "HTTP");
    changed |= classify_wordpot_message(&mut e, &rest);
    changed |= super::attck::promote_attck_technique_fields("wordpot", &mut e);

    if ip != TUNNEL_PEER_IP {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    }

    let Ok(port) = port_str.parse::<i64>().map_err(|_| ()).and_then(|p| if p != 0 { Ok(p) } else { Err(()) }) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    };

    let Some(real) = super::viamap::lookup(vm, port, extract_line_time(&e), extract_dest_port(&e)) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), false);
    };
    let real = real.to_string();

    e["message"] = Value::from(format!("{} {}", join_host_port(&real, &port_str), rest));
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
    #[test]
    fn loopback_source_is_marked_as_an_internal_probe() {
        // #1677: every sensor here is fronted by a Docker healthcheck that
        // connects to its own listening port, and the sensor logs it exactly
        // as it logs a real connection.
        let line = json!({"src_ip": "127.0.0.1", "src_port": 37253, "sensor": "sentrypeer"}).to_string();
        let (out, resolved) = enrich_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "sentrypeer");
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(e["internal_probe"], json!(true));
        assert!(resolved, "a probe is terminal, never queued for retry");
    }

    #[test]
    fn ipv6_loopback_counts_too() {
        let line = json!({"src_ip": "::1", "src_port": 1, "sensor": "http-honeypot"}).to_string();
        let (out, _) = enrich_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "http-honeypot");
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(e["internal_probe"], json!(true));
    }

    #[test]
    fn a_real_attacker_is_never_marked() {
        let line = json!({"src_ip": "223.123.126.43", "src_port": 44321, "sensor": "cowrie"}).to_string();
        let (out, _) = enrich_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "cowrie");
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert!(e.get("internal_probe").is_none(), "only loopback is a probe");
        assert_eq!(e["src_ip"], json!("223.123.126.43"), "and the address is untouched");
    }

    #[test]
    fn marking_a_probe_does_not_rewrite_its_address() {
        // The address is the evidence that this was self-generated. Enriching
        // it away would turn a probe into a plausible-looking attack.
        let line = json!({"src_ip": "127.0.0.1", "src_port": 502, "sensor": "conpot"}).to_string();
        let (out, _) = enrich_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "conpot");
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(e["src_ip"], json!("127.0.0.1"));
        assert_eq!(e["internal_probe"], json!(true));
    }


    use super::*;
    use serde_json::json;

    fn vm_with(port: i64, ip: &str) -> ViaMap {
        let mut m = ViaMap::new();
        // at/dest_port 0 so these keep exercising the join itself rather than
        // #1771's plausibility checks, which have their own tests in viamap.
        m.insert(port, vec![super::super::viamap::ViaEntry {
            ip: ip.to_string(), at: 0, dest_port: 0,
        }]);
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
