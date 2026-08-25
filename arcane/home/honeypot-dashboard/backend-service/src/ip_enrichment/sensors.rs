//! Ported from ip-enrichment-worker/enrich.go plus the bespoke per-sensor
//! files (beelzebub.go/hellpot.go/galah.go/sentrypeer.go/wordpot.go): the
//! generic tunnel-peer src_ip join, dionaea_incident.json's nested-shape
//! variant, and five sensors whose raw log line doesn't match the generic
//! src_ip/src_port shape at all.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
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
    mark_probe_from(e, &ip)
}

/// The same rule, for the enrichers that derive the address themselves.
///
/// mark_internal_probe reads `src_ip` off the event, which is a field
/// enrich_line has already populated by the time it runs. The per-sensor
/// enrichers do not have that: they read the address out of their own
/// sensor's field first -- sentrypeer's "source_ip", hellpot's
/// REMOTE_ADDR, galah's "srcIP", wordpot's message prefix -- and only
/// write `src_ip` at the end, on paths that vary. So they pass what they
/// found instead of relying on a field that is not there yet.
///
/// This is why #1918 existed at all. Every one of those enrichers skipped
/// the probe marking entirely, so their healthchecks were excluded from
/// `source.ip` (loopback is not an attacker) but never flagged as probes
/// -- landing in the unattributed residue instead. Measured over 24h:
/// 2,879 loopback events unflagged, of which 2,864 came from these four
/// sensors and 2,857 from sentrypeer alone, which inflated that residue
/// roughly threefold.
fn mark_probe_from(e: &mut Value, ip: &str) -> bool {
    if !LOOPBACK_IPS.contains(&ip) {
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
    let Some(real) = super::viamap::lookup(lookup, port, line_at) else {
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
                        // #1917: the connection object says which of its own
                        // ports the attacker reached, and that is what makes
                        // this join safe. Measured on live data: an mssql
                        // connection on 1433 resolved to the client of a
                        // telnet dial 21 minutes earlier that reused the same
                        // ephemeral port -- inside the time window, newest
                        // entry the map had, and a different attacker. The
                        // destination port rules it out outright.
                        let want_port = map
                            .get("local_port")
                            .and_then(Value::as_f64)
                            .map(|p| p as i64)
                            .unwrap_or(0);
                        if let Some(real) =
                            super::viamap::lookup_to_port(vm, port as i64, line_at, want_port)
                        {
                            map.insert("remote_ip".to_string(), Value::from(real.to_string()));
                            changed += 1;
                        } else {
                            // Better queued than answered wrongly: the right
                            // entry usually arrives within a second, and the
                            // pending queue flushes it unenriched if it never
                            // does.
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

    let Some(real) = super::viamap::lookup(vm, port, extract_line_time(&e)) else {
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

/// One rule for deciding who sent a relayed request (#1876).
///
/// A sensor behind the tunnel can be told who its client was by more than
/// one mechanism, and they are not equally trustworthy:
///
///   * the via_port join answers from portbridge's own record of the
///     connection it relayed -- evidence *about* the connection;
///   * a forwarded header answers from inside the request -- content, and
///     on a path portbridge relays it is authored by the attacker.
///
/// So where both speak, the connection wins. Where they disagree the
/// disagreement is kept rather than resolved away: on a relayed path a
/// contradicting header is an attacker claiming a different source, and
/// discarding it erases the attempt while believing it is the bug #1419
/// removed. Where only one speaks it is used; where neither does the line
/// waits, because the tunnel peer is our own address and reporting it as a
/// source states something false.
///
/// Sensors record, this decides. A sensor cannot tell the paths apart --
/// both present the tunnel peer, and any header a relay adds an attacker
/// can also send -- so the decision belongs where portbridge's connection
/// log is, which is here.
pub struct SourceVerdict {
    pub ip: String,
    /// Set only when a second mechanism contradicted `ip`.
    pub claimed: Option<String>,
    pub resolved: bool,
}

pub fn adjudicate_source(observed: &str, relayed: Option<String>, claimed: Option<String>) -> SourceVerdict {
    // Not relayed: the sensor is looking straight at the client, so no join
    // applies and no header may override what the connection shows.
    if observed != TUNNEL_PEER_IP {
        return SourceVerdict { ip: observed.to_string(), claimed: None, resolved: true };
    }
    match (relayed, claimed) {
        (Some(relayed), Some(claimed)) if relayed != claimed => {
            SourceVerdict { ip: relayed, claimed: Some(claimed), resolved: true }
        }
        (Some(relayed), _) => SourceVerdict { ip: relayed, claimed: None, resolved: true },
        // portbridge never saw this connection, so the header is the only
        // evidence there is.
        (None, Some(claimed)) => SourceVerdict { ip: claimed, claimed: None, resolved: true },
        (None, None) => SourceVerdict { ip: observed.to_string(), claimed: None, resolved: false },
    }
}

/// The hop a forwarded header appended last, or None if nothing usable.
///
/// The last hop, not the first: Cloudflare appends the real client to
/// whatever the client already sent rather than replacing it, so the
/// leftmost entry is attacker-controlled and the rightmost is the one
/// Cloudflare itself wrote. A value that is not an address is not evidence
/// and must never reach a field the dashboard renders as one.
/// Who the proxy chain in front of a sensor says the client is.
///
/// The obvious reading -- the last hop of X-Forwarded-For -- is wrong here,
/// and shipped wrong for months. Each proxy *appends the peer it saw*, so on
/// the Cloudflare -> Traefik -> sensor path the chain ends with the address
/// Traefik saw, which is Cloudflare's edge. Measured on a live request:
/// `X-Forwarded-For: <client>, 172.69.150.126`, the trailing address being a
/// Cloudflare edge node. #1511 took the last hop, so every proxied galah
/// event was filed against Cloudflare rather than against an attacker --
/// 172.69.x sitting in the source list looking like ordinary traffic.
///
/// Cf-Connecting-Ip is the direct answer wherever Cloudflare set it: one
/// value, the client, with no chain to index into. The fallback is the
/// second-to-last hop, which is the entry Cloudflare itself appended. Both
/// hold against a client that pre-seeds the header, because whatever an
/// attacker writes stays to the *left* of what Cloudflare appends and so
/// never becomes either answer.
///
/// This is only ever a claim. Whether it may be believed depends on the
/// request having genuinely arrived through that chain, which is the
/// caller's business and not this function's -- see enrich_galah_line.
pub fn forwarded_claim(e: &Value) -> Option<String> {
    if let Some(cf) = recorded(e, &["cf_connecting_ip", "CF_CONNECTING_IP"])
        .or_else(|| header_value(e, "cf-connecting-ip"))
        .and_then(|v| valid_ip(&v))
    {
        return Some(cf);
    }
    let raw = forwarded_header(e)?;
    let hops: Vec<&str> = raw.split(',').map(str::trim).filter(|h| !h.is_empty()).collect();
    // Two or more hops means a proxy appended its own peer behind the entry
    // that identifies the client; a single hop means nothing was appended.
    let idx = if hops.len() >= 2 { hops.len() - 2 } else { 0 };
    valid_ip(hops.get(idx)?)
}

fn valid_ip(candidate: &str) -> Option<String> {
    candidate.parse::<std::net::IpAddr>().ok().map(|_| candidate.to_string())
}

/// The raw X-Forwarded-For a sensor recorded, wherever it put it.
///
/// hellpot logs it as its own field, because it logs almost nothing else
/// (hellpot/xff_trust_patch.py). galah already logs every request header,
/// so it needs no patch to record one -- the value has been in
/// httpRequest.headers the whole time, and the sensor was resolving it
/// itself rather than leaving the decision to the worker (#1891).
///
/// Header names arrive in whatever case the client sent, so the lookup is
/// case-insensitive: an attacker choosing `x-forwarded-for` should not be
/// able to sidestep the adjudication by lowercasing it.
fn forwarded_header(e: &Value) -> Option<String> {
    recorded(e, &["XFF", "xff"]).or_else(|| header_value(e, "x-forwarded-for"))
}

/// A field a sensor recorded directly, under whichever name it uses.
///
/// Sensors that log their whole header map need no help -- galah is one.
/// The ones that log almost nothing have to be given a field, and each was
/// given one in its own house style: hellpot's patch writes `XFF` next to
/// its bare message, wordpot's writes `xff` and `cf_connecting_ip`
/// alongside the snake_case fields it already emits. Renaming either would
/// orphan everything already on disk for no gain, so the spellings live
/// here -- this is the one place that has to know all of them anyway.
fn recorded(e: &Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        e.get(*name).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string)
    })
}

/// One request header out of whatever the sensor recorded, by name.
///
/// Header names arrive in the case the sender chose, so the match is
/// case-insensitive: an attacker writing `x-forwarded-for` must not get
/// different handling from one writing `X-Forwarded-For`.
fn header_value(e: &Value, name: &str) -> Option<String> {
    let headers = e.get("httpRequest")?.get("headers")?.as_object()?;
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| value.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Write a verdict onto a line, so every sensor records a contradicted
/// claim under the same field names.
pub fn apply_verdict(e: &mut Value, v: &SourceVerdict) -> bool {
    let mut changed = set_if_changed(e, "src_ip", v.ip.clone());
    if let Some(claimed) = &v.claimed {
        changed |= set_if_changed(e, "src_ip_claimed", claimed.clone());
        if e.get("src_ip_conflict").and_then(Value::as_bool) != Some(true) {
            e["src_ip_conflict"] = Value::Bool(true);
            changed = true;
        }
    }
    changed
}

/// Clients already resolved for a connection that is still open (#1876).
///
/// HellPot is a tarpit: it holds a connection for as long as the client will
/// stay, then writes FINISH when it finally closes. Observed live at 26 and
/// 60 hours. viamap only accepts a dial within MAX_AGE_SECONDS (6h), so the
/// closing line of a long hold can never join -- the dial it needs aged out
/// of the map long before.
///
/// Re-deriving per line cannot fix that. Remembering can: the port in
/// REMOTE_ADDR is stable across NEW -> FINISH for one connection, so the
/// answer found when it opened still applies when it closes, however much
/// later that is.
///
/// Port reuse is safe because the entry is dropped when the connection
/// closes. An operating system will not hand out a source port whose
/// connection is still established, so the only reuse that can happen is
/// after the FINISH that evicted the entry -- and the next NEW writes a
/// fresh one before anything reads it.
///
/// Widening MAX_AGE_SECONDS was the alternative and is the wrong lever: it
/// would loosen the join for every sensor to fix one, and a six-hour-old
/// dial genuinely is ambiguous for anything that is not a tarpit.
fn held_connections() -> &'static Mutex<HashMap<i64, (String, i64)>> {
    static HELD: OnceLock<Mutex<HashMap<i64, (String, i64)>>> = OnceLock::new();
    HELD.get_or_init(|| Mutex::new(HashMap::new()))
}

/// How long a remembered connection stays useful. Past this it is a leak
/// rather than a memory -- a connection nothing has written a line for in
/// four days is not still open.
const HELD_TTL_SECONDS: i64 = 4 * 24 * 3600;

/// Bounds the map even if closing lines are lost entirely. Ports are capped
/// at 65535, so this is a backstop against a pathological run rather than an
/// expected limit.
const HELD_CAPACITY: usize = 4096;

fn remember_connection(port: i64, client: &str, at: i64) {
    let Ok(mut held) = held_connections().lock() else { return };
    if held.len() >= HELD_CAPACITY {
        held.retain(|_, (_, seen)| at - *seen <= HELD_TTL_SECONDS);
        if held.len() >= HELD_CAPACITY {
            return; // still full: drop the new entry rather than grow without bound
        }
    }
    held.insert(port, (client.to_string(), at));
}

fn recall_connection(port: i64, at: i64) -> Option<String> {
    let Ok(held) = held_connections().lock() else { return None };
    let (client, seen) = held.get(&port)?;
    if at - *seen > HELD_TTL_SECONDS {
        return None;
    }
    Some(client.clone())
}

fn forget_connection(port: i64) {
    if let Ok(mut held) = held_connections().lock() {
        held.remove(&port);
    }
}

/// Whether this line is the last one a connection will produce.
fn closes_connection(e: &Value) -> bool {
    matches!(
        e.get("message").and_then(Value::as_str),
        Some("FINISH") | Some("END_ON_ERR")
    )
}

/// hellpot.json: REMOTE_ADDR is a single "ip:port" string (fasthttp's
/// RemoteAddr()). No destination-port field; every event is HTTP by
/// definition (a single-protocol tarpit).
/// hellpot's Traefik-facing listen port, as its own `DST_PORT` field
/// reports it. Same job as GALAH_PROXIED_PORT and WORDPOT_PROXIED_PORT: a
/// port portbridge never dials, so the path is a fact rather than an
/// inference. Kept in step with hellpot's xff_trust_patch.py and the socat
/// target in vps/docker-compose.yml.
const HELLPOT_PROXIED_PORT: &str = "8090";

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
    changed |= mark_probe_from(&mut e, &ip);

    if ip != TUNNEL_PEER_IP {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    }

    // #1908: which door, before which evidence.
    //
    // #1876 left this asking portbridge and falling back to the header when
    // portbridge had nothing -- right on the raw path, and unsound on the
    // proxied one. The map is keyed by port alone over a six-hour window,
    // so "portbridge has an entry for socat's ephemeral source port" is a
    // coincidence there rather than an answer, and under this traffic a
    // likely one. It would then quietly file the request against an
    // unrelated attacker, which reads exactly like a correct result.
    //
    // The two doors are separate ports now (xff_trust_patch.py), so the
    // question is answered rather than inferred.
    if e.get("DST_PORT").and_then(Value::as_str) == Some(HELLPOT_PROXIED_PORT) {
        // Cloudflare -> Traefik is the only route to this port, so the
        // chain is the evidence, and no join is attempted at all.
        let Some(client) = forwarded_claim(&e) else {
            changed |= set_if_changed(&mut e, "src_ip", ip);
            return (marshal_if_changed(line, &e, changed), false);
        };
        e["REMOTE_ADDR"] = Value::from(join_host_port(&client, &port_str));
        changed |= set_if_changed(&mut e, "src_ip", client);
        return (marshal_if_changed(line, &e, changed), true);
    }

    let Ok(port) = port_str.parse::<i64>().map_err(|_| ()).and_then(|p| if p != 0 { Ok(p) } else { Err(()) }) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    };

    // #1876: the dial first, then what this connection already resolved to.
    //
    // Both are the same join -- portbridge's record of who it relayed --
    // one read live and one read from when this connection opened. The
    // live map is preferred where it still holds the entry; the memory
    // covers the case it cannot, which is a hold longer than the map's
    // window.
    // Every mechanism that can speak, then one rule to decide between them.
    //
    // The live dial map and this connection's remembered answer are the
    // same join read two ways -- one current, one from when the connection
    // opened -- so the memory is a fallback rather than a rival. The header
    // is a different mechanism entirely, and adjudicate_source ranks it.
    let at = extract_line_time(&e);
    let relayed = super::viamap::lookup(vm, port, at)
        .map(|real| real.to_string())
        .or_else(|| recall_connection(port, at));
    let verdict = adjudicate_source(&ip, relayed, forwarded_claim(&e));

    if !verdict.resolved {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), false);
    }

    if closes_connection(&e) {
        // Nothing further will be written for this connection, so the
        // entry stops being a memory and starts being a leak.
        forget_connection(port);
    } else {
        remember_connection(port, &verdict.ip, at);
    }

    e["REMOTE_ADDR"] = Value::from(join_host_port(&verdict.ip, &port_str));
    e["src_port"] = Value::from(port);
    apply_verdict(&mut e, &verdict);
    (marshal_if_changed(line, &e, true), true)
}

/// galah's event_log.json: flat srcIP/srcPort fields already. Promotes
/// body_sha256 from httpRequest.bodySha256 and dst_port from the server's
/// own "port" string. srcHost/tags (galah's own pre-join enrichment,
/// looked up against the tunnel peer address) are deliberately left
/// untouched, not deleted, not trusted.
/// galah's Traefik-facing listen port, as it appears in the sensor's own
/// `port` field.
///
/// Its whole job is to be a port portbridge never dials, so that "which
/// door did this come through" is answerable from the log line instead of
/// inferred. Changing it means changing galah's config.yaml `ports:` list
/// and the socat target in vps/docker-compose.yml at the same time; leaving
/// it merely wrong makes proxied requests fall back to the raw-port branch,
/// where they resolve to the tunnel address rather than to anything untrue.
const GALAH_PROXIED_PORT: &str = "8890";

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
    changed |= mark_probe_from(&mut e, &ip);
    if ip != TUNNEL_PEER_IP {
        if !ip.is_empty() {
            changed |= set_if_changed(&mut e, "src_ip", ip);
        }
        return (marshal_if_changed(line, &e, changed), true);
    }

    // Which of galah's two front doors this arrived at decides what counts
    // as evidence, so the listen port is read before anything else.
    //
    // The two doors used to be one, and that is the whole defect behind
    // #1891. Traefik and portbridge both landed on :8888 and both dial from
    // the tunnel address, so a request that had crossed Cloudflare and one
    // sent straight at the raw port were indistinguishable by the time a
    // sensor or this worker saw them. Everything downstream was then a
    // guess. galah takes a `ports:` list natively, so the doors are simply
    // separate now (config.yaml, and the socat in vps/docker-compose.yml).
    if e.get("port").and_then(Value::as_str) == Some(GALAH_PROXIED_PORT) {
        // Only Traefik can reach this port. It is published on the
        // WireGuard address, no portbridge rule targets it, and the sole
        // dialler is socat-hp-galah -- so the Cloudflare -> Traefik chain
        // is the only way a request arrives, and what that chain says about
        // the client is the best evidence available. A via_port join is
        // deliberately *not* attempted: portbridge never carried this
        // connection, so any entry matching socat's ephemeral source port
        // would be a coincidence, and the map keeps six hours of them.
        let Some(client) = forwarded_claim(&e) else {
            changed |= set_if_changed(&mut e, "src_ip", ip);
            return (marshal_if_changed(line, &e, changed), false);
        };
        e["srcIP"] = Value::from(client.clone());
        changed |= set_if_changed(&mut e, "src_ip", client);
        return (marshal_if_changed(line, &e, changed), true);
    }

    let port: Option<i64> = e.get("srcPort").and_then(Value::as_str).and_then(|s| s.parse().ok());
    let Some(port) = port.filter(|p| *p != 0) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    };

    // The raw port: portbridge relayed this, so its connection log knows
    // who dialled, and a forwarding header is just bytes the attacker
    // chose to send. #1511 had it the other way round -- galah's own
    // xff_trust_patch.py rewrote srcIP from X-Forwarded-For whenever
    // RemoteAddr was the tunnel peer, which on this port is *always*.
    // Confirmed against the running stack before removing it: a request to
    // the raw port carrying `X-Forwarded-For: 198.51.100.77` was stored
    // with that as source.ip, so anyone could file their traffic under any
    // address they liked. Same defect as #1883, in the code #1883 was
    // copied from.
    //
    // portbridge's record wins here because it is evidence *about* the
    // connection rather than content carried inside it. A header that
    // disagrees is kept and flagged rather than dropped: on this path a
    // contradiction is someone trying the above, which is worth seeing.
    let at = extract_line_time(&e);
    let relayed = super::viamap::lookup(vm, port, at).map(|real| real.to_string());
    let verdict = adjudicate_source(&ip, relayed, forwarded_claim(&e));

    if !verdict.resolved {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), false);
    }

    e["srcIP"] = Value::from(verdict.ip.clone());
    e["src_port"] = Value::from(port);
    apply_verdict(&mut e, &verdict);
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
    changed |= mark_probe_from(&mut e, &ip);

    if ip != TUNNEL_PEER_IP {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    }

    let Ok(port) = port_str.parse::<i64>().map_err(|_| ()).and_then(|p| if p != 0 { Ok(p) } else { Err(()) }) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    };

    let Some(real) = super::viamap::lookup(vm, port, extract_line_time(&e)) else {
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
/// wordpot's Traefik-facing listen port, as its own `dst_port` field
/// reports it. Same job as GALAH_PROXIED_PORT: a port portbridge never
/// dials, so the path is a fact rather than an inference. Kept in step with
/// wordpot_patch.py's WORDPOT_PROXIED_PORT and the socat target in
/// vps/docker-compose.yml.
const WORDPOT_PROXIED_PORT: &str = "8090";

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
    let (mut ip, mut port_str, rest) = (caps[1].to_string(), caps[2].to_string(), caps[3].to_string());

    // #1908: the sentence is wordpot's prose and the fields are the
    // request, so the fields win where the sensor recorded them. Older
    // lines have only the sentence and keep parsing exactly as before.
    if let Some(recorded) = e.get("src_ip").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        ip = recorded.to_string();
    }
    if let Some(recorded) = e.get("src_port").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        port_str = recorded.to_string();
    }

    let mut changed = false;
    changed |= set_if_changed(&mut e, "sensor", "wordpot");
    changed |= set_if_changed(&mut e, "protocol", "HTTP");
    changed |= classify_wordpot_message(&mut e, &rest);
    changed |= super::attck::promote_attck_technique_fields("wordpot", &mut e);
    changed |= mark_probe_from(&mut e, &ip);

    if ip != TUNNEL_PEER_IP {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    }

    // Which door this arrived at, exactly as for galah (#1908). wordpot
    // binds one port by default, which is why both ways in shared one and
    // why the sensor used to guess between them -- badly, in three separate
    // ways at once. wordpot_patch.py opens a second listener that only
    // socat-hp-wordpot can reach, so the question is now answered by the
    // log line rather than inferred from it.
    if e.get("dst_port").and_then(Value::as_str) == Some(WORDPOT_PROXIED_PORT) {
        // Cloudflare -> Traefik is the only route here, so what that chain
        // says about the client is the evidence. No via_port join: the
        // connection was socat's, portbridge never carried it, and a
        // matching entry would be a coincidence out of six hours of them.
        let Some(client) = forwarded_claim(&e) else {
            changed |= set_if_changed(&mut e, "src_ip", ip);
            return (marshal_if_changed(line, &e, changed), false);
        };
        e["message"] = Value::from(format!("{} {}", join_host_port(&client, &port_str), rest));
        changed |= set_if_changed(&mut e, "src_ip", client);
        return (marshal_if_changed(line, &e, changed), true);
    }

    let Ok(port) = port_str.parse::<i64>().map_err(|_| ()).and_then(|p| if p != 0 { Ok(p) } else { Err(()) }) else {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), true);
    };

    // The raw port: portbridge relayed this and its log knows who dialled,
    // so a forwarding header is just bytes the attacker chose to send. It
    // is kept and flagged rather than dropped -- on this path a
    // contradiction is someone trying what #1908 found working.
    let relayed = super::viamap::lookup(vm, port, extract_line_time(&e)).map(|real| real.to_string());
    let verdict = adjudicate_source(&ip, relayed, forwarded_claim(&e));
    if !verdict.resolved {
        changed |= set_if_changed(&mut e, "src_ip", ip);
        return (marshal_if_changed(line, &e, changed), false);
    }

    e["message"] = Value::from(format!("{} {}", join_host_port(&verdict.ip, &port_str), rest));
    e["src_port"] = Value::from(port);
    apply_verdict(&mut e, &verdict);
    (marshal_if_changed(line, &e, true), true)
}

/// net.SplitHostPort equivalent for the plain "ip:port" shape every
/// bespoke sensor here uses (no IPv6 brackets in any real captured line).
fn split_host_port(addr: &str) -> Option<(String, String)> {
    // IPv6 arrives bracketed. Go renders a v6 peer as "[::1]:1234", and
    // rsplit_once(':') leaves the brackets welded to the address -- so the
    // result matched no loopback constant, parsed as no IpAddr, and would
    // have been written into src_ip as "[::1]" for everything downstream
    // to trip over.
    //
    // Found by #1918's own IPv6 test rather than by a report: a v6 client
    // is rare enough against these sensors that nothing had exercised the
    // path, which is exactly how it stayed wrong quietly.
    if let Some(rest) = addr.strip_prefix('[') {
        let (ip, port) = rest.split_once("]:")?;
        if ip.is_empty() || port.is_empty() {
            return None;
        }
        return Some((ip.to_string(), port.to_string()));
    }
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
        // at 0 so these keep exercising the join itself rather than
        // #1771's plausibility checks, which have their own tests in viamap.
        m.insert(port, vec![super::super::viamap::ViaEntry {
            // target_port 0 opts these fixtures out of #1917's
            // destination-port check; the tests that exercise it build
            // their own entries with a real port.
            ip: ip.to_string(), at: 0, target_port: 0,
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

    // ---- #1876: the adjudication rule, and the tarpit's connection memory.

    fn hellpot_line(remote: &str, xff: Option<&str>, message: &str) -> Vec<u8> {
        let mut e = serde_json::json!({
            "level": "info",
            "REMOTE_ADDR": remote,
            "URL": "/wp-login.php",
            "USERAGENT": "curl/8.18.0",
            "message": message,
            "time": "2026-08-24T20:00:00Z",
        });
        if let Some(xff) = xff {
            e["XFF"] = Value::from(xff);
        }
        serde_json::to_vec(&e).unwrap()
    }

    fn field(out: &[u8], key: &str) -> Option<String> {
        let e: Value = serde_json::from_slice(out).unwrap();
        e.get(key).and_then(Value::as_str).map(str::to_string)
    }

    #[test]
    fn the_connection_wins_over_a_contradicting_header() {
        // On a relayed path the header is attacker-authored, so a
        // disagreement is a spoof attempt rather than a puzzle -- and it is
        // kept, because discarding it would erase the attempt.
        let verdict = adjudicate_source(
            TUNNEL_PEER_IP,
            Some("203.0.113.7".into()),
            Some("198.51.100.9".into()),
        );
        assert_eq!(verdict.ip, "203.0.113.7");
        assert_eq!(verdict.claimed.as_deref(), Some("198.51.100.9"));
        assert!(verdict.resolved);
    }

    #[test]
    fn agreement_is_not_recorded_as_a_conflict() {
        let verdict = adjudicate_source(
            TUNNEL_PEER_IP,
            Some("203.0.113.7".into()),
            Some("203.0.113.7".into()),
        );
        assert_eq!(verdict.ip, "203.0.113.7");
        assert!(verdict.claimed.is_none());
    }

    #[test]
    fn the_header_answers_when_portbridge_never_saw_the_connection() {
        let verdict = adjudicate_source(TUNNEL_PEER_IP, None, Some("198.51.100.9".into()));
        assert_eq!(verdict.ip, "198.51.100.9");
        assert!(verdict.claimed.is_none());
        assert!(verdict.resolved);
    }

    #[test]
    fn nothing_answering_leaves_the_line_for_retry() {
        let verdict = adjudicate_source(TUNNEL_PEER_IP, None, None);
        assert!(!verdict.resolved, "the tunnel peer is our own address, not a source");
    }

    #[test]
    fn a_source_preserved_connection_ignores_any_header() {
        // RemoteAddr is already the attacker; no header may override what
        // the connection itself shows.
        let verdict = adjudicate_source("203.0.113.7", None, Some("198.51.100.9".into()));
        assert_eq!(verdict.ip, "203.0.113.7");
    }

    #[test]
    fn the_hop_cloudflare_appended_wins_not_the_last_one() {
        // This test used to assert the last hop, on the reasoning that
        // Cloudflare appends the real client to whatever the client sent,
        // so the attacker's own value ends up left of the truth. The first
        // half is right and the conclusion does not follow: Traefik sits
        // behind Cloudflare and appends the peer *it* saw, which is a
        // Cloudflare edge node. So the chain ends one hop past the client.
        //
        // Not a hypothetical -- a request through the live subdomain
        // arrived as `<client>, 172.69.150.126`, and every proxied galah
        // event had been filed against addresses like that one.
        let e: Value = serde_json::json!({"XFF": "1.2.3.4, 198.51.100.9, 172.69.150.126"});
        assert_eq!(forwarded_claim(&e).as_deref(), Some("198.51.100.9"));
    }

    #[test]
    fn a_lone_hop_is_taken_as_it_stands() {
        // Nothing appended anything, so there is no proxy entry to skip
        // past. hellpot's own patch records the header verbatim and can
        // see chains this short.
        let e: Value = serde_json::json!({"XFF": "198.51.100.9"});
        assert_eq!(forwarded_claim(&e).as_deref(), Some("198.51.100.9"));
    }

    #[test]
    fn a_header_that_is_not_an_address_is_not_evidence() {
        let e: Value = serde_json::json!({"XFF": "not-an-address"});
        assert!(forwarded_claim(&e).is_none());
        let empty: Value = serde_json::json!({});
        assert!(forwarded_claim(&empty).is_none());
    }

    #[test]
    fn a_tarpit_hold_longer_than_the_dial_window_still_attributes_on_close() {
        // The residue this exists for: HellPot held connections for 26 and
        // 60 hours, and viamap accepts a dial for six. The opening line
        // resolves against the live map; the closing line, days later, has
        // only what the connection already resolved to.
        let port = 60001_i64;
        forget_connection(port);
        let mut vm: ViaMap = ViaMap::new();
        super::super::viamap::parse_portbridge_line(
            serde_json::to_vec(&serde_json::json!({
                "sensor": "portbridge", "event": "connect",
                "src_ip": "203.0.113.7", "via_port": port,
                "time": "2026-08-24T20:00:00Z",
            }))
            .unwrap()
            .as_slice(),
            &mut vm,
        );

        let addr = format!("{TUNNEL_PEER_IP}:{port}");
        let (opened, resolved) = enrich_hellpot_line(&hellpot_line(&addr, None, "NEW"), &vm, &ViaMap::new(), "hellpot");
        assert!(resolved, "the opening line must resolve against the live map");
        assert_eq!(field(&opened, "src_ip").as_deref(), Some("203.0.113.7"));

        // The dial has aged out entirely by the time the tarpit lets go.
        let (closed, resolved) =
            enrich_hellpot_line(&hellpot_line(&addr, None, "FINISH"), &ViaMap::new(), &ViaMap::new(), "hellpot");
        assert!(resolved, "the closing line must not be left unattributed");
        assert_eq!(
            field(&closed, "src_ip").as_deref(),
            Some("203.0.113.7"),
            "the closing line must carry the answer the connection already had"
        );
    }

    #[test]
    fn a_closed_connection_is_forgotten_so_a_reused_port_is_not_mistaken() {
        let port = 60002_i64;
        forget_connection(port);
        let addr = format!("{TUNNEL_PEER_IP}:{port}");

        // Drive the real path rather than seeding the memory by hand, so
        // the remembered timestamp is the one the code itself would store.
        let mut vm: ViaMap = ViaMap::new();
        super::super::viamap::parse_portbridge_line(
            serde_json::to_vec(&serde_json::json!({
                "sensor": "portbridge", "event": "connect",
                "src_ip": "203.0.113.7", "via_port": port,
                "time": "2026-08-24T20:00:00Z",
            }))
            .unwrap()
            .as_slice(),
            &mut vm,
        );
        let (_, resolved) = enrich_hellpot_line(&hellpot_line(&addr, None, "NEW"), &vm, &ViaMap::new(), "hellpot");
        assert!(resolved, "the opening line must resolve");

        let (_, resolved) =
            enrich_hellpot_line(&hellpot_line(&addr, None, "FINISH"), &ViaMap::new(), &ViaMap::new(), "hellpot");
        assert!(resolved, "the closing line resolves from the memory");

        // Same port, a later connection, nothing to join against: it must
        // not inherit the previous connection's client.
        let (out, resolved) =
            enrich_hellpot_line(&hellpot_line(&addr, None, "NEW"), &ViaMap::new(), &ViaMap::new(), "hellpot");
        assert!(!resolved, "a reused port must not resolve from a closed connection");
        assert_eq!(field(&out, "src_ip").as_deref(), Some(TUNNEL_PEER_IP));
    }

    // ---- galah: which door a request came through (#1891) ----

    /// A galah line as the sensor writes one, with the headers it records.
    fn galah_line(listen_port: &str, src_port: &str, headers: Value) -> String {
        json!({
            "msg": "successfulResponse",
            "srcIP": TUNNEL_PEER_IP,
            "srcPort": src_port,
            "port": listen_port,
            "httpRequest": {"request": "/", "headers": headers},
        })
        .to_string()
    }

    #[test]
    fn a_forwarding_header_cannot_name_the_source_on_the_raw_port() {
        // The bug this whole change exists for. galah's own patch rewrote
        // srcIP from X-Forwarded-For whenever the peer was the tunnel
        // address -- which on the raw port is every single request -- so
        // sending the header was enough to choose your own identity.
        // Reproduced against the running stack before the fix: a request
        // carrying 198.51.100.77 was stored under exactly that address.
        let line = galah_line(
            "8888",
            "43112",
            json!({"X-Forwarded-For": "198.51.100.77"}),
        );
        let (out, resolved) = enrich_galah_line(
            line.as_bytes(), &vm_with(43112, "203.0.113.9"), &ViaMap::new(), "galah",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(e["src_ip"], json!("203.0.113.9"), "portbridge saw who dialled");
        // Kept rather than dropped: on this path the header is somebody
        // trying the above, and that is worth having in the record.
        assert_eq!(e["src_ip_claimed"], json!("198.51.100.77"));
        assert_eq!(e["src_ip_conflict"], json!(true));
    }

    #[test]
    fn the_raw_port_still_resolves_ordinary_traffic() {
        // Most galah traffic carries no forwarding header at all; the join
        // has to go on working exactly as before.
        let line = galah_line("8888", "51982", json!({"User-Agent": "curl/7.68.0"}));
        let (out, resolved) = enrich_galah_line(
            line.as_bytes(), &vm_with(51982, "45.79.207.110"), &ViaMap::new(), "galah",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(e["src_ip"], json!("45.79.207.110"));
        assert!(e.get("src_ip_conflict").is_none(), "nothing contradicted it");
    }

    #[test]
    fn the_proxied_port_reads_the_client_not_cloudflares_edge() {
        // Traefik appends the peer *it* saw, which is a Cloudflare edge
        // node, so the last hop of the chain is never the attacker.
        // Measured live: `<client>, 172.69.150.126`. #1511 took that last
        // hop, which is why Cloudflare addresses turned up in galah's
        // source list looking like ordinary traffic.
        let line = galah_line(
            GALAH_PROXIED_PORT,
            "34228",
            json!({"X-Forwarded-For": "203.0.113.9, 172.69.150.126"}),
        );
        let (out, resolved) = enrich_galah_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(e["src_ip"], json!("203.0.113.9"));
    }

    #[test]
    fn a_client_cannot_prepend_its_way_into_the_answer() {
        // Cloudflare appends the address it accepted the connection from,
        // so anything the client wrote itself stays to the left of it and
        // is never what gets read.
        let line = galah_line(
            GALAH_PROXIED_PORT,
            "34229",
            json!({"X-Forwarded-For": "198.51.100.77, 203.0.113.9, 172.69.150.126"}),
        );
        let (out, _) = enrich_galah_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah");
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["src_ip"], json!("203.0.113.9"), "the hop Cloudflare appended");
    }

    #[test]
    fn cf_connecting_ip_is_preferred_where_cloudflare_set_it() {
        let line = galah_line(
            GALAH_PROXIED_PORT,
            "34230",
            json!({
                "Cf-Connecting-Ip": "203.0.113.9",
                "X-Forwarded-For": "198.51.100.77, 172.69.150.126",
            }),
        );
        let (out, _) = enrich_galah_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah");
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["src_ip"], json!("203.0.113.9"));
    }

    #[test]
    fn the_proxied_port_never_joins_against_portbridge() {
        // portbridge does not carry this connection, so socat's ephemeral
        // source port matching an entry is a coincidence -- and with six
        // hours of history per port under this traffic, a likely one.
        // Taking it would swap in an unrelated attacker's address.
        let line = galah_line(
            GALAH_PROXIED_PORT,
            "34228",
            json!({"X-Forwarded-For": "203.0.113.9, 172.69.150.126"}),
        );
        let (out, _) = enrich_galah_line(
            line.as_bytes(), &vm_with(34228, "198.51.100.77"), &ViaMap::new(), "galah",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["src_ip"], json!("203.0.113.9"), "the colliding entry is ignored");
    }

    #[test]
    fn a_header_name_in_any_case_is_still_the_same_header() {
        let line = galah_line(
            GALAH_PROXIED_PORT,
            "34231",
            json!({"x-forwarded-for": "203.0.113.9, 172.69.150.126"}),
        );
        let (out, _) = enrich_galah_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah");
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["src_ip"], json!("203.0.113.9"));
    }

    #[test]
    fn a_proxied_request_with_no_chain_is_left_unresolved() {
        // Nothing to read and nothing to join against. Retrying later is
        // right; inventing an address is not.
        let line = galah_line(GALAH_PROXIED_PORT, "34232", json!({"User-Agent": "curl/8"}));
        let (out, resolved) = enrich_galah_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(!resolved);
        assert_eq!(e["src_ip"], json!(TUNNEL_PEER_IP));
    }

    #[test]
    fn garbage_in_the_chain_does_not_become_a_source() {
        let line = galah_line(
            GALAH_PROXIED_PORT,
            "34233",
            json!({"X-Forwarded-For": "not-an-address, 172.69.150.126"}),
        );
        let (out, resolved) = enrich_galah_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(!resolved);
        assert_eq!(e["src_ip"], json!(TUNNEL_PEER_IP));
    }

    // ---- wordpot: the same two doors (#1908) ----

    /// A wordpot line as its patched formatter writes one: wordpot's own
    /// sentence, plus what the request actually was.
    fn wordpot_line(dst_port: &str, src_port: &str, extra: Value) -> String {
        let mut e = json!({
            "time": "2026-08-24T22:06:34",
            "level": "INFO",
            "message": format!("{}:{} probed for the login page", TUNNEL_PEER_IP, src_port),
            "src_ip": TUNNEL_PEER_IP,
            "src_port": src_port,
            "dst_port": dst_port,
        });
        for (k, v) in extra.as_object().unwrap() {
            e[k] = v.clone();
        }
        e.to_string()
    }

    #[test]
    fn wordpot_ignores_a_forwarding_header_on_the_raw_port() {
        // Verified against the running stack before the fix: a request to
        // wordpot's raw port carrying this header was logged as
        // "198.51.100.77 probed for the login page". The header decided.
        let line = wordpot_line("80", "53992", json!({"xff": "198.51.100.77"}));
        let (out, resolved) = enrich_wordpot_line(
            line.as_bytes(), &vm_with(53992, "203.0.113.9"), &ViaMap::new(), "wordpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(e["src_ip"], json!("203.0.113.9"), "portbridge saw who dialled");
        assert_eq!(e["src_ip_claimed"], json!("198.51.100.77"));
        assert_eq!(e["src_ip_conflict"], json!(true));
        // The sentence is rewritten to agree with the verdict, since the
        // address in it is what every downstream reader has always used.
        assert_eq!(
            e["message"],
            json!("203.0.113.9:53992 probed for the login page"),
        );
    }

    #[test]
    fn wordpot_resolves_the_proxied_door_from_the_chain() {
        let line = wordpot_line(
            WORDPOT_PROXIED_PORT,
            "41010",
            json!({"xff": "203.0.113.9, 172.69.150.126"}),
        );
        let (out, resolved) = enrich_wordpot_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "wordpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(e["src_ip"], json!("203.0.113.9"), "not Cloudflare's edge");
        assert_eq!(
            e["message"],
            json!("203.0.113.9:41010 probed for the login page"),
        );
    }

    #[test]
    fn wordpot_does_not_join_the_proxied_door_against_portbridge() {
        let line = wordpot_line(
            WORDPOT_PROXIED_PORT,
            "41010",
            json!({"cf_connecting_ip": "203.0.113.9"}),
        );
        let (out, _) = enrich_wordpot_line(
            line.as_bytes(), &vm_with(41010, "198.51.100.77"), &ViaMap::new(), "wordpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["src_ip"], json!("203.0.113.9"), "the colliding entry is ignored");
    }

    #[test]
    fn wordpot_lines_without_the_new_fields_still_parse() {
        // Everything already on disk was written before the sensor
        // recorded any of this, and has to keep resolving from the
        // sentence alone.
        let line = json!({
            "time": "2026-08-22T09:00:00",
            "level": "INFO",
            "message": format!("{}:53992 probed for the login page", TUNNEL_PEER_IP),
        })
        .to_string();
        let (out, resolved) = enrich_wordpot_line(
            line.as_bytes(), &vm_with(53992, "203.0.113.9"), &ViaMap::new(), "wordpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(e["src_ip"], json!("203.0.113.9"));
    }

    // ---- hellpot: the same two doors (#1908) ----

    #[test]
    fn hellpot_resolves_the_proxied_door_from_the_chain() {
        let line = json!({
            "REMOTE_ADDR": format!("{}:44520", TUNNEL_PEER_IP),
            "DST_PORT": HELLPOT_PROXIED_PORT,
            "XFF": "203.0.113.9, 172.69.150.126",
            "URL": "/",
        })
        .to_string();
        let (out, resolved) = enrich_hellpot_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "hellpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(e["src_ip"], json!("203.0.113.9"), "not Cloudflare's edge");
        assert_eq!(e["REMOTE_ADDR"], json!("203.0.113.9:44520"));
    }

    #[test]
    fn hellpot_does_not_join_the_proxied_door_against_portbridge() {
        // The reason the door had to become a fact: this entry matches
        // socat's ephemeral source port by coincidence, and taking it
        // would file the request against an unrelated attacker.
        let line = json!({
            "REMOTE_ADDR": format!("{}:44520", TUNNEL_PEER_IP),
            "DST_PORT": HELLPOT_PROXIED_PORT,
            "XFF": "203.0.113.9, 172.69.150.126",
            "URL": "/",
        })
        .to_string();
        let (out, _) = enrich_hellpot_line(
            line.as_bytes(), &vm_with(44520, "198.51.100.77"), &ViaMap::new(), "hellpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["src_ip"], json!("203.0.113.9"), "the colliding entry is ignored");
    }

    #[test]
    fn hellpot_still_joins_the_raw_door() {
        let line = json!({
            "REMOTE_ADDR": format!("{}:44521", TUNNEL_PEER_IP),
            "DST_PORT": "8080",
            "URL": "/",
        })
        .to_string();
        let (out, resolved) = enrich_hellpot_line(
            line.as_bytes(), &vm_with(44521, "45.79.207.110"), &ViaMap::new(), "hellpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(resolved);
        assert_eq!(e["src_ip"], json!("45.79.207.110"));
    }

    // ---- #1918: every enricher marks its own healthchecks ----
    //
    // The generic enrich_line always did. The per-sensor enrichers never
    // did, and nothing noticed because the symptom is an absence: the
    // event is correctly kept out of source.ip, and simply never flagged,
    // so it lands in the unattributed residue looking like a sensor that
    // could not be attributed. 2,879 loopback events in 24h were sitting
    // there, 2,857 of them sentrypeer's.
    //
    // A test per sensor rather than one on the shared helper, because the
    // defect was never in the rule -- it was that each enricher has to opt
    // in, and four of them had not. A helper test would have passed
    // throughout.

    #[test]
    fn sentrypeer_healthchecks_are_marked_as_probes() {
        // sentrypeer writes source_ip as "ip:port", and its healthcheck is
        // a bare TCP connect: no SIP method, no message, no called number.
        let line = json!({
            "app_name": "sentrypeer",
            "source_ip": "127.0.0.1:44577",
            "destination_ip": "0.0.0.0:5060",
            "sip_method": "",
            "transport_type": "TCP",
        })
        .to_string();
        let (out, resolved) = enrich_sentrypeer_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "sentrypeer",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert_eq!(e["internal_probe"], json!(true));
        assert!(resolved, "a probe is terminal, never queued for retry");
        // The address stays: it is the evidence that this was ours.
        assert_eq!(e["src_ip"], json!("127.0.0.1"));
    }

    #[test]
    fn hellpot_healthchecks_are_marked_as_probes() {
        let line = json!({"REMOTE_ADDR": "127.0.0.1:51234", "URL": "/"}).to_string();
        let (out, _) = enrich_hellpot_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "hellpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(e["internal_probe"], json!(true));
    }

    #[test]
    fn galah_healthchecks_are_marked_as_probes() {
        let line = json!({
            "msg": "successfulResponse",
            "srcIP": "127.0.0.1",
            "srcPort": "51235",
            "port": "8888",
            "httpRequest": {"request": "/"},
        })
        .to_string();
        let (out, _) = enrich_galah_line(line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "galah");
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(e["internal_probe"], json!(true));
    }

    #[test]
    fn wordpot_healthchecks_are_marked_as_probes() {
        let line = json!({
            "time": "2026-08-25T06:54:08",
            "level": "INFO",
            "message": "127.0.0.1:51236 probed for the login page",
        })
        .to_string();
        let (out, _) = enrich_wordpot_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "wordpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(e["internal_probe"], json!(true));
    }

    #[test]
    fn a_real_attacker_is_still_never_marked_by_the_per_sensor_enrichers() {
        // The other half. Flagging too eagerly would delete real traffic
        // from every view, which is worse than the bug being fixed.
        let line = json!({"app_name": "sentrypeer", "source_ip": "203.0.113.9:5060"}).to_string();
        let (out, _) = enrich_sentrypeer_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "sentrypeer",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();

        assert!(e.get("internal_probe").is_none());
        assert_eq!(e["src_ip"], json!("203.0.113.9"));
    }

    #[test]
    fn ipv6_loopback_counts_for_the_per_sensor_enrichers_too() {
        let line = json!({"REMOTE_ADDR": "[::1]:51237", "URL": "/"}).to_string();
        let (out, _) = enrich_hellpot_line(
            line.as_bytes(), &ViaMap::new(), &ViaMap::new(), "hellpot",
        );
        let e: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(e["internal_probe"], json!(true));
    }
}
