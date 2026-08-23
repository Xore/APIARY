//! Ported from ip-enrichment-worker/tftpsessions.go: dionaea's TFTP events
//! reach it over a plain UDP forward (tftp-relay, #747), never the
//! WireGuard/portbridge tunnel every other affected sensor goes through —
//! so they need a different trigger than the tunnel-peer check, and a
//! different port-to-real-IP map, joined against tftp-relay's own session
//! log instead of portbridge's.

use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use super::viamap::ViaMap;

/// Reads tftp-relay's own session log — a `{relay_port, client_ip}` line
/// per TFTP session. Same "read the whole file every refresh tick"
/// simplicity as the original portbridge loader; TFTP session volume is
/// low enough that this doesn't need portbridge's rotation-aware
/// two-generation read.
pub fn build_tftp_session_map(logs_dir: &Path) -> ViaMap {
    let mut m = ViaMap::new();
    let Ok(file) = File::open(logs_dir.join("tftp-relay").join("sessions.json")) else { return m };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let Ok(e) = serde_json::from_str::<Value>(&line) else { continue };
        let Some(ip) = e.get("client_ip").and_then(Value::as_str).filter(|s| !s.is_empty()) else { continue };
        let Some(port) = e.get("relay_port").and_then(Value::as_f64).filter(|p| *p != 0.0) else { continue };
        // tftp-relay's sessions.json carries no timestamp and no service
        // port, so these entries opt out of #1771's checks (at/dest_port 0)
        // and keep their previous behaviour. Relay ports are handed out per
        // TFTP session from a small pool that turns over far more slowly
        // than portbridge's ephemeral range, so the reuse this guards
        // against is not a live concern here.
        m.entry(port as i64).or_default().push(super::viamap::ViaEntry {
            ip: ip.to_string(),
            at: 0,
            dest_port: 0,
        });
    }
    m
}

/// Reports whether `e` is one of dionaea's TFTP connection events, relayed
/// through tftp-relay — these carry the relay container's own internal
/// address as src_ip, never the tunnel peer IP.
pub fn is_tftp_relay_record(e: &Value, persona: &str) -> bool {
    if persona != "dionaea" {
        return false;
    }
    e.get("connection")
        .and_then(|c| c.get("protocol"))
        .and_then(Value::as_str)
        == Some("TftpServerHandler")
}
