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
        // tftp-relay's sessions.json carries no timestamp, so these entries
        // opt out of #1771's causality check (at 0) and keep their previous
        // behaviour. Relay ports are handed out per
        // TFTP session from a small pool that turns over far more slowly
        // than portbridge's ephemeral range, so the reuse this guards
        // against is not a live concern here.
        m.entry(port as i64).or_default().push(super::viamap::ViaEntry {
            ip: ip.to_string(),
            at: 0,
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


#[cfg(test)]
mod tests {
    // Ported from the Go worker's tftpsessions_test.go before that tree was
    // retired (#1890). This module had no tests at all on the Rust side,
    // which mattered more here than the count suggests: TFTP is the one
    // sensor path that does not go through portbridge, so nothing else
    // would have caught this map silently coming back empty.
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Same throwaway-directory pattern tail.rs and rotate.rs already use,
    // plus a counter so tests in this module cannot collide with each
    // other when the harness runs them in parallel.
    static NEXT: AtomicU32 = AtomicU32::new(0);

    fn temp_logs_dir() -> PathBuf {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("ip-enrich-tftp-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn logs_with(lines: &[&str]) -> PathBuf {
        let dir = temp_logs_dir();
        let relay = dir.join("tftp-relay");
        std::fs::create_dir_all(&relay).unwrap();
        let mut f = std::fs::File::create(relay.join("sessions.json")).unwrap();
        for line in lines {
            writeln!(f, "{line}").unwrap();
        }
        dir
    }

    #[test]
    fn sessions_are_indexed_by_relay_port() {
        let dir = logs_with(&[
            r#"{"relay_port":42285,"client_ip":"203.0.113.9","timestamp":"2026-08-05T21:05:27Z"}"#,
            r#"{"relay_port":42286,"client_ip":"203.0.113.10","timestamp":"2026-08-05T21:06:00Z"}"#,
        ]);
        let m = build_tftp_session_map(&dir);

        assert_eq!(super::super::viamap::lookup(&m, 42285, 0), Some("203.0.113.9"));
        assert_eq!(super::super::viamap::lookup(&m, 42286, 0), Some("203.0.113.10"));
    }

    #[test]
    fn a_reused_relay_port_resolves_to_the_later_session() {
        // These entries carry no timestamp, so the plausibility check
        // cannot separate them -- the only thing that can is order.
        let dir = logs_with(&[
            r#"{"relay_port":42285,"client_ip":"203.0.113.9"}"#,
            r#"{"relay_port":42285,"client_ip":"203.0.113.99"}"#,
        ]);
        let m = build_tftp_session_map(&dir);

        assert_eq!(super::super::viamap::lookup(&m, 42285, 0), Some("203.0.113.99"));
    }

    #[test]
    fn malformed_lines_are_skipped_rather_than_fatal() {
        // One bad line in a session log must not cost the whole map --
        // the relay writes this file live while the worker reads it.
        let dir = logs_with(&[
            "not json",
            r#"{"relay_port":42285}"#,
            r#"{"client_ip":"203.0.113.9"}"#,
            r#"{"relay_port":42286,"client_ip":"203.0.113.10"}"#,
        ]);
        let m = build_tftp_session_map(&dir);

        assert_eq!(m.len(), 1, "only the well-formed entry survives");
        assert_eq!(super::super::viamap::lookup(&m, 42286, 0), Some("203.0.113.10"));
    }

    #[test]
    fn a_missing_session_log_is_an_empty_map_not_an_error() {
        // tftp-relay may simply not have run yet.
        let dir = temp_logs_dir();
        assert!(build_tftp_session_map(&dir).is_empty());
    }

    #[test]
    fn only_dionaeas_tftp_connections_use_the_relay_join() {
        let tftp = json!({"connection": {"protocol": "TftpServerHandler"}});
        assert!(is_tftp_relay_record(&tftp, "dionaea"));
        assert!(!is_tftp_relay_record(&tftp, "conpot"), "another persona's record");

        let smb = json!({"connection": {"protocol": "SMBDServer"}});
        assert!(!is_tftp_relay_record(&smb, "dionaea"), "a non-TFTP protocol");

        assert!(!is_tftp_relay_record(&json!({}), "dionaea"), "no connection object");
    }
}
