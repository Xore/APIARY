//! Ported from ip-enrichment-worker/viamap.go: indexes portbridge's own
//! connection log by via_port (the tunnel-side ephemeral port portbridge
//! dialed the honeypot from, which equals the src_port a non-PROXY-wrapped
//! sensor observes for that same connection) — the same join
//! dashboard/classify.go's buildViaMap/viaLookup does read-time, done here
//! at ingest time instead.

use serde_json::Value;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::tail::read_new_lines;

/// One portbridge connection, as the join needs to see it.
#[derive(Clone, Debug, PartialEq)]
pub struct ViaEntry {
    /// The real client address portbridge accepted the connection from.
    pub ip: String,
    /// portbridge's dial time (epoch seconds), 0 when the line carried none.
    pub at: i64,
    /// The public port the connection arrived on, 0 when unknown. A second
    /// discriminator for the common reuse case where the same ephemeral port
    /// is later dialled for a different service.
    pub dest_port: i64,
}

/// via_port -> the recent connections that used it, oldest first.
///
/// #1771: this was `via_port -> ip`, keeping only the newest connection per
/// port, and the join took whatever was there. Ephemeral ports are reused
/// within seconds under this traffic (measured: the same via_port dialled
/// 29 seconds apart), and sensors emit many lines per connection over its
/// whole lifetime, so a connection's later lines routinely resolved against
/// a *different attacker's* entry -- silently, since a wrong address looks
/// exactly like a right one. One conpot connection was split across two
/// unrelated IPs this way.
///
/// Keeping a short history per port lets `lookup` pick the connection that
/// was actually open when the sensor line was written, instead of the most
/// recent one to touch the port.
pub type ViaMap = HashMap<i64, Vec<ViaEntry>>;

/// How many connections to remember per via_port. The key space is bounded
/// by the port number range, so this bounds the whole map; four is well
/// past the observed reuse depth within any one sensor's line lifetime.
const HISTORY: usize = 4;

/// How far before a sensor line a portbridge entry may have been dialled and
/// still plausibly describe it. Generous on purpose: a cowrie session can
/// stay open for a long time and every line it writes has to keep resolving
/// against the connect that opened it. It exists to reject a *backlog
/// replay* -- lines processed hours late against a live map -- not to
/// second-guess long sessions.
const MAX_AGE_SECONDS: i64 = 6 * 3600;

/// Tolerance for a sensor clock running slightly ahead of portbridge's.
/// portbridge logs at dial time, strictly before the honeypot can see the
/// connection, so an entry stamped meaningfully *after* the line cannot be
/// that line's origin -- that is the check doing the real work here.
const CLOCK_SKEW_SECONDS: i64 = 2;

pub fn read_portbridge_lines(path: &Path, m: &mut ViaMap) {
    let Ok(file) = File::open(path) else { return };
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        parse_portbridge_line(line.as_bytes(), m);
    }
}

pub fn parse_portbridge_line(line: &[u8], m: &mut ViaMap) {
    let Ok(e) = serde_json::from_slice::<Value>(line) else { return };
    if e.get("sensor").and_then(Value::as_str) != Some("portbridge") {
        return;
    }
    let Some(ip) = e.get("src_ip").and_then(Value::as_str).filter(|s| !s.is_empty()) else { return };
    let Some(via_port) = e.get("via_port").and_then(Value::as_f64).filter(|p| *p != 0.0) else { return };
    let entry = ViaEntry {
        ip: ip.to_string(),
        at: e.get("time").and_then(Value::as_str).and_then(parse_time).unwrap_or(0),
        dest_port: e.get("port").and_then(Value::as_f64).unwrap_or(0.0) as i64,
    };
    let slot = m.entry(via_port as i64).or_default();
    // portbridge ships each connection once; the duplicate-shipping bug that
    // made every line arrive twice (#1776) would otherwise fill the history
    // with copies of one connection and push real ones out.
    if slot.last() == Some(&entry) {
        return;
    }
    slot.push(entry);
    if slot.len() > HISTORY {
        slot.remove(0);
    }
}

/// portbridge writes RFC3339 with a `Z` (see connLogger's record builder).
fn parse_time(value: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(value).ok().map(|t| t.timestamp())
}

/// The address that was behind `via_port` when a sensor line timestamped
/// `line_at` (epoch seconds; 0 when the line carried no usable timestamp)
/// was written, for a connection to `dest_port` (0 when unknown).
///
/// Returns None rather than a best guess: an unattributed event is honest,
/// a confidently wrong attacker is not.
pub fn lookup(m: &ViaMap, via_port: i64, line_at: i64, dest_port: i64) -> Option<&str> {
    let slot = m.get(&via_port)?;
    slot.iter()
        .rev()
        .find(|entry| plausible(entry, line_at, dest_port))
        .map(|entry| entry.ip.as_str())
}

fn plausible(entry: &ViaEntry, line_at: i64, dest_port: i64) -> bool {
    // A connection to a different service is a different connection, whatever
    // the timestamps say. Only applied when both sides know their port.
    if entry.dest_port != 0 && dest_port != 0 && entry.dest_port != dest_port {
        return false;
    }
    // Without usable timestamps on both sides there is nothing to check, so
    // keep the pre-#1771 behaviour rather than dropping the join entirely.
    if entry.at == 0 || line_at == 0 {
        return true;
    }
    if entry.at > line_at + CLOCK_SKEW_SECONDS {
        return false; // dialled after the event it would explain
    }
    line_at - entry.at <= MAX_AGE_SECONDS
}

/// Maintains the via_port -> src_ip map incrementally across `refresh()`
/// calls instead of re-reading both portbridge generations (up to ~10MiB
/// combined) from scratch every tick forever — a real production incident
/// (#1206): under a small CPU limit, full-file-every-2s cost compounded
/// with the live file's size across a container's uptime, throttling the
/// process (>95% of CFS scheduling periods) badly enough to push the
/// highest-volume sensor's join attempts outside PENDING_TIMEOUT almost
/// entirely after ~2 days up. portbridge.json.1 (the previous, static
/// generation) is only re-parsed when it actually changes (mtime+size);
/// portbridge.json (the live, growing file) is tailed for new bytes only.
/// via_port's key space is a port number, so the accumulated map is
/// inherently bounded regardless of log volume or uptime — entries are
/// never explicitly evicted, only overwritten by a newer entry for the
/// same port.
pub struct ViaMapBuilder {
    portbridge_dir: PathBuf,
    map: ViaMap,
    live_offset: i64,
    gen_mtime: Option<SystemTime>,
    gen_size: u64,
}

impl ViaMapBuilder {
    pub fn new(portbridge_dir: PathBuf) -> Self {
        let mut b = Self { portbridge_dir, map: ViaMap::new(), live_offset: 0, gen_mtime: None, gen_size: 0 };
        b.refresh();
        b
    }

    /// Returns an independent snapshot each call — the builder's own map is
    /// never handed out directly, so a caller publishing it behind an
    /// `Arc`/`RwLock` never observes an in-progress mutation.
    pub fn refresh(&mut self) -> ViaMap {
        let gen_path = self.portbridge_dir.join("portbridge.json.1");
        if let Ok(meta) = fs::metadata(&gen_path) {
            let mtime = meta.modified().ok();
            if mtime != self.gen_mtime || meta.len() != self.gen_size {
                read_portbridge_lines(&gen_path, &mut self.map);
                self.gen_mtime = mtime;
                self.gen_size = meta.len();
            }
        }

        let live_path = self.portbridge_dir.join("portbridge.json");
        if let Ok((lines, new_offset)) = read_new_lines(&live_path, self.live_offset) {
            for line in &lines {
                parse_portbridge_line(line, &mut self.map);
            }
            self.live_offset = new_offset;
        }

        self.map.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-08-23T14:07:47Z, the conpot connection from the #1771 report.
    const T: i64 = 1787494067;

    fn line(ip: &str, at: &str, port: i64) -> String {
        format!(r#"{{"sensor":"portbridge","src_ip":"{ip}","via_port":4000,"time":"{at}","port":{port}}}"#)
    }

    fn feed(lines: &[String]) -> ViaMap {
        let mut m = ViaMap::new();
        for l in lines {
            parse_portbridge_line(l.as_bytes(), &mut m);
        }
        m
    }

    #[test]
    fn ignores_lines_from_a_different_sensor() {
        let mut m = ViaMap::new();
        parse_portbridge_line(br#"{"sensor":"cowrie","src_ip":"1.1.1.1","via_port":4000}"#, &mut m);
        assert!(m.is_empty());
    }

    #[test]
    fn resolves_the_connection_that_was_open_when_the_line_was_written() {
        let m = feed(&[line("1.1.1.1", "2026-08-23T14:07:47Z", 1025)]);
        assert_eq!(lookup(&m, 4000, T + 1, 1025), Some("1.1.1.1"));
    }

    #[test]
    fn a_reuse_after_the_event_cannot_explain_it() {
        // The measured #1771 case: one conpot connection's 51 lines all
        // stamped 14:07:47, and the port dialled again 18 seconds later.
        // Before this, the later lines took the newer entry and the single
        // connection was reported as two different attackers.
        let m = feed(&[
            line("1.1.1.1", "2026-08-23T14:07:47Z", 1025),
            line("2.2.2.2", "2026-08-23T14:08:05Z", 1025),
        ]);
        assert_eq!(lookup(&m, 4000, T, 1025), Some("1.1.1.1"));
    }

    #[test]
    fn the_newer_connections_own_lines_still_resolve_to_it() {
        let m = feed(&[
            line("1.1.1.1", "2026-08-23T14:07:47Z", 1025),
            line("2.2.2.2", "2026-08-23T14:08:05Z", 1025),
        ]);
        assert_eq!(lookup(&m, 4000, T + 30, 1025), Some("2.2.2.2"));
    }

    #[test]
    fn a_different_service_on_the_same_port_is_a_different_connection() {
        // Reuse across services was the common shape in the live log: the
        // same via_port dialled for 445, then 8443, then 5900, then 23.
        let m = feed(&[line("1.1.1.1", "2026-08-23T14:07:47Z", 23)]);
        assert_eq!(lookup(&m, 4000, T + 1, 1025), None);
    }

    #[test]
    fn a_long_session_still_resolves_against_the_connect_that_opened_it() {
        // A cowrie session can stay open for a long time and every line it
        // writes has to keep resolving. The guard must not turn those into
        // misses -- that would trade one bug for another.
        let m = feed(&[line("1.1.1.1", "2026-08-23T14:07:47Z", 22)]);
        assert_eq!(lookup(&m, 4000, T + 3000, 22), Some("1.1.1.1"));
    }

    #[test]
    fn a_replayed_backlog_does_not_join_against_a_live_map() {
        // #1770's 45-hour outage recovery: lines processed long after the
        // fact, against entries for entirely unrelated connections.
        let m = feed(&[line("1.1.1.1", "2026-08-23T14:07:47Z", 22)]);
        assert_eq!(lookup(&m, 4000, T + 45 * 3600, 22), None);
    }

    #[test]
    fn history_is_bounded_and_keeps_the_newest() {
        let mut m = ViaMap::new();
        for i in 0..10 {
            parse_portbridge_line(
                line(&format!("1.1.1.{i}"), "2026-08-23T14:07:47Z", 22).as_bytes(), &mut m);
        }
        assert_eq!(m[&4000].len(), HISTORY);
        assert_eq!(m[&4000].last().unwrap().ip, "1.1.1.9");
    }

    #[test]
    fn a_duplicated_line_does_not_evict_real_history() {
        // #1776 shipped every portbridge line twice for a while; that must
        // not halve the useful depth of this history.
        let mut m = ViaMap::new();
        let l = line("1.1.1.1", "2026-08-23T14:07:47Z", 22);
        parse_portbridge_line(l.as_bytes(), &mut m);
        parse_portbridge_line(l.as_bytes(), &mut m);
        assert_eq!(m[&4000].len(), 1);
    }

    #[test]
    fn entries_without_timestamps_keep_the_old_behaviour() {
        // tftp-relay's session map carries neither, and an unparseable
        // sensor timestamp yields 0 -- neither should start dropping joins.
        let m = feed(&[r#"{"sensor":"portbridge","src_ip":"1.1.1.1","via_port":4000}"#.to_string()]);
        assert_eq!(lookup(&m, 4000, 0, 0), Some("1.1.1.1"));
        assert_eq!(lookup(&m, 4000, T, 1025), Some("1.1.1.1"));
    }

    #[test]
    fn an_unknown_port_is_still_a_miss() {
        let m = feed(&[line("1.1.1.1", "2026-08-23T14:07:47Z", 22)]);
        assert_eq!(lookup(&m, 4001, T, 22), None);
    }
}
