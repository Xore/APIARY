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

/// via_port -> real source IP.
pub type ViaMap = HashMap<i64, String>;

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
    m.insert(via_port as i64, ip.to_string());
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

    #[test]
    fn later_entry_for_the_same_port_overwrites_the_earlier_one() {
        let mut m = ViaMap::new();
        parse_portbridge_line(br#"{"sensor":"portbridge","src_ip":"1.1.1.1","via_port":4000}"#, &mut m);
        parse_portbridge_line(br#"{"sensor":"portbridge","src_ip":"2.2.2.2","via_port":4000}"#, &mut m);
        assert_eq!(m.get(&4000), Some(&"2.2.2.2".to_string()));
    }

    #[test]
    fn ignores_lines_from_a_different_sensor() {
        let mut m = ViaMap::new();
        parse_portbridge_line(br#"{"sensor":"cowrie","src_ip":"1.1.1.1","via_port":4000}"#, &mut m);
        assert!(m.is_empty());
    }
}
