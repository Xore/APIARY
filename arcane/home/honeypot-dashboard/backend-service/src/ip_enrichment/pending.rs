//! Ported from ip-enrichment-worker/pending.go: lines whose src_ip is the
//! tunnel peer but whose matching portbridge via_port entry hasn't landed
//! yet get held briefly and retried — portbridge logs a connection's
//! via_port at dial time, before the honeypot itself ever sees the
//! resulting connection, so a miss is almost always a brief race, not a
//! permanent condition.

use std::time::{Duration, Instant};

use super::viamap::ViaMap;

/// Shared signature every enrich function has, so `PendingQueue::drain` can
/// retry any of them through one code path without knowing which kind of
/// source it's got.
pub type EnrichFn = fn(&[u8], &ViaMap, &ViaMap, &str) -> (Vec<u8>, bool);

struct PendingLine {
    line: Vec<u8>,
    deadline: Instant,
}

#[derive(Default)]
pub struct PendingQueue {
    items: Vec<PendingLine>,
}

impl PendingQueue {
    pub fn add(&mut self, line: Vec<u8>, timeout: Duration, now: Instant) {
        self.items.push(PendingLine { line, deadline: now + timeout });
    }

    /// Retries every pending line against `vm`/`tftp_vm` via `enrich`,
    /// returning (in original order) every line that either resolved or
    /// timed out — ready to write now, enriched or not. Lines still within
    /// their window and still unresolved stay queued for the next call.
    pub fn drain(&mut self, vm: &ViaMap, tftp_vm: &ViaMap, now: Instant, persona: &str, enrich: EnrichFn) -> Vec<Vec<u8>> {
        let mut ready = Vec::new();
        let mut remaining = Vec::with_capacity(self.items.len());
        for item in self.items.drain(..) {
            let (out, resolved) = enrich(&item.line, vm, tftp_vm, persona);
            if resolved || now >= item.deadline {
                ready.push(out);
            } else {
                remaining.push(item);
            }
        }
        self.items = remaining;
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use super::super::sensors::enrich_line;

    fn never_resolves(line: &[u8], _vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
        (line.to_vec(), false)
    }

    #[test]
    fn unresolved_line_stays_queued_until_its_deadline() {
        let mut q = PendingQueue::default();
        let vm = HashMap::new();
        let now = Instant::now();
        q.add(b"line".to_vec(), Duration::from_secs(5), now);
        let ready = q.drain(&vm, &vm, now, "cowrie", never_resolves);
        assert!(ready.is_empty(), "still within its timeout window, must stay queued");
        let later = now + Duration::from_secs(6);
        let ready2 = q.drain(&vm, &vm, later, "cowrie", never_resolves);
        assert_eq!(ready2.len(), 1, "past its deadline, must be flushed even though unresolved");
    }

    // Ported from the Go worker's pending_test.go before that tree was
    // retired (#1890). The queue's whole reason to exist is that a sensor
    // line often arrives before portbridge's record of the connection it
    // describes, so the case where the map catches up is the one that has
    // to work -- the timeout case below is the fallback.
    #[test]
    fn a_queued_line_resolves_once_the_map_catches_up() {
        let mut q = PendingQueue::default();
        let now = Instant::now();
        q.add(
            br#"{"src_ip":"10.8.0.1","src_port":1}"#.to_vec(),
            Duration::from_secs(5),
            now,
        );

        // Nothing yet: portbridge has not logged the dial.
        let ready = q.drain(
            &ViaMap::new(),
            &ViaMap::new(),
            now + Duration::from_secs(1),
            "",
            enrich_line,
        );
        assert!(ready.is_empty(), "not ready before resolution or timeout");

        let mut vm = ViaMap::new();
        vm.insert(1, vec![super::super::viamap::ViaEntry { ip: "203.0.113.9".into(), at: 0 }]);
        let ready = q.drain(&vm, &ViaMap::new(), now + Duration::from_secs(2), "", enrich_line);

        assert_eq!(ready.len(), 1, "the line resolves and flushes");
        let out: serde_json::Value = serde_json::from_slice(&ready[0]).unwrap();
        assert_eq!(out["src_ip"], serde_json::json!("203.0.113.9"));
    }

    #[test]
    fn a_flushed_line_is_never_retried() {
        // Once a line has left the queue it must not come back when the
        // map later gains the entry, or it is emitted twice.
        let mut q = PendingQueue::default();
        let now = Instant::now();
        q.add(
            br#"{"src_ip":"10.8.0.1","src_port":1}"#.to_vec(),
            Duration::from_secs(5),
            now,
        );

        let ready = q.drain(&ViaMap::new(), &ViaMap::new(), now + Duration::from_secs(6), "", enrich_line);
        assert_eq!(ready.len(), 1, "flushes unenriched at its deadline");

        let mut vm = ViaMap::new();
        vm.insert(1, vec![super::super::viamap::ViaEntry { ip: "203.0.113.9".into(), at: 0 }]);
        let again = q.drain(&vm, &ViaMap::new(), now + Duration::from_secs(7), "", enrich_line);
        assert!(again.is_empty(), "an already-flushed line must not reappear");
    }
}
