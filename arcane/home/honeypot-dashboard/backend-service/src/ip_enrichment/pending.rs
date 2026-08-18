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
}
