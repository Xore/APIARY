//! #2181: the shared panic boundary every WORKER_LOOPS cycle runs behind.
//!
//! worker.rs's reports-scheduler comment used to claim tokio's task model
//! made explicit recover() wrapping unnecessary. That confused two
//! directions of isolation: tokio does keep a panicking *task* from taking
//! down the process, but nothing keeps a panicking *item* from unwinding
//! the loop task that ran it inline — ticker and all later items included.
//! And because these loops re-reach the same record on their next pass (a
//! scheduled definition stays due, a tail offset stays put, an ES window is
//! refetched), one poisoned record meant a worker bricked until an operator
//! noticed. #2118 was exactly that instance.
//!
//! Two granularities, both plain `catch_unwind` over futures via
//! AssertUnwindSafe:
//!   * [`cycle`] wraps one tick/pass body — any residual panic costs that
//!     pass only; the loop proceeds to its next sleep/tick with the pass
//!     degraded, never dead.
//!   * [`item`] wraps one record inside a pass — its siblings in the same
//!     batch still get their turn immediately, not merely next tick.
//!
//! Diagnostics follow the house surfacing contract (the way es_importer
//! surfaces failed artifacts and payload_inventory has logged #2118's
//! per-file boundary since dda3a489): one warn line naming the record,
//! plus the panic payload under `detail=`.

use std::any::Any;
use std::future::Future;
use std::panic::AssertUnwindSafe;

use futures::FutureExt;

/// Flattens any panic payload into printable text — same field shape
/// payload_inventory.rs logs for its own boundary.
pub(crate) fn panic_detail(payload: Box<dyn Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string())
}

/// Runs one whole tick/cycle body. Returns None only when it panicked, so
/// call sites can degrade (`unwrap_or`, match arm) rather than crash: a lost
/// cycle self-heals next interval, and the log line already said why.
pub(crate) async fn cycle<F, T>(worker: &'static str, fut: F) -> Option<T>
where
    F: Future<Output = T>,
{
    match AssertUnwindSafe(fut).catch_unwind().await {
        Ok(value) => Some(value),
        Err(payload) => {
            let detail = panic_detail(payload);
            tracing::warn!(
                worker,
                %detail,
                "worker cycle panicked; everything left in this pass is skipped -- the loop continues next tick (#2181)"
            );
            None
        }
    }
}

/// Runs one record of a pass. Same contract as [`cycle`], with the record
/// named so poison is attributable without replaying anything.
pub(crate) async fn item<F, T>(
    worker: &'static str,
    record: impl std::fmt::Display,
    fut: F,
) -> Option<T>
where
    F: Future<Output = T>,
{
    match AssertUnwindSafe(fut).catch_unwind().await {
        Ok(value) => Some(value),
        Err(payload) => {
            let detail = panic_detail(payload);
            tracing::warn!(
                worker,
                record = %record,
                %detail,
                "worker record panicked; isolated and skipped -- the rest of this pass continues (#2181)"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payloads_flatten_to_their_text() {
        assert_eq!(panic_detail(Box::new("plain &str")), "plain &str");
        assert_eq!(panic_detail(Box::new("owned String".to_string())), "owned String");
        // Anything else must stay printable rather than re-panic the logger.
        assert_eq!(panic_detail(Box::new(7u32)), "non-string panic payload");
    }

    #[tokio::test]
    async fn a_healthy_item_and_cycle_pass_through() {
        let doubled = item("test-worker", "record-1", async { 21 * 2 }).await;
        assert_eq!(doubled, Some(42));
        let cycled = cycle("test-worker", async { "tick" }).await;
        assert_eq!(cycled, Some("tick"));
    }

    #[tokio::test]
    async fn a_panicking_record_is_caught_and_named() {
        let result = item("test-worker", "poisoned-record", async {
            // The shape any poisoned capture could produce: a deep frame
            // unwinds through catch_unwind before it reaches the loop task.
            fn inner() -> u32 {
                panic!("byte offset 256 is not a char boundary");
            }
            inner()
        })
        .await;
        assert!(result.is_none(), "a panicking record must return None, not unwind");
    }

    #[tokio::test]
    async fn a_panicking_cycle_is_caught_and_degradable() {
        let result = cycle("test-worker", async { panic!("scan aborted") }).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn later_items_survive_an_earlier_panicked_sibling() {
        let first = item("test-worker", "bad", async { panic!("nope") }).await;
        let second = item("test-worker", "good", async { 1 + 1 }).await;
        assert_eq!((first, second), (None, Some(2)));
    }
}
