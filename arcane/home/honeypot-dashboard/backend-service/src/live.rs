//! /api/v1/live — Server-Sent Events stream of new honeypot events,
//! oldest-first within a batch so the feed page can prepend in arrival
//! order.
//!
//! One poller per process serves every connection (#2042): each SSE
//! stream used to run its own identical ES query every POLL_INTERVAL, so
//! N open tabs cost N near-simultaneous searches over the event indices
//! every 3s. A single background task now advances one process-wide
//! resume position and publishes each fetched batch to every subscriber
//! on a broadcast channel. Still per-replica only — any replica can serve
//! any stream, each simply runs its own poller; moving the fan-out out of
//! the process entirely (redis with the worker port, #1610) would be the
//! next step and buys nothing at current fleet scale.

use std::{convert::Infallible, time::Duration};

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::Stream;
use serde_json::json;
use tokio::sync::{broadcast, OnceCell};

use crate::{events, AppState};

const POLL_INTERVAL: Duration = Duration::from_secs(3);
const BATCH: u64 = 50;

/// Published batches buffered for a subscriber before it counts as
/// lagged. 64 batches of up to BATCH rows at one batch/POLL_INTERVAL is
/// minutes of slack — hitting Lagged means a genuinely stuck consumer,
/// not a slow paint, and closing the stream is the honest recovery: the
/// browser's EventSource reconnects and re-renders the backlog from
/// /api/v1/events.
const BROADCAST_CAPACITY: usize = 64;

static LIVE_FEED: OnceCell<broadcast::Sender<Vec<String>>> = OnceCell::const_new();

async fn shared_feed_sender(state: &AppState) -> broadcast::Sender<Vec<String>> {
    LIVE_FEED
        .get_or_init(|| async {
            let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
            tokio::spawn(poll_loop(state.clone(), tx.clone()));
            tx
        })
        .await
        .clone()
}

async fn poll_loop(state: AppState, tx: broadcast::Sender<Vec<String>>) {
    // Start at "now": pages already rendered the backlog via
    // /api/v1/events; a stream's subscription point is its start
    // position — the same semantics each per-connection poller had.
    //
    // The resume position is the full sort tuple, not a scalar timestamp
    // (#1979): paging `size: BATCH` sorted only by @timestamp and resuming
    // from `gt last_timestamp` permanently dropped every event sharing the
    // boundary hit's millisecond whenever a batch ended mid-burst — and
    // bursts routinely land Filebeat batches with equal-precision
    // @timestamps (@timestamp is plain `date`, i.e. millisecond
    // resolution). Sorting with a deterministic tiebreak and resuming via
    // search_after makes the position exact.
    //
    // _doc rather than _id for the tiebreak: _id is not sortable without
    // fielddata (removed in ES 6), while _doc is the documented cheap
    // order. Its known weakness is segment merges renumbering docs
    // *between* polls, which can at worst duplicate or shift the single
    // boundary millisecond — strictly better than the old scheme, which
    // lost the rest of that millisecond on every truncated batch, forever.
    // The proper primitive is PIT + _shard_doc; not worth its open/close
    // lifecycle while the poller survives in this shape.
    //
    // The coarse `gte` range filter stays purely so ES prunes whole old
    // segments per tick instead of walking them to reach the search_after
    // offset; it cannot exclude anything the tuple hasn't already covered
    // (inclusive bound, tuple is stricter).
    let mut position = json!([chrono::Utc::now().timestamp_millis(), -1]);
    let mut ticker = tokio::time::interval(POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let mut body = json!({
            "size": BATCH,
            "sort": [
                {"@timestamp": {"order": "asc"}},
                {"_doc": {"order": "asc"}}
            ],
            "query": {"bool": {
                "filter": [{"range": {"@timestamp": {"gte": position[0]}}}],
                "must_not": events::suricata_noise_exclusion()
            }}
        });
        body["search_after"] = position.clone();
        let Ok(result) = state.es.search(body).await else {
            // Transient ES failure: skip this tick, the position holds and
            // keepalive comments hold the connections open.
            continue;
        };
        let hits = result["hits"]["hits"].as_array().cloned().unwrap_or_default();
        // Advance before publishing: even a partially-consumed batch must
        // move the tuple to its own last hit, or the next tick re-reads
        // the tail of this one.
        if let Some(sort_tuple) = hits.last().map(|h| &h["sort"]).filter(|v| v.is_array()) {
            position = sort_tuple.clone();
        }
        // One message per tick keeps BROADCAST_CAPACITY counting batches,
        // not rows.
        let mut rows = Vec::with_capacity(hits.len());
        for hit in &hits {
            // row_from_hit rather than row_from_source (#1962): the
            // stream's rows carry the document id, same as search-hit
            // rows, so the events page can key selection by identity
            // instead of a position-embedding composite.
            match serde_json::to_string(&events::row_from_hit(hit)) {
                Ok(data) => rows.push(data),
                Err(error) => tracing::warn!(%error, "live feed: dropping unserializable row"),
            }
        }
        if !rows.is_empty() {
            // Err only means no stream is currently subscribed.
            let _ = tx.send(rows);
        }
    }
}

pub async fn stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = shared_feed_sender(&state).await.subscribe();
    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(rows) => {
                    for data in rows {
                        yield Ok(Event::default().event("event").data(data));
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "live feed: subscriber lagged; closing so the client re-syncs from /api/v1/events");
                    break;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default().interval(Duration::from_secs(15)))
}
