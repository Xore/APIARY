//! /api/v1/live — Server-Sent Events stream of new honeypot events. Each
//! connection polls ES every 3s for documents past its own resume
//! position and emits them oldest-first, so the feed page can prepend in
//! arrival order. Per-connection polling keeps this tier stateless (any
//! replica can serve any stream); the shared-subscription fan-out moves
//! to redis with the worker port (#1610).

use std::{convert::Infallible, time::Duration};

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::Stream;
use serde_json::json;

use crate::{events, AppState};

const POLL_INTERVAL: Duration = Duration::from_secs(3);
const BATCH: u64 = 50;

pub async fn stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = async_stream::stream! {
        // Start at "now": the page already rendered the backlog via
        // /api/v1/events; the stream only carries what happens next.
        //
        // The resume position is the full sort tuple, not a scalar
        // timestamp (#1979): paging `size: BATCH` sorted only by
        // @timestamp and resuming from `gt last_timestamp` permanently
        // dropped every event sharing the boundary hit's millisecond
        // whenever a batch ended mid-burst — and bursts routinely land
        // Filebeat batches with equal-precision @timestamps (@timestamp
        // is plain `date`, i.e. millisecond resolution). Sorting with a
        // deterministic tiebreak and resuming via search_after makes the
        // position exact.
        //
        // _doc rather than _id for the tiebreak: _id is not sortable
        // without fielddata (removed in ES 6), while _doc is the
        // documented cheap order. Its known weakness is segment merges
        // renumbering docs *between* polls, which can at worst duplicate
        // or shift the single boundary millisecond — strictly better than
        // the old scheme, which lost the rest of that millisecond on
        // every truncated batch, forever. The proper primitive is
        // PIT + _shard_doc; not worth its open/close lifecycle here while
        // per-connection polling survives at all (#1610 replaces it).
        //
        // The coarse `gte` range filter stays purely so ES prunes whole
        // old segments per tick instead of walking them to reach the
        // search_after offset; it cannot exclude anything the tuple
        // hasn't already covered (inclusive bound, tuple is stricter).
        let mut position =
            json!([chrono::Utc::now().timestamp_millis(), -1]);
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
                // Transient ES failure: skip this tick, keepalive comments
                // hold the connection open.
                continue;
            };
            let hits = result["hits"]["hits"].as_array().cloned().unwrap_or_default();
            // Advance before emitting: even a partially-consumed batch
            // must move the tuple to its own last hit, or the next tick
            // re-reads the tail of this one.
            if let Some(sort_tuple) = hits.last().map(|h| &h["sort"]).filter(|v| v.is_array()) {
                position = sort_tuple.clone();
            }
            for hit in &hits {
                // row_from_hit rather than row_from_source (#1962): the
                // stream's rows carry the document id, same as search-hit
                // rows, so the events page can key selection by identity
                // instead of a position-embedding composite.
                let row = events::row_from_hit(hit);
                if let Ok(data) = serde_json::to_string(&row) {
                    yield Ok(Event::default().event("event").data(data));
                }
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default().interval(Duration::from_secs(15)))
}

