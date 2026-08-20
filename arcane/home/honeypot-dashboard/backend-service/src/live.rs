//! /api/v1/live — Server-Sent Events stream of new honeypot events. Each
//! connection polls ES every 3s for documents newer than its own
//! high-water mark and emits them oldest-first, so the feed page can
//! prepend in arrival order. Per-connection polling keeps this tier
//! stateless (any replica can serve any stream); the shared-subscription
//! fan-out moves to redis with the worker port (#1610).

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
        let mut watermark = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let body = json!({
                "size": BATCH,
                "sort": [{"@timestamp": {"order": "asc"}}],
                "query": {"bool": {
                    "filter": [{"range": {"@timestamp": {"gt": watermark}}}],
                    "must_not": events::suricata_noise_exclusion()
                }}
            });
            let Ok(result) = state.es.search(body).await else {
                // Transient ES failure: skip this tick, keepalive comments
                // hold the connection open.
                continue;
            };
            let hits = result["hits"]["hits"].as_array().cloned().unwrap_or_default();
            for hit in hits {
                let source = &hit["_source"];
                if let Some(ts) = source["@timestamp"].as_str() {
                    watermark = ts.to_string();
                }
                let row = events::row_from_source(source);
                if let Ok(data) = serde_json::to_string(&row) {
                    yield Ok(Event::default().event("event").data(data));
                }
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default().interval(Duration::from_secs(15)))
}
