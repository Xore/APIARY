#!/usr/bin/env python3
"""#154 phase 5 (first half): wires decode_correlate.py, campaign_correlator.py,
and criticality_rules.py -- proven only against the synthetic corpus until
now -- against real Elasticsearch data, writing provenance-rich campaign
verdicts to a new `agent-intrusion-campaigns` index for a future dashboard
page to read.

Structurally follows ml-worker/worker.py's own established pattern
(source indices, ES client, poll loop) rather than inventing a new one --
same ES-unavailable handling posture, same "never raise out of the poll
loop" discipline. Deliberately simpler where this worker's own job allows
it: campaign correlation needs to see events across the whole time window
at once (campaign_correlator.py's own `window` parameter, not just
whatever arrived since the last poll), so this re-queries a bounded
rolling window fresh every cycle rather than maintaining ml-worker's own
incremental equal-timestamp checkpoint -- a real, deliberate tradeoff
(some repeated ES query cost) for a lot less state-management complexity,
reasonable at this worker's own poll cadence and data volume.

Every one of decode_correlate/campaign_correlator/criticality_rules stays
completely untouched by this file -- it only adapts real ES documents into
the same {event_id, timestamp, raw} shape those modules already consume
(proven against the corpus), and adapts their output into ES documents.
"""
from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timedelta, timezone

from elasticsearch import Elasticsearch
from loguru import logger

import campaign_correlator as corr
import criticality_rules as rules

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
SOURCE_INDICES = ["honeypot-v2-*", "suricata-v2-*"]
CAMPAIGN_INDEX = "agent-intrusion-campaigns"
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "300"))
# Matches campaign_correlator.correlate_campaigns's own default -- kept as
# a separate constant (not importing corr's default directly) so this
# worker's own fetch window and the correlator's own union-find window stay
# independently readable at their respective call sites; test_worker.py
# checks they're actually equal, since letting them drift would mean
# fetching less data than the correlator could ever meaningfully use.
CORRELATION_WINDOW = timedelta(hours=72)
# How far back each poll re-fetches -- wider than CORRELATION_WINDOW alone
# so a campaign whose *first* event is close to the fetch boundary still
# has its full window available rather than being truncated mid-campaign.
FETCH_WINDOW = timedelta(days=int(os.getenv("FETCH_WINDOW_DAYS", "10")))
# Only campaigns at or above this severity get written -- "low" (no rule
# matched anywhere in the campaign) is exactly the isolated/benign case
# this whole pipeline exists to *not* separately alarm on; writing one
# document per such campaign would just recreate the noise problem #154
# opens with, one index over.
MIN_SEVERITY_TO_WRITE = {"high", "critical"}


def fetch_window_events(es: Elasticsearch, index_pattern: str, since: str, page_size: int = 1000) -> list[dict]:
    """Scrolls every event in `index_pattern` at or after `since`, mapped
    into the {event_id, timestamp, raw} shape campaign_correlator.py and
    criticality_rules.py already consume (proven against the corpus).
    Real ES `_id`s are used directly as event_id -- unlike the corpus's own
    corpus-NNN placeholders, these are real document identifiers a
    dashboard page can link straight back to (#154 phase 5's own "links
    back to raw evidence" requirement)."""
    events: list[dict] = []
    query = {
        "query": {"range": {"@timestamp": {"gte": since}}},
        "sort": [{"@timestamp": {"order": "asc"}}],
        "size": page_size,
    }
    try:
        resp = es.search(index=index_pattern, body=query, scroll="2m")
        scroll_id = resp["_scroll_id"]
        hits = resp["hits"]["hits"]
        while hits:
            for hit in hits:
                source = hit["_source"]
                ts = source.get("@timestamp")
                if not ts:
                    continue  # can't correlate/order an event with no timestamp
                events.append({
                    "event_id": hit["_id"],
                    "timestamp": ts,
                    "source_index": hit["_index"],
                    "raw": source,
                })
            resp = es.scroll(scroll_id=scroll_id, scroll="2m")
            scroll_id = resp["_scroll_id"]
            hits = resp["hits"]["hits"]
        es.clear_scroll(scroll_id=scroll_id)
    except Exception as exc:
        logger.warning(f"Fetch error for {index_pattern}: {exc}")
    return events


def _normalize_timestamp(ts: str) -> str:
    """campaign_correlator.py's own _parse_ts expects a bare
    "%Y-%m-%dT%H:%M:%SZ" (matching the corpus's own fixture format
    exactly) -- real Elasticsearch @timestamp values are full ISO 8601 and
    routinely carry fractional seconds and/or a numeric UTC offset instead
    of a literal "Z". Confirmed live against this stack's own real
    honeypot-v2-*/suricata-v2-* documents. Normalizes to whole seconds,
    UTC, "Z"-suffixed -- second-level precision is what campaign
    correlation's own time window (hours) needs, not sub-second accuracy."""
    cleaned = ts.replace("Z", "+00:00")
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_campaign_verdict(campaign: corr.Campaign, events_by_id: dict) -> dict | None:
    """Runs criticality_rules against every member event, scores the whole
    campaign, and returns a full provenance-rich verdict document -- or
    None if the campaign doesn't clear MIN_SEVERITY_TO_WRITE. Deterministic
    campaign_id (sha256 of the sorted event_id list) makes re-processing
    the same campaign on a later poll cycle an idempotent upsert, not a
    duplicate document -- the same campaign reappearing in every cycle's
    rolling FETCH_WINDOW is expected, not a bug to work around."""
    matches_per_event = {eid: rules.evaluate_event(events_by_id[eid]["raw"]) for eid in campaign.event_ids}
    severity, categories = rules.campaign_severity(matches_per_event)
    if severity not in MIN_SEVERITY_TO_WRITE:
        return None

    campaign_id = hashlib.sha256("|".join(sorted(campaign.event_ids)).encode()).hexdigest()[:16]
    event_docs = []
    for eid in campaign.event_ids:
        event = events_by_id[eid]
        matches = matches_per_event[eid]
        event_docs.append({
            "event_id": eid,
            # .get, not a direct index: real events fetch_window_events
            # builds always carry this, but callers driving this function
            # against events built some other way (the corpus's own fixture
            # events have no ES index to name) shouldn't hard-crash over a
            # field that's genuinely optional context, not load-bearing for
            # anything this function itself does with it.
            "source_index": event.get("source_index", ""),
            "timestamp": event["timestamp"],
            "matched_rules": [
                {"rule": m.rule, "reason": m.reason, "trust_boundary": rules.TRUST_BOUNDARIES.get(m.rule, "")}
                for m in matches
            ],
        })

    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "campaign_id": campaign_id,
        "start": campaign.start,
        "end": campaign.end,
        "severity": severity,
        "matched_categories": sorted(categories),
        "correlation_identifiers": sorted(campaign.identifiers),
        "event_count": len(campaign.event_ids),
        "events": event_docs,
    }


def write_campaign_verdict(es: Elasticsearch, verdict: dict) -> None:
    try:
        es.index(index=CAMPAIGN_INDEX, id=verdict["campaign_id"], document=verdict)
    except Exception as exc:
        logger.warning(f"Failed to write campaign verdict {verdict['campaign_id']} (non-fatal): {exc}")


def run_cycle(es: Elasticsearch) -> int:
    """One full fetch -> correlate -> score -> write pass. Returns the
    number of campaign verdicts written (for logging/tests), never raises
    -- an unreachable ES or a malformed document degrades this cycle's
    output, not the worker process itself, matching every other worker in
    this tree's own "poll again next cycle" resilience posture."""
    since = (datetime.now(timezone.utc) - FETCH_WINDOW).strftime("%Y-%m-%dT%H:%M:%SZ")
    events = []
    for index_pattern in SOURCE_INDICES:
        events.extend(fetch_window_events(es, index_pattern, since))

    if not events:
        return 0

    for e in events:
        e["timestamp"] = _normalize_timestamp(e["timestamp"])
    events.sort(key=lambda e: e["timestamp"])

    events_by_id = {e["event_id"]: e for e in events}
    campaigns = corr.correlate_campaigns(events, window=CORRELATION_WINDOW)

    written = 0
    for campaign in campaigns:
        verdict = build_campaign_verdict(campaign, events_by_id)
        if verdict is not None:
            write_campaign_verdict(es, verdict)
            written += 1
    return written


def main() -> None:
    es = Elasticsearch(ES_HOST)
    logger.info(f"agent-intrusion-worker ready. ES={ES_HOST} poll={POLL_INTERVAL}s fetch_window={FETCH_WINDOW}")
    while True:
        try:
            written = run_cycle(es)
            logger.info(f"cycle complete: {written} campaign verdict(s) written")
        except Exception as exc:
            logger.error(f"Unhandled error in poll cycle (continuing): {exc}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
