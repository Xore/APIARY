#!/usr/bin/env python3
"""
ML Worker — honeypot-stack anomaly detection service.

Polls all honeypot Elasticsearch indices, runs three complementary
unsupervised models, and writes scored anomalies back to ES index
'ml-anomalies'. Notifies the dashboard via Redis pub/sub.

See docs/ml-worker-plan.md for full architecture and roadmap.
"""
import os
import time
import json
import hashlib
from collections import deque
from datetime import datetime, time as dt_time, timezone, timedelta

import numpy as np
import redis
from elasticsearch import Elasticsearch
from loguru import logger

from models.isolation_forest import IsoForestModel, MAX_TRAIN_SAMPLES, _get_ip, _get_port, _get_transport_proto
from models.lstm_autoencoder import LSTMAEModel
from models.session_features import SessionFeatureTracker

# ---------------------------------------------------------------------------
# Configuration (all overridable via env vars)
# ---------------------------------------------------------------------------
ES_HOST          = os.getenv("ES_HOST",           "http://elasticsearch:9200")
# Empty, not a redis:// default: absent unless explicitly configured, and
# best-effort when it is. ml-gpu-coordinated-roadmap.md §1 decision 1 /
# Milestone B step 5 -- Elasticsearch is the authoritative write and the
# initial dashboard transport; Redis is a notification nice-to-have, and the
# base ml-worker/docker-compose.yml no longer runs a Redis service at all
# (#62). A REDIS_URL set on a host that added one back still works.
REDIS_URL        = os.getenv("REDIS_URL",         "")
POLL_INTERVAL    = int(os.getenv("POLL_INTERVAL",   "30"))     # seconds
# #172: explicit UTC wall-clock slots, not a restart-relative interval --
# ml-gpu-coordinated-roadmap.md §1 decision 7: "Explicit UTC slots replace
# restart-relative retraining intervals so GPU workloads can actually be
# separated." A restart-relative timer (the old RETRAIN_INTERVAL-since-
# process-start) can't be scheduled against anything else, since its next
# firing depends on when the process happened to (re)start. Four slots
# roughly matches the old 6h-interval default's cadence, now at fixed,
# predictable times instead.
RETRAIN_SLOTS_UTC = os.getenv("RETRAIN_SLOTS_UTC", "03:00,09:00,15:00,21:00")
THRESHOLD        = float(os.getenv("ML_ALERT_THRESHOLD", "0.75"))
MODEL_DIR        = os.getenv("MODEL_DIR",         "/models")
LOG_LEVEL        = os.getenv("LOG_LEVEL",         "INFO")

# Drift detection (#65, docs/ml-worker-plan.md §11.4): a rolling window over
# the last DRIFT_WINDOW composite scores this worker actually computed.
# Exceeding DRIFT_ANOMALY_RATE could mean a real attack campaign or a stale
# model failing to generalize -- this can't tell which, which is why it
# triggers *retraining* (still gated by the acceptance bar, so a bad
# retrain still can't make things worse) rather than any automatic response
# to the traffic itself.
DRIFT_WINDOW       = int(os.getenv("DRIFT_WINDOW", "500"))
DRIFT_ANOMALY_RATE = float(os.getenv("DRIFT_ANOMALY_RATE", "0.15"))

# #190: the regular poll path had no cap, unlike the retrain path
# (MAX_TRAIN_SAMPLES) -- a backlog large enough to need more than one
# cycle (from downtime, a slow retrain blocking this same loop, or just a
# traffic burst) turned into a single, arbitrarily long scoring pass with
# no checkpoint progress and no crash-safety net until the whole thing
# finished. Capped to the same order of magnitude as one retrain's own
# fetch -- large enough that ordinary cycles still complete in one pass,
# small enough that a real backlog now checkpoints incrementally across
# several cycles instead of one unbounded one.
MAX_POLL_BATCH = int(os.getenv("MAX_POLL_BATCH", "5000"))

# #188: fetch_new_events() already retries every POLL_INTERVAL by nature of
# the main loop calling it again next cycle -- no separate backoff/jitter is
# added here, since a fixed retry is simpler and there's no evidence a
# backend that's briefly unreachable benefits from anything more elaborate.
# What was missing was distinguishing "briefly lost ES, recovered" from
# "unreachable for an extended period" -- this many CONSECUTIVE failed
# cycles for one index pattern before it's treated as sustained rather
# than a transient blip (the one blip actually observed, #167/#188's own
# report, self-healed after exactly one cycle).
ES_UNAVAILABLE_ALERT_AFTER = int(os.getenv("ES_UNAVAILABLE_ALERT_AFTER", "3"))

# Source indices to monitor. #61 found these matched zero real indices --
# the actual shape (docs/ml-worker-plan.md §2/§5.3, verified live 2026-07-31)
# is one unified honeypot-v2-* data stream for every sensor (disambiguated
# per-event by extract_features()'s own field reads, not by index name --
# event.sensor isn't reliably set for every sensor, see #132) plus
# suricata-v2-<event_type>-* for network/IDS events.
SOURCE_INDICES = [
    "honeypot-v2-*",
    "suricata-v2-*",
]

ANOMALY_INDEX  = "ml-anomalies"
STATE_INDEX    = "ml-worker-state"
METRICS_INDEX  = "ml-worker-metrics"
REDIS_CHANNEL  = "ml-anomaly-events"

SEVERITY_BANDS = [
    (0.95, "critical"),
    (0.85, "high"),
    (0.75, "medium"),
]

# Ensemble formula, docs/ml-worker-plan.md §4.4. Single source of truth (#63)
# -- previously duplicated verbatim in write_anomaly() and the main loop,
# a silent-drift risk on any future weight tuning.
COMPOSITE_WEIGHTS = {"isolation_forest": 0.4, "lstm_ae": 0.4, "hbos": 0.2}


def compute_composite(scores: dict) -> float:
    return sum(COMPOSITE_WEIGHTS[k] * scores.get(k, 0.0) for k in COMPOSITE_WEIGHTS)


def severity(score: float) -> str:
    for threshold, label in SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "low"


def ensure_index(es: Elasticsearch, index: str, mapping: dict) -> None:
    if not es.indices.exists(index=index):
        es.indices.create(index=index, body=mapping)
        logger.info(f"Created index {index}")


def load_checkpoint(es: Elasticsearch, index_pattern: str) -> dict:
    """Return the complete checkpoint tuple for this index pattern:
    {"last_timestamp": str, "seen_ids": [str, ...]}.

    seen_ids are the document IDs already processed exactly AT
    last_timestamp (#168) -- a plain timestamp checkpoint with an exclusive
    `gt` requery silently drops any sibling document that shares the exact
    @timestamp with the checkpointed one but arrived (or was returned by ES)
    after the checkpoint was saved. ml-gpu-coordinated-roadmap.md §1 names
    this explicitly: "timestamp-only checkpoints can skip equal-timestamp
    events." Pairing the timestamp with the set of IDs already handled at
    that exact boundary, and requerying inclusively (see fetch_new_events),
    fixes it without needing a full PIT/search_after implementation.
    """
    try:
        doc = es.get(index=STATE_INDEX,
                     id=hashlib.md5(index_pattern.encode()).hexdigest())
        source = doc["_source"]
        return {
            "last_timestamp": source["last_timestamp"],
            "seen_ids": source.get("seen_ids", []),
        }
    except Exception:
        # Default: start from 1 hour ago on first run
        return {
            "last_timestamp": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            "seen_ids": [],
        }


def save_checkpoint(es: Elasticsearch, index_pattern: str, last_timestamp: str, seen_ids: list) -> None:
    doc_id = hashlib.md5(index_pattern.encode()).hexdigest()
    es.index(index=STATE_INDEX, id=doc_id,
             document={
                 "index_pattern": index_pattern,
                 "last_timestamp": last_timestamp,
                 "seen_ids": seen_ids,
             })


def advance_checkpoint(events: list, previous: dict) -> dict:
    """Compute the next checkpoint tuple (#168) from a batch of processed
    events (ascending by @timestamp) and the checkpoint they were fetched
    against. Keeps only the IDs at the NEW max timestamp -- everything
    strictly before it can never be re-queried once the checkpoint advances
    past it (an inclusive requery against the new, later last_timestamp
    excludes anything earlier entirely), so seen_ids stays bounded by
    however many documents happen to share one exact timestamp, not by
    total history.
    """
    if not events:
        return previous
    max_ts = max(e["_source"].get("@timestamp", "") for e in events)
    if not max_ts:
        return previous
    seen_ids = [e["_id"] for e in events if e["_source"].get("@timestamp") == max_ts]
    return {"last_timestamp": max_ts, "seen_ids": seen_ids}


def fetch_new_events(es: Elasticsearch, index_pattern: str,
                    since: str, page_size: int = 500,
                    max_total: "int | None" = None,
                    exclude_ids: "set | None" = None) -> "tuple[list, bool]":
    """Scroll events from the given index pattern at or after `since`
    (inclusive). Returns (events, ok) -- ok is False when the ES call
    itself failed, distinct from a genuinely empty (events=[], ok=True)
    poll (#188: the caller could not previously tell "nothing new" apart
    from "the fetch failed", since both returned an empty list the same
    way). A scroll that fails partway still returns whatever pages were
    already read with ok=False -- safe to checkpoint against per
    advance_checkpoint's own equal-timestamp handling (#168): every event
    already read sorts at or before anything not yet read, so advancing
    only as far as what's in hand can't skip anything, it just leaves the
    rest for the next poll to pick back up.

    Inclusive (gte) rather than the original exclusive (gt) so a caller
    protecting a persisted checkpoint (#168) can safely re-include the exact
    boundary timestamp and filter out only the specific documents already
    processed there via exclude_ids -- gt alone can never distinguish
    "already handled" from "arrived later with the same timestamp" and
    silently drops the latter. exclude_ids is optional: the retrain path
    below has no persisted checkpoint to protect (it always re-fetches a
    fresh 24h window from a freshly computed wall-clock `since` on every
    call) and leaves it unset.

    max_total bounds how much this pulls into memory in one call -- the
    normal poll path leaves it unset (checkpoints keep each call small
    already), but the retrain path's 24h window across 2 index patterns has
    no other cap, and MAX_TRAIN_SAMPLES only bounds what retrain() fits on
    AFTER everything's already been fetched and held in memory (#62 task 33).
    """
    exclude_ids = exclude_ids or set()
    events = []
    query = {
        "query": {"range": {"@timestamp": {"gte": since}}},
        "sort":  [{"@timestamp": {"order": "asc"}}],
        "size":  page_size,
    }
    try:
        resp = es.search(index=index_pattern, body=query, scroll="2m")
        scroll_id = resp["_scroll_id"]
        hits = resp["hits"]["hits"]
        while hits:
            for hit in hits:
                if hit["_id"] in exclude_ids:
                    continue
                events.append(hit)
            if max_total is not None and len(events) >= max_total:
                events = events[:max_total]
                break
            resp = es.scroll(scroll_id=scroll_id, scroll="2m")
            scroll_id = resp["_scroll_id"]
            hits = resp["hits"]["hits"]
        es.clear_scroll(scroll_id=scroll_id)
    except Exception as exc:
        logger.warning(f"Fetch error for {index_pattern}: {exc}")
        return events, False
    return events, True


def write_retrain_metric(es: Elasticsearch, model_name: str, result) -> None:
    """Evidence for one retrain() call, accepted or not (#65,
    docs/ml-worker-plan.md §11.1/§11.4). Best-effort like write_anomaly()'s
    Redis publish: a metrics-write failure must never take down the retrain
    cycle that already succeeded or failed on its own terms."""
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "kind": "retrain",
        "model": model_name,
        "accepted": result.accepted,
        "reason": result.reason,
        "train_samples": result.train_samples,
        "holdout_samples": result.holdout_samples,
        "anomaly_rate_new": round(result.anomaly_rate_new, 4),
        "anomaly_rate_previous": round(result.anomaly_rate_previous, 4) if result.anomaly_rate_previous is not None else None,
    }
    try:
        es.index(index=METRICS_INDEX, document=doc)
    except Exception as exc:
        logger.warning(f"Failed to write retrain metric for {model_name} (non-fatal): {exc}")
    level = logger.info if result.accepted else logger.warning
    level(f"retrain[{model_name}] accepted={result.accepted} reason={result.reason}")


def write_es_unavailable_metric(es: Elasticsearch, index_pattern: str,
                               consecutive_failures: int, downtime_seconds: int) -> None:
    """Retrospective evidence that Elasticsearch was unreachable for a
    sustained period, not a transient blip (#188) -- written on recovery,
    not during the outage. Elasticsearch is unreachable BY DEFINITION for
    as long as this would need to write, so there's no way to surface a
    sustained outage in real time through the only channel this worker has
    (this same ES index); the log's ERROR-level line (see run_worker(),
    logged once the outage crosses ES_UNAVAILABLE_ALERT_AFTER cycles) is
    the real-time signal, this is the durable, after-the-fact record.
    downtime_seconds is an estimate (consecutive_failures * POLL_INTERVAL),
    not measured wall-clock time, since nothing here observes ES going down
    the instant it happens."""
    doc = {
        "@timestamp":           datetime.now(timezone.utc).isoformat(),
        "kind":                 "es_unavailable",
        "source_index":         index_pattern,
        "consecutive_failures": consecutive_failures,
        "downtime_seconds":     downtime_seconds,
    }
    try:
        es.index(index=METRICS_INDEX, document=doc)
    except Exception as exc:
        logger.warning(f"Failed to write es_unavailable metric (non-fatal): {exc}")
    logger.warning(
        f"{index_pattern}: Elasticsearch recovered after {consecutive_failures} consecutive "
        f"failed poll cycles (~{downtime_seconds}s) -- treating that as a sustained outage, not a blip"
    )


def backlog_count(es: Elasticsearch, index_pattern: str, since: str) -> "int | None":
    """How many documents are queued at or after this checkpoint (#190) --
    called only when a poll cycle's fetch hit MAX_POLL_BATCH, so this stays
    a signal tied to genuine buildup rather than an every-30s metric write
    regardless of whether there's anything to report (ml-worker-metrics has
    no retention policy of its own; a lag metric worth having in steady
    state is a separate, deliberate addition, not a side effect of this
    fix). None on a query failure -- best-effort, must never take the poll
    cycle down over a metric."""
    try:
        resp = es.count(index=index_pattern, body={"query": {"range": {"@timestamp": {"gte": since}}}})
        return resp.get("count")
    except Exception as exc:
        logger.warning(f"Backlog count failed for {index_pattern} (non-fatal): {exc}")
        return None


def write_backlog_metric(es: Elasticsearch, index_pattern: str, backlog: int) -> None:
    doc = {
        "@timestamp":    datetime.now(timezone.utc).isoformat(),
        "kind":          "backlog",
        "source_index":  index_pattern,
        "backlog_count": backlog,
    }
    try:
        es.index(index=METRICS_INDEX, document=doc)
    except Exception as exc:
        logger.warning(f"Failed to write backlog metric (non-fatal): {exc}")
    logger.warning(f"{index_pattern}: {backlog} events still queued past the checkpoint after this cycle's capped batch")


def write_malformed_event_metric(es: Elasticsearch, event: dict, exc: Exception) -> None:
    """Evidence that one event was skipped rather than crashing the batch
    (#171) -- best-effort, same rationale as write_retrain_metric()/
    write_drift_metric(): a metrics-write failure must never make a
    skip-and-continue decision take anything else down with it."""
    doc = {
        "@timestamp":      datetime.now(timezone.utc).isoformat(),
        "kind":            "malformed_event",
        "source_event_id": event.get("_id"),
        "source_index":    event.get("_index"),
        "error":           str(exc),
    }
    try:
        es.index(index=METRICS_INDEX, document=doc)
    except Exception as write_exc:
        logger.warning(f"Failed to write malformed-event metric (non-fatal): {write_exc}")
    logger.warning(f"Skipping malformed event {doc['source_event_id']} in {doc['source_index']}: {exc}")


def score_and_write_events(es: Elasticsearch, rdb, iso_model, lstm_model,
                          events: list, recent_flags, session_tracker=None) -> None:
    """Score every event in one fetched batch, writing anomalies over
    THRESHOLD and updating recent_flags for drift detection. Extracted from
    run_worker()'s loop so a malformed event's failure mode is directly
    testable (#171) rather than only reachable by driving the whole
    infinite polling loop.

    One event's failure (a non-numeric destination.port, any other shape
    extract_features() doesn't defensively handle) is caught, logged with
    enough context to diagnose, and recorded as a best-effort metric --
    never allowed to abort the rest of the batch. run_worker() advances the
    checkpoint after this returns, over the full `events` list regardless
    of which ones failed here, so a malformed event's position is always
    skipped past rather than being re-fetched and failing again forever
    (roadmap baseline: "bad events cannot stop a batch").

    session_tracker (#277): supplies real cmd_count/failed_logins_1h/
    unique_ports_1h, observed exactly once per event here and reused for
    both iso_model.extract_features() and lstm_model.score() -- optional
    (defaults to None, falling back to extract_features()'s own pre-#277
    neutral defaults) only so existing direct callers/tests that don't care
    about these three features don't have to construct a tracker.
    """
    for event in events:
        try:
            src = event.get("_source", {})
            session_feats = session_tracker.observe(src) if session_tracker is not None else {}
            features = iso_model.extract_features(src, **session_feats)

            iso_score  = iso_model.score(features)
            hbos_score = iso_model.hbos_score(features)  # fast pre-filter
            lstm_score = 0.0

            # Only run LSTM if HBOS flagged as potentially anomalous
            if hbos_score > 0.5:
                lstm_score = lstm_model.score(src, cmd_count=session_feats.get("cmd_count", 0))

            scores = {
                "isolation_forest": iso_score,
                "hbos":             hbos_score,
                "lstm_ae":          lstm_score,
            }
            composite = compute_composite(scores)
            recent_flags.append(composite >= THRESHOLD)

            if composite >= THRESHOLD:
                explanation = iso_model.explain(features, scores)
                write_anomaly(es, rdb, event, scores, explanation)
        except Exception as exc:
            write_malformed_event_metric(es, event, exc)


def parse_retrain_slots(raw: str) -> list:
    """Parse RETRAIN_SLOTS_UTC (#172) -- comma-separated HH:MM values, UTC
    -- into sorted (hour, minute) tuples. Empty/blank entries are skipped
    so a trailing comma or blank env var doesn't raise."""
    slots = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        hour_str, minute_str = part.split(":")
        slots.append((int(hour_str), int(minute_str)))
    return sorted(slots)


def next_retrain_slot_id(now: datetime, slots: list) -> "str | None":
    """Pure decision function (#172): given the current UTC time and the
    configured slot boundaries, return an identifier (that boundary's own
    ISO timestamp) for the most recent slot that has already passed --
    today's, or yesterday's last one if none have passed yet today. None if
    no slots are configured.

    This identifier is compared against the last one a retrain actually
    fired for (persisted, see load/save_last_fired_slot) to decide whether
    one is due. Because it's derived purely from wall-clock time and the
    configured schedule -- never from when this process happened to start
    -- two workers (or the same worker restarted at any two different
    times) asked "what's due right now?" always agree, which is exactly
    the coordination property a restart-relative interval couldn't offer.
    """
    if not slots:
        return None
    today = now.date()
    candidates = [datetime.combine(today, dt_time(h, m), tzinfo=timezone.utc) for h, m in slots]
    passed = [c for c in candidates if c <= now]
    if passed:
        boundary = max(passed)
    else:
        h, m = slots[-1]
        boundary = datetime.combine(today - timedelta(days=1), dt_time(h, m), tzinfo=timezone.utc)
    return boundary.isoformat()


RETRAIN_SCHEDULE_STATE_ID = "retrain-schedule"


def load_last_fired_slot(es: Elasticsearch) -> "str | None":
    """Persisted (not in-memory) so a restart doesn't immediately re-fire
    the slot it just handled minutes ago -- in-memory-only state would
    reintroduce restart-sensitivity through the back door (#172)."""
    try:
        doc = es.get(index=STATE_INDEX, id=RETRAIN_SCHEDULE_STATE_ID)
        return doc["_source"].get("last_fired_slot_id")
    except Exception:
        return None


def save_last_fired_slot(es: Elasticsearch, slot_id: str) -> None:
    es.index(index=STATE_INDEX, id=RETRAIN_SCHEDULE_STATE_ID,
             document={"last_fired_slot_id": slot_id})


def drift_rate_if_triggered(recent_flags, window: int, rate_threshold: float) -> "float | None":
    """Pure decision function (#65): given the rolling window of recent
    composite>=THRESHOLD flags, returns the observed rate if drift should
    trigger, else None. Separated from run_worker()'s loop so the trigger
    condition is testable directly rather than only by driving the whole
    infinite polling loop."""
    if len(recent_flags) < window:
        return None
    rate = sum(recent_flags) / len(recent_flags)
    return rate if rate > rate_threshold else None


def write_drift_metric(es: Elasticsearch, window: int, rate: float) -> None:
    """Evidence for one drift-detection trigger (#65, docs/ml-worker-plan.md
    §11.4). Best-effort, same rationale as write_retrain_metric()."""
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "kind": "drift",
        "drift_window": window,
        "drift_rate": round(rate, 4),
    }
    try:
        es.index(index=METRICS_INDEX, document=doc)
    except Exception as exc:
        logger.warning(f"Failed to write drift metric (non-fatal): {exc}")


def anomaly_doc_id(source_index: "str | None", source_event_id: "str | None") -> str:
    """Deterministic ES document ID for ml-anomalies (#168), derived from
    the source event's own identity rather than letting Elasticsearch
    assign a random one. source_index is included (not source_event_id
    alone) because that ID is only unique within its own source index --
    honeypot-v2-* and suricata-v2-* auto-generated IDs are not guaranteed
    disjoint from each other."""
    return hashlib.md5(f"{source_index or ''}|{source_event_id or ''}".encode()).hexdigest()


def write_anomaly(es: Elasticsearch, rdb: "redis.Redis | None",
                 event: dict, scores: dict, explanation: str) -> None:
    src = event.get("_source", {})
    composite = compute_composite(scores)
    if composite < THRESHOLD:
        return

    # src_ip/dst_port/proto use the same real-document field reads as
    # extract_features() (#62 task 33) -- src.get("src_ip") etc. never
    # matches a real document's top level, so a correctly-fired anomaly
    # would otherwise still get written with a null src_ip, which is the
    # one field an operator actually needs to act on it.
    doc = {
        "@timestamp":        src.get("@timestamp", datetime.now(timezone.utc).isoformat()),
        "source_event_id":   event.get("_id"),
        "source_index":      event.get("_index"),
        "src_ip":            _get_ip(src) or None,
        "src_country":       (src.get("source") or {}).get("geo", {}).get("country_iso_code"),
        "composite_score":   round(composite, 4),
        "severity":          severity(composite),
        "model_scores":      {k: round(v, 4) for k, v in scores.items()},
        "explanation":       explanation,
        "event_type":        (src.get("event") or {}).get("category"),
        "dst_port":          _get_port(src) or None,
        "proto":             _get_transport_proto(src),
    }

    # The Elasticsearch write is the authoritative action -- a dashboard
    # polling ml-anomalies will see this finding regardless of what happens
    # below. Redis is a best-effort wake-up only (ml-gpu-coordinated-roadmap.md
    # §1 decision 1), so a broker that is absent, unreachable, or refusing
    # connections must never be able to take an anomaly write down with it.
    #
    # id= is deterministic from the source event (#168), not ES-assigned:
    # the same source event reprocessed -- a checkpoint replay, a
    # crash-retry, or fetch_new_events' own equal-timestamp boundary
    # requery -- overwrites the same anomaly document instead of creating a
    # duplicate finding for something scored exactly once conceptually.
    es.index(index=ANOMALY_INDEX, id=anomaly_doc_id(doc["source_index"], doc["source_event_id"]), document=doc)
    if rdb is not None:
        try:
            rdb.publish(REDIS_CHANNEL, json.dumps({
                "severity": doc["severity"],
                "composite_score": doc["composite_score"],
                "src_ip": doc["src_ip"],
                "explanation": explanation[:120],
            }))
        except Exception as exc:
            logger.warning(f"Redis publish failed (non-fatal, ES write already committed): {exc}")
    logger.info(f"Anomaly [{doc['severity']}] score={composite:.3f} src={doc['src_ip']}")


def run_worker() -> None:
    logger.remove()
    logger.add(lambda m: print(m, end=""), level=LOG_LEVEL)

    logger.info("ML Worker starting...")

    es  = Elasticsearch(ES_HOST, request_timeout=30)
    rdb = redis.from_url(REDIS_URL) if REDIS_URL else None
    if rdb is None:
        logger.info("REDIS_URL not set -- anomaly notifications are ES-only (this is the default, see #62)")

    # Wait for Elasticsearch to be ready
    for attempt in range(30):
        try:
            if es.ping():
                break
        except Exception:
            pass
        logger.info(f"Waiting for Elasticsearch... ({attempt+1}/30)")
        time.sleep(10)
    else:
        logger.error("Elasticsearch not reachable after 5 minutes, exiting.")
        return

    # Ensure required indices exist
    ensure_index(es, ANOMALY_INDEX, {
        "mappings": {
            "properties": {
                "@timestamp":       {"type": "date"},
                "source_event_id":  {"type": "keyword"},
                "source_index":     {"type": "keyword"},
                "src_ip":           {"type": "ip"},
                "src_country":      {"type": "keyword"},
                "composite_score":  {"type": "float"},
                "severity":         {"type": "keyword"},
                "model_scores":     {"type": "object"},
                "explanation":      {"type": "text"},
                "event_type":       {"type": "keyword"},
                "dst_port":         {"type": "integer"},
                "proto":            {"type": "keyword"},
            }
        }
    })
    ensure_index(es, STATE_INDEX, {"mappings": {"properties": {}}})
    # #65: METRICS_INDEX was declared but never written to until now --
    # retrain acceptance/rejection evidence (docs/ml-worker-plan.md §11.1)
    # and drift-detection events (§11.4) both land here.
    ensure_index(es, METRICS_INDEX, {
        "mappings": {
            "properties": {
                "@timestamp":            {"type": "date"},
                "kind":                  {"type": "keyword"},  # "retrain" | "drift"
                "model":                 {"type": "keyword"},
                "accepted":              {"type": "boolean"},
                "reason":                {"type": "text"},
                "train_samples":         {"type": "integer"},
                "holdout_samples":       {"type": "integer"},
                "anomaly_rate_new":      {"type": "float"},
                "anomaly_rate_previous": {"type": "float"},
                "drift_window":          {"type": "integer"},
                "drift_rate":            {"type": "float"},
                "source_event_id":       {"type": "keyword"},  # kind="malformed_event" (#171)
                "source_index":          {"type": "keyword"},
                "error":                 {"type": "text"},
                "backlog_count":         {"type": "integer"},  # kind="backlog" (#190)
                "consecutive_failures":  {"type": "integer"},  # kind="es_unavailable" (#188)
                "downtime_seconds":      {"type": "integer"},
            }
        }
    })

    # Initialise models
    iso_model      = IsoForestModel(model_dir=MODEL_DIR)
    lstm_model     = LSTMAEModel(model_dir=MODEL_DIR)
    session_tracker = SessionFeatureTracker(model_dir=MODEL_DIR)  # #277: real cmd_count/failed_logins_1h/unique_ports_1h

    retrain_slots = parse_retrain_slots(RETRAIN_SLOTS_UTC)
    last_fired_slot_id = load_last_fired_slot(es)  # #172: persisted, not restart-relative
    recent_flags = deque(maxlen=DRIFT_WINDOW)  # composite >= THRESHOLD, drift detection (#65)
    consecutive_es_failures = {idx: 0 for idx in SOURCE_INDICES}  # #188

    logger.info(f"Worker ready. Poll={POLL_INTERVAL}s Threshold={THRESHOLD}")

    while True:
        cycle_start = time.time()

        for index_pattern in SOURCE_INDICES:
            checkpoint = load_checkpoint(es, index_pattern)
            events, ok = fetch_new_events(
                es, index_pattern, checkpoint["last_timestamp"],
                exclude_ids=set(checkpoint["seen_ids"]),
                max_total=MAX_POLL_BATCH,
            )

            # #188: distinguish a transient blip from a sustained outage --
            # fetch_new_events() already retries next cycle either way (no
            # separate backoff), this only tracks how many cycles in a row
            # have failed for THIS index pattern.
            if not ok:
                consecutive_es_failures[index_pattern] += 1
                n = consecutive_es_failures[index_pattern]
                if n == ES_UNAVAILABLE_ALERT_AFTER:
                    logger.error(
                        f"{index_pattern}: Elasticsearch has failed {n} consecutive poll "
                        f"cycles (~{n * POLL_INTERVAL}s) -- treating as a sustained outage, not a blip"
                    )
            elif consecutive_es_failures[index_pattern] >= ES_UNAVAILABLE_ALERT_AFTER:
                # Recovered after crossing the sustained-outage threshold --
                # this is the only point a durable record of it can be
                # written, since ES itself was unreachable for its duration.
                n = consecutive_es_failures[index_pattern]
                write_es_unavailable_metric(es, index_pattern, n, n * POLL_INTERVAL)
                consecutive_es_failures[index_pattern] = 0
            else:
                consecutive_es_failures[index_pattern] = 0

            if not events:
                continue

            logger.debug(f"{index_pattern}: {len(events)} new events")

            score_and_write_events(es, rdb, iso_model, lstm_model, events, recent_flags, session_tracker)

            # Advance the checkpoint (#168): the new (timestamp, seen_ids)
            # tuple, not just the last event's timestamp -- see
            # advance_checkpoint()'s own docstring for why.
            new_checkpoint = advance_checkpoint(events, checkpoint)
            save_checkpoint(es, index_pattern, new_checkpoint["last_timestamp"], new_checkpoint["seen_ids"])

            # #190: MAX_POLL_BATCH being exactly what came back means there's
            # very likely more behind it -- surface that now (a count query,
            # not another fetch) rather than let it stay invisible until an
            # operator happens to query Elasticsearch directly.
            if len(events) >= MAX_POLL_BATCH:
                remaining = backlog_count(es, index_pattern, new_checkpoint["last_timestamp"])
                if remaining:
                    write_backlog_metric(es, index_pattern, remaining)

        # #170: persist LSTM-AE's per-IP sliding windows every cycle, not
        # just on retrain -- a crash/OOM/restart between retrains would
        # otherwise still lose in-progress sessions' temporal state even
        # though the fix exists. Cheap and bounded (MAX_PERSISTED_IPS), so
        # every POLL_INTERVAL is a fine cadence rather than needing a
        # separate timer or graceful-shutdown hook.
        lstm_model.save_buffers()
        session_tracker.save()  # #277: same rationale, for the cmd_count/rolling-window state

        # Drift detection (#65): a full window of real scores, sustained
        # above DRIFT_ANOMALY_RATE, forces an early retrain regardless of
        # the scheduled slots below -- this stays event-driven (#172 only
        # concerns the *scheduled* path). The window is cleared after
        # triggering so a persistent drift condition retrains once and then
        # re-accumulates a fresh window, rather than firing again every
        # single poll cycle on the same stale evidence.
        drift_rate = drift_rate_if_triggered(recent_flags, DRIFT_WINDOW, DRIFT_ANOMALY_RATE)
        if drift_rate is not None:
            logger.warning(
                f"Drift detected: {drift_rate:.1%} anomaly rate over the last "
                f"{DRIFT_WINDOW} events (threshold {DRIFT_ANOMALY_RATE:.0%}) -- "
                "triggering an early retrain"
            )
            write_drift_metric(es, DRIFT_WINDOW, drift_rate)
            recent_flags.clear()

        # #172: scheduled retraining now fires at explicit UTC slot
        # boundaries (persisted last_fired_slot_id), not a restart-relative
        # interval -- see parse_retrain_slots()/next_retrain_slot_id()'s own
        # docstrings for why this makes the schedule coordinable rather
        # than dependent on when this process happened to (re)start.
        due_slot_id = next_retrain_slot_id(datetime.now(timezone.utc), retrain_slots)
        scheduled_due = due_slot_id is not None and due_slot_id != last_fired_slot_id

        # #190: this runs synchronously in the same loop as event polling --
        # observed live to block it for ~8 minutes (LSTM fine-tuning on a
        # real 40k-event batch), during which nothing above this line runs
        # at all. Deliberately left this way rather than moved to a
        # background thread: the acceptance gate's promise (a rejected
        # candidate never replaces the active model, #65) and the atomic
        # promotion fix (#169) both assume nothing else is concurrently
        # reading self.iso/self.hbos/self.net while retrain() mutates them
        # in place (LSTM especially -- fine-tuning literally steps the live
        # model's weights before deciding whether to keep them). Making this
        # concurrent needs a real concurrency story for that, not just
        # spawning a thread. Revisit if Milestone I's shared-GPU scheduling
        # (#84) needs retrain and polling decoupled; MAX_POLL_BATCH above at
        # least bounds how large a backlog blocking this causes.
        if drift_rate is not None or scheduled_due:
            logger.info("Starting model retraining...")
            all_events = []
            for idx in SOURCE_INDICES:
                since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
                idx_events, _ok = fetch_new_events(
                    es, idx, since_24h, page_size=5000,
                    max_total=MAX_TRAIN_SAMPLES,
                )
                all_events.extend(idx_events)

            if len(all_events) > 100:
                sources = [e["_source"] for e in all_events]
                iso_result = iso_model.retrain(sources)
                lstm_result = lstm_model.retrain(sources)
                write_retrain_metric(es, "isolation_forest_hbos", iso_result)
                write_retrain_metric(es, "lstm_ae", lstm_result)
                logger.info(f"Retrain cycle on {len(all_events)} events complete")

            if scheduled_due:
                # Mark this slot handled regardless of whether len(all_events)
                # cleared the 100-event floor -- otherwise a quiet slot would
                # keep re-attempting (and re-fetching 24h of events) every
                # single POLL_INTERVAL for the rest of the day instead of
                # waiting for the next slot, same as the old code always
                # resetting last_retrain even on a no-op cycle.
                last_fired_slot_id = due_slot_id
                save_last_fired_slot(es, due_slot_id)

        elapsed = time.time() - cycle_start
        sleep_for = max(0, POLL_INTERVAL - elapsed)
        time.sleep(sleep_for)


if __name__ == "__main__":
    run_worker()
