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
from datetime import datetime, timezone, timedelta

import numpy as np
import redis
from elasticsearch import Elasticsearch
from loguru import logger

from models.isolation_forest import IsoForestModel, MAX_TRAIN_SAMPLES, _get_ip, _get_port, _get_transport_proto
from models.lstm_autoencoder import LSTMAEModel

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
RETRAIN_INTERVAL = int(os.getenv("RETRAIN_INTERVAL", "21600")) # 6 hours
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


def load_checkpoint(es: Elasticsearch, index_pattern: str) -> str:
    """Return the last processed @timestamp for this index pattern."""
    try:
        doc = es.get(index=STATE_INDEX,
                     id=hashlib.md5(index_pattern.encode()).hexdigest())
        return doc["_source"]["last_timestamp"]
    except Exception:
        # Default: start from 1 hour ago on first run
        return (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()


def save_checkpoint(es: Elasticsearch, index_pattern: str, ts: str) -> None:
    doc_id = hashlib.md5(index_pattern.encode()).hexdigest()
    es.index(index=STATE_INDEX, id=doc_id,
             document={"index_pattern": index_pattern, "last_timestamp": ts})


def fetch_new_events(es: Elasticsearch, index_pattern: str,
                    since: str, page_size: int = 500,
                    max_total: "int | None" = None) -> list:
    """Scroll new events from the given index pattern since timestamp.

    max_total bounds how much this pulls into memory in one call -- the
    normal poll path leaves it unset (checkpoints keep each call small
    already), but the retrain path's 24h window across 2 index patterns has
    no other cap, and MAX_TRAIN_SAMPLES only bounds what retrain() fits on
    AFTER everything's already been fetched and held in memory (#62 task 33).
    """
    events = []
    query = {
        "query": {"range": {"@timestamp": {"gt": since}}},
        "sort":  [{"@timestamp": {"order": "asc"}}],
        "size":  page_size,
    }
    try:
        resp = es.search(index=index_pattern, body=query, scroll="2m")
        scroll_id = resp["_scroll_id"]
        hits = resp["hits"]["hits"]
        while hits:
            events.extend(hits)
            if max_total is not None and len(events) >= max_total:
                events = events[:max_total]
                break
            resp = es.scroll(scroll_id=scroll_id, scroll="2m")
            scroll_id = resp["_scroll_id"]
            hits = resp["hits"]["hits"]
        es.clear_scroll(scroll_id=scroll_id)
    except Exception as exc:
        logger.warning(f"Fetch error for {index_pattern}: {exc}")
    return events


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
    es.index(index=ANOMALY_INDEX, document=doc)
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
            }
        }
    })

    # Initialise models
    iso_model  = IsoForestModel(model_dir=MODEL_DIR)
    lstm_model = LSTMAEModel(model_dir=MODEL_DIR)

    last_retrain = time.time()
    recent_flags = deque(maxlen=DRIFT_WINDOW)  # composite >= THRESHOLD, drift detection (#65)

    logger.info(f"Worker ready. Poll={POLL_INTERVAL}s Threshold={THRESHOLD}")

    while True:
        cycle_start = time.time()

        for index_pattern in SOURCE_INDICES:
            since     = load_checkpoint(es, index_pattern)
            events    = fetch_new_events(es, index_pattern, since)

            if not events:
                continue

            logger.debug(f"{index_pattern}: {len(events)} new events")

            for event in events:
                src = event.get("_source", {})
                features = iso_model.extract_features(src)

                iso_score   = iso_model.score(features)
                hbos_score  = iso_model.hbos_score(features)  # fast pre-filter
                lstm_score  = 0.0

                # Only run LSTM if HBOS flagged as potentially anomalous
                if hbos_score > 0.5:
                    lstm_score = lstm_model.score(src)

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

            # Update checkpoint to latest event timestamp
            latest_ts = events[-1]["_source"].get("@timestamp")
            if latest_ts:
                save_checkpoint(es, index_pattern, latest_ts)

        # Drift detection (#65): a full window of real scores, sustained
        # above DRIFT_ANOMALY_RATE, forces an early retrain instead of
        # waiting out the rest of RETRAIN_INTERVAL. The window is cleared
        # after triggering so a persistent drift condition retrains once
        # and then re-accumulates a fresh window, rather than firing again
        # every single poll cycle on the same stale evidence.
        drift_rate = drift_rate_if_triggered(recent_flags, DRIFT_WINDOW, DRIFT_ANOMALY_RATE)
        if drift_rate is not None:
            logger.warning(
                f"Drift detected: {drift_rate:.1%} anomaly rate over the last "
                f"{DRIFT_WINDOW} events (threshold {DRIFT_ANOMALY_RATE:.0%}) -- "
                "triggering an early retrain"
            )
            write_drift_metric(es, DRIFT_WINDOW, drift_rate)
            last_retrain = 0  # forces the retrain block below to fire this cycle
            recent_flags.clear()

        # Periodic retraining
        if time.time() - last_retrain > RETRAIN_INTERVAL:
            logger.info("Starting model retraining...")
            all_events = []
            for idx in SOURCE_INDICES:
                since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
                all_events.extend(fetch_new_events(
                    es, idx, since_24h, page_size=5000,
                    max_total=MAX_TRAIN_SAMPLES,
                ))

            if len(all_events) > 100:
                sources = [e["_source"] for e in all_events]
                iso_result = iso_model.retrain(sources)
                lstm_result = lstm_model.retrain(sources)
                write_retrain_metric(es, "isolation_forest_hbos", iso_result)
                write_retrain_metric(es, "lstm_ae", lstm_result)
                logger.info(f"Retrain cycle on {len(all_events)} events complete")
            last_retrain = time.time()

        elapsed = time.time() - cycle_start
        sleep_for = max(0, POLL_INTERVAL - elapsed)
        time.sleep(sleep_for)


if __name__ == "__main__":
    run_worker()
