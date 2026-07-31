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
from datetime import datetime, timezone, timedelta

import numpy as np
import redis
from elasticsearch import Elasticsearch
from loguru import logger

from models.isolation_forest import IsoForestModel
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

# Source indices to monitor
SOURCE_INDICES = [
    "cowrie-*",
    "dionaea-*",
    "honeypot-network-*",
    "conpot-*",
    "http-honeypot-*",
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
                    since: str, page_size: int = 500) -> list:
    """Scroll all new events from the given index pattern since timestamp."""
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
            resp = es.scroll(scroll_id=scroll_id, scroll="2m")
            scroll_id = resp["_scroll_id"]
            hits = resp["hits"]["hits"]
        es.clear_scroll(scroll_id=scroll_id)
    except Exception as exc:
        logger.warning(f"Fetch error for {index_pattern}: {exc}")
    return events


def write_anomaly(es: Elasticsearch, rdb: "redis.Redis | None",
                 event: dict, scores: dict, explanation: str) -> None:
    src = event.get("_source", {})
    composite = (
        0.4 * scores.get("isolation_forest", 0.0)
        + 0.4 * scores.get("lstm_ae", 0.0)
        + 0.2 * scores.get("hbos", 0.0)
    )
    if composite < THRESHOLD:
        return

    doc = {
        "@timestamp":        src.get("@timestamp", datetime.now(timezone.utc).isoformat()),
        "source_event_id":   event.get("_id"),
        "source_index":      event.get("_index"),
        "src_ip":            src.get("src_ip") or src.get("id.orig_h"),
        "src_country":       src.get("geoip", {}).get("country_iso_code"),
        "composite_score":   round(composite, 4),
        "severity":          severity(composite),
        "model_scores":      {k: round(v, 4) for k, v in scores.items()},
        "explanation":       explanation,
        "event_type":        src.get("event_type") or src.get("type"),
        "dst_port":          src.get("dst_port") or src.get("id.resp_p"),
        "proto":             src.get("proto"),
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

    # Initialise models
    iso_model  = IsoForestModel(model_dir=MODEL_DIR)
    lstm_model = LSTMAEModel(model_dir=MODEL_DIR)

    last_retrain = time.time()

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
                    lstm_score = lstm_model.score(
                        src_ip=src.get("src_ip") or src.get("id.orig_h", "0.0.0.0"),
                        features=features,
                    )

                scores = {
                    "isolation_forest": iso_score,
                    "hbos":             hbos_score,
                    "lstm_ae":          lstm_score,
                }
                composite = 0.4*iso_score + 0.4*lstm_score + 0.2*hbos_score

                if composite >= THRESHOLD:
                    explanation = iso_model.explain(features, scores)
                    write_anomaly(es, rdb, event, scores, explanation)

            # Update checkpoint to latest event timestamp
            latest_ts = events[-1]["_source"].get("@timestamp")
            if latest_ts:
                save_checkpoint(es, index_pattern, latest_ts)

        # Periodic retraining
        if time.time() - last_retrain > RETRAIN_INTERVAL:
            logger.info("Starting model retraining...")
            all_events = []
            for idx in SOURCE_INDICES:
                since_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
                all_events.extend(fetch_new_events(es, idx, since_24h, page_size=5000))

            if len(all_events) > 100:
                iso_model.retrain([e["_source"] for e in all_events])
                lstm_model.retrain([e["_source"] for e in all_events])
                logger.info(f"Retrained on {len(all_events)} events")
            last_retrain = time.time()

        elapsed = time.time() - cycle_start
        sleep_for = max(0, POLL_INTERVAL - elapsed)
        time.sleep(sleep_for)


if __name__ == "__main__":
    run_worker()
