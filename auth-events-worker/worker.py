#!/usr/bin/env python3
"""
auth-events-worker — Keycloak/gateway authentication-failure telemetry
(#1066, #981 follow-up).

Polls Keycloak's admin events API for LOGIN_ERROR events across every
realm client (Kibana, EveBox, Arkime, TANNER, RevDeck, Dockge, the Traefik
dashboard, and apiary-dashboard's own native OIDC), and writes redacted
structured docs to Elasticsearch for the dashboard's /auth-events page to
read. Elasticsearch is the transport, same architecture as ml-worker --
the dashboard never talks to Keycloak directly.

Redaction (#981's own explicit constraint: "without logging
tokens/codes/cookies"): only an explicit allowlist of fields from each
Keycloak event is stored. Verified live against real LOGIN_ERROR events
(2026-08-09) that none of Keycloak's own field names carry a replayable
credential -- `code_id`/`selected_credential_id` are Keycloak's own
internal correlation UUIDs, not the actual authorization code or
credential value -- but the allowlist stays explicit rather than "store
whatever Keycloak sends" so a future Keycloak version adding a more
sensitive detail key doesn't silently start leaking it.
"""
import os
import time
from datetime import datetime, timezone, timedelta

import requests
from elasticsearch import Elasticsearch
from loguru import logger

# ---------------------------------------------------------------------------
# Configuration (all overridable via env vars, matching ml-worker's convention)
# ---------------------------------------------------------------------------
ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))  # seconds

KEYCLOAK_ISSUER_URL = os.getenv("KEYCLOAK_ISSUER_URL", "")  # e.g. https://auth.honeypot.example/realms/apiary
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "apiary")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "auth-events-poller")
KEYCLOAK_CLIENT_SECRET_FILE = os.getenv("KEYCLOAK_CLIENT_SECRET_FILE", "/run/secrets/client-secret")

EVENTS_INDEX = "auth-failure-events"
STATE_INDEX = "auth-events-worker-state"
STATE_DOC_ID = "checkpoint"

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# Explicit allowlist -- see module docstring. Anything Keycloak's `details`
# object carries outside this list is dropped, not stored.
DETAILS_ALLOWLIST = {
    "auth_method", "auth_type", "redirect_uri", "code_id",
    "username", "selected_credential_id",
}


def read_client_secret() -> str:
    with open(KEYCLOAK_CLIENT_SECRET_FILE, "r") as f:
        return f.read().strip()


def fetch_admin_token(client_secret: str) -> str:
    resp = requests.post(
        f"{KEYCLOAK_ISSUER_URL}/protocol/openid-connect/token",
        data={
            "grant_type": "client_credentials",
            "client_id": KEYCLOAK_CLIENT_ID,
            "client_secret": client_secret,
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def issuer_base() -> str:
    # KEYCLOAK_ISSUER_URL is .../realms/<realm> (the OIDC issuer) -- the
    # admin REST API lives under .../admin/realms/<realm>, a sibling path
    # under the same host, not a suffix of the issuer path itself.
    root = KEYCLOAK_ISSUER_URL.split("/realms/")[0]
    return f"{root}/admin/realms/{KEYCLOAK_REALM}"


def ensure_index(es: Elasticsearch, index: str, mapping: dict) -> None:
    if not es.indices.exists(index=index):
        es.indices.create(index=index, body=mapping)
        logger.info(f"Created index {index}")


def load_checkpoint(es: Elasticsearch) -> int:
    """Last processed Keycloak event `time` (epoch millis). Keycloak events
    carry a stable unique `id`, used as this worker's ES document _id (see
    write_events) -- re-processing the same event on overlapping fetches is
    therefore a harmless no-op, not a duplicate, so this checkpoint only
    needs to be a coarse "don't refetch ancient history" bound, unlike
    ml-worker's own equal-timestamp seen_ids tracking (STATE_INDEX docstring
    there) which exists because ITS source events have no such natural key.
    """
    try:
        doc = es.get(index=STATE_INDEX, id=STATE_DOC_ID)
        return int(doc["_source"]["last_time_ms"])
    except Exception:
        # First run: start from 24h ago, not the epoch -- avoids a
        # first-run flood from Keycloak's full 90-day event retention
        # (eventsExpiration in apiary-realm.json) landing in ES all at once.
        return int((datetime.now(timezone.utc) - timedelta(hours=24)).timestamp() * 1000)


def save_checkpoint(es: Elasticsearch, last_time_ms: int) -> None:
    es.index(index=STATE_INDEX, id=STATE_DOC_ID, document={"last_time_ms": last_time_ms})


def fetch_login_errors(token: str, date_from: str) -> list:
    """Keycloak's events endpoint filters dateFrom at DAY granularity only
    (confirmed live, 2026-08-09 -- a bare yyyy-MM-dd, no time-of-day
    component accepted), so this always returns the whole day and the
    caller filters to `time > checkpoint` itself rather than relying on the
    API for sub-day precision."""
    resp = requests.get(
        f"{issuer_base()}/events",
        params={"type": "LOGIN_ERROR", "dateFrom": date_from, "max": 1000},
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def redact(event: dict) -> dict:
    details = event.get("details") or {}
    return {
        "@timestamp": datetime.fromtimestamp(event["time"] / 1000, tz=timezone.utc).isoformat(),
        "event_id": event["id"],
        "type": event.get("type", "LOGIN_ERROR"),
        "realm": KEYCLOAK_REALM,
        "client_id": event.get("clientId"),
        "user_id": event.get("userId"),
        "ip_address": event.get("ipAddress"),
        "error": event.get("error"),
        "details": {k: v for k, v in details.items() if k in DETAILS_ALLOWLIST},
    }


def write_events(es: Elasticsearch, events: list) -> None:
    for event in events:
        doc = redact(event)
        # event_id as the ES _id: indexing the same Keycloak event twice
        # (an overlapping day refetch) overwrites the identical document
        # rather than creating a duplicate -- see load_checkpoint's docstring.
        es.index(index=EVENTS_INDEX, id=doc["event_id"], document=doc)


def run_worker() -> None:
    logger.remove()
    logger.add(lambda msg: print(msg, end=""), level=LOG_LEVEL)

    if not KEYCLOAK_ISSUER_URL:
        raise SystemExit("KEYCLOAK_ISSUER_URL is required")

    es = Elasticsearch(ES_HOST, request_timeout=30)
    for _ in range(30):
        try:
            if es.ping():
                break
        except Exception:
            pass
        logger.info("Waiting for Elasticsearch...")
        time.sleep(10)
    else:
        raise SystemExit("Elasticsearch never became reachable")

    ensure_index(es, EVENTS_INDEX, {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "event_id": {"type": "keyword"},
                "type": {"type": "keyword"},
                "realm": {"type": "keyword"},
                "client_id": {"type": "keyword"},
                "user_id": {"type": "keyword"},
                "ip_address": {"type": "ip"},
                "error": {"type": "keyword"},
                "details": {"type": "object", "enabled": True},
            }
        }
    })
    ensure_index(es, STATE_INDEX, {"mappings": {"properties": {"last_time_ms": {"type": "long"}}}})

    client_secret = read_client_secret()
    logger.info(f"auth-events-worker starting, polling every {POLL_INTERVAL}s")

    while True:
        cycle_start = time.time()
        try:
            checkpoint = load_checkpoint(es)
            token = fetch_admin_token(client_secret)

            # Cover every day from the checkpoint through today (inclusive)
            # -- almost always just today, except right after a restart
            # that's been down across a UTC day boundary.
            start_date = datetime.fromtimestamp(checkpoint / 1000, tz=timezone.utc).date()
            today = datetime.now(timezone.utc).date()
            all_new = []
            d = start_date
            while d <= today:
                events = fetch_login_errors(token, d.isoformat())
                all_new.extend(e for e in events if e["time"] > checkpoint)
                d += timedelta(days=1)

            if all_new:
                write_events(es, all_new)
                new_checkpoint = max(e["time"] for e in all_new)
                save_checkpoint(es, new_checkpoint)
                logger.info(f"Wrote {len(all_new)} new LOGIN_ERROR event(s)")
        except Exception as exc:
            logger.error(f"Cycle failed: {exc}")

        elapsed = time.time() - cycle_start
        time.sleep(max(0, POLL_INTERVAL - elapsed))


if __name__ == "__main__":
    run_worker()
