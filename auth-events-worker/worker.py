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
import argparse
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from elasticsearch import Elasticsearch
from loguru import logger

# ---------------------------------------------------------------------------
# Configuration (all overridable via env vars, matching ml-worker's convention)
# ---------------------------------------------------------------------------
ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))  # seconds

# #2219: Keycloak caps every admin-events response at `max` rows and
# truncates silently -- HTTP 200, a valid JSON array, just fewer events
# than the day actually holds. fetch_login_errors walks `first` forward
# until a page comes back short; these knobs bound that walk.
PAGE_SIZE = int(os.getenv("AUTH_EVENTS_PAGE_SIZE", "1000"))
MAX_PAGES_PER_DAY = int(os.getenv("AUTH_EVENTS_MAX_PAGES_PER_DAY", "100"))

KEYCLOAK_ISSUER_URL = os.getenv("KEYCLOAK_ISSUER_URL", "")  # e.g. https://auth.honeypot.example/realms/apiary
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "apiary")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "auth-events-poller")
KEYCLOAK_CLIENT_SECRET_FILE = os.getenv("KEYCLOAK_CLIENT_SECRET_FILE", "/run/secrets/client-secret")

EVENTS_INDEX = "auth-failure-events"
STATE_INDEX = "auth-events-worker-state"
STATE_DOC_ID = "checkpoint"

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# #787: a hung cycle (confirmed live -- a Keycloak connection failure right
# as urllib3's connection pool held a now-dead socket) left the process
# technically running but silently dead: no further cycles, no further
# logs, forever, with nothing to detect or restart it (no healthcheck was
# ever wired up for this worker). Same heartbeat-file pattern llm-worker's
# own healthcheck() already uses -- the loop below writes this on every
# cycle attempt, success or caught failure; --healthcheck fails once it
# goes stale for longer than a few missed polls, which is what actually
# catches "the loop stopped iterating" instead of just "the process exited."
STATUS_PATH = Path(os.getenv("AUTH_EVENTS_STATUS_PATH", str(Path(tempfile.gettempdir()) / "auth-events-worker-status.json")))

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


def fetch_login_errors_page(token: str, date_from: str, first: int, page_size: int) -> list:
    resp = requests.get(
        f"{issuer_base()}/events",
        params={"type": "LOGIN_ERROR", "dateFrom": date_from, "first": first, "max": page_size},
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def fetch_login_errors(
    token: str, date_from: str, *, page_size: int = PAGE_SIZE, max_pages: int = MAX_PAGES_PER_DAY
) -> tuple[list, bool]:
    """Two separate Keycloak quirks shape this fetch:

    1. `dateFrom` filters at DAY granularity only (confirmed live,
       2026-08-09 -- a bare yyyy-MM-dd, no time-of-day component accepted),
       so this always returns the whole day and the caller keeps filtering
       to `time > checkpoint` itself rather than relying on the API for
       sub-day precision.
    2. (#2219) Every response is silently capped at `max` rows -- HTTP 200,
       a valid array, no marker that anything is missing. A single-page
       fetch permanently dropped everything past row 1,000 on any day busy
       enough (exactly a credential-spray burst against this endpoint's own
       SSO front door), so pages walk `first` forward until one comes back
       short. Nothing here assumes which end of the day Keycloak orders
       from, or that consecutive windows are disjoint -- overlapping or
       repeated rows are harmless because each event's stable `id` becomes
       its ES document _id downstream (write_events).

    Returns (events, drained). drained=False means MAX_PAGES_PER_DAY full
    pages came back without ever reaching a short one -- server-side
    misbehaviour, not a bigger day -- and the caller must hold the
    checkpoint back from past this day so the next cycle re-drains it.
    """
    all_events: list = []
    for pages_fetched in range(1, max_pages + 1):
        page = fetch_login_errors_page(token, date_from, first=(pages_fetched - 1) * page_size, page_size=page_size)
        if not isinstance(page, list):
            raise ValueError(f"unexpected non-list response from Keycloak events API: {type(page).__name__}")
        all_events.extend(page)
        if len(page) < page_size:
            if pages_fetched > 1:
                # Deliberate audit trail for large days (#2219): nothing was
                # lost -- every row above the old cap is ingested -- but a
                # LOGIN_ERROR volume this size is itself worth an operator's
                # attention.
                logger.warning(
                    f"day {date_from}: {len(all_events)} LOGIN_ERROR event(s) across "
                    f"{pages_fetched} page(s) -- heavy day, no truncation"
                )
            return all_events, True

    logger.error(
        f"day {date_from}: still consuming full {page_size}-row page(s) after {max_pages} "
        f"({len(all_events)} event(s)) -- pager never saw a short page; stopping this day "
        f"incomplete. The checkpoint will hold back from past it and the next cycle re-drains."
    )
    return all_events, False


def collect_new_events(token: str, checkpoint: int, start_date, today) -> tuple[list, bool]:
    """Days strictly ascending from start_date through today, client-side
    filtered to `time > checkpoint` per #1066's day-granularity contract.

    Returns (new_events, fully_drained). fully_drained=False stops the walk
    at the first day whose pager could not finish: everything collected up
    to there is valid (duplicate-free via overwrite on the next pass), but
    walking PAST an incompletely-drained day while its tail is still missing
    would fence that tail behind the checkpoint forever -- the exact failure
    mode #2219 describes. Days partition time, so nothing later can carry a
    timestamp inside the blocked day's gap either way."""
    all_new: list = []
    d = start_date
    while d <= today:
        events_for_day, drained = fetch_login_errors(token, d.isoformat())
        all_new.extend(e for e in events_for_day if e["time"] > checkpoint)
        if not drained:
            return all_new, False
        d += timedelta(days=1)
    return all_new, True


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


def write_status(ok: bool) -> None:
    payload = {"ok": ok, "updated_at": datetime.now(timezone.utc).isoformat()}
    temporary = STATUS_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    temporary.replace(STATUS_PATH)


def healthcheck() -> int:
    try:
        status = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
        updated = datetime.fromisoformat(str(status["updated_at"]))
        max_age = max(90, POLL_INTERVAL * 3)
        return 0 if (datetime.now(timezone.utc) - updated).total_seconds() <= max_age else 1
    except (OSError, ValueError, KeyError, TypeError):
        return 1


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
            all_new, fully_drained = collect_new_events(token, checkpoint, start_date, today)

            if all_new:
                write_events(es, all_new)
                # Advancing to max(e["time"]) is safe even when
                # fully_drained is False: collect_new_events stops the walk
                # at the first undrained day, so everything in all_new is
                # bounded by that day -- which the next cycle re-enters via
                # its own start_date anyway (#2219).
                new_checkpoint = max(e["time"] for e in all_new)
                save_checkpoint(es, new_checkpoint)
                logger.info(f"Wrote {len(all_new)} new LOGIN_ERROR event(s)")
            write_status(True)
        except Exception as exc:
            logger.error(f"Cycle failed: {exc}")
            write_status(False)

        elapsed = time.time() - cycle_start
        time.sleep(max(0, POLL_INTERVAL - elapsed))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--healthcheck", action="store_true", help="check the bounded status heartbeat")
    args = parser.parse_args()
    if args.healthcheck:
        sys.exit(healthcheck())
    run_worker()
