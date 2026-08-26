#!/usr/bin/env python3
"""Read-only end-to-end health gate for dashboard-next and Elasticsearch ingestion.

One command for the tail end of RECOVERY.md / BACKUP-ESSENTIALS.md /
CGNAT-DEPLOYMENT.md: fetch source-health through dashboard-next, judge it,
print one JSON verdict, exit nonzero when anything is wrong.

This used to scrape the retired Go dashboard's ``/api/stats`` (Sensors[].State,
ES.Sources[].Count, FilebeatState, YARA.Enabled) — a response shape deleted
with the Go service in #1659, so the gate could only ever fail. #2086 ports it
onto the Rust backend's ``/api/v1/source-health``, reached through
dashboard-next's token-checked ``/bff`` passthrough (the #1608 split-host
seam — the backend itself publishes no ports):

    Go api/stats                        /bff/api/v1/source-health successor
    ----------------------------------  -----------------------------------
    Sensors[name].State == "waiting"    name absent from sensors[] (terms
                                        agg only buckets sensors that have
                                        logged at least once)
    ES.Sources[name].Count <= 0         sensors[name].documents <= 0
    (implicit) sensor gone quiet        sensors[name].state == "STALE" --
                                        rate-aware per #1931, so quiet-by-
                                        nature decoys are not failed for it
    ES.State not green/yellow           cluster_status not green/yellow
    FilebeatState != "healthy"          pipeline.state != "healthy"
    IngestState == "stale"              ingest.state == "stale"
    YARA disabled or errors             yara.enabled false, yara.errors > 0

The passthrough requires the BFF's service token: pass --token or export
DASHBOARD_SERVICE_TOKEN (the stack .env name compose maps into both
dashboard containers). With neither set the request goes out unauthenticated
and fails with 401 rather than pretending to verify.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

# Core decoys as they are actually named in event.sensor today. The old
# default list said "http" (never a sensor name — http-honeypot) and tanner
# (ten events ever; its snare/tanner pair is Traefik-served and all but
# silent, so requiring it would keep the gate permanently red).
DEFAULT_REQUIRE = "cowrie,dionaea,multipot,http-honeypot,conpot,suricata"

SOURCE_HEALTH_PATH = "/bff/api/v1/source-health"


def get(url, token):
    request = urllib.request.Request(url)
    if token:
        request.add_header("X-Service-Token", token)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dashboard",
        default="http://10.8.0.2:19090",
        help="dashboard-next base URL (default: the home-bound published port)",
    )
    parser.add_argument(
        "--require",
        default=DEFAULT_REQUIRE,
        help="comma-separated event.sensor names that must have fed recently",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("SERVICE_TOKEN") or os.environ.get("DASHBOARD_SERVICE_TOKEN", ""),
        help="BFF service token (default: $SERVICE_TOKEN or $DASHBOARD_SERVICE_TOKEN)",
    )
    args = parser.parse_args()

    failures = []
    try:
        health = get(args.dashboard.rstrip("/") + SOURCE_HEALTH_PATH, args.token)
    except urllib.error.HTTPError as error:
        detail = f"source-health unreachable: HTTP {error.code}"
        if error.code == 401:
            detail += " (BFF service token required: --token or $DASHBOARD_SERVICE_TOKEN)"
        print(json.dumps({"failures": [detail]}, indent=2))
        return 1
    except (urllib.error.URLError, OSError, ValueError) as error:
        print(json.dumps({"failures": [f"source-health unreachable: {error}"]}, indent=2))
        return 1

    sensors = {row["sensor"]: row for row in health.get("sensors", [])}
    for name in [value.strip() for value in args.require.split(",") if value.strip()]:
        if name not in sensors:
            failures.append(f"dashboard sensor has never logged: {name}")
            continue
        row = sensors[name]
        if row.get("documents", 0) <= 0:
            failures.append(f"dashboard sensor has no documents: {name}")
        elif row.get("state") == "STALE":
            failures.append(f"dashboard sensor feed stale: {name} (last {row.get('last_seen', '?')})")

    cluster_status = health.get("cluster_status")
    if cluster_status not in ("green", "yellow"):
        failures.append(f"Elasticsearch state: {cluster_status}")

    pipeline = health.get("pipeline", {})
    if pipeline.get("state") != "healthy":
        failures.append(f"Filebeat state: {pipeline.get('state')}")

    ingest = health.get("ingest", {})
    # delayed is the amber run-up, not a gate failure -- same verdict split
    # elastic.go made, and a just-restored stack legitimately spends time in it.
    if ingest.get("state") == "stale":
        failures.append(f"Elasticsearch ingestion stale: age {ingest.get('age_seconds')}s")

    yara = health.get("yara", {})
    if not yara.get("enabled") or yara.get("errors", 0):
        failures.append(f"YARA state: {yara}")

    print(
        json.dumps(
            {
                "events": health.get("total_documents"),
                "sensors": sensors,
                "elasticsearch": {
                    "cluster_status": cluster_status,
                    "ingest": ingest,
                    "dead_letters": health.get("dead_letters"),
                    "recent_dead_letters": health.get("recent_dead_letters"),
                },
                "filebeat": pipeline,
                "yara": yara,
                "failures": failures,
            },
            indent=2,
        )
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
