#!/usr/bin/env python3
"""Read-only end-to-end health gate for dashboard and Elasticsearch ingestion."""

import argparse
import json
import sys
import urllib.request


def get(url):
    with urllib.request.urlopen(url, timeout=15) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dashboard", default="http://10.8.0.2:19090")
    parser.add_argument("--require", default="cowrie,dionaea,multipot,http,conpot,tanner,suricata")
    args = parser.parse_args()
    stats = get(args.dashboard.rstrip("/") + "/api/stats")
    failures = []
    sensors = {row["Name"]: row for row in stats.get("Sensors", [])}
    indexed = {row["Name"]: row["Count"] for row in stats.get("ES", {}).get("Sources", [])}
    for name in [value.strip() for value in args.require.split(",") if value.strip()]:
        if name not in sensors:
            failures.append(f"dashboard sensor missing: {name}")
        elif sensors[name]["State"] == "waiting":
            failures.append(f"dashboard sensor has never logged: {name}")
        if indexed.get(name, 0) <= 0:
            failures.append(f"Elasticsearch source has no documents: {name}")
    es = stats.get("ES", {})
    if es.get("State") not in ("green", "yellow"):
        failures.append(f"Elasticsearch state: {es.get('State')}")
    if es.get("FilebeatState") != "healthy":
        failures.append(f"Filebeat state: {es.get('FilebeatState')}")
    if es.get("IngestState") == "stale":
        failures.append(f"Elasticsearch ingestion stale: {es.get('LastIngestAge')}")
    yara = stats.get("YARA", {})
    if not yara.get("Enabled") or yara.get("Errors", 0):
        failures.append(f"YARA state: {yara}")
    print(json.dumps({"events": stats.get("Total"), "sensors": sensors, "indexed": indexed, "elasticsearch": es, "yara": yara, "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
