#!/usr/bin/env python3
"""backfill-ttylog-attribution.py — populate src_ip/country/session on
cowrie-ttylog-v1 documents that were imported before #1691.

backend-service's es_importer.rs joins this attribution on at import time now,
but only for recordings it imports from that point forward. Everything already
in the index keeps rendering an em dash in the recordings list. This walks the
existing documents once and fills them in.

The join is the same two-hop one es_importer.rs::ttylog_attribution does, for
the same reason. Cowrie's `cowrie.log.closed` event carries both the shasum and
the session, and usually the real attacker IP — but roughly a third of them
carry `10.8.0.1`, the WireGuard tunnel address, because the enrichment pipeline
does not rewrite src_ip on every close event. Country is worse: `source.geo.*`
is only ever populated on the session's `cowrie.session.connect` event. So the
close event resolves shasum -> session only, and the connect event for that
session supplies the address and the geo. A recording whose session left no
connect event stays unattributed rather than being attributed to the tunnel.

Run on the homeserver, where Elasticsearch is reachable:

    scripts/backfill-ttylog-attribution.py --dry-run     # report, change nothing
    scripts/backfill-ttylog-attribution.py               # backfill
    scripts/backfill-ttylog-attribution.py --all         # also re-do already-filled docs
    scripts/backfill-ttylog-attribution.py --purge-temp-names   # delete #1696 phantoms

Env:
    ES_URL      Elasticsearch base URL (default: http://localhost:9200)
    BATCH       shasums per round trip (default: 500)

Idempotent: re-running only touches documents that are still missing
attribution, unless --all is passed.

--purge-temp-names deletes the #1696 phantom documents: entries the importer
created from cowrie's *in-progress* ttylog filename
(`YYYYMMDD-HHMMSS-<session>-<pid>i.log`) before cowrie renamed the file to its
content hash. Their `shasum` is not a hash, so they can never be attributed,
and each is a truncated duplicate of a document that also exists under the
correct hash. 3,521 of 3,713 documents were such phantoms when this was
written. Run it once after deploying the importer fix that stops creating them.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

ES_URL = os.environ.get("ES_URL", "http://localhost:9200").rstrip("/")
BATCH = int(os.environ.get("BATCH", "500"))
TTYLOG_INDEX = "cowrie-ttylog-v1"
EVENTS_INDEX = "honeypot-v2-*"
# The tunnel address the close event carries when enrichment did not rewrite
# it. Never a real attacker; treated as absent.
TUNNEL_IP = "10.8.0.1"


def request(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"{ES_URL}{path}", data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as e:
        sys.exit(f"elasticsearch {method} {path} -> {e.code}: {e.read().decode(errors='replace')[:400]}")


def bulk(lines: list[str]) -> int:
    """Returns the number of failed items."""
    payload = ("\n".join(lines) + "\n").encode()
    req = urllib.request.Request(
        f"{ES_URL}/_bulk", data=payload, method="POST",
        headers={"Content-Type": "application/x-ndjson"},
    )
    with urllib.request.urlopen(req, timeout=300) as response:
        result = json.loads(response.read())
    if not result.get("errors"):
        return 0
    failed = 0
    for item in result.get("items", []):
        op = next(iter(item.values()))
        if op.get("status", 200) >= 300:
            failed += 1
            if failed <= 3:
                print(f"  ! {op.get('_id')}: {op.get('error', {}).get('reason', '?')}", file=sys.stderr)
    return failed


def scan_recordings(include_filled: bool):
    """Yield (id, shasum) for every recording needing attribution."""
    query = {"match_all": {}} if include_filled else {
        "bool": {"must_not": [{"exists": {"field": "session"}}]}
    }
    body = {"size": BATCH, "_source": ["shasum"], "query": query,
            "sort": [{"_doc": "asc"}]}
    result = request("POST", f"/{TTYLOG_INDEX}/_search?scroll=5m", body)
    scroll_id = result.get("_scroll_id")
    try:
        while True:
            hits = result["hits"]["hits"]
            if not hits:
                return
            for hit in hits:
                shasum = hit["_source"].get("shasum") or hit["_id"]
                if shasum:
                    yield hit["_id"], shasum
            result = request("POST", "/_search/scroll",
                             {"scroll": "5m", "scroll_id": scroll_id})
            scroll_id = result.get("_scroll_id", scroll_id)
    finally:
        if scroll_id:
            try:
                request("DELETE", "/_search/scroll", {"scroll_id": [scroll_id]})
            except SystemExit:
                pass


def attribution(shasums: list[str]) -> dict[str, tuple[str, str, str]]:
    """shasum -> (session, src_ip, country), omitting anything unresolvable."""
    if not shasums:
        return {}
    closed = request("POST", f"/{EVENTS_INDEX}/_search", {
        "size": len(shasums),
        "query": {"bool": {"filter": [
            {"term": {"honeypot.eventid": "cowrie.log.closed"}},
            {"terms": {"honeypot.shasum": shasums}},
        ]}},
        "_source": ["honeypot.shasum", "honeypot.session"],
    })
    sessions: dict[str, str] = {}
    for hit in closed["hits"]["hits"]:
        hp = hit["_source"].get("honeypot", {})
        if hp.get("shasum") and hp.get("session"):
            sessions[hp["shasum"]] = hp["session"]
    if not sessions:
        return {}

    wanted = sorted(set(sessions.values()))
    connected = request("POST", f"/{EVENTS_INDEX}/_search", {
        "size": len(wanted),
        "query": {"bool": {"filter": [
            {"term": {"honeypot.eventid": "cowrie.session.connect"}},
            {"terms": {"honeypot.session": wanted}},
        ]}},
        "_source": ["honeypot.session", "honeypot.src_ip", "source.geo.country_name"],
    })
    origins: dict[str, tuple[str, str]] = {}
    for hit in connected["hits"]["hits"]:
        source = hit["_source"]
        hp = source.get("honeypot", {})
        session = hp.get("session")
        if not session:
            continue
        src_ip = hp.get("src_ip") or ""
        if src_ip == TUNNEL_IP:
            src_ip = ""
        country = (source.get("source", {}).get("geo", {}) or {}).get("country_name", "")
        origins[session] = (src_ip, country)

    out: dict[str, tuple[str, str, str]] = {}
    for shasum, session in sessions.items():
        if session in origins:
            src_ip, country = origins[session]
            out[shasum] = (session, src_ip, country)
    return out


def purge_temp_names(dry_run: bool) -> int:
    """Delete #1696 phantoms: documents whose shasum is not a sha256.

    Matched positively (not by a `*.log` suffix) so anything else that ever
    lands in that directory under a non-hash name is caught too. The real
    documents are keyed by exactly 64 lowercase hex characters.
    """
    query = {"bool": {"must_not": [{"regexp": {"shasum": "[0-9a-f]{64}"}}]}}
    count = request("POST", f"/{TTYLOG_INDEX}/_count", {"query": query})["count"]
    print(f"phantom documents (shasum is not a sha256): {count}")
    if not count:
        return 0
    sample = request("POST", f"/{TTYLOG_INDEX}/_search",
                     {"size": 3, "_source": ["shasum"], "query": query})
    for hit in sample["hits"]["hits"]:
        print(f"  e.g. {hit['_source'].get('shasum')!r}")
    if dry_run:
        print(f"\nwould delete {count} document(s)")
        return 0
    result = request("POST", f"/{TTYLOG_INDEX}/_delete_by_query?refresh=true&conflicts=proceed",
                     {"query": query})
    print(f"\ndeleted {result.get('deleted', 0)} document(s)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would change, write nothing")
    parser.add_argument("--all", action="store_true", dest="include_filled",
                        help="also reprocess documents that already have attribution")
    parser.add_argument("--purge-temp-names", action="store_true",
                        help="delete #1696 phantom documents keyed by a temporary filename")
    args = parser.parse_args()

    total = request("GET", f"/{TTYLOG_INDEX}/_count")["count"]
    print(f"{TTYLOG_INDEX}: {total} documents")

    if args.purge_temp_names:
        return purge_temp_names(args.dry_run)

    seen = matched = written = failed = 0
    batch: list[tuple[str, str]] = []

    def flush() -> None:
        nonlocal matched, written, failed
        if not batch:
            return
        found = attribution([shasum for _, shasum in batch])
        matched += len(found)
        lines: list[str] = []
        for doc_id, shasum in batch:
            hit = found.get(shasum)
            if not hit:
                continue
            session, src_ip, country = hit
            lines.append(json.dumps({"update": {"_index": TTYLOG_INDEX, "_id": doc_id}}))
            lines.append(json.dumps({"doc": {"session": session, "src_ip": src_ip,
                                             "country": country}}))
        if lines and not args.dry_run:
            failed += bulk(lines)
            written += len(lines) // 2
        elif lines:
            written += len(lines) // 2
        batch.clear()

    for doc_id, shasum in scan_recordings(args.include_filled):
        seen += 1
        batch.append((doc_id, shasum))
        if len(batch) >= BATCH:
            flush()
            print(f"  {seen} scanned, {matched} resolved…")
    flush()

    verb = "would update" if args.dry_run else "updated"
    print(f"\nscanned {seen}, resolved {matched}, {verb} {written}"
          + (f", {failed} failed" if failed else ""))
    if seen and not matched:
        print("nothing resolved — check that honeypot-v2-* still retains the "
              "cowrie events for these recordings; attribution cannot be "
              "recovered once those events age out.", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
