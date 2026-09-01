#!/usr/bin/env python3
"""backfill-ttylog-attribution.py — delete #1696 phantom cowrie-ttylog-v1
documents keyed by cowrie's in-progress ttylog filename.

#2282: this script used to also backfill src_ip/session/country onto
cowrie-ttylog-v1 documents. That attribution mode is deleted, not
deprecated -- #1716 (e094b849) removed the import-time join it mirrored
and the recordings-list consumer of those fields. Confirmed directly
against the current backend, not assumed: backend-service/src/stores.rs's
`recordings()` builds every recordings-list column from the
`cowrie.log.closed` event itself, never from cowrie-ttylog-v1;
backend-service/src/replay.rs's ttylog lookup keys purely on `shasum` and
reads only `ttylog_base64`; backend-service/src/es_importer.rs carries its
own note at the old join site: "Nothing reads those fields any more...
The documents already written keep their fields; they are simply
ignored." Running the old attribution mode today would rewrite thousands
of live documents to store data nothing reads -- and because the index is
content-addressed (one recording can be produced by thousands of distinct
sessions from different source IPs), it would stamp one arbitrarily-chosen
session's address onto a document shared by all of them, manufacturing
exactly the misattribution #1716 exists to prevent. See #2282 for the full
history if this needs re-deriving.

The purge mode below is unrelated to any of that and remains valid: it is
storage hygiene against #1696 phantom documents, independent of whether
anything reads attribution fields.

Elasticsearch has no host-published port (arcane/home/honeypot-elk/
compose.yml), so it is only reachable by name from inside the honeynet
network -- `curl http://localhost:9200` from the host has never worked.
Run this the way scripts/reset-logs.sh reaches ES, from a throwaway
container joined to that network:

    docker run --rm --network honeynet -v "$PWD/scripts:/s:ro" \
      python:3-alpine python /s/backfill-ttylog-attribution.py --purge-temp-names --dry-run

Env:
    ES_URL   Elasticsearch base URL (default: http://elasticsearch:9200)

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

ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200").rstrip("/")
TTYLOG_INDEX = "cowrie-ttylog-v1"


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
    parser.add_argument("--purge-temp-names", action="store_true",
                        help="delete #1696 phantom documents keyed by a temporary filename")
    args = parser.parse_args()

    if not args.purge_temp_names:
        parser.error(
            "no action given -- the attribution-backfill modes this script "
            "used to also offer were removed in #2282 (their consumer is "
            "gone, see this file's module docstring); --purge-temp-names is "
            "the only surviving mode"
        )

    total = request("GET", f"/{TTYLOG_INDEX}/_count")["count"]
    print(f"{TTYLOG_INDEX}: {total} documents")

    return purge_temp_names(args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
