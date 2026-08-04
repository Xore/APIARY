#!/usr/bin/env python3
"""Ship Ghidra/sandbox/GitHub-analysis results into Elasticsearch.

#378: these result stores were local-disk-JSON-only -- the dashboard
(dashboard/ghidra.go, sandbox.go, github_analysis.go) reads them fresh off
disk and they were never queryable alongside the raw honeypot-v2-*/
portbridge-v2-* event stream. This worker is a read-only secondary indexer:
local JSON stays the dashboard's source of truth (safer migration path per
the issue's own writeup), this only mirrors it into ES.

Payload Workbench runs used to be mirrored here too, but the #405 follow-up
moved workbench storage to Elasticsearch directly (dashboard/workbench_es.go)
-- the dashboard is the only writer now, so there is no local JSON left for
this importer to mirror.

Each source directory is polled on an interval. A file is only re-sent when
its mtime advances past what a small local state file last recorded, so a
steady-state pass costs one stat() per file, not one ES write. Document _id
is deterministic (sha256 / job id / run id) so a re-sent file overwrites
its own document instead of duplicating it -- the same convention
ml-worker/worker.py uses for anomaly docs.

Horizontal scaling (per the issue's second ask -- "can we run more workers
to import things faster"): files are partitioned across replicas by
sha256(path) % SHARD_COUNT. There's no queue in this stack to distribute
work through, so this is the same lock-free partitioning primitive as
Elasticsearch's own hash-based shard routing. SHARD_INDEX defaults to the
trailing "-N" of $HOSTNAME (what `docker compose up --scale ... =N` assigns
containers without an explicit container_name), so scaling out only
requires setting SHARD_COUNT to match the replica count -- see the compose
file comment next to this service.
"""
import hashlib
import json
import os
import re
import time
from pathlib import Path

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from loguru import logger

ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
IMPORT_INTERVAL = int(os.getenv("IMPORT_INTERVAL", "300"))
STATE_FILE = Path(os.getenv("IMPORTER_STATE", "/state/es-results-importer.json"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

SHARD_COUNT = int(os.getenv("SHARD_COUNT", "1"))
_hostname_shard = re.search(r"-(\d+)$", os.getenv("HOSTNAME", ""))
SHARD_INDEX = int(os.getenv("SHARD_INDEX", _hostname_shard.group(1) if _hostname_shard else "0")) % max(SHARD_COUNT, 1)

# (env var, source label, ES index, id field(s) in the JSON, namespace field
# in the ES document). id_fields is a tuple tried in order -- the first
# present, non-empty value wins -- since not every producer stamps the same
# key (workbench runs use "id", everything else uses "sha256"/"job").
SOURCES = [
    {
        "env": "GHIDRA_RESULTS_DIR",
        "label": "ghidra",
        "index": "ghidra-analysis-v1",
        "id_fields": ("sha256",),
        "glob": "*_ghidra.json",
    },
    {
        "env": "SANDBOX_RESULTS_DIR",
        "label": "sandbox",
        "index": "sandbox-analysis-v1",
        "id_fields": ("job", "sha256"),
        "glob": "*.json",
        "skip": {"status.json"},
    },
    {
        "env": "WINDOWS_SANDBOX_RESULTS_DIR",
        "label": "sandbox",
        "index": "sandbox-analysis-v1",
        "id_fields": ("job", "sha256"),
        "glob": "*.json",
        "skip": {"status.json"},
    },
    {
        "env": "GITHUB_ANALYSIS_RESULTS_DIR",
        "label": "github_analysis",
        "index": "github-analysis-v1",
        "id_fields": ("sha256",),
        "glob": "*.json",
        "skip": {"status.json"},
    },
    {
        # #404: dashboard/revdeck.go's own standalone Rev·Deck submissions --
        # distinct from the "revdeck" field ghidra-analysis-v1 already
        # carries when Rev·Deck runs embedded inside a full Ghidra analysis.
        "env": "REVDECK_RESULTS_DIR",
        "label": "revdeck",
        "index": "revdeck-analysis-v1",
        "id_fields": ("sha256",),
        "glob": "*_revdeck.json",
    },
]


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(STATE_FILE)


def owns(path: Path) -> bool:
    if SHARD_COUNT <= 1:
        return True
    digest = int(hashlib.sha256(str(path).encode()).hexdigest(), 16)
    return digest % SHARD_COUNT == SHARD_INDEX


def doc_id(source: dict, payload: dict, path: Path) -> str:
    for field in source["id_fields"]:
        value = payload.get(field)
        if value:
            return f"{source['label']}:{value}"
    # Falls back to the filename when a result predates a producer stamping
    # its id field -- still deterministic, so re-imports still overwrite
    # rather than duplicate.
    return f"{source['label']}:{path.stem}"


def build_document(source: dict, payload: dict) -> dict:
    doc = {source["label"]: payload, "event": {"category": source["label"]}}
    ts = payload.get("completed_at") or payload.get("updated_at") or payload.get("requested_at")
    if ts:
        doc["@timestamp"] = ts
    sha256 = payload.get("sha256") or payload.get("payload_sha256")
    if sha256:
        doc["file"] = {"hash": {"sha256": sha256}}
    for field in ("exit_status", "risk_level", "risk_score", "family", "platform"):
        if payload.get(field) not in (None, ""):
            doc[field] = payload[field]
    if source["label"] == "sandbox":
        classification = payload.get("classification") or {}
        if classification.get("family"):
            doc["family"] = classification["family"]
    if source["label"] == "github_analysis":
        verdict = payload.get("verdict") or {}
        if verdict.get("level"):
            doc["risk_level"] = verdict["level"]
    return doc


def scan_source(source: dict, root: Path, state: dict) -> list:
    """Returns pending (key, mtime, action) triples for changed files.

    Deliberately does not touch `state` itself -- the caller only records a
    file as imported once bulk() confirms its document actually made it
    into ES, otherwise a transient ES error would get silently swallowed:
    the file wouldn't change again, so nothing would ever retry it.
    """
    pending = []
    skip = source.get("skip", set())
    for path in sorted(root.glob(source["glob"])):
        if not path.is_file() or path.name in skip:
            continue
        if not owns(path):
            continue
        key = str(path)
        mtime = path.stat().st_mtime
        if state.get(key) == mtime:
            continue
        try:
            payload = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning(f"{source['label']}: skipping unreadable {path}: {exc}")
            continue
        action = {
            "_op_type": "index",
            "_index": source["index"],
            "_id": doc_id(source, payload, path),
            "_source": build_document(source, payload),
        }
        pending.append((key, mtime, action))
    return pending


def run_pass(es: Elasticsearch, state: dict) -> int:
    total = 0
    for source in SOURCES:
        root = os.getenv(source["env"], "")
        if not root:
            continue
        root_path = Path(root)
        if source.get("subdir"):
            root_path = root_path / source["subdir"]
        if not root_path.is_dir():
            continue
        pending = scan_source(source, root_path, state)
        if not pending:
            continue
        actions = [action for _, _, action in pending]
        ok, errors = bulk(es, actions, stats_only=False, raise_on_error=False)
        failed_ids = {e.get("index", {}).get("_id") for e in errors}
        if failed_ids:
            logger.warning(f"{source['label']}: {len(failed_ids)} document(s) failed to index, will retry next pass")
        for key, mtime, action in pending:
            if action["_id"] not in failed_ids:
                state[key] = mtime
        total += ok
        logger.info(f"{source['label']}: indexed {ok} document(s)")
    return total


def run_worker() -> None:
    logger.remove()
    logger.add(lambda m: print(m, end=""), level=LOG_LEVEL)
    logger.info(f"es-results-importer starting (shard {SHARD_INDEX}/{SHARD_COUNT})")

    es = Elasticsearch(ES_HOST, request_timeout=30)
    for attempt in range(30):
        try:
            if es.ping():
                break
        except Exception:
            pass
        logger.info(f"Waiting for Elasticsearch... ({attempt + 1}/30)")
        time.sleep(10)
    else:
        logger.error("Elasticsearch not reachable after 5 minutes, exiting.")
        return

    state = load_state()
    while True:
        try:
            indexed = run_pass(es, state)
            if indexed:
                save_state(state)
        except Exception as exc:
            logger.error(f"import pass failed (will retry next interval): {exc}")
        time.sleep(IMPORT_INTERVAL)


if __name__ == "__main__":
    run_worker()
