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

#638/#612: cowrie's TTY session recordings are a genuine binary artifact
(not a JSON result), and the dashboard must never read them off disk
directly -- so unlike every JSON source above, this one (`binary: True`)
skips json.loads entirely and base64-encodes the raw file straight into its
own ES document. The file is already content-addressed by cowrie itself
(renamed to its own sha256 on session close, see cowrie/core/ttylog.py's
ttylog_inputhash -- identical sessions share one file, same dedup cowrie
already applies to its downloads/ directory), so the filename alone is a
stable, globally-unique document ID -- no doc_id()/id_fields lookup needed.

#638/#763: dashboard/ghidra.go's per-sample report/callgraph downloads are
the second binary-artifact case, added the same way but with one real
difference from ttylog's shape -- the filename is NOT already a unique
content hash on its own (it's "{sha256}_ghidra_report.html" /
"{sha256}_callgraph.svg", a fixed suffix on the sample's own hash, not a
hash of the artifact bytes themselves), and there are two distinct
artifact kinds sharing one index. `binary` sources carrying `id_suffix`/
`artifact_kind` (scan_source's own binary branch) derive doc _id as
"<sha256>:<kind>" instead of reusing the bare filename, so the report and
callgraph for one sample coexist in ghidra-report-artifacts-v1 without
colliding.
"""
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
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
        # #638/#763: dashboard/ghidra.go's own report-download route used to
        # os.Open this file straight off GHIDRA_RESULTS_DIR -- now it only
        # ever reads ghidra-report-artifacts-v1. id_suffix/artifact_kind
        # (see scan_source's binary branch) derive the doc _id
        # ("<sha256>:report") from the filename itself, the same way
        # generate_report.py's build_report() names it
        # ({sha256}_ghidra_report.html -- genuinely HTML, despite the
        # ReportPDF/report_pdf field naming throughout dashboard/ghidra.go;
        # the worker's automatic call never passes --pdf).
        "env": "GHIDRA_RESULTS_DIR",
        "label": "ghidra_report_html",
        "index": "ghidra-report-artifacts-v1",
        "glob": "*_ghidra_report.html",
        "binary": True,
        "id_suffix": "_ghidra_report.html",
        "artifact_kind": "report",
        "content_type": "text/html",
    },
    {
        # Same index, the other artifact kind -- doc _id "<sha256>:callgraph".
        # ghidra-worker.py only writes this file when graphviz is installed
        # on the host, so a host without it simply never produces anything
        # for this glob to match -- no special-casing needed here for that.
        "env": "GHIDRA_RESULTS_DIR",
        "label": "ghidra_callgraph_svg",
        "index": "ghidra-report-artifacts-v1",
        "glob": "*_callgraph.svg",
        "binary": True,
        "id_suffix": "_callgraph.svg",
        "artifact_kind": "callgraph",
        "content_type": "image/svg+xml",
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
        # #498: GHOSTS-sandbox's own export dir (sandbox/ghosts/run_pending.sh
        # writes windows-ghosts-<job>.json here) -- same label/index as the
        # two sandbox sources above, so all three merge into one ES mirror.
        "env": "GHOSTS_SANDBOX_RESULTS_DIR",
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
    {
        # #1134: cape-analysis-v1 had no writer anywhere -- CAPE_RESULTS_DIR
        # was never mounted into this container (or the dashboard's own)
        # at all, despite #319 already wiring the Go side against it.
        # cape-worker.py's own write_status() (status.json, same convention
        # ghidra-worker.py's own status.json uses) needs the same skip.
        "env": "CAPE_RESULTS_DIR",
        "label": "cape",
        "index": "cape-analysis-v1",
        "id_fields": ("sha256",),
        "glob": "*_cape.json",
        "skip": {"status.json"},
    },
    {
        "env": "COWRIE_TTYLOG_DIR",
        "label": "cowrie_ttylog",
        "index": "cowrie-ttylog-v1",
        "glob": "*",
        "binary": True,
    },
    {
        # #666: reporter/metrics.go overwrites this one file in place on
        # every send attempt (no per-event id to key off of), so id_fields
        # is empty -- doc_id() falls back to path.stem ("metrics"), giving
        # one stable, always-overwritten document rather than a growing
        # history. Per #638, this is the dashboard's only path to these
        # counters -- never mount the reporter's own volume into the
        # dashboard service directly.
        "env": "REPORTER_METRICS_DIR",
        "label": "reporter_metrics",
        "index": "reporter-metrics-v1",
        "id_fields": (),
        "glob": "metrics.json",
    },
]

# #638/#764: sandbox export artifacts (guest/host PCAP, diagnostics ZIP).
# Unlike every binary source above, a single document -- even chunked
# generously -- isn't the right primitive here at all: a 64MB PCAP is
# ~85MB base64'd, well past what a normal ES document should hold even
# with the larger caps the Ghidra artifacts above use. scan_source's own
# "chunked" branch splits the file across CHUNK_BYTES-sized documents
# instead (see its own comment for the doc-id/manifest shape).
#
# Generated rather than hand-repeated 9 times (3 artifact kinds x 3
# sandbox backends -- the same fan-out the JSON "sandbox" sources above
# already repeat by hand 3 times over): the shape is identical across
# every combination, only the env var and kind/suffix differ, and
# hand-repeating a real behavior difference (see ghidra_report_html/
# ghidra_callgraph_svg above, which stayed as two explicit dicts
# specifically because they *aren't* interchangeable copies of each
# other) would just be noise here.
_SANDBOX_RESULT_ENV_VARS = ("SANDBOX_RESULTS_DIR", "WINDOWS_SANDBOX_RESULTS_DIR", "GHOSTS_SANDBOX_RESULTS_DIR")
_SANDBOX_EXPORT_KINDS = (
    (".host.pcap", "host_pcap", "application/vnd.tcpdump.pcap"),
    (".guest.pcap", "guest_pcap", "application/vnd.tcpdump.pcap"),
    (".diagnostics.zip", "diagnostics", "application/zip"),
)
for _env in _SANDBOX_RESULT_ENV_VARS:
    for _suffix, _kind, _content_type in _SANDBOX_EXPORT_KINDS:
        SOURCES.append({
            "env": _env,
            "label": f"sandbox_export_{_kind}",
            "index": "sandbox-export-artifacts-v1",
            "glob": f"*{_suffix}",
            "chunked": True,
            "id_suffix": _suffix,
            "artifact_kind": _kind,
            "content_type": _content_type,
        })

# A cowrie session left connected for hours (an attacker idling, or a stuck
# shell) can produce a ttylog well beyond a normal few-KB/MB session. Rather
# than let one pathological session bloat a bulk() batch or approach
# Elasticsearch's own ~100MB HTTP body ceiling, cap what this importer will
# ever base64-encode into a single document and skip (not crash on) anything
# larger -- the file stays on disk either way (#611), so nothing is lost,
# just not mirrored into ES until this cap is deliberately raised.
MAX_TTYLOG_BYTES = int(os.getenv("MAX_TTYLOG_BYTES", str(20 * 1024 * 1024)))

# #638/#764: chunked sources (sandbox export artifacts) split a file across
# CHUNK_BYTES-sized documents instead of capping/skipping it -- there's no
# upper artifact size this can't eventually index given enough chunks, so
# MAX_CHUNKED_ARTIFACT_BYTES exists only as a sanity ceiling against a
# genuinely pathological file (a corrupted or runaway capture) turning into
# an absurd number of tiny documents, not as a real limit anyone should
# expect to hit -- 64MB guest PCAPs are the documented normal case
# (dashboard/sandbox.go's own attachSandboxDownloads history) and comfortably
# clear this by 4x. 8MB raw per chunk (~11MB base64'd) stays well under
# Elasticsearch's own ~100MB HTTP body ceiling with real headroom for bulk()
# batching several chunks in one request.
CHUNK_BYTES = int(os.getenv("SANDBOX_ARTIFACT_CHUNK_BYTES", str(8 * 1024 * 1024)))
MAX_CHUNKED_ARTIFACT_BYTES = int(os.getenv("MAX_CHUNKED_ARTIFACT_BYTES", str(256 * 1024 * 1024)))


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
    binary = source.get("binary", False)
    chunked = source.get("chunked", False)
    for path in sorted(root.glob(source["glob"])):
        if not path.is_file() or path.name in skip:
            continue
        if not owns(path):
            continue
        key = str(path)
        mtime = path.stat().st_mtime
        if state.get(key) == mtime:
            continue

        if chunked:
            # #638/#764: sandbox export artifacts -- split across multiple
            # documents instead of one large (or capped/skipped) one. Doc
            # _id is "<job>:<kind>:<chunk_index>"; chunk 0 doubles as the
            # artifact's own manifest (it carries filename/content_type/
            # total_chunks/size_bytes alongside its own data), so a reader
            # that only needs to know "does this exist, how big is it"
            # (dashboard/sandbox.go's attachSandboxDownloads) never has to
            # fetch more than one document.
            size = path.stat().st_size
            if size == 0:
                continue
            if size > MAX_CHUNKED_ARTIFACT_BYTES:
                logger.warning(f"{source['label']}: skipping {path} ({size} bytes, over the {MAX_CHUNKED_ARTIFACT_BYTES}-byte sanity cap)")
                continue
            try:
                data = path.read_bytes()
            except OSError as exc:
                logger.warning(f"{source['label']}: skipping unreadable {path}: {exc}")
                continue
            job = path.name[: -len(source["id_suffix"])]
            kind = source["artifact_kind"]
            total_chunks = (len(data) + CHUNK_BYTES - 1) // CHUNK_BYTES
            now = datetime.now(timezone.utc).isoformat()
            for index in range(total_chunks):
                chunk = data[index * CHUNK_BYTES: (index + 1) * CHUNK_BYTES]
                action = {
                    "_op_type": "index",
                    "_index": source["index"],
                    "_id": f"{job}:{kind}:{index}",
                    "_source": {
                        "job": job,
                        "kind": kind,
                        "filename": path.name,
                        "content_type": source["content_type"],
                        "chunk_index": index,
                        "total_chunks": total_chunks,
                        "size_bytes": len(data),
                        "imported_at": now,
                        "data_base64": base64.b64encode(chunk).decode("ascii"),
                    },
                }
                # Every chunk shares this file's (key, mtime) -- run_pass's
                # own state-advancement logic only marks `key` imported once
                # NONE of its actions failed, so a partial write (chunk 3 of
                # 8 fails, the rest succeed) still gets retried next pass
                # instead of silently leaving a hole a stale mtime would
                # never revisit.
                pending.append((key, mtime, action))
            continue

        if binary:
            size = path.stat().st_size
            if size > MAX_TTYLOG_BYTES:
                logger.warning(f"{source['label']}: skipping {path} ({size} bytes, over the {MAX_TTYLOG_BYTES}-byte cap)")
                continue
            try:
                raw = path.read_bytes()
            except OSError as exc:
                logger.warning(f"{source['label']}: skipping unreadable {path}: {exc}")
                continue
            if "id_suffix" in source:
                # #638/#763: Ghidra report/callgraph artifacts. The sha256 is
                # the filename with its known suffix stripped (build_report()/
                # ghidra-worker.py's own naming convention), and doc _id is
                # "sha256:kind" so the two artifact kinds for one sample share
                # this index without colliding.
                sha256 = path.name[: -len(source["id_suffix"])]
                artifact_doc_id = f"{sha256}:{source['artifact_kind']}"
                action = {
                    "_op_type": "index",
                    "_index": source["index"],
                    "_id": artifact_doc_id,
                    "_source": {
                        "sha256": sha256,
                        "kind": source["artifact_kind"],
                        "filename": path.name,
                        "content_type": source["content_type"],
                        "size_bytes": len(raw),
                        "imported_at": datetime.now(timezone.utc).isoformat(),
                        "data_base64": base64.b64encode(raw).decode("ascii"),
                    },
                }
            else:
                # cowrie_ttylog's original shape -- the filename IS the
                # content hash already (cowrie renames on session close),
                # so it alone is a stable, globally-unique document id.
                action = {
                    "_op_type": "index",
                    "_index": source["index"],
                    "_id": path.name,
                    "_source": {
                        "shasum": path.name,
                        "size_bytes": len(raw),
                        "imported_at": datetime.now(timezone.utc).isoformat(),
                        "ttylog_base64": base64.b64encode(raw).decode("ascii"),
                    },
                }
            pending.append((key, mtime, action))
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


def advance_state_after_bulk(pending: list, failed_ids: set, state: dict) -> None:
    """Given `pending` (key, mtime, action) triples and the doc _ids
    bulk() reported as failed, advance state[key] only for keys whose
    EVERY action succeeded.

    #638/#764: a chunked artifact's pending entries all share one key
    (see scan_source's own comment on this) -- advancing state[key] the
    moment *any* one action for it succeeds, the way a naive per-tuple
    loop would, risks marking the whole file "imported" while an earlier
    chunk in the same batch actually failed (its mtime would then never
    trigger a retry again, silently and permanently orphaning that
    chunk). Pulled out of run_pass() so this correctness-critical logic
    is directly unit-testable without a real Elasticsearch connection.
    """
    failed_keys = {key for key, _, action in pending if action["_id"] in failed_ids}
    for key, mtime, action in pending:
        if key not in failed_keys:
            state[key] = mtime


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
        advance_state_after_bulk(pending, failed_ids, state)
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
