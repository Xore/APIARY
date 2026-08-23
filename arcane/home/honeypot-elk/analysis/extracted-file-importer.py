#!/usr/bin/env python3
"""Ship Zeek's wire-extracted files into Elasticsearch (#1738, decision 5).

Zeek writes two halves of the same fact and neither is much use alone: a
files.log row carrying the hashes, mime type and the connection uid, and the
bytes themselves under an opaque per-file name. This joins them and stores
both, so the artefact survives the VPS being wiped or rebuilt -- which
disk-only storage does not.

Deliberately not a Filebeat input. Filebeat ships lines; this has to read a
second file per line, base64 it, and pair the two. That is an importer's job,
and the existing es-results-importer sets the precedent for one.

What this does NOT do, on purpose:

  * decompress, unpack, parse or execute anything. These are attacker-supplied
    binaries; the only operation performed on the bytes is base64.
  * trust the filename from the wire. Zeek names extracted files by its own
    file id, and only that name is ever used to open anything.
  * re-send. A file already in the index is skipped by sha256, so a restart or
    a re-read of the log does not duplicate.
"""

import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from urllib import error, request

ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200")
FILES_LOG_DIR = Path(os.environ.get("ZEEK_LOG_DIR", "/logs/zeek"))
EXTRACT_DIR = Path(os.environ.get("ZEEK_EXTRACT_DIR", "/logs/zeek-extract"))
STATE_PATH = Path(os.environ.get("STATE_PATH", "/state/extracted-files.json"))
INTERVAL = int(os.environ.get("IMPORT_INTERVAL", "60"))

# Must not exceed the extraction policy's own per-file cap, or this would
# happily ship something that policy meant to bound. Kept slightly above it so
# a policy change upward is visible as a skip rather than silent truncation.
MAX_BYTES = int(os.environ.get("MAX_FILE_BYTES", str(16 * 1024 * 1024)))


def log(message: str) -> None:
    print(f"extracted-file-importer: {message}", file=sys.stderr, flush=True)


def load_state() -> set:
    try:
        return set(json.loads(STATE_PATH.read_text())["seen"])
    except Exception:
        return set()


def save_state(seen: set) -> None:
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Bounded: keeping every hash forever would grow without limit, and the
        # index itself is the real duplicate guard. This only avoids re-reading
        # the same files each cycle.
        trimmed = list(seen)[-50000:]
        STATE_PATH.write_text(json.dumps({"seen": trimmed}))
    except OSError as exc:
        log(f"could not persist state: {exc}")


def es_post(path: str, body: bytes, content_type: str = "application/json"):
    req = request.Request(f"{ES_URL}{path}", data=body, method="POST")
    req.add_header("Content-Type", content_type)
    with request.urlopen(req, timeout=30) as response:
        return json.loads(response.read())


def already_indexed(sha256: str) -> bool:
    """The index is the authority, not the state file -- a wiped state file
    must not cause every artefact to be re-sent."""
    query = json.dumps({"query": {"term": {"file.hash.sha256": sha256}}, "size": 0})
    try:
        result = es_post("/extracted-files-v1-*/_search", query.encode())
        return result.get("hits", {}).get("total", {}).get("value", 0) > 0
    except error.HTTPError as exc:
        # A missing index is not an error: nothing has been shipped yet.
        if exc.code == 404:
            return False
        raise


def read_files_log() -> list:
    """Every files.log Zeek has written, including rotated ones -- an artefact
    extracted just before a rotation would otherwise never be paired."""
    records = []
    for path in sorted(FILES_LOG_DIR.glob("files*.log")):
        try:
            with path.open() as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError as exc:
            log(f"could not read {path}: {exc}")
    return records


def find_extracted(record: dict) -> Path | None:
    """Locate the bytes for a files.log row.

    Only Zeek's own identifiers are used to build the path. The filename the
    wire supplied is never touched -- it is attacker-controlled input, and the
    whole point of Zeek's naming is that it is not.
    """
    name = record.get("extracted")
    if name:
        candidate = EXTRACT_DIR / Path(name).name
        if candidate.is_file():
            return candidate
    fuid = record.get("fuid")
    if fuid:
        candidate = EXTRACT_DIR / f"{Path(fuid).name}.bin"
        if candidate.is_file():
            return candidate
    return None


def _first(value):
    """Zeek's older files.log schema used sets for the connection fields; the
    current one uses scalars. Accept either."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def build_document(record: dict, path: Path, raw: bytes) -> dict:
    # Hash the bytes we actually hold rather than trusting the log's value:
    # if they disagree, the file on disk is what got shipped, so it is what
    # should be identified.
    sha256 = hashlib.sha256(raw).hexdigest()
    return {
        "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "event": {"sensor": "zeek", "category": "extracted_file"},
        "file": {
            "hash": {
                "sha256": sha256,
                "md5": record.get("md5"),
                "sha1": record.get("sha1"),
            },
            "size": len(raw),
            "mime_type": record.get("mime_type"),
            "source": record.get("source"),
            "extracted_name": path.name,
            "bytes": base64.b64encode(raw).decode("ascii"),
        },
        # Field names verified against real Zeek 8 JSON output rather than
        # assumed: this schema carries `uid` and `id.orig_h`/`id.resp_h`, not
        # the `conn_uids`/`tx_hosts`/`rx_hosts` of older documentation. The
        # older names are accepted as a fallback so a schema change in either
        # direction degrades to a missing field rather than a wrong one.
        "network": {
            "session_id": record.get("uid") or _first(record.get("conn_uids")),
            "transport": "tcp",
        },
        "source": {
            "ip": record.get("id.orig_h") or _first(record.get("tx_hosts")),
            "port": record.get("id.orig_p"),
        },
        "destination": {
            "ip": record.get("id.resp_h") or _first(record.get("rx_hosts")),
            "port": record.get("id.resp_p"),
        },
    }


def import_once(seen: set) -> int:
    shipped = 0
    for record in read_files_log():
        path = find_extracted(record)
        if path is None:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size == 0 or size > MAX_BYTES:
            if size > MAX_BYTES:
                log(f"skipping {path.name}: {size} bytes exceeds the {MAX_BYTES} cap")
            continue
        try:
            raw = path.read_bytes()
        except OSError as exc:
            log(f"could not read {path}: {exc}")
            continue

        sha256 = hashlib.sha256(raw).hexdigest()
        if sha256 in seen:
            continue
        try:
            if already_indexed(sha256):
                seen.add(sha256)
                continue
            document = build_document(record, path, raw)
            index = "extracted-files-v1-" + time.strftime("%Y.%m.%d", time.gmtime())
            es_post(f"/{index}/_doc", json.dumps(document).encode())
            seen.add(sha256)
            shipped += 1
        except (error.URLError, error.HTTPError, OSError) as exc:
            # Leave it unseen so the next cycle retries rather than losing it.
            log(f"could not ship {path.name}: {exc}")
    return shipped


def main() -> int:
    log(f"watching {EXTRACT_DIR} against {FILES_LOG_DIR}, every {INTERVAL}s")
    seen = load_state()
    while True:
        try:
            shipped = import_once(seen)
            if shipped:
                log(f"shipped {shipped} artefact(s)")
                save_state(seen)
        except Exception as exc:  # keep the loop alive; a bad cycle is not fatal
            log(f"cycle failed: {exc}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
