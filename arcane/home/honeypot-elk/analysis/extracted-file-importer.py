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


def load_state() -> dict:
    try:
        data = json.loads(STATE_PATH.read_text())
        return {
            "seen": set(data.get("seen", [])),
            # byte offset already consumed per files*.log filename (#2645):
            # without this, every cycle re-reads and re-parses the entire
            # on-disk log history, which only grows over the day.
            "offsets": {k: int(v) for k, v in data.get("offsets", {}).items()},
        }
    except Exception:
        return {"seen": set(), "offsets": {}}


def save_state(state: dict) -> None:
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        # Bounded: keeping every hash forever would grow without limit, and the
        # index itself is the real duplicate guard. This only avoids re-reading
        # the same files each cycle.
        trimmed = list(state["seen"])[-50000:]
        STATE_PATH.write_text(json.dumps({"seen": trimmed, "offsets": state["offsets"]}))
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


def read_files_log(offsets: dict) -> list:
    """New lines from every files.log Zeek has written, including rotated
    ones -- an artefact extracted just before a rotation would otherwise
    never be paired.

    #2645: this used to re-read every byte of every files*.log from scratch
    on every cycle. Rotated logs are never deleted here, so that on-disk
    corpus only grows across the day, and re-parsing all of it into a fresh
    `records` list every INTERVAL seconds meant the transient working set
    -- and with it, resident memory the allocator does not hand back to the
    OS -- grew right along with it, independent of how many records were
    actually new or skipped. Tracking a per-file byte offset bounds each
    cycle's work to only what was appended since the last one.
    """
    records = []
    seen_names = set()
    for path in sorted(FILES_LOG_DIR.glob("files*.log")):
        name = path.name
        seen_names.add(name)
        try:
            size = path.stat().st_size
        except OSError as exc:
            log(f"could not stat {path}: {exc}")
            continue
        start = offsets.get(name, 0)
        if size < start:
            # Rotated or truncated since we last looked: start over.
            start = 0
        if start >= size:
            offsets[name] = start
            continue
        try:
            with path.open("rb") as handle:
                handle.seek(start)
                chunk = handle.read()
        except OSError as exc:
            log(f"could not read {path}: {exc}")
            continue
        # Only advance past complete lines. A trailing partial line means
        # Zeek is mid-write; leave those bytes unconsumed so the next cycle
        # reads the whole record instead of a half one.
        pieces = chunk.split(b"\n")
        if chunk.endswith(b"\n"):
            complete, consumed = pieces[:-1], len(chunk)
        else:
            complete, consumed = pieces[:-1], len(chunk) - len(pieces[-1])
        for raw_line in complete:
            line = raw_line.strip()
            if not line or line.startswith(b"#"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        offsets[name] = start + consumed
    # Drop offsets for files that no longer exist so this dict does not grow
    # without bound as logs get rotated away.
    for stale in set(offsets) - seen_names:
        del offsets[stale]
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


def hash_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """sha256 of a file read in fixed-size windows, so a single artefact --
    including one over MAX_BYTES -- never has to be held whole in memory
    just to identify it."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def build_document(record: dict, path: Path, sha256: str, size: int, raw: bytes | None) -> dict:
    file_doc = {
        "hash": {
            "sha256": sha256,
            "md5": record.get("md5"),
            "sha1": record.get("sha1"),
        },
        "size": size,
        "mime_type": record.get("mime_type"),
        "source": record.get("source"),
        "extracted_name": path.name,
    }
    if raw is None:
        # #2645: over MAX_BYTES. The bytes are deliberately never shipped
        # (that is the whole point of the cap), but the artefact's
        # existence must still be auditable instead of vanishing with no
        # trace -- see the module docstring's "re-send" note for why
        # sha256 is the identity key either way.
        file_doc["oversized"] = True
    else:
        file_doc["bytes"] = base64.b64encode(raw).decode("ascii")
    return {
        "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
        "event": {"sensor": "zeek", "category": "extracted_file"},
        "file": file_doc,
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


def _ship(seen: set, record: dict, path: Path, sha256: str, size: int, raw: bytes | None) -> bool:
    """Index one document (full or metadata-only) unless it is already
    seen or already indexed. Returns whether it was actually shipped."""
    if sha256 in seen:
        return False
    try:
        if already_indexed(sha256):
            seen.add(sha256)
            return False
        document = build_document(record, path, sha256, size, raw)
        index = "extracted-files-v1-" + time.strftime("%Y.%m.%d", time.gmtime())
        es_post(f"/{index}/_doc", json.dumps(document).encode())
        seen.add(sha256)
        return True
    except (error.URLError, error.HTTPError, OSError) as exc:
        # Leave it unseen so the next cycle retries rather than losing it.
        log(f"could not ship {path.name}: {exc}")
        return False


def import_once(state: dict) -> int:
    seen = state["seen"]
    shipped = 0
    for record in read_files_log(state["offsets"]):
        path = find_extracted(record)
        if path is None:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size == 0:
            continue
        if size > MAX_BYTES:
            # #2645: over cap does not mean invisible any more -- the bytes
            # are still never shipped, but a metadata-only record is, so the
            # artefact is auditable instead of vanishing with no trace.
            # Hashed in fixed windows so an oversized file never has to be
            # held whole in memory just to identify it.
            try:
                sha256 = hash_file(path)
            except OSError as exc:
                log(f"could not hash {path}: {exc}")
                continue
            log(f"{path.name}: {size} bytes exceeds the {MAX_BYTES} cap; indexing metadata only")
            if _ship(seen, record, path, sha256, size, None):
                shipped += 1
            continue
        try:
            raw = path.read_bytes()
        except OSError as exc:
            log(f"could not read {path}: {exc}")
            continue

        sha256 = hashlib.sha256(raw).hexdigest()
        if _ship(seen, record, path, sha256, size, raw):
            shipped += 1
    return shipped


def main() -> int:
    log(f"watching {EXTRACT_DIR} against {FILES_LOG_DIR}, every {INTERVAL}s")
    state = load_state()
    while True:
        try:
            shipped = import_once(state)
            if shipped:
                log(f"shipped {shipped} artefact(s)")
        except Exception as exc:  # keep the loop alive; a bad cycle is not fatal
            log(f"cycle failed: {exc}")
        # Always persist: offsets must survive a restart even on a cycle
        # that shipped nothing, or a restart forces a full log re-scan.
        save_state(state)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
