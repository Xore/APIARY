#!/usr/bin/env python3
"""Static-tools sidecar: fuzzy hashing (ssdeep/tlsh) and structural parsing (lief).

Loopback-only HTTP service alongside the Ghidra REST container and Ollama in
docker-compose.ghidra.yml, for the same reason those two are containers
instead of host pip installs: analysis/ghidra/worker/ghidra-worker.py is a
host-side script that runs stdlib-only on purpose (see its own module
docstring), and ssdeep/tlsh/lief are compiled/C-extension dependencies that
would break that guarantee -- and that a bare `pip install` would leave one
version drift away from breaking after the next OS upgrade, same risk the
worker's docstring names. Bundling them in an isolated container instead
keeps the host script dependency-free and keeps "run a third-party parser
against attacker-supplied bytes" contained the same way Ghidra's own parsing
already is: loopback-only, no-new-privileges, nothing else reachable from it.

Endpoints. All POST bodies are the raw sample bytes, not multipart -- this
service has exactly one caller (the worker), so there is no reason to speak
the third-party multipart contract GhidraClient has to for the real Ghidra
REST service:

    GET  /v1/health       -> {"status": "ok"}
    POST /v1/fuzzy-hash    body: raw bytes
                            -> {"ssdeep": str|null, "ssdeep_error": str|null,
                                "tlsh": str|null, "tlsh_error": str|null}
    POST /v1/lief-parse    body: raw bytes
                            -> structural metadata (200), or
                               {"error": "..."} (422) if lief did not
                               recognise the format
"""
from __future__ import annotations

import json
import logging
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import lief
import ssdeep
import tlsh

# lief logs "Failed to open ..." itself on unparseable input via its own
# logger, which by default writes to stderr with no way to distinguish it
# from a real problem in this service. Every sample this pipeline queues has
# already round-tripped through Ghidra, so a lief parse failure is expected
# and unremarkable often enough that it should not look like this service is
# breaking.
lief.logging.set_level(lief.logging.LEVEL.CRITICAL)

MAX_BODY = 512 * 1024 * 1024  # 512 MiB -- far bigger than anything this
# pipeline handles; the point is a bound, not a realistic ceiling, so a bad
# or hostile Content-Length cannot be used to make this service allocate an
# unbounded read.
MAX_SECTIONS = 200  # capped so one adversarial section table cannot inflate
# the result JSON the dashboard has to render -- same reasoning as
# ghidra-worker.py's MAX_FUNCTIONS.
MAX_LIBRARIES = 500


def fuzzy_hash(data: bytes) -> dict:
    out = {"ssdeep": None, "ssdeep_error": None, "tlsh": None, "tlsh_error": None}
    try:
        out["ssdeep"] = ssdeep.hash(data)
    except Exception as e:  # noqa: BLE001 -- report, never crash the request
        out["ssdeep_error"] = str(e)
    try:
        h = tlsh.hash(data)
        # py-tlsh does not raise on input that is too small or too uniform to
        # build the digest's quartile buckets from (fewer than 50 bytes, or
        # not enough byte-value variation) -- it returns the literal string
        # "TNULL". Passing that through as if it were a hash would make two
        # unrelated tiny files look identical to family clustering. Treating
        # it as "no hash" instead matches every other place in this pipeline
        # that would rather say nothing than something meaningless (see
        # normalise_risk in worker/ghidra-worker.py).
        out["tlsh"] = None if not h or h == "TNULL" else h
        if out["tlsh"] is None:
            out["tlsh_error"] = "input too small or too uniform to hash (TNULL)"
    except Exception as e:  # noqa: BLE001
        out["tlsh_error"] = str(e)
    return out


def _section_entropy(section) -> float | None:
    try:
        return round(float(section.entropy), 3)
    except Exception:  # noqa: BLE001 -- some section kinds have no content
        return None


def _elf_extra(b: "lief.ELF.Binary") -> dict:
    return {
        "libraries": sorted(set(b.libraries))[:MAX_LIBRARIES],
        # No static symbol table is the ordinary stripped-binary signal for
        # ELF; dynamic_symbols (imports/exports via the PLT/GOT) survive
        # stripping and are not evidence either way.
        "stripped": len(list(b.symtab_symbols)) == 0,
    }


def _pe_extra(b: "lief.PE.Binary") -> dict:
    out = {}
    try:
        libs = sorted({imp.name for imp in b.imports if imp.name})
        out["libraries"] = libs[:MAX_LIBRARIES]
    except Exception:  # noqa: BLE001
        pass
    try:
        # Declared, not verified: a malware author can set this to anything,
        # including a plausible-looking date to blend in. Reported as-is,
        # like everything else here -- the page this feeds already treats
        # every static-analysis field as evidence to read, not a verdict.
        out["compile_timestamp"] = int(b.header.time_date_stamps)
    except Exception:  # noqa: BLE001
        pass
    try:
        out["is_dll"] = bool(b.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL))
    except Exception:  # noqa: BLE001
        pass
    try:
        out["stripped"] = len(list(b.debug)) == 0
    except Exception:  # noqa: BLE001
        pass
    return out


def _macho_extra(b: "lief.MachO.Binary") -> dict:
    try:
        return {"libraries": sorted(set(b.libraries))[:MAX_LIBRARIES]}
    except Exception:  # noqa: BLE001
        return {}


_FORMAT_EXTRA = {"ELF": _elf_extra, "PE": _pe_extra, "MACHO": _macho_extra}


def lief_parse(data: bytes) -> dict | None:
    """Structural metadata for one sample, or None if lief did not recognise it.

    lief.parse() does not raise on unparseable input -- it logs a warning
    through its own logger (suppressed above) and returns None. A caller that
    only wraps this in try/except would silently treat "not a binary lief
    understands" as "no data", the same class of miss the worker's own header
    comment records for a socket recv() that returns b"" instead of raising.
    Checked explicitly instead.
    """
    binary = lief.parse(data)
    if binary is None:
        return None

    out = {
        "format": binary.format.name,
        "entrypoint": hex(binary.entrypoint),
        "sections": [],
    }
    try:
        out["architecture"] = binary.header.machine_type.name
    except Exception:  # noqa: BLE001
        pass
    try:
        out["is_pie"] = bool(binary.is_pie)
    except Exception:  # noqa: BLE001
        pass

    sections = list(binary.sections)
    out["section_count"] = len(sections)
    out["sections_truncated"] = len(sections) > MAX_SECTIONS
    for section in sections[:MAX_SECTIONS]:
        out["sections"].append({
            "name": section.name,
            "size": int(section.size),
            "entropy": _section_entropy(section),
        })

    extra = _FORMAT_EXTRA.get(out["format"])
    if extra:
        try:
            out.update(extra(binary))
        except Exception:  # noqa: BLE001
            pass
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "honeypot-statictools/1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        logging.info("%s - %s", self.address_string(), fmt % args)

    def _json(self, obj: dict, status: int = 200) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json({"error": "invalid Content-Length"}, 400)
            return None
        if length <= 0:
            self._json({"error": "empty body"}, 400)
            return None
        if length > MAX_BODY:
            self._json({"error": f"body exceeds {MAX_BODY} bytes"}, 413)
            return None
        return self.rfile.read(length)

    def do_GET(self) -> None:
        if self.path == "/v1/health":
            return self._json({"status": "ok"})
        self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        if self.path == "/v1/fuzzy-hash":
            data = self._read_body()
            if data is None:
                return
            return self._json(fuzzy_hash(data))
        if self.path == "/v1/lief-parse":
            data = self._read_body()
            if data is None:
                return
            parsed = lief_parse(data)
            if parsed is None:
                return self._json(
                    {"error": "lief did not recognise this file's format"}, 422)
            return self._json(parsed)
        self._json({"error": "not found"}, 404)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    port = 9091
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    logging.info("statictools listening on :%d", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
