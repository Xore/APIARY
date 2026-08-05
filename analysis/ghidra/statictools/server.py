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
    POST /v1/capa          body: raw bytes
                            -> capability summary (200), or
                               {"error": "...", "unsupported": "..."} (422) if
                               capa's default backend cannot handle this
                               sample's architecture/format/OS (#78)
    POST /v1/floss          body: raw bytes
                            -> string summary (200), or
                               {"error": "...", "unsupported": "..."} (422) if
                               floss's decoding/stack-string analysis does not
                               cover this sample's format -- PE and raw
                               shellcode only, confirmed against a real ELF
                               binary (#207)
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile
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


CAPA_RULES_DIR = os.environ.get("CAPA_RULES_DIR", "/app/capa-rules")
# capa's library-function signatures (.sig files) -- separate from the rules
# above, and not passed explicitly before #498 found every capa call failing
# with "Using default signature path, but it doesn't exist": capa's "use
# embedded signatures by default" only holds for its own installed CLI
# distribution, not the flare-capa pip package this image installs. See the
# Dockerfile's CAPA_SIGS_VERSION for where this directory comes from.
CAPA_SIGS_DIR = os.environ.get("CAPA_SIGS_DIR", "/app/capa-sigs")
# capa's own rule matching is the slowest thing this service does -- ssdeep/
# tlsh/lief are all sub-second, capa can run minutes on a large binary. Kept
# comfortably under worker/ghidra-worker.py's STATICTOOLS_TIMEOUT (300s, the
# client's own wait budget) so this process's timeout fires first and returns
# a clean 500 instead of the worker giving up on the connection while capa is
# still running, orphaning the subprocess.
CAPA_TIMEOUT = int(os.environ.get("CAPA_TIMEOUT", "240"))
MAX_CAPABILITIES = 500  # same reasoning as MAX_SECTIONS/MAX_LIBRARIES above.

# capa (v9.4.0) exit codes that mean "capa correctly declined to analyse this
# specific input", not "this service is broken" -- see the E_* constants in
# https://github.com/mandiant/capa/blob/v9.4.0/capa/main.py. 17 (unsupported
# architecture) is the one that matters most here: capa's default (vivisect)
# backend only covers x86/amd64/arm64, so MIPS/ARM32/etc. samples -- common in
# this honeypot's IoT catch -- hit this on every run. That is a real coverage
# gap, tracked in #195, not a bug in this endpoint.
_CAPA_UNSUPPORTED_EXIT_CODES = {
    13: "corrupt or unrecognised file",
    14: "file limitation short-circuited analysis (e.g. packed input)",
    16: "unsupported file format",
    17: "unsupported architecture -- capa's default backend covers only "
        "x86/amd64/arm64",
    18: "unsupported OS",
}


def _capa_summarise(doc: dict) -> dict:
    """Reduce capa's full result document to a report-sized shape.

    capa's raw -j output includes a full match-evidence tree per rule (every
    location a feature matched, nested per basic block/function) -- useful
    for an interactive explorer, far more than a triage report or dashboard
    card needs. This keeps name/namespace/count per capability plus the
    deduplicated ATT&CK/MBC tags, the same "evidence over verdict" shape
    fuzzy_hash()/lief_parse() already give the rest of this pipeline.
    """
    analysis = ((doc.get("meta") or {}).get("analysis")) or {}
    capabilities = []
    attacks, mbcs = {}, {}
    for rule_name, entry in (doc.get("rules") or {}).items():
        meta = entry.get("meta") or {}
        if meta.get("lib") or meta.get("is_subscope_rule"):
            # Helper/subscope rules other rules build on, not capabilities in
            # their own right -- capa's own default (non -v) text rendering
            # excludes these from the top-level view the same way.
            continue
        capabilities.append({
            "name": meta.get("name") or rule_name,
            "namespace": meta.get("namespace") or "",
            "matches": len(entry.get("matches") or []),
        })
        for a in meta.get("attack") or []:
            attacks[a.get("id") or a.get("tactic", "")] = a
        for m in meta.get("mbc") or []:
            mbcs[m.get("id") or m.get("objective", "")] = m

    capabilities.sort(key=lambda c: c["name"])
    truncated = len(capabilities) > MAX_CAPABILITIES
    return {
        "arch": analysis.get("arch") or "",
        "os": analysis.get("os") or "",
        "format": analysis.get("format") or "",
        "capabilities": capabilities[:MAX_CAPABILITIES],
        "capabilities_truncated": truncated,
        "attack": sorted(attacks.values(), key=lambda a: a.get("id", "")),
        "mbc": sorted(mbcs.values(), key=lambda m: m.get("id", "")),
    }


def capa_scan(data: bytes) -> dict:
    """Run capa's default backend against one sample.

    Returns a capability summary (see _capa_summarise), or
    {"unsupported": "..."} when capa declined this specific input --
    routine for an architecture/format/OS its default backend does not cover,
    the same "expected, not exceptional" treatment lief_parse() gives an
    unrecognised format. Raises RuntimeError/ValueError for anything else, so
    the handler can tell a real failure from an expected non-match.
    """
    fd, tmp_path = tempfile.mkstemp(prefix="capa-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        proc = subprocess.run(
            ["capa", "-j", "-q", "-r", CAPA_RULES_DIR, "-s", CAPA_SIGS_DIR, tmp_path],
            capture_output=True, timeout=CAPA_TIMEOUT, text=True,
        )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    reason = _CAPA_UNSUPPORTED_EXIT_CODES.get(proc.returncode)
    if reason is not None:
        return {"unsupported": reason}
    if proc.returncode != 0:
        raise RuntimeError(
            f"capa exited {proc.returncode}: {(proc.stderr or '')[:2000]}")

    return _capa_summarise(json.loads(proc.stdout))


# flare-floss's own timeout budget -- kept comfortably under
# worker/ghidra-worker.py's STATICTOOLS_TIMEOUT (300s, the client's own wait
# budget per request), same reasoning as CAPA_TIMEOUT above: so this
# process's own timeout fires first and returns a clean 500 instead of the
# worker giving up on the connection while floss is still emulating,
# orphaning the subprocess.
FLOSS_TIMEOUT = int(os.environ.get("FLOSS_TIMEOUT", "240"))
MAX_STRINGS_PER_CATEGORY = 200  # same truncation reasoning as MAX_CAPABILITIES.

# floss's own error text when its emulation-based categories (decoded/stack/
# tight strings -- the actual "obfuscated string solver" value floss adds
# beyond plain string extraction) do not cover this sample's format.
# Confirmed directly against a real ELF binary and a separate corrupt/
# garbage file: both hit this identical message, since floss's format
# auto-detection cannot identify a valid PE/shellcode structure in either
# case (#207). Matched on message text, not floss's exit code alone (255,
# floss's one generic "analysis failed" code for this and other fatal
# errors) -- the code alone can't distinguish "declined this format" from
# "crashed for some other reason."
_FLOSS_UNSUPPORTED_MARKER = ("FLOSS currently supports the following formats "
                             "for string decoding and stackstrings")


def _floss_strings(entries: list | None) -> tuple[list[str], int]:
    items = [e.get("string", "") for e in (entries or []) if e.get("string")]
    return items[:MAX_STRINGS_PER_CATEGORY], len(items)


def _floss_summarise(doc: dict) -> dict:
    """Reduce floss's full result document to a report-sized shape.

    floss's raw -j output carries per-string metadata (stack frame offsets,
    decoding-routine addresses, ...) useful for an interactive explorer, far
    more than a triage report or dashboard card needs -- same "evidence over
    verbose metadata" shape _capa_summarise() above already gives.
    """
    strings = doc.get("strings") or {}
    static, static_total = _floss_strings(strings.get("static_strings"))
    stack, stack_total = _floss_strings(strings.get("stack_strings"))
    tight, tight_total = _floss_strings(strings.get("tight_strings"))
    decoded, decoded_total = _floss_strings(strings.get("decoded_strings"))
    return {
        "static_strings": static,
        "static_strings_total": static_total,
        "stack_strings": stack,
        "stack_strings_total": stack_total,
        "tight_strings": tight,
        "tight_strings_total": tight_total,
        "decoded_strings": decoded,
        "decoded_strings_total": decoded_total,
        "truncated": (
            len(static) < static_total or len(stack) < stack_total or
            len(tight) < tight_total or len(decoded) < decoded_total
        ),
    }


def floss_scan(data: bytes) -> dict:
    """Run floss's full default analysis (static, stack, tight, and decoded
    strings) against one sample.

    Returns a string summary (see _floss_summarise), or {"unsupported": "..."}
    when floss declined this input. That fires often on this pipeline's own
    catch: floss's emulation-based categories only cover PE and raw
    shellcode (confirmed directly, see _FLOSS_UNSUPPORTED_MARKER above), and
    this honeypot's catch is predominantly ELF (MIPS/ARM32 IoT malware) --
    a real, distinct signal, not a bug in this endpoint, the same shape as
    capa's own architecture-coverage gap (#195). Deliberately does not retry
    in a static-strings-only mode on the unsupported path: that category
    duplicates what the worker already gets from Ghidra's own
    /results/{job}/strings endpoint, so there is nothing to gain from
    running it, only wasted compute on a large sample. Raises RuntimeError
    for anything else, so the handler can tell a real failure from an
    expected non-match.
    """
    fd, tmp_path = tempfile.mkstemp(prefix="floss-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        proc = subprocess.run(
            ["floss", "-j", tmp_path],
            capture_output=True, timeout=FLOSS_TIMEOUT, text=True,
        )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    if proc.returncode != 0:
        if _FLOSS_UNSUPPORTED_MARKER in (proc.stderr or ""):
            return {"unsupported": "unsupported format for string decoding "
                                    "-- floss's decoding/stack-string "
                                    "analysis covers PE and raw shellcode "
                                    "only"}
        raise RuntimeError(
            f"floss exited {proc.returncode}: {(proc.stderr or '')[:2000]}")

    return _floss_summarise(json.loads(proc.stdout))


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
        if self.path == "/v1/capa":
            data = self._read_body()
            if data is None:
                return
            try:
                result = capa_scan(data)
            except subprocess.TimeoutExpired:
                return self._json({"error": "capa timed out"}, 500)
            except (RuntimeError, OSError, ValueError) as e:
                return self._json({"error": str(e)}, 500)
            if "unsupported" in result:
                return self._json(
                    {"error": "capa cannot analyse this sample",
                     "unsupported": result["unsupported"]}, 422)
            return self._json(result)
        if self.path == "/v1/floss":
            data = self._read_body()
            if data is None:
                return
            try:
                result = floss_scan(data)
            except subprocess.TimeoutExpired:
                return self._json({"error": "floss timed out"}, 500)
            except (RuntimeError, OSError, ValueError) as e:
                return self._json({"error": str(e)}, 500)
            if "unsupported" in result:
                return self._json(
                    {"error": "floss cannot decode strings for this sample",
                     "unsupported": result["unsupported"]}, 422)
            return self._json(result)
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
