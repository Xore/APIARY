#!/usr/bin/env python3
"""Tier B evidence: real Ghidra output over the #159 corpus, cached (issue #1805).

Tier A feeds models `objdump -d --source` disassembly recorded in the corpus
manifest. Production Rev·Deck reads Ghidra's decompiled pseudocode -- messy C
with recovered types, `uchar *`, `local_18`, `FUN_00401234` -- which is a
different reasoning task. This module produces that second representation for
the same binaries so the two can be compared with the question set and the
rubric held fixed.

It drives the **existing** headless service in analysis/ghidra/service/ -- the
same container and the same post-scripts production uses. A second Ghidra
integration written for the benchmark would measure a path nobody runs.

Ghidra runs **once per binary, ever**, not once per model. 700 builds at ~18 s
is a one-time cost of a few hours; repeating it per candidate would make a
multi-model round unaffordable, and would let decompiler variance show up as
model variance. Every model must see byte-identical evidence for a given case.

The cache key is (binary sha256, Ghidra version, post-script sha256, analysis
options). All four change what the model is shown, so all four are recorded and
reported. Without that, a score change after a Ghidra upgrade is unattributable
-- the #568 stale-assumption failure, one layer down.

## What this deliberately does not do

**Ghidra-triage Tier B.** That slot's evidence is imports + strings + function
signatures (see `_evidence()` in ghidra-worker.py), and the corpus cannot supply
it: the builds are `-c` object files with no import table, and 10 of the 14 case
sources contain no string literal at all. Measured on the live service, a corpus
object yields 0 imports and 20 strings that are entirely DWARF and section-name
noise. A number derived from that would be a measurement of nothing.

**Linked harness binaries.** #1805 suggested preferring them as Ghidra input.
Measured, they are worse: their imports are toolchain plumbing
(`__libc_start_main`, `__cxa_finalize`, `_ITM_*`), 19 of 20 functions are CRT
scaffolding, and -- decisively -- their strings include the harness's own assert
expressions, e.g. `"rotate_checksum(one, 1) == 0x41"`. Those asserts *are* the
240 executable semantic checks, i.e. the ground truth. Feeding a harness binary
to a model hands it the answer key as evidence.

**Injection coverage.** Since #1948, `process_and_injection.c` carries its
payload as a referenced string literal (`kInjectionNote`, passed through execv
argv), so it survives compilation into `.rodata`; `build_corpus.py` asserts that
needle in every built artifact of the fixture -- unstripped and stripped, every
toolchain, every optimisation level -- and fails the build otherwise. Before
that fix the payload lived only in a C comment -- stripped by the compiler,
absent from all objects, reaching Tier A solely via `objdump --source`
re-reading the `.c` from disk. Survival *in the binary* is still not survival
*in the evidence*: whether the needle reaches a model is proven per cache entry
by `assert_injection_present()` below, and a False there must be reported as
"not covered" rather than a passing gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

BENCHMARKS_DIR = Path(__file__).resolve().parent
CORPUS_DIR = BENCHMARKS_DIR / "corpus"

DEFAULT_SERVICE = "http://127.0.0.1:9090"
DEFAULT_CACHE = Path.home() / "ghidra-tier-b-cache"

# Analysis options are whatever the production service applies; it exposes no
# knob, so the identity of the service image is the option set. Recorded as a
# literal so a future change to the service must change this string too.
ANALYSIS_OPTIONS = "service-default:analyzeHeadless+export_json.py"

POLL_SECONDS = 3
POLL_ATTEMPTS = 200


class GhidraCacheError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _request(url: str, *, body: bytes | None = None, content_type: str | None = None,
             method: str | None = None, timeout: int = 120) -> Any:
    req = urllib.request.Request(url, data=body, method=method or ("POST" if body else "GET"))
    if content_type:
        req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise GhidraCacheError(f"{url} -> HTTP {exc.code}: {exc.read()[:200]!r}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise GhidraCacheError(f"{url} -> {exc}") from exc
    if not raw:
        return None
    return json.loads(raw)


def service_version(base: str) -> str:
    """Ghidra's own version, for the cache key.

    Read from the running service rather than configured here: the point of the
    key is to notice when the thing that produced the evidence changed.
    """
    caps = _request(f"{base}/v1/capabilities", timeout=30) or {}
    version = caps.get("ghidra_version") or caps.get("version")
    if version:
        return str(version)
    # The current service does not publish its version through the API. Fall
    # back to the env override so the key is never silently blank -- an empty
    # component would make two different Ghidras look like one.
    version = os.environ.get("GHIDRA_VERSION")
    if not version:
        raise GhidraCacheError(
            "service does not report a Ghidra version and GHIDRA_VERSION is unset; "
            "refusing to build a cache whose key cannot identify the decompiler"
        )
    return version


def post_script_sha256() -> str:
    """Hash the post-scripts that shape the exported JSON."""
    parts = []
    for name in ("service/export_json.py", "scripts/export_imports.py"):
        path = BENCHMARKS_DIR.parent / name
        parts.append(sha256_path(path) if path.exists() else f"missing:{name}")
    return sha256_bytes("|".join(parts).encode())


def cache_key(binary_sha256: str, ghidra_version: str, scripts_sha256: str,
              options: str = ANALYSIS_OPTIONS) -> str:
    return sha256_bytes("|".join([binary_sha256, ghidra_version, scripts_sha256, options]).encode())


def _multipart(path: Path) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    ctype = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    body = b"".join([
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'.encode(),
        f"Content-Type: {ctype}\r\n\r\n".encode(),
        path.read_bytes(),
        f"\r\n--{boundary}--\r\n".encode(),
    ])
    return body, f"multipart/form-data; boundary={boundary}"


def analyze(base: str, path: Path) -> str:
    body, content_type = _multipart(path)
    response = _request(f"{base}/analyze", body=body, content_type=content_type, timeout=300)
    job_id = (response or {}).get("job_id")
    if not job_id:
        raise GhidraCacheError(f"no job_id for {path.name}: {response!r}")
    return job_id


def wait(base: str, job_id: str) -> dict[str, Any]:
    for _ in range(POLL_ATTEMPTS):
        status = _request(f"{base}/status/{job_id}", timeout=60) or {}
        state = status.get("status")
        if state == "done":
            return status
        if state in {"failed", "error"}:
            raise GhidraCacheError(f"job {job_id} failed: {status}")
        time.sleep(POLL_SECONDS)
    raise GhidraCacheError(f"job {job_id} did not finish in {POLL_ATTEMPTS * POLL_SECONDS}s")


def extract(base: str, job_id: str) -> dict[str, Any]:
    """Pull everything a tier might need, once, while the job's artifacts exist.

    Decompilation failures are recorded, not raised: a case Ghidra cannot handle
    is a coverage outcome, and a model that says the evidence does not support a
    conclusion on unusable input is behaving correctly.
    """
    functions_raw = _request(f"{base}/results/{job_id}/functions?limit=1000", timeout=120) or {}
    functions = functions_raw.get("functions", []) if isinstance(functions_raw, dict) else functions_raw
    strings_raw = _request(f"{base}/results/{job_id}/strings", timeout=120) or {}
    imports_raw = _request(f"{base}/results/{job_id}/imports", timeout=120)
    imports = imports_raw if isinstance(imports_raw, list) else (imports_raw or {}).get("imports", [])

    decompiled = {}
    failures = []
    for function in functions:
        addr = function.get("addr") or function.get("address")
        if not addr:
            continue
        try:
            result = _request(f"{base}/v1/results/{job_id}/function/{addr}/decompile", timeout=120)
        except GhidraCacheError as exc:
            failures.append({"addr": addr, "error": str(exc)})
            continue
        if result and result.get("pseudocode"):
            decompiled[addr] = {
                "pseudocode": result["pseudocode"],
                "signature": result.get("signature"),
            }
        else:
            failures.append({"addr": addr, "error": "empty pseudocode"})

    return {
        "functions": functions,
        "strings": strings_raw.get("strings", []) if isinstance(strings_raw, dict) else strings_raw,
        "imports": imports,
        "decompiled": decompiled,
        "decompile_failures": failures,
    }


def assert_injection_present(entry: dict[str, Any], needle: str) -> bool:
    """True only if `needle` really reached the model's evidence.

    The injection gate is worth nothing unless the payload survives the
    round-trip into Ghidra's output. Callers must record the False case as
    'not covered' rather than letting the forbidden-term check find nothing and
    report a unanimous pass. Since #1948 the payload is a referenced string
    literal asserted present in every built object by `build_corpus.py`, but
    that proves only binary-level survival; this check is what proves
    evidence-level reach. Historically (pre-#1948) it returned False for every
    build because the payload was a source comment.
    """
    haystack = json.dumps(entry.get("evidence", entry), separators=(",", ":"))
    return needle.lower() in haystack.lower()


def build(corpus_dir: Path, cache_dir: Path, base: str, toolchain: str | None,
          opt_level: str | None, stripped: bool, limit: int | None) -> dict[str, Any]:
    manifest_path = corpus_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    version = service_version(base)
    scripts = post_script_sha256()

    builds = manifest["builds"]
    if toolchain:
        builds = [b for b in builds if b["toolchain"] == toolchain]
    if opt_level:
        builds = [b for b in builds if b["opt_level"] == opt_level]
    if limit:
        builds = builds[:limit]

    variant = "stripped" if stripped else "unstripped"
    cache_dir.mkdir(parents=True, exist_ok=True)
    index: list[dict[str, Any]] = []
    hits = misses = errors = 0

    for build_entry in builds:
        case = Path(build_entry["case_source"]).stem
        record = build_entry[variant]
        binary_sha = record["sha256"]
        key = cache_key(binary_sha, version, scripts)
        target = cache_dir / f"{key}.json"

        row = {
            "case": case,
            "toolchain": build_entry["toolchain"],
            "opt_level": build_entry["opt_level"],
            "variant": variant,
            "binary_sha256": binary_sha,
            "cache_key": key,
            "path": str(target),
        }

        if target.exists():
            hits += 1
            row["state"] = "cached"
            index.append(row)
            continue

        binary = corpus_dir / record["path"]
        if not binary.exists():
            errors += 1
            row["state"] = "missing-binary"
            row["error"] = (
                f"{binary} not found -- the corpus binaries are not committed; "
                "rebuild them with corpus/ci_verify.sh, which also proves the "
                "rebuild reproduces manifest.json byte-for-byte"
            )
            index.append(row)
            print(f"  MISSING {case} {build_entry['toolchain']} {build_entry['opt_level']}", flush=True)
            continue

        actual = sha256_path(binary)
        if actual != binary_sha:
            errors += 1
            row["state"] = "hash-mismatch"
            row["error"] = f"on disk {actual}, manifest {binary_sha}"
            index.append(row)
            print(f"  MISMATCH {case}: {actual} != {binary_sha}", flush=True)
            continue

        started = time.monotonic()
        try:
            job_id = analyze(base, binary)
            wait(base, job_id)
            evidence = extract(base, job_id)
        except GhidraCacheError as exc:
            errors += 1
            row["state"] = "error"
            row["error"] = str(exc)
            index.append(row)
            print(f"  ERROR {case}: {exc}", flush=True)
            continue

        entry = {
            "cache_key": key,
            "binary_sha256": binary_sha,
            "ghidra_version": version,
            "post_scripts_sha256": scripts,
            "analysis_options": ANALYSIS_OPTIONS,
            "case": case,
            "toolchain": build_entry["toolchain"],
            "opt_level": build_entry["opt_level"],
            "variant": variant,
            "source": build_entry["case_source"],
            "extracted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "wall_seconds": round(time.monotonic() - started, 1),
            "evidence": evidence,
        }
        target.write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        misses += 1
        row["state"] = "extracted"
        row["functions"] = len(evidence["functions"])
        row["decompiled"] = len(evidence["decompiled"])
        row["decompile_failures"] = len(evidence["decompile_failures"])
        index.append(row)
        print(f"  {case:26s} {build_entry['toolchain']:14s} {build_entry['opt_level']:4s} "
              f"fn={len(evidence['functions'])} decompiled={len(evidence['decompiled'])} "
              f"{entry['wall_seconds']}s", flush=True)

    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "service": base,
        "ghidra_version": version,
        "post_scripts_sha256": scripts,
        "analysis_options": ANALYSIS_OPTIONS,
        "corpus_manifest_sha256": sha256_path(manifest_path),
        "variant": variant,
        "counts": {"cached": hits, "extracted": misses, "errors": errors, "total": len(builds)},
        "entries": index,
    }
    (cache_dir / "index.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n",
                                          encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=CORPUS_DIR,
                        help="directory holding the rebuilt corpus binaries and manifest.json")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--service", default=DEFAULT_SERVICE)
    parser.add_argument("--toolchain", default="gcc-x86_64",
                        help="restrict to one toolchain; the Tier A baseline used gcc-x86_64")
    parser.add_argument("--opt-level", default="-O0",
                        help="restrict to one optimisation level; Tier A used -O0")
    parser.add_argument("--stripped", action="store_true",
                        help="extract the stripped variant instead of the unstripped one")
    parser.add_argument("--limit", type=int, help="stop after N builds (smoke tests)")
    parser.add_argument("--all", action="store_true",
                        help="every toolchain and optimisation level (700 builds, hours)")
    args = parser.parse_args()

    toolchain = None if args.all else args.toolchain
    opt_level = None if args.all else args.opt_level

    summary = build(args.corpus, args.cache, args.service.rstrip("/"),
                    toolchain, opt_level, args.stripped, args.limit)
    counts = summary["counts"]
    print(f"\nghidra {summary['ghidra_version']}  key includes scripts "
          f"{summary['post_scripts_sha256'][:12]}  options {summary['analysis_options']}")
    print(f"{counts['extracted']} extracted, {counts['cached']} already cached, "
          f"{counts['errors']} errors, {counts['total']} builds considered")
    print(f"index: {args.cache / 'index.json'}")
    return 1 if counts["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
