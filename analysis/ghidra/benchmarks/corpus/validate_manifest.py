"""Structural and safety validation of manifest.json -- the fast, no-
compiler-needed half of #159's "CI verifies provenance, fixture safety,
hashes, and reproducible generation." The other half (does a real rebuild
reproduce this file byte-for-byte, and does the compiled code actually
behave correctly) needs the full cross-compiler toolchain and lives in
ci_verify.sh / verify_semantics.py instead -- this script is meant to run
fast, in ordinary CI, with nothing installed beyond stdlib Python.

Usage: python3 validate_manifest.py
"""
import hashlib
import json
import re
import sys
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent
ALLOWED_SPLITS = {"train", "validation", "test"}
REQUIRED_BUILD_KEYS = {
    "case_source", "split", "toolchain", "arch", "compiler",
    "compiler_version", "target_triple", "opt_level", "compile_command",
    "unstripped", "stripped",
}
REQUIRED_ARTIFACT_KEYS = {"path", "sha256", "size", "disassembly"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Fixture-safety patterns per #159's corpus design rules ("no real malware,
# credentials, or C2 indicators", "small, non-routable, non-weaponized
# fixtures"). Loopback (127.0.0.0/8) and RFC 1918 private ranges are the
# corpus's own documented safe pattern (loopback_connect.c) and are not
# flagged; anything else that looks like a routable IPv4 literal is.
PRIVATE_OR_LOOPBACK_IPV4 = re.compile(
    r"^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)
IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
CREDENTIAL_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id shape
    re.compile(r"\bpassword\s*=\s*[\"'][^\"']{3,}[\"']", re.IGNORECASE),
]


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    global failures
    failures += 1


failures = 0


def check_source_safety() -> None:
    for src in sorted((CORPUS_DIR / "src").glob("*.c")):
        text = src.read_text()
        for m in IPV4_RE.finditer(text):
            ip = m.group(0)
            if not PRIVATE_OR_LOOPBACK_IPV4.match(ip):
                fail(f"{src.name}: contains a non-private/non-loopback IPv4 literal: {ip}")
        for pattern in CREDENTIAL_PATTERNS:
            if pattern.search(text):
                fail(f"{src.name}: matches a credential-like pattern ({pattern.pattern[:40]}...)")


def check_manifest() -> dict:
    manifest_path = CORPUS_DIR / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"manifest.json does not parse: {exc}")
        return {}

    builds = manifest.get("builds", [])
    if not builds:
        fail("manifest.json has no builds")
        return manifest

    sources = {p.name for p in (CORPUS_DIR / "src").glob("*.c")}
    seen_combos = set()
    for i, build in enumerate(builds):
        missing = REQUIRED_BUILD_KEYS - build.keys()
        if missing:
            fail(f"builds[{i}] missing keys: {sorted(missing)}")
            continue

        if build["case_source"] not in sources:
            fail(f"builds[{i}]: case_source {build['case_source']!r} has no matching file in src/")

        if build["split"] not in ALLOWED_SPLITS:
            fail(f"builds[{i}] ({build['case_source']}, {build['toolchain']}, {build['opt_level']}): "
                 f"split {build['split']!r} not in {sorted(ALLOWED_SPLITS)}")

        combo = (build["case_source"], build["toolchain"], build["opt_level"])
        if combo in seen_combos:
            fail(f"duplicate build combo: {combo}")
        seen_combos.add(combo)

        for kind in ("unstripped", "stripped"):
            artifact = build.get(kind, {})
            missing_artifact = REQUIRED_ARTIFACT_KEYS - artifact.keys()
            if missing_artifact:
                fail(f"builds[{i}].{kind} missing keys: {sorted(missing_artifact)}")
                continue
            if not SHA256_RE.match(artifact["sha256"]):
                fail(f"builds[{i}].{kind}: sha256 {artifact['sha256']!r} is not 64 lowercase hex chars")
            if not artifact["disassembly"].strip():
                fail(f"builds[{i}].{kind}: empty disassembly")
            # #2036: objdump's echoed invocation path leaking into a stored
            # disassembly blob means normalize_disassembly() failed to strip
            # it -- turns that drift back into a CI failure instead of a
            # silent build-directory dependency baked into the artifact.
            # Scoped to the first non-empty line only (the exact line
            # normalize_disassembly is responsible for): unstripped builds
            # run objdump with --source, which legitimately interleaves the
            # original C source -- including comment lines starting with
            # "/*" -- deeper in the blob, and those are not a path leak.
            first_line = next(
                (l for l in artifact["disassembly"].splitlines() if l.strip()), "")
            if first_line.startswith("/"):
                fail(f"builds[{i}].{kind}: disassembly's first line starts with '/' "
                     f"(looks like an unnormalized absolute-path objdump header): "
                     f"{first_line[:80]!r}")

    # Every source file must be covered by at least one build -- an orphaned
    # fixture with no build entries would silently never reach the manifest
    # a model or rubric ever sees.
    covered = {b["case_source"] for b in builds}
    orphaned = sources - covered
    if orphaned:
        fail(f"src/*.c files with no manifest.json build entries: {sorted(orphaned)}")

    return manifest


def check_rubric_and_harness_coverage(manifest: dict) -> None:
    rubric_path = CORPUS_DIR / "rev_cases_v2_rubric.json"
    try:
        rubric = json.loads(rubric_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"rev_cases_v2_rubric.json does not parse: {exc}")
        return

    case_stems = {Path(b["case_source"]).stem for b in manifest.get("builds", [])}
    rubric_cases = set(rubric.get("cases", {}).keys())
    missing_rubric = case_stems - rubric_cases
    if missing_rubric:
        fail(f"cases in manifest.json with no rev_cases_v2_rubric.json entry: {sorted(missing_rubric)}")

    harness_dir = CORPUS_DIR / "harness"
    covered_by_harness = {p.stem[: -len("_harness")] for p in harness_dir.glob("*_harness.c")}
    excluded_path = CORPUS_DIR / "verify_semantics.py"
    excluded_text = excluded_path.read_text() if excluded_path.exists() else ""
    unaccounted = [c for c in case_stems if c not in covered_by_harness and c not in excluded_text]
    if unaccounted:
        fail(f"cases with neither a harness nor a recorded EXCLUDED reason in verify_semantics.py: {sorted(unaccounted)}")


def check_scoring_contract() -> None:
    contract_path = CORPUS_DIR / "rev_cases_v2_contract.json"
    rubric_path = CORPUS_DIR / "rev_cases_v2_rubric.json"
    try:
        contract = json.loads(contract_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"rev_cases_v2_contract.json does not parse: {exc}")
        return

    actual_hash = hashlib.sha256(rubric_path.read_bytes()).hexdigest()
    if contract.get("rubric_sha256") != actual_hash:
        fail(f"rev_cases_v2_contract.json's rubric_sha256 ({contract.get('rubric_sha256')!r}) "
             f"does not match the actual current rev_cases_v2_rubric.json ({actual_hash!r}) -- "
             f"the rubric changed without updating the contract that pins it")

    rubric = json.loads(rubric_path.read_text())
    actual_cases = sorted(rubric.get("cases", {}).keys())
    contract_cases = sorted(contract.get("cases", []))
    if actual_cases != contract_cases:
        fail(f"rev_cases_v2_contract.json's case list does not match the rubric's actual cases: "
             f"contract has {contract_cases}, rubric has {actual_cases}")
    if contract.get("case_count") != len(actual_cases):
        fail(f"rev_cases_v2_contract.json's case_count ({contract.get('case_count')}) "
             f"does not match the actual case count ({len(actual_cases)})")


def main() -> int:
    manifest = check_manifest()
    check_source_safety()
    check_scoring_contract()
    if manifest:
        check_rubric_and_harness_coverage(manifest)

    if failures:
        print(f"\n{failures} failure(s)")
        return 1
    build_count = len(manifest.get("builds", []))
    print(f"OK: {build_count} builds, all structural/safety checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
