#!/usr/bin/env python3
"""Regression test for #2111: the sandbox artifact download endpoint used
to reassemble sandbox-export-artifacts-v1 chunks by concatenating whatever
an ES query returned, with no comparison against the per-chunk
total_chunks stamp and no contiguous chunk_index check. A partially
indexed artifact -- reachable while #764's per-file retry loop keeps
failing, e.g. via #2109's oversized-bulk loop -- was served as a 200 OK
with the correct filename/content type and a silently truncated body.

The fix landed as commit 3928943b ("fix(dashboard): artifact download
validates the chunk set before serving", PR #2144) *before* this issue's
own dispatch: #2144 is a duplicate report of the same bug, and its
squash-merge trailer referenced only its own PR number, so GitHub never
auto-closed #2111. The source-level fix, and six Rust unit tests
(including the missing-middle-chunk and missing-tail-chunk shapes the
issue's acceptance criteria call out by name), are already present on
this branch. This test pins the source-level contract in a way that
survives independently of the Rust test suite, so a future refactor that
quietly drops the check fails a plain `pytest` run too.
"""
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
ARTIFACTS_RS = (
    REPO_ROOT
    / "arcane"
    / "home"
    / "honeypot-dashboard"
    / "backend-service"
    / "src"
    / "artifacts.rs"
)


def _read_source():
    return ARTIFACTS_RS.read_text()


def test_artifacts_rs_exists():
    assert ARTIFACTS_RS.is_file(), f"expected {ARTIFACTS_RS} to exist"


def test_validated_chunk_set_reads_total_chunks_and_chunk_index():
    src = _read_source()
    assert "fn validated_chunk_set" in src, "chunk-set validator is missing"
    assert 'source["total_chunks"]' in src, "validator must read total_chunks from each hit"
    assert 'source["chunk_index"]' in src, "validator must read chunk_index from each hit"


def test_download_validates_before_decoding_any_chunk_bytes():
    """validated_chunk_set(...) must run, and be allowed to reject the
    request, before the reassembly loop touches a single chunk's
    data_base64 -- otherwise a partial set can still leak decoded bytes
    ahead of the error."""
    src = _read_source()
    validate_call = src.find("validated_chunk_set(&sources)")
    decode_call = src.find('.decode(source["data_base64"]')
    assert validate_call != -1, "validated_chunk_set(&sources) call not found in download()"
    assert decode_call != -1, "per-chunk data_base64 decode not found in download()"
    assert validate_call < decode_call, (
        "chunk-set validation must happen before any chunk is decoded, "
        "so a partial set never reaches the byte-assembly step"
    )


def test_partial_set_is_rejected_with_an_explicit_error_not_200():
    src = _read_source()
    assert (
        "validated_chunk_set(&sources).map_err(|message| (StatusCode::SERVICE_UNAVAILABLE"
        in src
    ), "a failed chunk-set validation must map to an explicit non-200 error response"


def test_chunk_count_and_contiguous_index_checks_are_present():
    src = _read_source()
    assert "indices.len() as u64 != total" in src, "chunk count vs total_chunks check missing"
    assert (
        "index != position as u64" in src
    ), "contiguous 0..=n-1 chunk_index check missing"


def test_acceptance_criteria_shapes_are_covered_by_rust_unit_tests():
    """The issue's acceptance criteria explicitly call out both a missing
    middle chunk and a missing tail chunk (the shape #764/#2109's retry
    loop actually produces: a prefix lands, the rest never does)."""
    src = _read_source()
    assert "fn a_missing_middle_chunk_is_named_in_the_error" in src
    assert "fn a_missing_tail_chunk_is_rejected_too" in src
    assert "fn a_duplicate_index_cannot_pass_as_a_full_set" in src
    assert "fn chunks_disagreeing_on_total_are_rejected" in src


def test_reassembly_size_is_capped_before_allocating():
    """MAX_ARTIFACT_DOWNLOAD_BYTES bounds the in-memory reassembly buffer
    at 256MiB -- half this service's 512M container limit -- and must be
    checked against the manifest's declared size before the Vec is
    allocated, not after, so an oversized artifact 413s instead of
    OOM-killing the process."""
    src = _read_source()
    assert "MAX_ARTIFACT_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024" in src
    assert "StatusCode::PAYLOAD_TOO_LARGE" in src
    cap_check = src.find("declared_size.unwrap_or(0) > MAX_ARTIFACT_DOWNLOAD_BYTES")
    alloc_call = src.find("Vec::with_capacity(declared_size")
    assert cap_check != -1, "oversized-artifact rejection check not found"
    assert alloc_call != -1, "reassembly buffer allocation not found"
    assert cap_check < alloc_call, "size must be validated before the buffer is allocated"


def test_reassembled_length_is_cross_checked_against_manifest_size():
    """Count/index validation alone cannot catch a stale-tail re-import
    (same filename, fewer chunks than a prior generation left behind), so
    the reassembled byte count must also be compared to the manifest's
    size_bytes after decoding."""
    src = _read_source()
    assert "size != bytes.len() as u64" in src
    assert "StatusCode::BAD_GATEWAY" in src
