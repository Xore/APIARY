#!/usr/bin/env python3
"""Regression test for #2209: TestServeSkipsLoggingOwnHealthcheck in
arcane/home/honeypot-multipot/multipot/protocols_logging_test.go:197 read
its plain bytes.Buffer while serve()'s emitter wrote it through unbuffered
logger.out, so `go test -race ./...` flagged a data race; `go test ./...`
alone passed because CI's quality.yml runs non-race only.

The fix wraps the capture with a sync.Mutex and routes writes through a
writerFunc adapter (the same pattern handler_panic_test.go:142-146 already
uses) so the read of buf.String() inside the assertion and the writes from
serve()'s goroutine can no longer race. The healthcheck-skip assertion
itself (no "connect" event logged for the container's own healthcheck) is
unchanged -- only the buffer access is guarded.

This test asserts the structural contract that made the race impossible
without depending on the full go toolchain being on the test host: the
buffer is now read under the mutex, and no test code accesses the
bytes.Buffer directly outside the locked section.
"""
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TEST_FILE = (
    REPO_ROOT
    / "arcane/home/honeypot-multipot/multipot/protocols_logging_test.go"
)


def _src() -> str:
    return TEST_FILE.read_text(encoding="utf-8")


def test_test_file_exists():
    assert TEST_FILE.exists(), f"{TEST_FILE} not found"


def test_test_uses_writer_func_for_capture():
    """The race-free pattern uses writerFunc to wrap the writes; the
    pre-fix code passed a bare bytes.Buffer to logger.out. This is the
    structural change that closes the race."""
    src = _src()
    func = re.search(
        r"func\s+TestServeSkipsLoggingOwnHealthcheck\b.*?(?=\nfunc\s+Test|\Z)",
        src,
        re.DOTALL,
    )
    assert func, "TestServeSkipsLoggingOwnHealthcheck function not found"
    body = func.group(0)
    assert "writerFunc" in body, (
        "TestServeSkipsLoggingOwnHealthcheck must route writes through a "
        "writerFunc adapter (the handler_panic_test.go pattern) so the "
        "mutex can wrap every write -- this is the structural change "
        "that closes the data race"
    )


def test_buffer_is_guarded_by_a_mutex():
    """The race was a write/read pair on the same bytes.Buffer without a
    happens-before edge. The fix introduces a sync.Mutex that the
    writerFunc holds for the duration of every Write call."""
    src = _src()
    func = re.search(
        r"func\s+TestServeSkipsLoggingOwnHealthcheck\b.*?(?=\nfunc\s+Test|\Z)",
        src,
        re.DOTALL,
    )
    assert func, "TestServeSkipsLoggingOwnHealthcheck function not found"
    body = func.group(0)
    assert re.search(r"var\s+\w*[Mm]u\s+sync\.Mutex", body), (
        "the test must declare a sync.Mutex to guard concurrent access "
        "to the capture buffer"
    )
    # The mutex must be held across the Write, and across the read of
    # buf.String() inside the assertion.
    assert body.count("mu.Lock()") >= 1, (
        "mu.Lock() must be called (for the writerFunc or the read, or both)"
    )
    assert body.count("mu.Unlock()") >= 1, (
        "mu.Unlock() must be called to release the mutex"
    )


def test_healthcheck_skip_assertion_still_present_and_unchanged():
    """The fix must NOT weaken the original assertion. The structural
    change (writerFunc + mutex) closes the race; the assertion still
    fails the test if a 'connect' event is logged for the container's
    own healthcheck."""
    src = _src()
    func = re.search(
        r"func\s+TestServeSkipsLoggingOwnHealthcheck\b.*?(?=\nfunc\s+Test|\Z)",
        src,
        re.DOTALL,
    )
    assert func is not None, "TestServeSkipsLoggingOwnHealthcheck function not found"
    body = func.group(0)
    assert "decodeEvents" in body, (
        "test must still call decodeEvents on the captured buffer"
    )
    # The original assertion: any 'connect' event means the healthcheck
    # was logged as a sensor interaction -- t.Fatalf.
    assert re.search(
        r"if\s+ev\.Event\s*==\s*[\"']connect[\"']\s*\{[^}]*t\.Fatalf",
        body,
        re.DOTALL,
    ), (
        "the healthcheck-skip assertion (t.Fatalf on a 'connect' event "
        "for the container's own healthcheck) must remain -- the fix "
        "guards the race, it does not weaken the contract"
    )


def test_no_unprotected_buf_access():
    """Guard against the regression coming back: a future edit that
    re-introduces a bare &buf{...} pattern in logger.out, or that
    reads buf.String() without holding the mutex."""
    src = _src()
    func = re.search(
        r"func\s+TestServeSkipsLoggingOwnHealthcheck\b.*?(?=\nfunc\s+Test|\Z)",
        src,
        re.DOTALL,
    )
    body = func.group(0)
    # The pre-fix code passed `&buf` directly to logger.out. That
    # pattern must no longer appear.
    assert not re.search(r"out:\s*&buf\b", body), (
        "logger.out must NOT be a bare &buf -- the pre-fix pattern that "
        "caused the data race because serve() wrote it through an "
        "unbuffered writer while the test read it on the main goroutine"
    )


if __name__ == "__main__":
    sys_exit = __import__("sys").exit
    sys_exit(pytest.main([__file__, "-v"]))
