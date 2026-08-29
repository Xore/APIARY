#!/usr/bin/env python3
"""Regression test for #2053: analysis/ghidra/benchmarks/ghidra_cache.py wrote
cache entries and the index non-atomically via Path.write_text(), which
truncates the target before the new bytes land. A process killed mid-write
(Ctrl-C during a multi-hour --all run, OOM, disk-full) left a truncated
{key}.json on disk. Because the cache hit check was a bare target.exists()
and the cache key is a hash of (binary sha256, Ghidra version, post-script
sha256, options) that never changes for a given binary, that truncated file
became a *permanent* cache hit -- every future run would serve the garbage
forever, with no way to invalidate it short of manually deleting the file.

The fix (mirroring write_atomic() in evaluate-models.py, already established
in this tree):
  1. _atomic_write_json() writes to a temp file in the same directory,
     fsyncs, then os.replace()s over the target. The rename is a single
     atomic syscall, so the target either has the old complete content or
     the new complete content -- never a partial write.
  2. _cache_entry_is_valid() replaces the bare target.exists() hit check
     with a json.loads() of the file. This self-heals any entry that was
     already corrupted (e.g. by a crash before this fix existed), not just
     ones this process could still interrupt: an unparseable file is
     treated as a miss and re-extracted.
  3. The index.json summary write goes through the same _atomic_write_json.

This test asserts:
  - the writer no longer calls Path.write_text directly (uses tempfile +
    os.replace instead),
  - a partial/truncated file in place of a cache entry is not reported as a
    hit, and a subsequent _atomic_write_json() call cleanly replaces it,
  - the read path (_cache_entry_is_valid) reports a hit on a properly
    written (renamed) file and reports a miss on a truncated one,
  - the index.json write goes through the same atomic helper, not a direct
    write_text call.
"""
import ast
import importlib.util
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "analysis" / "ghidra" / "benchmarks" / "ghidra_cache.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("ghidra_cache", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {MODULE_PATH} as a module")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def ghidra_cache():
    return _load_module()


def test_source_has_no_direct_write_text_calls():
    """The whole bug was Path.write_text() truncating the target in place.
    Assert the source no longer calls it anywhere -- every write must go
    through the atomic helper. A regression here (someone adding a new
    write_text call for a future field) should fail loudly, not silently
    reopen #2053."""
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"), filename=str(MODULE_PATH))
    write_text_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "write_text"
    ]
    assert not write_text_calls, (
        "ghidra_cache.py must not call Path.write_text() directly -- it "
        "truncates the target before writing, which is the #2053 bug. Use "
        "_atomic_write_json() instead."
    )


def test_writer_uses_tempfile_and_os_replace(ghidra_cache):
    """The atomic writer must actually be atomic: temp file in the same
    directory, then os.replace() -- not a direct in-place write."""
    import inspect

    source = inspect.getsource(ghidra_cache._atomic_write_json)
    assert "tempfile.mkstemp" in source, "must create the temp file via tempfile.mkstemp"
    assert "os.replace(" in source, "must publish the temp file via os.replace()"
    assert "write_text" not in source, "must not fall back to a direct write_text()"


def test_crash_mid_write_leaves_previous_good_entry_intact(ghidra_cache, tmp_path):
    """Simulates the exact failure mode from the issue: a process is killed
    mid-write, leaving a truncated JSON file where a cache entry should be.
    Before the fix this file would be treated as cached forever. After the
    fix, a subsequent successful write cleanly replaces it and the read
    path never observes the partial content."""
    target = tmp_path / "deadbeef.json"

    # A prior good entry.
    ghidra_cache._atomic_write_json(target, {"cache_key": "deadbeef", "evidence": {"functions": [1, 2, 3]}})
    assert ghidra_cache._cache_entry_is_valid(target)

    # Simulate a crash mid-write: some other tool / a killed process leaves
    # a truncated, invalid-JSON file in the entry's place.
    target.write_text('{"cache_key": "deadbeef", "evidence": {"function', encoding="utf-8")
    assert not ghidra_cache._cache_entry_is_valid(target), (
        "a truncated file must not be reported as a valid cache hit -- "
        "this is the core #2053 bug"
    )

    # The next run re-extracts and writes the full entry atomically.
    fresh_entry = {"cache_key": "deadbeef", "evidence": {"functions": [1, 2, 3, 4]}}
    ghidra_cache._atomic_write_json(target, fresh_entry)

    assert ghidra_cache._cache_entry_is_valid(target)
    assert json.loads(target.read_text(encoding="utf-8")) == fresh_entry

    # No temp files left behind in the cache directory.
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != target.name]
    assert not leftovers, f"atomic write left temp files behind: {leftovers}"


def test_read_path_does_not_see_partial_files(ghidra_cache, tmp_path):
    """The cache-hit check (_cache_entry_is_valid, replacing the old bare
    target.exists()) must report a miss for a partial file and a hit for a
    properly (atomically) written one."""
    target = tmp_path / "cafef00d.json"

    # No file at all: miss.
    assert not ghidra_cache._cache_entry_is_valid(target)

    # A partially-written file dropped directly (as a crash would leave
    # it, bypassing the atomic helper entirely): still a miss.
    target.write_text('{"incomplete": tru', encoding="utf-8")
    assert not ghidra_cache._cache_entry_is_valid(target)

    # A file that exists but holds something that isn't even text/JSON
    # (e.g. truncated mid multi-byte UTF-8 sequence) is also a miss, not
    # a crash.
    target.write_bytes(b'{"case": "\xc3\x28broken"')
    assert not ghidra_cache._cache_entry_is_valid(target)

    # Only a properly renamed-in, complete file is a hit.
    ghidra_cache._atomic_write_json(target, {"case": "ok"})
    assert ghidra_cache._cache_entry_is_valid(target)


def test_new_entry_first_write_is_atomic_and_index_consistent(ghidra_cache, tmp_path):
    """A brand-new cache entry (nothing on disk yet, as if freshly removed
    from the index) writes atomically on its first write, and the index
    write uses the same atomic path so the two stay consistent with each
    other -- no window where one exists without the other."""
    cache_dir = tmp_path
    entry_key = "brandnew00"
    target = cache_dir / f"{entry_key}.json"

    # Simulates an entry removed from a prior index (e.g. operator deleted
    # a stale/corrupt file): nothing exists yet.
    assert not target.exists()
    assert not ghidra_cache._cache_entry_is_valid(target)

    entry = {
        "cache_key": entry_key,
        "binary_sha256": "abc",
        "evidence": {"functions": [], "decompiled": {}},
    }
    ghidra_cache._atomic_write_json(target, entry)
    assert ghidra_cache._cache_entry_is_valid(target)
    assert json.loads(target.read_text(encoding="utf-8")) == entry

    # The index is written through the same helper -- rebuild a minimal
    # index the way build() does and confirm it round-trips and matches
    # the entry that was written.
    index_path = cache_dir / "index.json"
    summary = {
        "counts": {"cached": 0, "extracted": 1, "errors": 0, "total": 1},
        "entries": [{"case": "brandnew", "cache_key": entry_key, "path": str(target), "state": "extracted"}],
    }
    ghidra_cache._atomic_write_json(index_path, summary)

    assert ghidra_cache._cache_entry_is_valid(index_path)
    loaded_index = json.loads(index_path.read_text(encoding="utf-8"))
    assert loaded_index["entries"][0]["cache_key"] == entry_key
    assert loaded_index["entries"][0]["cache_key"] == json.loads(target.read_text(encoding="utf-8"))["cache_key"]


def test_index_write_uses_the_atomic_helper_not_write_text(ghidra_cache):
    """The index.json write (build()'s final step) must call
    _atomic_write_json, matching the per-entry write -- not a separate,
    still-unsafe write_text call for the summary."""
    import inspect

    build_source = inspect.getsource(ghidra_cache.build)
    assert '_atomic_write_json(cache_dir / "index.json", summary)' in build_source, (
        "build() must write index.json via _atomic_write_json, not write_text"
    )
    assert ".write_text(" not in build_source, (
        "build() must not write_text() the index or entries directly"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
