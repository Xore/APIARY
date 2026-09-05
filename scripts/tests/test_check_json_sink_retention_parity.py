#!/usr/bin/env python3
"""Exercise check-json-sink-retention-parity.py's tree_contains() writer
proof against a synthetic fixture, not the real tree -- the real-tree run
(scripts/check-json-sink-retention-parity.py itself) is the audit; this is
what proves the two false-positive paths #2921 found stay closed.

Both scenarios reproduce #2921's own repro steps, against a throwaway git
repo built under tmp_path so `git ls-files` (which tree_contains() now
calls) has something real to answer from:

1. The implementation file is deleted but its own test file, which asserts
   on the same token verbatim, is not -- a test is evidence the
   implementation was ONCE correct, never evidence it is PRESENT.
2. The implementation file is deleted (and its test file, to isolate this
   case) but a stale __pycache__/*.pyc left over from a previous test run
   still carries the token as a bytecode constant -- a build artifact must
   never stand in for tracked source.
3. The same two, in a tree that is not a git checkout at all -- the shape
   tests/docs/test_2216_* and test_2826_* run the script out of, and the
   shape an exported tarball has. `git ls-files` cannot answer there, and
   an unanswerable question is not a finding: the proof falls back to
   reading the tree, with both false-positive paths still closed.

Usage: scripts/tests/test_check_json_sink_retention_parity.py
"""
import importlib.util
import py_compile
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "check-json-sink-retention-parity.py"
spec = importlib.util.spec_from_file_location("check_json_sink_retention_parity", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

fails = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        fails.append(label)


def _git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def _fresh_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git("init", "-q", cwd=repo)
    _git("config", "user.email", "test@example.invalid", cwd=repo)
    _git("config", "user.name", "test", cwd=repo)
    return repo


def _commit_all(repo: Path):
    _git("add", "-A", cwd=repo)
    _git("commit", "-q", "-m", "fixture", cwd=repo)


def test_test_file_alone_does_not_satisfy_the_proof(tmp_path):
    repo = _fresh_repo(tmp_path)
    impl_dir = repo / "widget"
    (impl_dir / "tests").mkdir(parents=True)
    (impl_dir / "widget.py").write_text("WIDGET_MAX_BYTES = 1024\n")
    (impl_dir / "tests" / "test_widget.py").write_text(
        "from widget import WIDGET_MAX_BYTES\nassert WIDGET_MAX_BYTES == 1024\n"
    )
    _commit_all(repo)

    orig_root = mod.ROOT
    mod.ROOT = repo
    mod._tracked_cache = None
    try:
        check(
            mod.tree_contains("widget", "WIDGET_MAX_BYTES") is True,
            "proof holds while the implementation still exists",
        )

        (impl_dir / "widget.py").unlink()
        _git("add", "-A", cwd=repo)
        _git("commit", "-q", "-m", "delete implementation, keep test", cwd=repo)
        mod._tracked_cache = None

        check(
            mod.tree_contains("widget", "WIDGET_MAX_BYTES") is False,
            "#2921: deleting the implementation but keeping its own test "
            "file must NOT satisfy the writer proof",
        )
    finally:
        mod.ROOT = orig_root
        mod._tracked_cache = None


def test_stale_pyc_does_not_satisfy_the_proof(tmp_path):
    repo = _fresh_repo(tmp_path)
    impl_dir = repo / "widget"
    impl_dir.mkdir()
    (impl_dir / "widget.py").write_text("WIDGET_MAX_BYTES = 1024\n")
    _commit_all(repo)

    orig_root = mod.ROOT
    mod.ROOT = repo
    mod._tracked_cache = None
    try:
        check(
            mod.tree_contains("widget", "WIDGET_MAX_BYTES") is True,
            "proof holds while the implementation still exists (pyc scenario setup)",
        )

        # Compile a .pyc carrying the token as a bytecode constant, the way
        # running the real module's tests would leave one behind -- then
        # delete the source it was compiled from, without ever `git add`ing
        # the __pycache__ directory (matching a real .gitignore).
        pycache = impl_dir / "__pycache__"
        pycache.mkdir()
        py_compile.compile(
            str(impl_dir / "widget.py"),
            cfile=str(pycache / "widget.cpython-311.pyc"),
        )
        (impl_dir / "widget.py").unlink()
        _git("add", "-A", cwd=repo)
        _git("commit", "-q", "-m", "delete implementation, leave stale pyc untracked", cwd=repo)
        mod._tracked_cache = None

        check(
            (pycache / "widget.cpython-311.pyc").exists(),
            "sanity: the stale .pyc is actually present on disk",
        )
        check(
            mod.tree_contains("widget", "WIDGET_MAX_BYTES") is False,
            "#2921: a stale untracked __pycache__/*.pyc carrying the token "
            "as a bytecode constant must NOT satisfy the writer proof",
        )
    finally:
        mod.ROOT = orig_root
        mod._tracked_cache = None


def test_a_tree_that_is_not_a_git_checkout_still_checks(tmp_path):
    """ROOT is not always a git checkout, and 128 is not a verdict.

    tests/docs/test_2216_* and test_2826_* run this script out of a
    throwaway root assembled under tmp_path, and an exported tarball has
    the same shape. `git ls-files` fails there, so tree_contains() reads
    the tree directly -- and both #2921 paths must stay closed anyway,
    which they do without git: __pycache__ is in SKIP_DIRS and test paths
    are excluded by path.
    """
    root = tmp_path / "not-a-repo"
    impl_dir = root / "widget"
    (impl_dir / "tests").mkdir(parents=True)
    (impl_dir / "widget.py").write_text("WIDGET_MAX_BYTES = 1024\n")

    orig_root = mod.ROOT
    mod.ROOT = root
    mod._tracked_cache = None
    try:
        check(
            mod._tracked_files() is None,
            "a non-checkout reports tracking as unavailable instead of raising",
        )
        check(
            mod.tree_contains("widget", "WIDGET_MAX_BYTES") is True,
            "the writer proof still holds against real source outside git",
        )

        (impl_dir / "tests" / "test_widget.py").write_text(
            "from widget import WIDGET_MAX_BYTES\nassert WIDGET_MAX_BYTES == 1024\n"
        )
        pycache = impl_dir / "__pycache__"
        pycache.mkdir()
        py_compile.compile(
            str(impl_dir / "widget.py"),
            cfile=str(pycache / "widget.cpython-311.pyc"),
        )
        (impl_dir / "widget.py").unlink()
        mod._tracked_cache = None

        check(
            mod.tree_contains("widget", "WIDGET_MAX_BYTES") is False,
            "#2921: outside git, neither the test file nor the stale .pyc "
            "may satisfy the writer proof either",
        )
    finally:
        mod.ROOT = orig_root
        mod._tracked_cache = None


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        test_test_file_alone_does_not_satisfy_the_proof(Path(tmp))
    with tempfile.TemporaryDirectory() as tmp:
        test_stale_pyc_does_not_satisfy_the_proof(Path(tmp))
    with tempfile.TemporaryDirectory() as tmp:
        test_a_tree_that_is_not_a_git_checkout_still_checks(Path(tmp))
    if fails:
        print(f"\n{len(fails)} check(s) failed: {fails}")
        sys.exit(1)
    print("\nall checks passed")
