#!/usr/bin/env python3
"""Tests for store_acl_patch.py (#1789).

Two things are worth pinning. The patch must inject cleanly and repeatedly --
a Docker rebuild runs it again on an already-patched layer only if caching is
cold, but a double-applied patch would corrupt store.py silently. And the
injected helper must actually copy a directory's default ACL onto a hardlink,
which is the whole reason it exists: the bug it fixes was invisible because the
file was there and merely unreadable.

The ACL test executes the injected code against a real directory rather than
asserting on the substituted text, and skips rather than fails where setfacl is
unavailable -- the behaviour is what matters, and a CI box without the acl
package cannot demonstrate it either way.
"""
import ast
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PATCH = Path(__file__).resolve().parent.parent / "store_acl_patch.py"

# The exact shape of dionaea's storehandler around the hardlink.
STORE_STUB = '''import os

logger = None


class storehandler:
    def handle_incident(self, icd):
        p = icd.path
        n = os.path.join(self.download_dir, "abc")
        try:
            os.stat(n)
        except OSError:
            os.link(p, n)
'''


def load_patch(target: Path):
    """Load store_acl_patch with TARGET redirected at `target`."""
    source = PATCH.read_text().replace(
        'Path("/opt/dionaea/lib/dionaea/python/dionaea/store.py")', f'Path({str(target)!r})'
    )
    namespace = {"__name__": "store_acl_patch_under_test"}
    exec(compile(source, str(PATCH), "exec"), namespace)
    return namespace


class ApplyPatch(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="store-acl-patch-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.store = self.dir / "store.py"
        self.store.write_text(STORE_STUB)
        self.ns = load_patch(self.store)

    def test_injects_after_the_link_and_stays_valid_python(self):
        self.ns["main"]()
        patched = self.store.read_text()
        ast.parse(patched)
        self.assertIn("_apply_download_dir_acl(n)", patched)
        self.assertIn("def _apply_download_dir_acl", patched)
        # Order matters: the ACL can only be applied to a link that exists.
        self.assertLess(
            patched.index("os.link(p, n)"), patched.index("_apply_download_dir_acl(n)")
        )

    def test_is_idempotent(self):
        self.ns["main"]()
        once = self.store.read_text()
        self.ns["main"]()
        self.assertEqual(once, self.store.read_text())
        self.assertEqual(once.count("def _apply_download_dir_acl"), 1)

    def test_refuses_to_patch_an_unrecognised_store(self):
        # Upstream moving the hardlink must fail the build, not silently skip:
        # a store.py this patch cannot find its anchor in is one whose
        # behaviour it can no longer vouch for.
        self.store.write_text("def unrelated():\n    return 1\n")
        ns = load_patch(self.store)
        with self.assertRaises(SystemExit):
            ns["main"]()


class ApplyAcl(unittest.TestCase):
    """The injected helper, executed for real against a directory ACL."""

    def setUp(self):
        if not shutil.which("setfacl") or not shutil.which("getfacl"):
            self.skipTest("acl tools not installed")
        self.dir = Path(tempfile.mkdtemp(prefix="store-acl-run-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

        store = self.dir / "store.py"
        store.write_text(STORE_STUB)
        ns = load_patch(store)
        ns["main"]()
        patched = {"logger": None}
        exec(compile(store.read_text(), "store.py", "exec"), patched)
        self.apply = patched["_apply_download_dir_acl"]

    def test_copies_the_default_acl_onto_a_hardlink(self):
        binaries = self.dir / "binaries"
        binaries.mkdir()
        # Same shape as the real payload store: one named reader, nothing for
        # group or other.
        rc = subprocess.run(
            ["setfacl", "-d", "-m", f"u:{os.getlogin() if os.getuid() else 'nobody'}:r-x",
             str(binaries)],
            capture_output=True,
        )
        if rc.returncode != 0:
            self.skipTest("cannot set a default ACL on this filesystem")

        # A file created elsewhere, then hardlinked in -- exactly what
        # store.py does, and exactly what loses the default ACL.
        source = self.dir / "tmpfile"
        source.write_bytes(b"MZ")
        source.chmod(0o600)
        linked = binaries / "deadbeef"
        os.link(source, linked)

        before = subprocess.run(["getfacl", "-p", str(linked)],
                                capture_output=True, text=True).stdout
        self.assertNotIn("user:", before.replace("user::", ""),
                         "precondition: a hardlink should carry no named ACL entry")

        self.apply(str(linked))

        after = subprocess.run(["getfacl", "-p", str(linked)],
                               capture_output=True, text=True).stdout
        named = [l for l in after.splitlines()
                 if l.startswith("user:") and not l.startswith("user::")]
        self.assertTrue(named, f"expected a named user entry after the fix, got:\n{after}")

    def test_a_store_without_a_default_acl_is_left_alone(self):
        plain = self.dir / "plain"
        plain.mkdir()
        target = plain / "file"
        target.write_bytes(b"x")
        before = subprocess.run(["getfacl", "-p", str(target)],
                                capture_output=True, text=True).stdout
        self.apply(str(target))
        after = subprocess.run(["getfacl", "-p", str(target)],
                               capture_output=True, text=True).stdout
        self.assertEqual(before, after)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
