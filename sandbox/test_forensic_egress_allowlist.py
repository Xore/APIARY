import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SANDBOX_DIR = Path(__file__).parent
READ_FILE = SANDBOX_DIR / "forensic-egress-allowed-domains-read.txt"
WRITE_FILE = SANDBOX_DIR / "forensic-egress-allowed-domains-write.txt"
SQUID_CONF = SANDBOX_DIR / "forensic-egress-squid.conf"


def _domains(path: Path) -> set[str]:
    return {
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def _bare(domain: str) -> str:
    return domain[1:] if domain.startswith(".") else domain


def _covers(a: str, b: str) -> bool:
    """True if squid's leading-dot ACL for `a` also matches `b` (or vice
    versa): equal domains, or one is a subdomain of the other."""
    bare_a, bare_b = _bare(a), _bare(b)
    return (
        bare_a == bare_b
        or bare_a.endswith("." + bare_b)
        or bare_b.endswith("." + bare_a)
    )


# #3072: the read/write split only means something if the two files are
# actually disjoint and both non-empty -- a domain listed in both classes, or
# an empty write-class file, would silently collapse the split back to the
# single-file behaviour it replaced. Disjointness is by squid ACL coverage,
# not literal string equality: a leading-dot entry matches every subdomain,
# so e.g. `.codeload.github.com` in one file and `.github.com` in the other
# are non-disjoint even though the strings differ.
class AllowlistSplitTest(unittest.TestCase):
    def test_read_and_write_classes_are_disjoint(self):
        read_domains, write_domains = _domains(READ_FILE), _domains(WRITE_FILE)
        overlap = {
            (r, w) for r in read_domains for w in write_domains if _covers(r, w)
        }
        self.assertEqual(overlap, set(), f"domains covered by both classes: {overlap}")

    def test_both_classes_non_empty(self):
        self.assertTrue(_domains(READ_FILE), "read-class allowlist is empty")
        self.assertTrue(_domains(WRITE_FILE), "write-class allowlist is empty")

    def test_squid_conf_parses_without_warnings(self):
        squid = shutil.which("squid")
        if not squid:
            self.skipTest("squid not installed on this host")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "allowed-domains-read.txt").write_text(READ_FILE.read_text())
            (tmp_path / "allowed-domains-write.txt").write_text(WRITE_FILE.read_text())
            conf = SQUID_CONF.read_text().replace("/etc/honeypot-sandbox/", f"{tmp_path}/")
            (tmp_path / "squid.conf").write_text(conf)
            result = subprocess.run(
                [squid, "-k", "parse", "-f", str(tmp_path / "squid.conf")],
                capture_output=True, text=True, timeout=30,
            )
            combined = (result.stdout + result.stderr).lower()
            self.assertNotIn("warning", combined, combined)
            self.assertNotIn("error", combined, combined)
            self.assertNotIn("fatal", combined, combined)


if __name__ == "__main__":
    unittest.main()
