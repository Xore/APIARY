import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("extract_iocs.py")
SPEC = importlib.util.spec_from_file_location("extract_iocs", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


# #482: extract_iocs.py previously only looked at runtime artifacts (Sysmon,
# PowerShell ScriptBlock, FakeNet-NG) -- a static IOC hardcoded in the
# sample but never exercised during this run's observation window produced
# zero IOCs. These tests cover the new static-string extraction pass over
# the sample binary itself, the new UNC/SMB-path pattern, and the
# static-vs-dynamic correlation in extract_all()'s summary.
class ParseSampleBinaryTest(unittest.TestCase):
    def test_finds_ascii_and_utf16_iocs_plus_unc_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.exe"
            data = (
                b"MZ some header junk "
                b"http://evil.example.com/beacon "
                b"198.51.100.7 "
                b"\\\\10.20.30.40\\admin$\\payload.exe "
                + "hidden-utf16.example.net".encode("utf-16-le")
            )
            sample.write_bytes(data)
            iocs = MODULE.parse_sample_binary(sample)

        self.assertEqual(iocs["remote_ips"], ["198.51.100.7"])
        self.assertEqual(iocs["download_urls"], ["http://evil.example.com/beacon"])
        self.assertIn("hidden-utf16.example.net", iocs["dns_domains"])
        self.assertEqual(iocs["unc_paths"], ["\\\\10.20.30.40\\admin$\\payload.exe"])

    def test_excludes_private_ips(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.exe"
            sample.write_bytes(b"connect to 10.0.0.5 and 192.168.1.1 only")
            iocs = MODULE.parse_sample_binary(sample)
        self.assertEqual(iocs["remote_ips"], [])

    def test_missing_sample_returns_empty(self):
        iocs = MODULE.parse_sample_binary(Path("/nonexistent/does-not-exist.exe"))
        self.assertEqual(iocs, {"remote_ips": [], "dns_domains": [], "download_urls": [], "unc_paths": []})


class ExtractAllCorrelationTest(unittest.TestCase):
    def test_static_only_excludes_iocs_also_seen_at_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "deadbeef"
            run_dir.mkdir()
            sample = Path(tmp) / "sample.exe"
            sample.write_bytes(
                b"198.51.100.7 203.0.113.9 evil.example.com backup.example.org"
            )

            # Simulate a dynamic IOC (203.0.113.9) that was actually observed
            # at runtime -- it must NOT show up in static_only_remote_ips,
            # only the one the binary carries but this run never triggered.
            import extract_iocs as ei

            real_parse = ei.parse_sysmon_evtx
            ei.parse_sysmon_evtx = lambda p: {
                "remote_ips": ["203.0.113.9"],
                "dns_domains": ["evil.example.com"],
            }
            try:
                (run_dir / "sysmon.evtx").write_bytes(b"fake")
                result = ei.extract_all(run_dir, sample)
            finally:
                ei.parse_sysmon_evtx = real_parse

            summary = result["summary"]
            written = json.loads((run_dir / "ioc_extracted.json").read_text())

        self.assertIn("203.0.113.9", summary["unique_remote_ips"])
        self.assertIn("198.51.100.7", summary["static_only_remote_ips"])
        self.assertNotIn("203.0.113.9", summary["static_only_remote_ips"])
        self.assertIn("backup.example.org", summary["static_only_dns_domains"])
        self.assertNotIn("evil.example.com", summary["static_only_dns_domains"])
        self.assertEqual(written["summary"], summary)

    def test_extract_all_without_sample_path_still_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "cafefeed"
            run_dir.mkdir()
            result = MODULE.extract_all(run_dir)
        self.assertEqual(result["summary"]["static_only_remote_ips"], [])


if __name__ == "__main__":
    unittest.main()
