import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

EXPORT_PATH = Path(__file__).with_name("export-result.py")
SPEC = importlib.util.spec_from_file_location("export_result", EXPORT_PATH)
EXPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORT)

WINDOWS_PATH = Path(__file__).parent / "windows" / "orchestrate" / "extract_iocs.py"
WSPEC = importlib.util.spec_from_file_location("extract_iocs", WINDOWS_PATH)
WINDOWS = importlib.util.module_from_spec(WSPEC)
WSPEC.loader.exec_module(WINDOWS)


# #1689: export-result.py duplicates extract_iocs.py's five IOC patterns
# rather than importing them, because the Linux exporter and the Windows
# orchestrator ship as separate units. Duplication drifts, and drift here is
# silent -- the dashboard's floss/sandbox cross-referencing joins on the
# literal IOC value, so the moment one pipeline spells a value differently
# from the other the correlation stops matching without anything erroring.
# These tests are what actually holds the two copies together.
class IOCPatternParity(unittest.TestCase):
    CORPUS = [
        "reach 203.0.113.9 on boot",
        "fallback 198.51.100.7:4444",
        "http://evil.example.com/stage2.exe",
        "https://cdn.badguy.net/a?b=1",
        "c2.badguy.net",
        r"\\192.168.1.5\share\payload.exe",
        r"\\fileserver\admin$\x.dll",
        "internal 10.0.0.5 must be ignored",
        "loopback 127.0.0.1 must be ignored",
        "link 172.16.4.4 and 192.168.9.9 ignored",
        "broadcast 255.255.255.255 ignored",
        "0.0.0.0 ignored",
        "no iocs in this line at all",
    ]

    def _windows_scan(self, strings):
        """extract_iocs.py's parse_sample_binary() body, applied to strings
        rather than to a file, so both implementations see identical input."""
        found = {
            "remote_ips": set(),
            "dns_domains": set(),
            "download_urls": set(),
            "unc_paths": set(),
        }
        for value in strings:
            for ip in WINDOWS.RE_IP.findall(value):
                if not WINDOWS.PRIVATE.match(ip):
                    found["remote_ips"].add(ip)
            for url in WINDOWS.RE_URL.findall(value):
                found["download_urls"].add(url)
            for domain in WINDOWS.RE_DOMAIN.findall(value):
                found["dns_domains"].add(domain)
            for unc in WINDOWS.RE_UNC.findall(value):
                found["unc_paths"].add(unc)
        return {key: sorted(value) for key, value in found.items()}

    def test_both_extractors_agree_on_the_same_strings(self):
        self.assertEqual(EXPORT._ioc_scan(self.CORPUS), self._windows_scan(self.CORPUS))

    def test_private_and_reserved_addresses_are_never_iocs(self):
        found = EXPORT._ioc_scan(self.CORPUS)["remote_ips"]
        for ignored in ("10.0.0.5", "127.0.0.1", "172.16.4.4", "192.168.9.9", "0.0.0.0"):
            self.assertNotIn(ignored, found)
        self.assertIn("203.0.113.9", found)
        self.assertIn("198.51.100.7", found)

    def test_patterns_compile_to_the_same_matcher(self):
        for mine, theirs in (
            (EXPORT.RE_IOC_IP, WINDOWS.RE_IP),
            (EXPORT.RE_IOC_URL, WINDOWS.RE_URL),
            (EXPORT.RE_IOC_DOMAIN, WINDOWS.RE_DOMAIN),
            (EXPORT.RE_IOC_UNC, WINDOWS.RE_UNC),
            (EXPORT.RE_IOC_PRIVATE, WINDOWS.PRIVATE),
        ):
            for value in self.CORPUS:
                self.assertEqual(
                    mine.findall(value),
                    theirs.findall(value),
                    f"{mine.pattern!r} and {theirs.pattern!r} disagree on {value!r}",
                )


class DynamicIOCs(unittest.TestCase):
    """zeek's conn.log is the source for what a run actually contacted. The
    isolated runs this sandbox does by default produce only link-local IPv6
    and ARP, which must yield nothing rather than noise."""

    def _run_dir(self, conn=(), dns=(), http=()):
        tmp = Path(tempfile.mkdtemp())
        logs = tmp / "zeek_logs"
        logs.mkdir()
        for name, records in (("conn.log", conn), ("dns.log", dns), ("http.log", http)):
            (logs / name).write_text("".join(json.dumps(r) + "\n" for r in records))
        return tmp

    def test_remote_responder_is_reported(self):
        run = self._run_dir(conn=[{"id.resp_h": "203.0.113.9", "local_resp": False}])
        self.assertEqual(EXPORT.dynamic_iocs(run, [])["remote_ips"], ["203.0.113.9"])

    def test_zeek_local_responder_is_not_an_ioc(self):
        run = self._run_dir(conn=[{"id.resp_h": "203.0.113.9", "local_resp": True}])
        self.assertEqual(EXPORT.dynamic_iocs(run, [])["remote_ips"], [])

    def test_private_responder_is_not_an_ioc(self):
        run = self._run_dir(conn=[{"id.resp_h": "192.168.1.20", "local_resp": False}])
        self.assertEqual(EXPORT.dynamic_iocs(run, [])["remote_ips"], [])

    def test_ipv6_link_local_chatter_yields_nothing(self):
        # What an isolated run actually captures. ff02::16 does not match the
        # IPv4 pattern at all, which is why this is silence and not noise.
        run = self._run_dir(conn=[{"id.resp_h": "ff02::16", "local_resp": False}])
        self.assertEqual(EXPORT.dynamic_iocs(run, [])["remote_ips"], [])

    def test_malformed_zeek_line_is_skipped_not_fatal(self):
        run = self._run_dir()
        (run / "zeek_logs" / "conn.log").write_text(
            "not json\n" + json.dumps({"id.resp_h": "203.0.113.9", "local_resp": False}) + "\n"
        )
        self.assertEqual(EXPORT.dynamic_iocs(run, [])["remote_ips"], ["203.0.113.9"])

    def test_dns_queries_from_tcpdump_count_as_observed(self):
        run = self._run_dir()
        self.assertIn("c2.badguy.net", EXPORT.dynamic_iocs(run, ["c2.badguy.net"])["dns_domains"])

    def test_http_host_becomes_a_url_and_a_domain(self):
        run = self._run_dir(http=[{"host": "evil.example.com", "uri": "/stage2.exe"}])
        found = EXPORT.dynamic_iocs(run, [])
        self.assertIn("http://evil.example.com/stage2.exe", found["download_urls"])
        self.assertIn("evil.example.com", found["dns_domains"])

    def test_missing_zeek_logs_are_not_an_error(self):
        run = Path(tempfile.mkdtemp())
        self.assertEqual(
            EXPORT.dynamic_iocs(run, []),
            {"remote_ips": [], "dns_domains": [], "download_urls": []},
        )


class ConfirmedIOCs(unittest.TestCase):
    """The badge #1689 restores reads confirmed_remote_ips: an address the
    sample carries *and* the run reached. Either side alone is not enough."""

    def _run(self, strings, conn):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "strings-ascii.txt").write_text("\n".join(strings) + "\n")
        (tmp / "strings-utf16le.txt").write_text("")
        logs = tmp / "zeek_logs"
        logs.mkdir()
        (logs / "conn.log").write_text("".join(json.dumps(r) + "\n" for r in conn))
        return tmp

    def test_static_and_observed_is_confirmed(self):
        run = self._run(
            ["callback 203.0.113.9"], [{"id.resp_h": "203.0.113.9", "local_resp": False}]
        )
        iocs = EXPORT.build_iocs(run, [])
        self.assertEqual(iocs["confirmed_remote_ips"], ["203.0.113.9"])
        self.assertEqual(iocs["static_only_remote_ips"], [])

    def test_carried_but_never_reached_is_static_only(self):
        run = self._run(["callback 203.0.113.9"], [])
        iocs = EXPORT.build_iocs(run, [])
        self.assertEqual(iocs["confirmed_remote_ips"], [])
        self.assertEqual(iocs["static_only_remote_ips"], ["203.0.113.9"])

    def test_reached_but_not_carried_is_not_confirmed(self):
        run = self._run(["nothing here"], [{"id.resp_h": "203.0.113.9", "local_resp": False}])
        iocs = EXPORT.build_iocs(run, [])
        self.assertEqual(iocs["confirmed_remote_ips"], [])
        self.assertEqual(iocs["remote_ips"], ["203.0.113.9"])

    def test_isolated_run_of_a_sample_with_iocs_confirms_nothing(self):
        # The default posture: the sample carries a C2 address, the run had no
        # network, so nothing is confirmed and the address is reported as a
        # dormant capability instead.
        run = self._run(["callback 203.0.113.9"], [{"id.resp_h": "ff02::16", "local_resp": False}])
        iocs = EXPORT.build_iocs(run, [])
        self.assertEqual(iocs["confirmed_remote_ips"], [])
        self.assertEqual(iocs["static_only_remote_ips"], ["203.0.113.9"])


if __name__ == "__main__":
    unittest.main()
