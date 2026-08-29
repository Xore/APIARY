import configparser
import unittest
from pathlib import Path

SANDBOX_ROOT = Path(__file__).resolve().parent.parent
FAKENET_INI = SANDBOX_ROOT / "config" / "fakenet.ini"
TOOLS_PS1 = SANDBOX_ROOT / "packer" / "scripts" / "04-tools.ps1"
ORCHESTRATOR_PS1 = SANDBOX_ROOT / "packer" / "scripts" / "11-detonation-orchestrator.ps1"
RUN_SAMPLE_PY = SANDBOX_ROOT / "orchestrate" / "run_sample.py"


# #2563: fakenet.ini used to claim packet capture (DumpPackets /
# DumpPacketsFilePrefix) in [FakeNet], a section diverterbase.py never reads
# -- so no capture ever ran despite the comment. These tests pin the fix: the
# keys live in [Diverter] (the section upstream actually reads them from),
# and every stage that must know about C:\Logs\fakenet_packets -- directory
# pre-creation, in-guest collection, host-side collection -- actually does.
class FakeNetPacketCaptureWiringTest(unittest.TestCase):
    def _read_ini(self):
        parser = configparser.ConfigParser()
        parser.read(FAKENET_INI)
        return parser

    def test_dump_packets_keys_live_in_diverter_section(self):
        parser = self._read_ini()
        self.assertEqual(parser.get("Diverter", "DumpPackets"), "Yes")
        self.assertTrue(
            parser.get("Diverter", "DumpPacketsFilePrefix").startswith(
                "C:\\Logs\\fakenet_packets"
            )
        )

    def test_dump_packets_keys_are_not_in_fakenet_section(self):
        parser = self._read_ini()
        self.assertNotIn("DumpPackets", parser["FakeNet"])
        self.assertNotIn("DumpPacketsFilePrefix", parser["FakeNet"])

    def test_capture_directory_precreated_at_build_time(self):
        text = TOOLS_PS1.read_text()
        self.assertIn(
            "New-Item 'C:\\Logs\\fakenet_packets' -ItemType Directory -Force",
            text,
        )

    def test_inguest_orchestrator_collects_packet_captures(self):
        text = ORCHESTRATOR_PS1.read_text()
        self.assertIn('Test-Path "C:\\Logs\\fakenet_packets"', text)
        self.assertIn(
            'Copy-Item "C:\\Logs\\fakenet_packets" '
            '"$analysisDir\\Logs\\fakenet_packets"',
            text,
        )

    def test_host_side_collector_pulls_packet_captures(self):
        text = RUN_SAMPLE_PY.read_text()
        self.assertIn("mget fakenet_packets\\\\*", text)

    def test_host_side_collector_pulls_fakenet_log(self):
        # The primary FakeNet log (listener startup, diversion decisions)
        # must also be collected -- this was the other half of #2563.
        text = RUN_SAMPLE_PY.read_text()
        self.assertIn("'fakenet_log.txt'", text)


if __name__ == "__main__":
    unittest.main()
