import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).with_name("run_sample.py")
SPEC = importlib.util.spec_from_file_location("run_sample", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


# #100/#2023: #100's own thread promised a five-point post-reclone
# verification (Regshot/FakeNet config/Procmon/FakeNet exe files, plus the
# Inbox/Logs SMB shares) before every "revert to golden", and it fell
# through when #358/#361 replaced snapshot-revert with destroy-and-reclone.
# A check that has only ever returned green is indistinguishable from a
# check that always returns green -- which is precisely how #100 happened
# in the first place -- so these tests exercise both a healthy and a
# deliberately broken golden image state, without needing a real disk or
# guest: evaluate_golden_tools_check() is the pure pass/fail half of
# verify_golden_image_contents(), split out for exactly this reason.
class EvaluateGoldenToolsCheckTest(unittest.TestCase):
    def _all_present(self):
        return {label: True for label in MODULE.GOLDEN_TOOL_FILES}

    def test_passes_when_every_tool_and_share_present(self):
        missing = MODULE.evaluate_golden_tools_check(
            self._all_present(), {"Inbox", "Logs"}
        )
        self.assertEqual(missing, [])

    def test_fails_on_a_missing_tool_file(self):
        # The exact regression #100 was: one provisioner path silently
        # never created, everything else fine.
        present = self._all_present()
        present["Regshot"] = False
        missing = MODULE.evaluate_golden_tools_check(present, {"Inbox", "Logs"})
        self.assertEqual(missing, ["Regshot"])

    def test_fails_on_every_missing_tool_file_independently(self):
        # Each of the four file checks must be able to fail on its own --
        # not just report "something is wrong" for any one of them.
        for label in MODULE.GOLDEN_TOOL_FILES:
            present = self._all_present()
            present[label] = False
            missing = MODULE.evaluate_golden_tools_check(present, {"Inbox", "Logs"})
            self.assertEqual(missing, [label], f"expected only {label!r} to be reported missing")

    def test_fails_on_a_missing_smb_share(self):
        missing = MODULE.evaluate_golden_tools_check(self._all_present(), {"Inbox"})
        self.assertEqual(missing, ["SMB share 'Logs'"])

    def test_fails_on_both_missing_shares(self):
        missing = MODULE.evaluate_golden_tools_check(self._all_present(), set())
        self.assertEqual(missing, ["SMB share 'Inbox'", "SMB share 'Logs'"])

    def test_reports_every_class_of_failure_at_once(self):
        present = self._all_present()
        present["Procmon"] = False
        present["FakeNet exe"] = False
        missing = MODULE.evaluate_golden_tools_check(present, {"Inbox"})
        self.assertEqual(
            set(missing), {"Procmon", "FakeNet exe", "SMB share 'Logs'"}
        )


class DecodeSmbShareNamesTest(unittest.TestCase):
    """The registry-parsing half, exercised against a real virt-win-reg
    export captured from an actual Windows disk
    (testdata_lanmanserver_shares.reg -- the live win11-sandbox image; only
    the \\Shares\\Security ACL byte blobs are neutralised, the Shares values
    themselves are verbatim).

    This layer is where #2023's original defect lived: the check ran a
    guestfish invocation that fails at argument parsing on every call, and
    the caller turned that failure into a pass. Unit tests over fabricated
    strings could not see it, because the fabricated string was never what
    the tool actually returns. So this parses the real thing.
    """

    def _fixture(self):
        return MODULE_PATH.with_name("testdata_lanmanserver_shares.reg").read_text()

    def test_decodes_the_real_export(self):
        # The real image predates #956's Samples -> Inbox rename, which is
        # why 'Inbox' is genuinely absent here rather than a test artefact.
        self.assertEqual(
            MODULE.decode_smb_share_names(self._fixture()),
            {"Logs", "Public", "Samples"},
        )

    def test_real_export_fails_the_required_share_check(self):
        missing = MODULE.evaluate_golden_tools_check(
            {label: True for label in MODULE.GOLDEN_TOOL_FILES},
            MODULE.decode_smb_share_names(self._fixture()),
        )
        self.assertEqual(missing, ["SMB share 'Inbox'"])

    def test_ignores_the_security_subkey(self):
        # \\Shares\\Security repeats the same value names against ACL blobs.
        # Counting those would report a share as defined purely because a
        # permission entry mentions it.
        text = self._fixture()
        self.assertIn("LanmanServer\\Shares\\Security]", text)
        self.assertNotIn("Security", MODULE.decode_smb_share_names(text))

    def test_returns_nothing_for_an_empty_or_unrelated_export(self):
        self.assertEqual(MODULE.decode_smb_share_names(""), set())
        self.assertEqual(
            MODULE.decode_smb_share_names("[HKEY_LOCAL_MACHINE\\SYSTEM\\Other]\n"),
            set(),
        )


class VerifyGoldenImageContentsTest(unittest.TestCase):
    """verify_golden_image_contents() itself, with the two acquisition calls
    mocked out -- proves the wiring (guestfish/virt-win-reg -> evaluate ->
    raise) without needing a real qcow2.

    The acquisition layer is deliberately not tested only here: it was run
    against the real win11-sandbox.qcow2 as well, because mocking it is
    exactly what hid the original defect.
    """

    def test_raises_and_names_the_missing_tool_when_a_file_is_absent(self):
        def fake_guestfish_ro(args, disk_path, timeout=60):
            if args[:2] == ["is-file", "/Tools/Regshot/Regshot-x64-Unicode.exe"]:
                return "false\n"
            return "true\n"

        with patch.object(MODULE, "_guestfish_ro", side_effect=fake_guestfish_ro), \
                patch.object(MODULE, "read_smb_share_names",
                             return_value={"Inbox", "Logs"}):
            with self.assertRaises(RuntimeError) as ctx:
                MODULE.verify_golden_image_contents(Path("/fake/disk.qcow2"))
        self.assertIn("Regshot", str(ctx.exception))
        self.assertIn("#100", str(ctx.exception))

    def test_does_not_raise_when_everything_is_present(self):
        with patch.object(MODULE, "_guestfish_ro", return_value="true\n"), \
                patch.object(MODULE, "read_smb_share_names",
                             return_value={"Inbox", "Logs"}):
            MODULE.verify_golden_image_contents(Path("/fake/disk.qcow2"))  # must not raise

    def test_share_read_failure_raises_and_is_never_converted_into_a_pass(self):
        # The regression guard for #2023's own defect. The previous shape
        # caught this exception and substituted the passing value, so check
        # 5 of 5 reported success on every run without ever reading a hive.
        # A check that could not run is not a check that passed.
        with patch.object(MODULE, "_guestfish_ro", return_value="true\n"), \
                patch.object(MODULE, "read_smb_share_names",
                             side_effect=RuntimeError("virt-win-reg failed: simulated")):
            with self.assertRaises(RuntimeError) as ctx:
                MODULE.verify_golden_image_contents(Path("/fake/disk.qcow2"))
        self.assertIn("simulated", str(ctx.exception))

    def test_a_failed_share_read_does_not_mask_a_missing_tool(self):
        def fake_guestfish_ro(args, disk_path, timeout=60):
            if args[:2] == ["is-file", "/Tools/FakeNet/fakenet.exe"]:
                return "false\n"
            return "true\n"

        with patch.object(MODULE, "_guestfish_ro", side_effect=fake_guestfish_ro), \
                patch.object(MODULE, "read_smb_share_names",
                             side_effect=RuntimeError("virt-win-reg failed: simulated")):
            with self.assertRaises(RuntimeError):
                MODULE.verify_golden_image_contents(Path("/fake/disk.qcow2"))


if __name__ == "__main__":
    unittest.main()
