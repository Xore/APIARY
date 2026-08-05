import importlib.util
import io
import subprocess
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("guest-clean-strings.py")
SPEC = importlib.util.spec_from_file_location("guest_clean_strings", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


# #530: GNU `strings -a` (invoked by guest-runner.sh) is exactly as
# permissive as dashboard/payload_analysis.go's own byte-range string scan --
# any run of printable bytes counts, no character-class filtering -- so it
# emits the identical class of noise this script filters: pure separator/
# punctuation runs, and real strings glued to boundary noise. Mirrors
# dashboard/string_extraction_test.go's TestCleanExtractedString* cases so
# the two independently-run extractors stay verified against the same
# expectations, not just the same intent.
class CleanTest(unittest.TestCase):
    def test_rejects_pure_noise_runs(self):
        for s in ["//////", "''''", "--------", "\\\\\\\\", "||||", "````"]:
            self.assertEqual(MODULE.clean(s), "", f"{s!r} must be rejected")

    def test_trims_boundary_noise_without_touching_the_middle(self):
        cases = [
            ("''''''''http://evil.example/a", "http://evil.example/a"),
            ("\\\\\\C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
            ('"quoted argument"', "quoted argument"),
            ("///usr/bin/curl///", "usr/bin/curl"),
        ]
        for raw, want in cases:
            self.assertEqual(MODULE.clean(raw), want)

    def test_keeps_low_alnum_but_informative_strings(self):
        for s in ["%s: %s (%d)", "a=1&b=2", "1.2.3.4"]:
            self.assertEqual(MODULE.clean(s), s)

    def test_rejects_empty_or_all_noise(self):
        self.assertEqual(MODULE.clean(""), "")
        self.assertEqual(MODULE.clean("   "), "")
        self.assertEqual(MODULE.clean("''''''''"), "")


class MainTest(unittest.TestCase):
    def test_filters_stdin_to_stdout(self):
        stdin = io.StringIO("//////\nC:\\Windows\\System32\\svchost.exe\n----\n")
        stdout = io.StringIO()
        real_stdin, real_stdout = MODULE.sys.stdin, MODULE.sys.stdout
        MODULE.sys.stdin, MODULE.sys.stdout = stdin, stdout
        try:
            MODULE.main()
        finally:
            MODULE.sys.stdin, MODULE.sys.stdout = real_stdin, real_stdout
        self.assertEqual(stdout.getvalue(), "C:\\Windows\\System32\\svchost.exe\n")

    # #498: guest-runner.sh always pipes this through `| head -n N`. A
    # StringIO swap (like the test above) can't reproduce a real closed-fd
    # SIGPIPE, so this runs the actual script as a subprocess -- confirmed
    # live during a #498 smoke-test sandbox run that an unhandled
    # BrokenPipeError traceback was landing in runner_log even though the
    # truncated output file itself was still complete and correct.
    def test_broken_pipe_from_downstream_head_is_silent(self):
        producer = subprocess.Popen(
            [sys.executable, "-c", "for i in range(200_000): print('hello world', i)"],
            stdout=subprocess.PIPE,
        )
        cleaner = subprocess.Popen(
            [sys.executable, str(MODULE_PATH)],
            stdin=producer.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        producer.stdout.close()
        head_out = subprocess.run(["head", "-n", "5"], stdin=cleaner.stdout, capture_output=True, text=True)
        cleaner.stdout.close()
        _, cleaner_err = cleaner.communicate(timeout=10)
        producer.wait(timeout=10)

        self.assertEqual(len(head_out.stdout.splitlines()), 5)
        self.assertNotIn(b"Traceback", cleaner_err)
        self.assertNotIn(b"BrokenPipeError", cleaner_err)


if __name__ == "__main__":
    unittest.main()
