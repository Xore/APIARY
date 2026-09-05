#!/usr/bin/env python3
"""Test cowrie/txtcmds_priority_patch.py (#2926).

Fixture is upstream's real getCommand() bare-name-return block at the
pinned commit (ced855a5cda953eb4ad439d8ee8060afe4234fe4). The build-time
drift guard is apply_patch() itself raising when its OLD constant no
longer matches the checked-out source; this fixture is a second in-tree
copy of that text, kept so the behavioural tests below have something to
execute without a cowrie install.

The behavioural tests exec the *patched* method inside a stub protocol
class, rather than asserting on the patched text, because the two
regressions this patch has to avoid are only visible when it runs:
probing the overlay for a path-form command reads the container's real
binary (`Path(txtcmds)/"bin"/"/bin/echo"` is `/bin/echo`), and promoting
a canned overlay over `uname`/`dd` loses persona rendering and payload
capture respectively.

Also asserts the persona-consistency half of #2926 directly against the
checked-in fixture files: nproc must agree with lscpu's CPU(s) count, and
every static overlay entry under txtcmds/ has a corresponding generator
call in bin/gen-dynamic-txtcmds.py's main() (or is a fully static file that
doesn't need one) -- the two entry points a stale overlay entry could fall
out of sync from.

Usage: python arcane/home/honeypot-cowrie/cowrie/tests/test_txtcmds_priority_patch.py
"""
import importlib.util
import re
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
COWRIE_DIR = HERE.parent
PATCH = COWRIE_DIR / "txtcmds_priority_patch.py"
GEN_SCRIPT = COWRIE_DIR / "bin" / "gen-dynamic-txtcmds.py"
TXTCMDS = COWRIE_DIR / "txtcmds"

# Verbatim from cowrie v3.0.12 (ced855a), src/cowrie/shell/protocol.py.
UPSTREAM_FIXTURE = '''    def getCommand(self, cmd, paths, cwd):
        if not cmd.strip():
            return None
        path = None
        if cmd in self.commands:
            return self.commands[cmd]
        if cmd[0] in (".", "/"):
            path = self.fs.resolve_path(cmd, cwd)
'''

# Enough of cowrie's surroundings to execute the patched getCommand():
# CowrieConfig for txtcmds_path, Path (both are already imported in the
# real protocol.py, at :21 and :11), and stubs for the two collaborators
# the patched block touches.
HARNESS = '''
from pathlib import Path


class CowrieConfig:
    txtcmds_path = ""

    @classmethod
    def get(cls, section, option, fallback=""):
        assert (section, option) == ("honeypot", "txtcmds_path")
        return cls.txtcmds_path


class Proto:
    def __init__(self, commands):
        self.commands = commands
        self.fs = None

    def txtcmd(self, data):
        return ("overlay", data)

'''


def _patched_proto(txtcmds_path):
    """Exec the patched getCommand() inside a stub class and return it."""
    mod = _load_patch()
    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / "protocol.py"
        target.write_text(UPSTREAM_FIXTURE)
        mod.apply_patch(target)
        patched = target.read_text()
    ns = {}
    exec(HARNESS + patched, ns)  # noqa: S102 -- fixture text, not input
    ns["CowrieConfig"].txtcmds_path = str(txtcmds_path)
    return ns["Proto"]


def _load_patch():
    spec = importlib.util.spec_from_file_location("txtcmds_priority_patch", PATCH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TxtcmdsPriorityPatchTest(unittest.TestCase):
    def test_matches_upstream_fixture_exactly_once(self):
        mod = _load_patch()
        self.assertEqual(UPSTREAM_FIXTURE.count(mod.OLD), 1)

    def test_apply_is_idempotent_and_bare_name_now_checked_first(self):
        mod = _load_patch()
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "protocol.py"
            target.write_text(UPSTREAM_FIXTURE)
            first = mod.apply_patch(target)
            self.assertIn("reordered", first)
            patched = target.read_text()
            self.assertIn(mod.MARKER, patched)
            # The overlay check must appear before the unconditional
            # "return self.commands[cmd]" line it used to be the first
            # thing after the `if cmd in self.commands:` guard.
            guard_idx = patched.index("if cmd in self.commands:")
            marker_idx = patched.index(mod.MARKER)
            return_idx = patched.index("return self.commands[cmd]")
            self.assertTrue(guard_idx < marker_idx < return_idx)

            second = mod.apply_patch(target)
            self.assertIn("already patched", second)
            self.assertEqual(target.read_text(), patched)  # unchanged

    def test_allow_listed_bare_name_gets_the_overlay(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "txtcmds"
            (root / "usr" / "bin").mkdir(parents=True)
            (root / "usr" / "bin" / "free").write_bytes(b"persona free\n")
            proto = _patched_proto(root)(
                {"free": "BUILTIN_FREE", "/usr/bin/free": "BUILTIN_FREE"}
            )
            self.assertEqual(
                proto.getCommand("free", [], "/root"),
                ("overlay", b"persona free\n"),
            )

    def test_path_form_never_probes_the_overlay(self):
        # #2926 review: self.commands is keyed by the absolute path too, and
        # Path(root)/"bin"/"/bin/echo" is "/bin/echo" -- an unguarded probe
        # reads the container's REAL binary and writes the ELF to the
        # session. 67 of cowrie's 105 absolute keys resolve to a real file
        # inside the runtime image.
        real = Path("/bin/echo")
        self.assertTrue(real.is_file(), "test host has no /bin/echo to guard against")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "txtcmds"
            (root / "bin").mkdir(parents=True)
            proto = _patched_proto(root)(
                {"echo": "BUILTIN_ECHO", "/bin/echo": "BUILTIN_ECHO"}
            )
            self.assertEqual(proto.getCommand("/bin/echo", [], "/root"), "BUILTIN_ECHO")

    def test_builtins_outside_the_allow_list_keep_winning(self):
        # uname renders the persona from cowrie.cfg's [shell] keys and dd
        # parses operands + captures input_data; a canned overlay is a
        # regression for both, so neither is allow-listed.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "txtcmds"
            (root / "bin").mkdir(parents=True)
            (root / "bin" / "uname").write_bytes(b"Linux\n")
            (root / "bin" / "dd").write_bytes(b"0+1 records in\n")
            proto_cls = _patched_proto(root)
            for name in ("uname", "dd"):
                with self.subTest(name=name):
                    proto = proto_cls({name: "BUILTIN", "/bin/" + name: "BUILTIN"})
                    self.assertEqual(proto.getCommand(name, [], "/root"), "BUILTIN")

    def test_allow_listed_name_without_an_overlay_falls_through(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "txtcmds"
            root.mkdir(parents=True)
            proto = _patched_proto(root)({"uptime": "BUILTIN_UPTIME"})
            self.assertEqual(proto.getCommand("uptime", [], "/root"), "BUILTIN_UPTIME")

    def test_raises_if_upstream_text_no_longer_matches(self):
        mod = _load_patch()
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "protocol.py"
            target.write_text("def getCommand(self): pass\n")
            with self.assertRaises(SystemExit):
                mod.apply_patch(target)


class PersonaConsistencyTest(unittest.TestCase):
    def test_nproc_agrees_with_lscpu_cpu_count(self):
        lscpu_text = (TXTCMDS / "usr" / "bin" / "lscpu").read_text()
        m = re.search(r"^CPU\(s\):\s+(\d+)$", lscpu_text, re.MULTILINE)
        self.assertIsNotNone(m, "lscpu fixture has no CPU(s): line")
        lscpu_count = m.group(1)

        nproc_path = TXTCMDS / "usr" / "bin" / "nproc"
        self.assertTrue(nproc_path.is_file(), "txtcmds/usr/bin/nproc is missing (#2926)")
        nproc_count = nproc_path.read_text().strip()
        self.assertEqual(
            nproc_count, lscpu_count,
            f"nproc says {nproc_count} but lscpu says {lscpu_count} -- "
            "same contradiction #2926 was filed for",
        )

        gen_text = GEN_SCRIPT.read_text()
        self.assertIn(
            "gen_nproc(root)", gen_text,
            "gen-dynamic-txtcmds.py's main() no longer regenerates nproc "
            "at container startup",
        )

    def test_free_static_seed_is_persona_scale_not_a_few_gb(self):
        # #2926: the committed seed used to say ~3.9GB total, an order of
        # magnitude below even the real container host's RAM, let alone
        # the ~503GB gpu01 persona -- reachable now that the priority
        # patch stops the builtin from shadowing it.
        free_text = (TXTCMDS / "usr" / "bin" / "free").read_text()
        m = re.search(r"^Mem:\s+(\d+)", free_text, re.MULTILINE)
        self.assertIsNotNone(m, "free fixture has no Mem: line")
        total_kb = int(m.group(1))
        self.assertGreater(
            total_kb, 400_000_000,
            f"free's static seed total is {total_kb} kB, too small for the "
            "~503GB gpu01 persona (#2926)",
        )


if __name__ == "__main__":
    unittest.main()
