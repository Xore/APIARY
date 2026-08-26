#!/usr/bin/env python3
"""Contract test for statictools' lief_parse() (#2072).

lief was the one unpinned install in an image whose entire reason for being
is "no dependency drifts underneath us silently". When it crossed its 1.0
major boundary the failure mode was exactly the silent one: blanket
except-Exception blocks turned API breakage into missing result fields, no
error anywhere -- and because lief's CPU accessor never was uniform across
its three formats (ELF machine_type / PE machine / Mach-O cpu_type), PE and
Mach-O samples lost their architecture field under 0.x just as much as
under 1.0. This pins the behaviour: hand-built header-only fixtures (no
third-party binaries needed) go through the real lief_parse(), and every
documented key must come back.

Runs against the exact version the Dockerfile pins -- quality.yml reads the
pin back out of that Dockerfile before invoking this, so the version under
test and the version shipped cannot drift apart.

ssdeep/tlsh are stubbed out: they are imported by server.py at module load,
but this test exercises the lief half of the service, and those two C
extensions have nothing to do with it (keeping them out means this also
runs on hosts where their build chain is not installed).
"""
import importlib.util
import logging
import struct
import sys
import types
from pathlib import Path

for _stub in ("ssdeep", "tlsh"):
    _m = types.ModuleType(_stub)
    _m.hash = lambda data: "stubbed"
    sys.modules[_stub] = _m

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("statictools_server", HERE.parent / "server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)

fails = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        fails.append(label)


def elf_fixture() -> bytes:
    # Minimal ELF64 EXEC, e_machine = EM_X86_64(62). Header-only: lief parses
    # it fine and reports zero sections/segments beyond the table itself.
    e = bytearray(64)
    e[0:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", e, 16, 2, 62)   # e_type=ET_EXEC, e_machine=X86_64
    struct.pack_into("<Q", e, 24, 0x1000)   # e_entry
    struct.pack_into("<Q", e, 40, 64)       # e_phoff
    struct.pack_into("<H", e, 52, 64)       # e_ehsize
    struct.pack_into("<H", e, 54, 56)       # e_phentsize
    struct.pack_into("<H", e, 56, 1)        # e_phnum
    return bytes(e)


def pe_fixture() -> bytes:
    # Minimal PE32+ COFF, Machine = IMAGE_FILE_MACHINE_AMD64 (0x8664), with a
    # non-zero TimeDateStamp so the reported compile_timestamp is checkable.
    p = bytearray(0x100)
    p[0:2] = b"MZ"
    struct.pack_into("<I", p, 0x3C, 0x40)   # e_lfanew -> PE signature
    p[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", p, 0x44,
                     0x8664, 0, 1700000000, 0, 0, 240, 0x0022)
    return bytes(p)


def macho_fixture() -> bytes:
    # Minimal Mach-O 64 (MH_MAGIC_64), cputype = CPU_TYPE_X86_64 (0x01000007).
    return struct.pack("<IIIIIIII",
                       0xfeedfacf, 0x01000007, 3, 2, 0, 0, 0, 0)


COMMON_KEYS = {"format", "entrypoint", "architecture", "is_pie",
               "section_count", "sections_truncated", "sections"}
EXPECTED_KEYS = {
    "ELF": COMMON_KEYS | {"libraries", "stripped"},
    "PE": COMMON_KEYS | {"libraries", "compile_timestamp", "is_dll", "stripped"},
    "MACHO": COMMON_KEYS | {"libraries"},
}


def test_every_documented_key_survives_per_format():
    results = {
        "ELF": server.lief_parse(elf_fixture()),
        "PE": server.lief_parse(pe_fixture()),
        "MACHO": server.lief_parse(macho_fixture()),
    }
    for fmt, result in results.items():
        check(result is not None, f"{fmt}: fixture parses at all")
        if result is None:
            continue
        missing = EXPECTED_KEYS[fmt] - set(result)
        check(not missing,
              f"{fmt}: all documented keys present (missing: {sorted(missing)})")
        check(result.get("format") == fmt, f"{fmt}: format reported as {fmt}")
        check(result.get("architecture") is not None,
              f"{fmt}: architecture survives the format-aware accessor "
              f"(got {result.get('architecture')!r})")

    check(results["ELF"].get("architecture") == "X86_64",
          "ELF: architecture reads EM_X86_64")
    check(results["PE"].get("architecture") == "AMD64",
          "PE: architecture reads IMAGE_FILE_MACHINE_AMD64")
    check(results["PE"].get("compile_timestamp") == 1700000000,
          "PE: declared compile_timestamp passes through")
    check(results["MACHO"].get("architecture") == "X86_64",
          "Mach-O: architecture reads CPU_TYPE_X86_64")


class Rotten:
    """Delegates to a real parsed binary except one poisoned accessor --
    standing in for 'the next lief release renamed this field', so the
    blast-radius guarantee is executed rather than asserted from source text."""

    def __init__(self, inner, poison):
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_poison", poison)

    def __getattr__(self, name):
        if name == self._poison:
            raise AttributeError(f"simulated upstream rename of .{name}")
        return getattr(self._inner, name)


def test_one_rotten_accessor_does_not_take_out_the_rest():
    elf = server.lief_parse.__globals__["lief"].parse(elf_fixture())
    elf_out = server._elf_extra(Rotten(elf, "symtab_symbols"))
    check("libraries" in elf_out,
          "ELF: symtab_symbols rotting leaves libraries intact")
    check("stripped" not in elf_out,
          "ELF: only the rotted field goes missing")

    pe = server.lief_parse.__globals__["lief"].parse(pe_fixture())
    pe_out = server._pe_extra(Rotten(pe, "imports"))
    check({"compile_timestamp", "is_dll", "stripped"} <= set(pe_out),
          "PE: imports rotting leaves timestamp/is_dll/stripped intact")
    check("libraries" not in pe_out,
          "PE: only the rotted field goes missing")


def test_unexpected_extra_failure_is_logged_not_silent():
    # The whole-block catch around extra() is the last line of defence now
    # that each field guards itself. It must leave a trace when it fires --
    # silence is what let #2072 hide for as long as it did.
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = Capture()
    server.logging.getLogger().addHandler(handler)
    original = dict(server._FORMAT_EXTRA)
    try:
        server._FORMAT_EXTRA["MACHO"] = lambda b: (_ for _ in ()).throw(
            RuntimeError("simulated structural breakage"))
        result = server.lief_parse(macho_fixture())
    finally:
        server._FORMAT_EXTRA.clear()
        server._FORMAT_EXTRA.update(original)
        server.logging.getLogger().removeHandler(handler)

    check(result is not None and "format" in result,
          "a broken extra block still returns the common fields")
    check(len(records) > 0,
          "the broken extra block is logged, not swallowed silently")


def test_unrecognised_input_stays_none():
    check(server.lief_parse(b"this is a text file, not a binary\n\x00\x01") is None,
          "non-binary input reports None (422 upstream), never a partial dict")


if __name__ == "__main__":
    test_every_documented_key_survives_per_format()
    test_one_rotten_accessor_does_not_take_out_the_rest()
    test_unexpected_extra_failure_is_logged_not_silent()
    test_unrecognised_input_stays_none()
    if fails:
        print(f"\n{len(fails)} failure(s)")
        sys.exit(1)
    print("\nall statictools lief_parse tests passed")
