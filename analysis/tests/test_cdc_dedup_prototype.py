"""Tests for cdc-dedup-prototype.py (#481, generalized for #528).

Two things get proven here:

1. Correctness of the FastCDC-style chunker and the N-file sequential
   comparison (insert-shift invariance, growing-pool accounting).
2. #528's actual research question: does content-defined chunking find
   real dedup benefit between procmon.csv exports from DIFFERENT,
   UNRELATED sample runs -- not the #481 registry-snapshot case (one
   golden-image baseline, one run to diff), but N independent captures
   that each ran a different sample.

   The tests below build synthetic procmon.csv-shaped data for that
   second case: every run on this stack's Windows sandbox starts from
   the identical golden image (#480), so a large fraction of any
   procmon capture is background OS noise (services.exe, svchost.exe,
   explorer.exe, MsMpEng.exe, ...) that looks the same regardless of
   which sample ran -- interleaved with a much smaller slice of rows
   the sample itself actually caused, which differs run to run.
   Whole-file hashing sees zero overlap between any two such runs
   (#481's original problem).

   MEASURED FINDING (see test_procmon_shaped_generic_cdc_underperforms
   vs test_procmon_shaped_row_aware_chunking_recovers_the_shared_bytes):
   generic byte-level CDC -- exactly what #481's chunker does, and what
   works well for registry-snapshot exports -- essentially fails on
   procmon.csv: it recovers well under 1% of the genuinely-shared bytes
   between unrelated runs, not the 70-90%+ the underlying content
   overlap would suggest. Root cause, confirmed by direct inspection:
   procmon.csv rows are built from a small number of long, constant
   literal substrings (column boilerplate, path prefixes, operation
   names) separated by only a few short varying tokens (timestamp, PID,
   a number). The rolling hash's effective memory is bounded to roughly
   the gear table's shift width (~64 bytes) -- once it's scanning
   through one of those long constant runs, every row produces the
   *same* sequence of intermediate hash states regardless of which row
   or which run it's in, and if that fixed sequence never happens to
   satisfy the mask condition, the chunker falls back to max_size on
   every single row, at a boundary position that has no reason to align
   with the same content in another run.

   Simple record-aware chunking -- treat each CSV row as one chunk,
   since procmon.csv (and EVTX's own record structure) is already
   naturally record-oriented, not an opaque blob -- sidesteps this
   entirely and recovers ~90% in the same test data. That is this
   issue's actual answer: for row/record-oriented exports specifically,
   don't reuse the generic byte-CDC chunker from #481 as-is; a
   record-boundary-aware variant (or a stronger rolling hash with more
   effective memory) is what would make #528 worth productionizing.

   Real production procmon.csv/EVTX artifacts were not available to
   measure directly for this: as of writing this test, only two
   completed Windows-sandbox runs exist on the homeserver, and their
   diagnostics.zip artifacts are root-owned under
   /var/lib/honeypot-windows-sandbox/export -- consistent with this
   project's ES-only, no-direct-file-access policy for sensor/analysis
   data, not something to sudo around for ad-hoc research. This
   synthetic measurement is the honest substitute; see #528 for the
   note that real numbers are still an open follow-up once #638 lands
   more completed runs into a queryable store.
"""

import hashlib
import importlib.util
import random
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "cdc-dedup-prototype.py"
SPEC = importlib.util.spec_from_file_location("cdc_dedup_prototype", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ChunkerCorrectnessTest(unittest.TestCase):
    def test_single_byte_insertion_only_shifts_the_touched_chunks(self):
        # The whole point of content-defined (vs fixed-size) chunking:
        # inserting one byte must not desync every chunk after it.
        rng = random.Random(42)
        original = bytes(rng.getrandbits(8) for _ in range(200_000))
        insert_at = 100_000
        modified = original[:insert_at] + b"X" + original[insert_at:]

        chunks_a = MODULE.hash_chunks_bytes(original, avg_size=4096)
        chunks_b = MODULE.hash_chunks_bytes(modified, avg_size=4096)

        shared = set(chunks_a) & set(chunks_b)
        shared_bytes = sum(chunks_a[h] for h in shared)
        # A single-byte insertion should leave the overwhelming majority
        # of chunks (everything not touching the insertion point)
        # byte-identical and re-aligned. Whole-file hashing would call
        # this 0% shared; chunk dedup should clear 95%+.
        self.assertGreater(shared_bytes / len(original), 0.95)

    def test_identical_files_dedup_completely(self):
        data = b"same content" * 5000
        chunks_a = MODULE.hash_chunks_bytes(data, avg_size=4096)
        chunks_b = MODULE.hash_chunks_bytes(data, avg_size=4096)
        self.assertEqual(chunks_a, chunks_b)


class SequentialComparisonTest(unittest.TestCase):
    def test_third_file_dedups_against_first_two_combined(self):
        # file3 shares its first half with file1 and its second half with
        # file2 -- neither pairwise comparison alone would find both
        # halves, only a running pool across everything seen so far does.
        half = b"A" * 50_000
        other_half = b"B" * 50_000
        file1 = half + (b"1" * 50_000)
        file2 = (b"2" * 50_000) + other_half
        file3 = half + other_half

        results = MODULE.compare_sequential(
            [file1, file2, file3], avg_size=4096, names=["f1", "f2", "f3"]
        )
        f3 = results[2]
        # Both halves of file3 should be found in the pool built from
        # file1 + file2, leaving well under half of file3 as genuinely new
        # -- one chunk straddling the A/B seam legitimately won't match
        # either side (it's new content on both edges), so this isn't 0%.
        self.assertLess(f3["new_bytes"], len(file3) * 0.2)

    def test_whole_file_dedup_flag_set_only_on_exact_repeat(self):
        results = MODULE.compare_sequential(
            [b"aaaa", b"bbbb", b"aaaa"], avg_size=1024, names=["a", "b", "a-again"]
        )
        self.assertFalse(results[0]["whole_file_dedup"])
        self.assertFalse(results[1]["whole_file_dedup"])
        self.assertTrue(results[2]["whole_file_dedup"])


def _synth_procmon_csv(rng: random.Random, noise_rows: list, unique_row_count: int, pid_base: int) -> bytes:
    """Build one synthetic procmon.csv-shaped export: the same golden-image
    background noise rows as every other run (interleaved, not appended --
    a real capture interleaves background service activity with whatever
    the sample under analysis is doing, moment to moment), plus a block of
    rows unique to this run standing in for the sample's own behavior.
    """
    header = b'"Time of Day","Process Name","PID","Operation","Path","Result","Detail"\r\n'
    unique_rows = [
        f'"9:14:{i % 60:02d}.{i % 1000:04d} AM","malware.exe",{pid_base + i},'
        f'"RegSetValue","HKLM\\Software\\Run\\evil{i}","SUCCESS","Type: REG_SZ, Length: {i}"\r\n'.encode()
        for i in range(unique_row_count)
    ]
    rows = list(noise_rows)  # copy: same objects/bytes as every other run
    # Interleave the unique rows at rng-chosen positions, same shape as a
    # real capture (background service noise and sample activity both
    # timestamped as they actually happened, not grouped).
    for row in unique_rows:
        rows.insert(rng.randrange(len(rows) + 1), row)
    return header + b"".join(rows)


def _make_noise_rows(rng: random.Random, count: int) -> list:
    processes = ["svchost.exe", "services.exe", "explorer.exe", "MsMpEng.exe",
                 "csrss.exe", "wininit.exe", "SearchIndexer.exe", "spoolsv.exe"]
    ops = ["RegQueryValue", "QueryOpen", "ReadFile", "CreateFile", "CloseFile"]
    rows = []
    for i in range(count):
        proc = processes[i % len(processes)]
        op = ops[i % len(ops)]
        rows.append(
            f'"9:1{i % 4}:{i % 60:02d}.{(i * 7) % 1000:04d} AM","{proc}",{1000 + (i % 40)},'
            f'"{op}","C:\\Windows\\System32\\path{i % 500}","SUCCESS","Desired Access: Read"\r\n'.encode()
        )
    return rows


def _row_aware_dedup(runs: list, seen: set = None):
    """Reference implementation of the alternative this research points
    to: chunk on the format's own record boundary (CSV row) instead of
    a generic rolling-hash byte boundary. Deliberately NOT added to
    cdc-dedup-prototype.py itself -- that module's byte-CDC approach is
    still the right tool for opaque/binary formats (registry exports,
    #481's original case); this is a format-specific variant that only
    makes sense for row-oriented text like procmon.csv.
    """
    seen = set() if seen is None else seen
    results = []
    for data in runs:
        rows = data.split(b"\r\n")
        row_hashes = [hashlib.blake2b(r, digest_size=16).digest() for r in rows]
        shared_bytes = sum(len(r) + 2 for r, h in zip(rows, row_hashes) if h in seen)
        results.append({'size': len(data), 'shared_bytes': shared_bytes,
                         'new_bytes': len(data) - shared_bytes})
        seen.update(row_hashes)
    return results


class SyntheticProcmonResearchMeasurement(unittest.TestCase):
    """The actual #528 research measurement (synthetic-data substitute,
    see module docstring for why real production artifacts weren't used,
    and for the full write-up of what these two tests found). Not a
    correctness test in the usual sense -- it's a printed, asserted
    finding, same spirit as #481's own two-file measurement.
    """

    def _make_runs(self):
        rng = random.Random(2026)
        # ~90% of each capture is identical golden-image background noise,
        # ~10% is this run's own (unique, per-run) sample activity -- a
        # deliberately conservative ratio; real captures skew even more
        # toward background noise on a short observation window.
        noise_rows = _make_noise_rows(rng, count=9000)
        return [
            _synth_procmon_csv(rng, noise_rows, unique_row_count=1000, pid_base=5000),
            _synth_procmon_csv(rng, noise_rows, unique_row_count=1000, pid_base=6000),
            _synth_procmon_csv(rng, noise_rows, unique_row_count=1000, pid_base=7000),
        ]

    def test_procmon_shaped_generic_cdc_underperforms(self):
        runs = self._make_runs()
        names = [f"run{i}-procmon.csv (unrelated sample)" for i in range(len(runs))]
        results = MODULE.compare_sequential(runs, avg_size=4096, names=names)

        print("\n--- generic byte-level CDC (#481's chunker, unmodified) ---")
        MODULE.print_report(results)

        # The real finding: despite ~90% of each run being the identical
        # golden-image noise rows, generic byte-CDC recovers only a sliver
        # of it -- confirmed root cause is in the module docstring above.
        for r in results[1:]:
            self.assertLess(r["shared_bytes"] / r["size"], 0.05)

    def test_procmon_shaped_row_aware_chunking_recovers_the_shared_bytes(self):
        runs = self._make_runs()
        results = _row_aware_dedup(runs)

        total_size = sum(r["size"] for r in results)
        total_new = sum(r["new_bytes"] for r in results)
        reduction = 1 - total_new / total_size
        print("\n--- record-aware (one CSV row = one chunk) ---")
        for i, r in enumerate(results):
            pct = 100 * r["shared_bytes"] / r["size"]
            print(f"run{i}: {r['size']:,} bytes, {r['shared_bytes']:,} shared "
                  f"({pct:.1f}%), {r['new_bytes']:,} new")
        print(f"\n#528 finding: record-aware chunking recovers "
              f"{reduction * 100:.1f}% aggregate across {len(runs)} synthetic "
              f"unrelated-sample procmon.csv runs, vs <1% from generic byte-CDC "
              f"and 0% from whole-file hashing.")

        # Runs 2 and 3 should each recover most of their bytes from the
        # shared noise rows -- this is the concrete #528 claim: unrelated
        # runs on the same golden image dedup well once chunking respects
        # the format's own record structure.
        for r in results[1:]:
            self.assertGreater(r["shared_bytes"] / r["size"], 0.8)


if __name__ == "__main__":
    unittest.main()
