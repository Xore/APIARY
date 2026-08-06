#!/usr/bin/env python3
"""Content-defined chunking dedup prototype (#481).

Research/prototype only -- not wired into dedupe-payloads.py. #481 asks
whether whole-file hashing (dedupe-payloads.py's actual approach: hardlink
byte-identical files, zero benefit otherwise) is the right primitive for
near-duplicate artifacts like registry snapshot exports, EVTX dumps, or
procmon logs, where two captures are 99%+ identical but differ scattered
throughout -- which makes them hash completely differently as whole files.

This implements FastCDC-style content-defined chunking: a rolling "gear"
hash slides over the file, and a chunk boundary is declared wherever the
hash's low bits happen to match a mask -- a boundary condition on local
content, not a fixed byte offset. That's the whole trick: insert one byte
anywhere in the file and only the chunk(s) touching that insertion shift;
every chunk before and after it re-aligns and matches its counterpart in
the other file exactly, the same way rsync/restic/borgbackup dedupe.
Fixed-size blocking (chunk every N bytes) does NOT have this property --
a single inserted byte shifts every following block by one byte and
desyncs the whole rest of the file, which is exactly why #481 rules it
out implicitly by asking for a "content-defined" (not fixed-size) scheme.

#528 follow-up: the original version of this script only ever took
exactly two files, which is fine for the registry-snapshot case #481 was
built around (one golden-image baseline, one run to diff against), but
#528 specifically asks about procmon.csv/EVTX exports *across different,
unrelated sample runs* -- there's no single baseline there, and the real
question is a store accumulating many runs over time, not one pair.
compare_sequential() below generalizes to N files: each file's storage
cost is measured against a running pool of every chunk seen in every
file before it (what a real backing store would already have on disk),
not each file's two-way overlap with just one other file in isolation.

Usage:
  cdc-dedup-prototype.py <file1> <file2> [<file3> ...] [--avg-chunk-kb N]

Prints a real measured comparison per file: whole-file hash dedup result
(0% unless byte-identical to something already seen) and content-defined
chunk-level dedup result (bytes already present in the running pool of
every prior file's chunks), plus an aggregate reduction figure.
"""

import argparse
import hashlib
import sys
from pathlib import Path

# Gear hash table: 256 random-looking 64-bit values, one per possible byte.
# Standard FastCDC construction -- a precomputed table, not derived from
# input data, so it's identical (and thus produces identical chunk
# boundaries) for any input this script ever processes.
import random as _random
_rng = _random.Random(1337)  # fixed seed: deterministic table, not a secret
GEAR = [_rng.getrandbits(64) for _ in range(256)]


def cdc_chunks(data: bytes, avg_size: int):
    """Yield (start, end) byte ranges using FastCDC-style boundaries.

    min_size/max_size bound the chunk size (avoids pathological tiny or
    huge chunks); the mask's bit-width controls the *average* chunk size
    (fewer required-zero bits -> boundaries found more often -> smaller
    average chunks), following FastCDC's own normalized chunking approach.
    """
    min_size = avg_size // 4
    max_size = avg_size * 4
    mask_bits = avg_size.bit_length() - 1
    mask = (1 << mask_bits) - 1

    n = len(data)
    start = 0
    while start < n:
        end = min(start + max_size, n)
        pos = start + min_size
        h = 0
        boundary = end
        while pos < end:
            h = ((h << 1) + GEAR[data[pos]]) & 0xFFFFFFFFFFFFFFFF
            if (h & mask) == 0:
                boundary = pos + 1
                break
            pos += 1
        yield start, boundary
        start = boundary


def hash_chunks_bytes(data: bytes, avg_size: int):
    chunks = {}
    for s, e in cdc_chunks(data, avg_size):
        h = hashlib.blake2b(data[s:e], digest_size=16).digest()
        chunks[h] = chunks.get(h, 0) + (e - s)
    return chunks


def hash_chunks(path: Path, avg_size: int):
    data = path.read_bytes()
    return hash_chunks_bytes(data, avg_size), len(data)


def compare_sequential(paths, avg_size, names=None):
    """Feed files in the given order against a growing pool of every chunk
    (and whole-file hash) seen in every file before it -- what a real
    backing store would already have on disk by the time file N arrives.
    Returns one result dict per file plus the running pool, so callers can
    print incrementally or just use the final aggregate.
    """
    names = names or [str(p) for p in paths]
    seen_chunks = {}
    seen_whole_hashes = set()
    results = []
    for name, path in zip(names, paths):
        data = path.read_bytes() if isinstance(path, Path) else path
        size = len(data)
        whole_hash = hashlib.sha256(data).hexdigest()
        whole_dedup = whole_hash in seen_whole_hashes
        seen_whole_hashes.add(whole_hash)

        chunks = hash_chunks_bytes(data, avg_size)
        shared_hashes = set(chunks) & set(seen_chunks)
        shared_bytes = sum(chunks[h] for h in shared_hashes)
        new_bytes = size - shared_bytes
        for h, n in chunks.items():
            seen_chunks[h] = seen_chunks.get(h, 0) + n

        results.append({
            'name': name, 'size': size, 'num_chunks': len(chunks),
            'whole_file_dedup': whole_dedup,
            'shared_chunks': len(shared_hashes), 'shared_bytes': shared_bytes,
            'new_bytes': new_bytes,
        })
    return results


def print_report(results):
    total_size = sum(r['size'] for r in results)
    total_new = sum(r['new_bytes'] for r in results)
    for r in results:
        pct = 100 * r['shared_bytes'] / r['size'] if r['size'] else 0
        print(f"{r['name']}: {r['size']:,} bytes, {r['num_chunks']:,} chunks -- "
              f"whole-file dedup: {'MATCH' if r['whole_file_dedup'] else 'no match'}; "
              f"chunk dedup against everything stored so far: "
              f"{r['shared_bytes']:,} bytes avoided ({pct:.1f}%), "
              f"{r['new_bytes']:,} new bytes to store")
    print()
    print(f"aggregate: {total_size:,} bytes across {len(results)} file(s) -- "
          f"whole-file approach stores {total_size:,} bytes "
          f"(0% reduction unless byte-identical), "
          f"chunk-dedup stores {total_new:,} bytes "
          f"({100 * (1 - total_new / total_size):.1f}% reduction)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('files', type=Path, nargs='+',
                     help='2 or more files to compare, in arrival order '
                          '(each measured against everything before it)')
    ap.add_argument('--avg-chunk-kb', type=int, default=8)
    args = ap.parse_args()
    if len(args.files) < 2:
        ap.error('need at least 2 files to compare')

    avg_size = args.avg_chunk_kb * 1024
    results = compare_sequential(args.files, avg_size,
                                  names=[f.name for f in args.files])
    print_report(results)


if __name__ == '__main__':
    main()
