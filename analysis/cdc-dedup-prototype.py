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

Usage:
  cdc-dedup-prototype.py <file1> <file2> [--avg-chunk-kb N]

Prints a real measured comparison: total bytes, whole-file hash dedup
result (0% unless byte-identical), and content-defined chunk-level dedup
result (bytes shared between file1 and file2 via matching chunk hashes).
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


def hash_chunks(path: Path, avg_size: int):
    data = path.read_bytes()
    chunks = {}
    total = 0
    for s, e in cdc_chunks(data, avg_size):
        h = hashlib.blake2b(data[s:e], digest_size=16).digest()
        chunks[h] = chunks.get(h, 0) + (e - s)
        total += (e - s)
    return chunks, total, len(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('file1', type=Path)
    ap.add_argument('file2', type=Path)
    ap.add_argument('--avg-chunk-kb', type=int, default=8)
    args = ap.parse_args()

    avg_size = args.avg_chunk_kb * 1024

    whole1 = hashlib.sha256(args.file1.read_bytes()).hexdigest()
    whole2 = hashlib.sha256(args.file2.read_bytes()).hexdigest()
    whole_file_dedup = whole1 == whole2

    chunks1, total1, size1 = hash_chunks(args.file1, avg_size)
    chunks2, total2, size2 = hash_chunks(args.file2, avg_size)

    shared_hashes = set(chunks1) & set(chunks2)
    shared_bytes = sum(chunks1[h] for h in shared_hashes)
    new_bytes_in_file2 = size2 - shared_bytes

    print(f'file1: {args.file1.name} ({size1:,} bytes, {len(chunks1):,} chunks)')
    print(f'file2: {args.file2.name} ({size2:,} bytes, {len(chunks2):,} chunks)')
    print(f'whole-file hash dedup (current dedupe-payloads.py approach): '
          f'{"MATCH -- fully deduped" if whole_file_dedup else "NO MATCH -- zero dedup benefit, full second copy stored"}')
    print(f'content-defined chunk dedup: {len(shared_hashes):,} of {len(chunks2):,} '
          f'chunks in file2 already exist in file1 '
          f'({shared_bytes:,} of {size2:,} bytes = {100 * shared_bytes / size2:.1f}% avoided)')
    print(f'storage if only file2 is new: whole-file={size2:,} bytes, '
          f'chunk-dedup={new_bytes_in_file2:,} bytes '
          f'({100 * (1 - new_bytes_in_file2 / size2):.1f}% reduction)')


if __name__ == '__main__':
    main()
