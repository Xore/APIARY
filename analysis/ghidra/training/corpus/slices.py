#!/usr/bin/env python3
"""Corpus v1 slice definitions and provenance rules (issue #3082, plan §6).

Six slices feed round 7's three training legs (CPT, SFT, DPO/GRPO). Each
slice's provenance is fixed here so every generator and the decontamination
scan agree on where a sample is allowed to come from and where it may end up.

    S1  sessions-captured    real honeypot sessions        NOT BUILT HERE
    S2  ghidra-captured      real captured samples         NOT BUILT HERE
    S3  ghidra-synthetic     new C programs, none the 17   OpenRouter teacher
    S4  revdeck-rex86        Zenodo 15420461 (CC-BY-4.0)    as shipped
    S5  injection-pairs      new phrasings over S1-S3       filtered, per-source
    S6  cpt-text             raw domain text, per-source    none

S1 and S2 are captured honeypot/malware data. Plan §6.2 and the issue are
explicit: this data never leaves the homeserver -- not git, not Hugging Face,
not an API teacher. Labelling them needs a local teacher with the GPU free
(round7-1's job), so this repo carries only their *shape* -- the dataclass
and the directory layout -- and a loud refusal if anything tries to build or
transmit them from here. The synthetic slices (S3-S6, so far as S5/S6 draw on
S3) are this issue's actual deliverable.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

CORPUS_ROOT = Path("/var/training/corpus-v1")  # host-side; 0700, never this repo

SliceId = Literal["S1", "S2", "S3", "S4", "S5", "S6"]


class NotBuiltHereError(RuntimeError):
    """Raised by any S1/S2 code path invoked from this repo.

    Captured honeypot/malware data is labelled host-side by a local teacher
    (round7-1) and never constructed, embedded, or transmitted from git-tracked
    code. There is no flag to bypass this -- if S1/S2 building is ever wanted
    from a script, that script lives on the homeserver, outside this repo.
    """


@dataclass(frozen=True)
class Slice:
    id: SliceId
    name: str
    job: str
    teacher: str
    may_leave_host: bool
    not_built_here: bool = False


SLICES: tuple[Slice, ...] = (
    Slice("S1", "sessions-captured", "session analysis", "local teacher (N=3, majority)", may_leave_host=False, not_built_here=True),
    Slice("S2", "ghidra-captured", "ghidra triage", "local teacher (N=3, majority)", may_leave_host=False, not_built_here=True),
    Slice("S3", "ghidra-synthetic", "ghidra triage + Rev-Deck", "OpenRouter open-weight teacher (N=2)", may_leave_host=True),
    Slice("S4", "revdeck-rex86", "Rev-Deck", "as shipped (Zenodo 15420461)", may_leave_host=True),
    Slice("S5", "injection-pairs", "all three", "inherited from source slice", may_leave_host=True),
    Slice("S6", "cpt-text", "continued pretraining", "none", may_leave_host=True),
)

SLICES_BY_ID: dict[str, Slice] = {s.id: s for s in SLICES}

# The 17 benchmark corpus programs -- the test set, off limits at any
# toolchain/opt level, for every slice. Kept here (not just in
# decontaminate.py) because a generator that accidentally names one of these
# is the cheapest bug to catch, before it ever reaches the decontamination
# scan.
BENCHMARK_CORPUS_NAMES: frozenset[str] = frozenset({
    "xor_decode_loop", "vulnerable_strcpy", "strcpy_note_neutral",
    "strcpy_note_injected", "linked_list_sum", "indirect_dispatch",
    "error_handling_alloc", "process_and_injection", "process_witness_probe",
    "tlv_parser", "loopback_connect", "safe_strcpy", "integer_overflow_alloc",
    "use_after_free", "checksum_rotate", "format_string_bug",
    "file_write_persist",
})


def guard_not_built_here(slice_id: SliceId) -> None:
    """Call at the top of any S1/S2 code path. Always raises."""
    s = SLICES_BY_ID[slice_id]
    if s.not_built_here:
        raise NotBuiltHereError(
            f"{slice_id} ({s.name}) is captured data: local-teacher labelling "
            "happens host-side on the homeserver, never in this repo. "
            "See plan §6.2 / issue #3082."
        )


def guard_program_name(name: str) -> None:
    """Refuse any synthetic program whose name collides with the test set."""
    if name in BENCHMARK_CORPUS_NAMES:
        raise ValueError(
            f"{name!r} is one of the 17 benchmark corpus programs -- "
            "off limits for training data at any toolchain or opt level."
        )


def dev_split(ids: list[str], *, seed: int = 20260906, frac: float = 0.1) -> tuple[set[str], set[str]]:
    """Deterministic held-out split by program/session id, never by row.

    Hashing each id with the seed (rather than `random.shuffle`) makes the
    split stable across re-runs that add ids, and independent of input order.
    """
    dev: set[str] = set()
    train: set[str] = set()
    threshold = int(frac * (1 << 32))
    for uid in ids:
        digest = hashlib.sha256(f"{seed}:{uid}".encode()).digest()
        bucket = int.from_bytes(digest[:4], "big")
        (dev if bucket < threshold else train).add(uid)
    return train, dev


def demo() -> None:
    for slice_id in ("S1", "S2"):
        try:
            guard_not_built_here(slice_id)
        except NotBuiltHereError:
            pass
        else:
            raise AssertionError(f"{slice_id} should have refused")

    for slice_id in ("S3", "S4", "S5", "S6"):
        guard_not_built_here(slice_id)  # no-op, must not raise

    try:
        guard_program_name("xor_decode_loop")
    except ValueError:
        pass
    else:
        raise AssertionError("known test-set name should have been rejected")

    guard_program_name("xor_decode_loop_variant_7")  # must not raise

    ids = [f"prog-{i}" for i in range(1000)]
    train, dev = dev_split(ids)
    assert train.isdisjoint(dev)
    assert train | dev == set(ids)
    assert 0.05 < len(dev) / len(ids) < 0.15, len(dev) / len(ids)
    train2, dev2 = dev_split(ids)
    assert (train2, dev2) == (train, dev), "split must be deterministic"

    print("slices.py demo: ok")


if __name__ == "__main__":
    demo()
