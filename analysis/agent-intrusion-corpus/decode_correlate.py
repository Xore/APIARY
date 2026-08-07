#!/usr/bin/env python3
"""#154 phase 2 (first half): "Safely identify and recursively decode bounded
base64 + gzip/zlib and chunked envelopes without executing content... treat
model output as advisory; deterministic rules own decoding."

Two pieces:

- `bounded_decode(data)` -- given raw bytes, tries base64-decode, then
  gzip/zlib-decompress, then (if that fails) brute-forces every single-byte
  XOR key looking for a gzip/zlib magic-bytes match before decompressing --
  repeating up to a hard depth/size cap. Never executes, evals, or imports
  anything from the decoded content; the result is always returned as
  `bytes` to the caller, who decides what (if anything) happens next. This
  is the module's entire job -- decoding, nothing downstream.
- `ChunkCorrelator` -- reassembles the campaign's own documented multi-part
  message protocol (type/channel/sequence/checksum fields, corroborated
  directly against docs/agent-intrusion-threat-model.md and the technical
  timeline this repo's corpus is built from) by (channel, sequence) before
  a chunked payload is even decodable -- a lone chunk's base64 is usually
  truncated mid-stream and correctly fails to decode on its own.

No third-party dependencies (stdlib gzip/zlib/base64 only), matching this
directory's own validate_corpus.py and analysis/ghidra/models/*.py's
stated "one less supply-chain surface" convention.
"""
from __future__ import annotations

import base64
import binascii
import dataclasses
import gzip
import hashlib
import re
import zlib

# ---------------------------------------------------------------------------
# Bounded, non-executing decoder
# ---------------------------------------------------------------------------

MAX_DEPTH = 5
MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MiB -- #154's own "bounded" requirement
GZIP_MAGIC = b"\x1f\x8b"


@dataclasses.dataclass
class DecodeStep:
    """One transform applied during a decode chain -- part of the
    provenance record #154's acceptance criteria requires ("Decoder is
    non-executing, bounded... and records provenance")."""
    transform: str  # "base64", "gzip", "zlib", or "xor:0x<hex>"
    input_sha256: str
    output_sha256: str
    output_len: int


@dataclasses.dataclass
class DecodeResult:
    ok: bool
    output: bytes
    chain: list[DecodeStep]
    truncated: bool
    reason: str = ""  # set when ok is False, or when truncated is True


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _try_base64(data: bytes) -> bytes | None:
    # validate=True rejects non-alphabet characters outright rather than
    # silently discarding them -- a permissive decode would happily "decode"
    # arbitrary text into garbage bytes and let a later stage claim a false
    # match. Two-pass because a lone chunk of a multi-part message (see
    # ChunkCorrelator below) or a URL-safe-alphabet blob would otherwise
    # never decode even after correct reassembly/normalization.
    for variant in (data, data.replace(b"-", b"+").replace(b"_", b"/")):
        padded = variant + b"=" * (-len(variant) % 4)
        try:
            return base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
    return None


def _try_decompress(data: bytes) -> tuple[bytes, str] | None:
    if data[:2] == GZIP_MAGIC:
        try:
            return gzip.decompress(data), "gzip"
        except (OSError, EOFError):
            return None
    try:
        return zlib.decompress(data), "zlib"
    except zlib.error:
        return None


def _try_xor_then_decompress(data: bytes) -> tuple[bytes, str, int] | None:
    """Brute-forces every single-byte XOR key (256 candidates -- tractable
    and a real, standard technique for exactly this shape of light
    obfuscation, not a shortcut) looking for one that reveals a gzip magic
    header. Stops at the first match; a corpus/campaign that XORs with
    anything longer than one byte would need a different technique this
    function deliberately does not attempt (see module docstring: this is
    the *bounded* decoder, not an exhaustive cryptanalysis tool)."""
    for key in range(256):
        candidate = bytes(b ^ key for b in data[:2])
        if candidate == GZIP_MAGIC:
            unxored = bytes(b ^ key for b in data)
            try:
                return gzip.decompress(unxored), "gzip", key
            except (OSError, EOFError):
                continue
    return None


def bounded_decode(data: bytes, max_depth: int = MAX_DEPTH, max_output: int = MAX_OUTPUT_BYTES) -> DecodeResult:
    """Repeatedly tries base64-decode then gzip/zlib-decompress (with a
    single-byte-XOR fallback in between) until nothing further peels off,
    the depth cap is hit, or an intermediate result would exceed
    max_output. Never raises on malformed/adversarial input -- every
    failure mode returns DecodeResult(ok=False, ...) with a reason,
    matching #154's own "must never... weaken the live sandbox boundary"
    posture: a parser that can be crashed by hostile input is itself a
    finding, not an acceptable implementation detail here."""
    chain: list[DecodeStep] = []
    current = data
    truncated = False

    for _ in range(max_depth):
        input_hash = _sha256(current)

        decoded = _try_base64(current)
        if decoded is not None and decoded != current:
            if len(decoded) > max_output:
                return DecodeResult(False, b"", chain, True, "base64 output exceeds max_output")
            chain.append(DecodeStep("base64", input_hash, _sha256(decoded), len(decoded)))
            current = decoded
            continue

        decompressed = _try_decompress(current)
        if decompressed is not None:
            out, transform = decompressed
            if len(out) > max_output:
                return DecodeResult(False, b"", chain, True, f"{transform} output exceeds max_output")
            chain.append(DecodeStep(transform, input_hash, _sha256(out), len(out)))
            current = out
            continue

        xor_result = _try_xor_then_decompress(current)
        if xor_result is not None:
            out, transform, key = xor_result
            if len(out) > max_output:
                return DecodeResult(False, b"", chain, True, f"xor+{transform} output exceeds max_output")
            chain.append(DecodeStep(f"xor:0x{key:02x}+{transform}", input_hash, _sha256(out), len(out)))
            current = out
            continue

        break  # nothing more to peel off -- current is the final layer

    if not chain:
        return DecodeResult(False, b"", chain, False, "no base64/gzip/zlib/xor+gzip layer detected")

    # Success requires either a *verified* transform in the chain, or a
    # final result that looks like real content -- a bare base64 decode
    # has no integrity check at all (any string in the base64 alphabet
    # "decodes" to *something*, valid or not), unlike gzip/zlib (and
    # xor+gzip/xor+zlib), which carry their own checksum (CRC32/Adler-32)
    # that corrupt/truncated input will almost always fail. Confirmed live
    # against exactly this failure mode: a single truncated chunk of a
    # multi-part message (see corpus-015 in tests/test_decode_correlate.py)
    # base64-decoded "successfully" into 21 bytes of pure high-entropy
    # noise with no further layer detected -- chain-non-empty alone would
    # have reported that as ok=True, a false positive on incomplete input.
    # But a *legitimate* plain (uncompressed) base64-only payload is real
    # and must still succeed -- distinguished by its final bytes actually
    # looking like text (decodes as UTF-8, no control characters), which
    # high-entropy compressed-but-not-yet-decompressed garbage essentially
    # never does over any non-trivial length.
    verified_transforms = {"gzip", "zlib"}
    has_verified_step = any(
        step.transform in verified_transforms or step.transform.split("+", 1)[-1] in verified_transforms
        for step in chain
    )
    if not has_verified_step and not looks_like_text(current):
        return DecodeResult(
            False, b"", chain, truncated,
            "decoded through base64 only, and the result doesn't look like real text -- "
            "no gzip/zlib/xor+gzip layer ever verified it; likely truncated or not actually encoded",
        )
    return DecodeResult(True, current, chain, truncated)


def looks_like_text(data: bytes) -> bool:
    """True if data decodes as UTF-8 with no control characters other than
    common whitespace -- real compressed-but-undecompressed binary data
    essentially never satisfies this over any non-trivial length, since
    gzip/zlib output is high-entropy and includes arbitrary byte values,
    while genuine final-layer plaintext (commands, JSON, etc.) does."""
    if not data:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(ch.isprintable() or ch in "\t\n\r " for ch in text)


# ---------------------------------------------------------------------------
# Candidate-blob extraction
# ---------------------------------------------------------------------------

# Matches the corpus/campaign's own message-protocol convention
# (type=...&channel=...&seq=...&chk=...&data=<blob>) and the Python
# literal form cowrie captures (base64.b64decode('<blob>')) -- both
# confirmed directly against corpus.jsonl's own raw fields, not guessed.
_DATA_FIELD_RE = re.compile(r"data=([A-Za-z0-9+/_=-]{8,})")
_PY_LITERAL_RE = re.compile(r"b64decode\(['\"]([A-Za-z0-9+/_=-]{8,})['\"]\)")
# No trailing \b: '=' is a non-word character, so a \b assertion right
# after it only matches when the next character is itself a word
# character (rare -- padding is normally followed by whitespace/EOL/
# punctuation) -- confirmed live, it silently dropped the padding from
# every real match instead. The character class's own {20,} plus greedy
# ={0,2} is a sufficient right boundary on its own.
_BARE_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}")


def extract_candidate_blob(raw_text: str) -> str | None:
    """Best-effort extraction of the one substring in a raw sensor string
    most likely to be an encoded payload -- tries the known protocol shapes
    first (most specific), falls back to the longest bare base64-alphabet
    run. Returns None rather than guessing on genuinely ambiguous input;
    callers should treat that as "nothing to decode here", not an error."""
    for pattern in (_DATA_FIELD_RE, _PY_LITERAL_RE):
        m = pattern.search(raw_text)
        if m:
            return m.group(1)
    candidates = _BARE_B64_RE.findall(raw_text)
    if candidates:
        return max(candidates, key=len)
    return None


# ---------------------------------------------------------------------------
# Chunk correlation
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class ChunkMessage:
    msg_type: str
    channel: str
    seq: int
    data: str
    checksum: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.msg_type, self.channel)


class ChunkCorrelator:
    """Groups the campaign's own message-protocol fields (type, channel,
    sequence number, checksum) into one reassembled blob per (type,
    channel) pair -- not by channel alone. Confirmed directly against this
    corpus's own fixture data (corpus-015/016, corpus-017): the real
    campaign's channel identifier can legitimately be reused across
    different message types from the same actor/session (a "stage"
    channel and a later "exfil" channel sharing the same ID is itself a
    correlation signal phase 3 should use -- see corpus-017's own notes),
    so keying reassembly on channel alone would wrongly merge a "stage"
    chunk with an unrelated "exfil" message that happens to reuse the same
    channel label.

    Deliberately narrow beyond that: only concatenates by ascending
    sequence number and reports whether every sequence number from 1..max
    *seen so far* is present with no gaps (no gap-filling, no reordering
    heuristics) -- a channel with a gap stays "incomplete" rather than
    silently decoding a truncated stream, matching bounded_decode's own
    "never guess" posture above.

    is_complete()'s real limitation, stated plainly rather than hidden
    behind a heuristic: the message protocol itself (confirmed against
    every corpus fixture using it) carries no "total part count" field, so
    "chunks 1..N seen, no gaps" is structurally indistinguishable from
    "this IS a genuine 1-chunk message" when N happens to be 1. The
    correlator cannot resolve that ambiguity on its own -- the real proof
    that a channel has *actually* received every part is a successful
    bounded_decode() of the reassembled bytes, not is_complete() returning
    True. Callers should attempt a decode after every add() and treat a
    continued decode failure as "still waiting on more chunks," not treat
    is_complete()==True as the final word."""

    def __init__(self) -> None:
        self._channels: dict[tuple[str, str], dict[int, ChunkMessage]] = {}

    def add(self, msg: ChunkMessage) -> None:
        self._channels.setdefault(msg.key, {})[msg.seq] = msg

    def is_complete(self, key: tuple[str, str]) -> bool:
        """No gaps in the sequence numbers seen so far for this (type,
        channel) -- see the class docstring for why this is necessary but
        not sufficient proof of true completeness."""
        parts = self._channels.get(key)
        if not parts:
            return False
        seqs = sorted(parts)
        return seqs == list(range(1, len(seqs) + 1))

    def reassembled_bytes(self, key: tuple[str, str]) -> bytes | None:
        if not self.is_complete(key):
            return None
        parts = self._channels[key]
        ordered = "".join(parts[seq].data for seq in sorted(parts))
        try:
            return ordered.encode("ascii")
        except UnicodeEncodeError:
            return None

    def keys(self) -> list[tuple[str, str]]:
        return list(self._channels)


def parse_chunk_message(raw_text: str) -> ChunkMessage | None:
    """Parses the campaign's own query-string-shaped message protocol
    (type=stage&channel=c9f2&seq=1&chk=a91f&data=<blob>) out of a raw
    sensor string. Returns None for anything that isn't shaped like a
    chunked message at all -- most corpus/production events aren't (a
    single-shot base64+gzip command like corpus-013 has no channel/seq at
    all, and correctly returns None here even though it's still something
    bounded_decode alone can handle)."""
    if "channel=" not in raw_text or "seq=" not in raw_text:
        return None
    type_m = re.search(r"type=([A-Za-z0-9_-]+)", raw_text)
    channel_m = re.search(r"channel=([A-Za-z0-9]+)", raw_text)
    seq_m = re.search(r"seq=(\d+)", raw_text)
    chk_m = re.search(r"chk=([A-Za-z0-9]+)", raw_text)
    data_m = _DATA_FIELD_RE.search(raw_text)
    if not (type_m and channel_m and seq_m and data_m):
        return None
    return ChunkMessage(
        msg_type=type_m.group(1),
        channel=channel_m.group(1),
        seq=int(seq_m.group(1)),
        data=data_m.group(1),
        checksum=chk_m.group(1) if chk_m else None,
    )
