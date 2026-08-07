"""Tests for importer.py's scan_source() binary/chunked branches
(#638/#763/#764) and the run_pass() state-advancement fix #764 needed.

No tests existed for this module before #763 -- these focus on the
binary-source generalization specifically (ttylog's existing shape must
stay byte-for-byte unchanged; the new id_suffix/artifact_kind shape for
Ghidra's report/callgraph artifacts must derive the right doc _id and
fields), the new chunked-source branch #764 added (sandbox export
artifacts split across multiple documents), and
advance_state_after_bulk()'s own correctness property (a chunked file's
multiple actions sharing one key must not have state[key] advance on a
partial success) -- not a full walk of every JSON source (those are
simple enough that a live read of build_document()/doc_id() covers the
risk better than a mock).
"""

import base64
import importlib.util
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "importer.py"
SPEC = importlib.util.spec_from_file_location("importer", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules["importer"] = MODULE
SPEC.loader.exec_module(MODULE)

SHA = "a" * 64


class ScanSourceBinaryTest(unittest.TestCase):
    def test_ttylog_source_shape_is_unchanged(self):
        """The original binary source (cowrie_ttylog): doc _id is the bare
        filename, _source uses shasum/ttylog_base64 -- this must stay
        exactly as it always was, since it's a live production mechanism
        this change did not intend to touch."""
        source = next(s for s in MODULE.SOURCES if s["label"] == "cowrie_ttylog")
        self.assertNotIn("id_suffix", source)

        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / SHA).write_bytes(b"ttylog bytes")
            pending = MODULE.scan_source(source, root, {})

        self.assertEqual(len(pending), 1)
        _, _, action = pending[0]
        self.assertEqual(action["_id"], SHA)
        self.assertEqual(action["_index"], "cowrie-ttylog-v1")
        self.assertEqual(action["_source"]["shasum"], SHA)
        self.assertEqual(
            base64.b64decode(action["_source"]["ttylog_base64"]), b"ttylog bytes"
        )
        self.assertNotIn("sha256", action["_source"])
        self.assertNotIn("kind", action["_source"])

    def test_ghidra_report_html_source_derives_sha_and_kind_from_filename(self):
        source = next(s for s in MODULE.SOURCES if s["label"] == "ghidra_report_html")
        self.assertEqual(source["index"], "ghidra-report-artifacts-v1")

        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / f"{SHA}_ghidra_report.html").write_bytes(b"<h1>report</h1>")
            pending = MODULE.scan_source(source, root, {})

        self.assertEqual(len(pending), 1)
        _, _, action = pending[0]
        self.assertEqual(action["_id"], f"{SHA}:report")
        self.assertEqual(action["_index"], "ghidra-report-artifacts-v1")
        self.assertEqual(action["_source"]["sha256"], SHA)
        self.assertEqual(action["_source"]["kind"], "report")
        self.assertEqual(action["_source"]["content_type"], "text/html")
        self.assertEqual(action["_source"]["filename"], f"{SHA}_ghidra_report.html")
        self.assertEqual(
            base64.b64decode(action["_source"]["data_base64"]), b"<h1>report</h1>"
        )

    def test_ghidra_callgraph_svg_source_derives_sha_and_kind_from_filename(self):
        source = next(s for s in MODULE.SOURCES if s["label"] == "ghidra_callgraph_svg")

        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / f"{SHA}_callgraph.svg").write_bytes(b"<svg/>")
            pending = MODULE.scan_source(source, root, {})

        self.assertEqual(len(pending), 1)
        _, _, action = pending[0]
        self.assertEqual(action["_id"], f"{SHA}:callgraph")
        self.assertEqual(action["_source"]["kind"], "callgraph")
        self.assertEqual(action["_source"]["content_type"], "image/svg+xml")

    def test_report_and_callgraph_for_the_same_sample_do_not_collide(self):
        """Both artifact kinds share ghidra-report-artifacts-v1 -- the whole
        point of "<sha256>:<kind>" doc ids is that indexing both for one
        sample produces two distinct documents, not one overwriting the
        other."""
        report_source = next(s for s in MODULE.SOURCES if s["label"] == "ghidra_report_html")
        callgraph_source = next(s for s in MODULE.SOURCES if s["label"] == "ghidra_callgraph_svg")

        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / f"{SHA}_ghidra_report.html").write_bytes(b"report")
            (root / f"{SHA}_callgraph.svg").write_bytes(b"<svg/>")
            report_pending = MODULE.scan_source(report_source, root, {})
            callgraph_pending = MODULE.scan_source(callgraph_source, root, {})

        report_id = report_pending[0][2]["_id"]
        callgraph_id = callgraph_pending[0][2]["_id"]
        self.assertNotEqual(report_id, callgraph_id)
        self.assertEqual({report_id, callgraph_id}, {f"{SHA}:report", f"{SHA}:callgraph"})

    def test_oversized_artifact_is_skipped_not_indexed(self):
        source = next(s for s in MODULE.SOURCES if s["label"] == "ghidra_report_html")
        original_max = MODULE.MAX_TTYLOG_BYTES
        MODULE.MAX_TTYLOG_BYTES = 10
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / f"{SHA}_ghidra_report.html").write_bytes(b"x" * 100)
                pending = MODULE.scan_source(source, root, {})
            self.assertEqual(pending, [])
        finally:
            MODULE.MAX_TTYLOG_BYTES = original_max

    def test_unchanged_mtime_is_not_rescanned(self):
        source = next(s for s in MODULE.SOURCES if s["label"] == "ghidra_report_html")
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / f"{SHA}_ghidra_report.html"
            path.write_bytes(b"report")
            state = {str(path): path.stat().st_mtime}
            pending = MODULE.scan_source(source, root, state)
        self.assertEqual(pending, [])


JOB = "linux-20260807T000000Z-0123456789ab"


class ScanSourceChunkedTest(unittest.TestCase):
    def _host_pcap_source(self):
        return next(
            s for s in MODULE.SOURCES
            if s["env"] == "SANDBOX_RESULTS_DIR" and s["label"] == "sandbox_export_host_pcap"
        )

    def test_nine_sandbox_export_sources_generated(self):
        """3 artifact kinds x 3 backends -- see SOURCES' own generation
        loop comment for why this is generated rather than hand-repeated."""
        chunked_sources = [s for s in MODULE.SOURCES if s.get("chunked")]
        self.assertEqual(len(chunked_sources), 9)
        envs = {s["env"] for s in chunked_sources}
        self.assertEqual(envs, {"SANDBOX_RESULTS_DIR", "WINDOWS_SANDBOX_RESULTS_DIR", "GHOSTS_SANDBOX_RESULTS_DIR"})
        kinds = {s["artifact_kind"] for s in chunked_sources}
        self.assertEqual(kinds, {"host_pcap", "guest_pcap", "diagnostics"})

    def test_small_file_produces_one_chunk_that_is_also_the_manifest(self):
        source = self._host_pcap_source()
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / f"{JOB}.host.pcap").write_bytes(b"tiny pcap")
            pending = MODULE.scan_source(source, root, {})

        self.assertEqual(len(pending), 1)
        _, _, action = pending[0]
        self.assertEqual(action["_id"], f"{JOB}:host_pcap:0")
        self.assertEqual(action["_source"]["chunk_index"], 0)
        self.assertEqual(action["_source"]["total_chunks"], 1)
        self.assertEqual(action["_source"]["size_bytes"], len(b"tiny pcap"))
        self.assertEqual(base64.b64decode(action["_source"]["data_base64"]), b"tiny pcap")

    def test_large_file_splits_into_multiple_chunks_that_reassemble_exactly(self):
        source = self._host_pcap_source()
        original_chunk_bytes = MODULE.CHUNK_BYTES
        MODULE.CHUNK_BYTES = 100  # force multiple chunks from a small fixture
        try:
            data = bytes(range(256)) * 3  # 768 bytes -> 8 chunks at 100 bytes each
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / f"{JOB}.host.pcap").write_bytes(data)
                pending = MODULE.scan_source(source, root, {})
        finally:
            MODULE.CHUNK_BYTES = original_chunk_bytes

        actions = sorted((a for _, _, a in pending), key=lambda a: a["_source"]["chunk_index"])
        self.assertEqual(len(actions), 8)
        for i, action in enumerate(actions):
            self.assertEqual(action["_id"], f"{JOB}:host_pcap:{i}")
            self.assertEqual(action["_source"]["total_chunks"], 8)
            self.assertEqual(action["_source"]["size_bytes"], len(data))
        reassembled = b"".join(base64.b64decode(a["_source"]["data_base64"]) for a in actions)
        self.assertEqual(reassembled, data)

    def test_every_chunk_shares_the_same_state_key(self):
        """#764's whole reason for advance_state_after_bulk(): every chunk
        of one file must report the identical (key, mtime) pair, since
        that's what lets state-advancement correctly treat them as one
        atomic unit."""
        source = self._host_pcap_source()
        original_chunk_bytes = MODULE.CHUNK_BYTES
        MODULE.CHUNK_BYTES = 10
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                path = root / f"{JOB}.host.pcap"
                path.write_bytes(b"x" * 55)
                pending = MODULE.scan_source(source, root, {})
        finally:
            MODULE.CHUNK_BYTES = original_chunk_bytes

        self.assertGreater(len(pending), 1)
        keys = {key for key, _, _ in pending}
        mtimes = {mtime for _, mtime, _ in pending}
        self.assertEqual(len(keys), 1)
        self.assertEqual(len(mtimes), 1)

    def test_empty_file_is_skipped(self):
        source = self._host_pcap_source()
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / f"{JOB}.host.pcap").write_bytes(b"")
            pending = MODULE.scan_source(source, root, {})
        self.assertEqual(pending, [])

    def test_oversized_file_is_skipped_by_the_sanity_cap(self):
        source = self._host_pcap_source()
        original_max = MODULE.MAX_CHUNKED_ARTIFACT_BYTES
        MODULE.MAX_CHUNKED_ARTIFACT_BYTES = 10
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / f"{JOB}.host.pcap").write_bytes(b"x" * 100)
                pending = MODULE.scan_source(source, root, {})
            self.assertEqual(pending, [])
        finally:
            MODULE.MAX_CHUNKED_ARTIFACT_BYTES = original_max


class AdvanceStateAfterBulkTest(unittest.TestCase):
    def test_single_action_key_advances_on_success_only(self):
        state = {}
        pending = [("keyA", 100.0, {"_id": "docA"})]
        MODULE.advance_state_after_bulk(pending, failed_ids=set(), state=state)
        self.assertEqual(state, {"keyA": 100.0})

        state = {}
        MODULE.advance_state_after_bulk(pending, failed_ids={"docA"}, state=state)
        self.assertEqual(state, {})

    def test_multi_action_key_does_not_advance_on_partial_failure(self):
        """The actual #764 bug this exists to prevent: a chunked file's
        pending list has several actions sharing one key. If even one
        fails, state[key] must not advance -- otherwise the failed
        chunk's mtime would never trigger a retry again."""
        state = {}
        pending = [
            ("job.pcap", 200.0, {"_id": "job:host_pcap:0"}),
            ("job.pcap", 200.0, {"_id": "job:host_pcap:1"}),
            ("job.pcap", 200.0, {"_id": "job:host_pcap:2"}),
        ]
        # Chunk 1 (the middle one, not first or last) fails -- the
        # regression this specifically guards against is "whichever chunk
        # is processed last wins", so failing a middle chunk is the most
        # discriminating case.
        MODULE.advance_state_after_bulk(pending, failed_ids={"job:host_pcap:1"}, state=state)
        self.assertEqual(state, {}, "a partial failure must not advance the shared key's state")

    def test_multi_action_key_advances_once_all_succeed(self):
        state = {}
        pending = [
            ("job.pcap", 200.0, {"_id": "job:host_pcap:0"}),
            ("job.pcap", 200.0, {"_id": "job:host_pcap:1"}),
        ]
        MODULE.advance_state_after_bulk(pending, failed_ids=set(), state=state)
        self.assertEqual(state, {"job.pcap": 200.0})

    def test_independent_keys_are_tracked_independently(self):
        state = {}
        pending = [
            ("keyA", 1.0, {"_id": "a:0"}),
            ("keyA", 1.0, {"_id": "a:1"}),
            ("keyB", 2.0, {"_id": "b:0"}),
        ]
        MODULE.advance_state_after_bulk(pending, failed_ids={"a:1"}, state=state)
        self.assertEqual(state, {"keyB": 2.0})


if __name__ == "__main__":
    unittest.main()
