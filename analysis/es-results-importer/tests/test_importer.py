"""Tests for importer.py's scan_source() binary branch (#638/#763).

No tests existed for this module before this change -- these focus on the
binary-source generalization specifically (ttylog's existing shape must
stay byte-for-byte unchanged; the new id_suffix/artifact_kind shape for
Ghidra's report/callgraph artifacts must derive the right doc _id and
fields), not a full walk of every JSON source (those are simple enough
that a live read of build_document()/doc_id() covers the risk better than
a mock).
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


if __name__ == "__main__":
    unittest.main()
