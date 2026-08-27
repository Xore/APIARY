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

    def test_plain_json_source_still_resolves_the_module_level_doc_id_function(self):
        """Regression test for a real production incident (#1134): the
        ghidra_report_html/callgraph branch above assigns a local variable
        also named `doc_id` (scan_source's own "doc_id = f'{sha256}:...'").
        Python's static scoping makes any name assigned anywhere in a
        function local to the WHOLE function -- so that local assignment
        shadowed the module-level doc_id() function for every call to
        scan_source(), including this one, on every plain-JSON source
        (ghidra/sandbox/github_analysis/revdeck/cape alike), unconditionally,
        regardless of which branch actually ran. Confirmed live: this
        crashed hp-es-results-importer's entire import pass, every source,
        every cycle, from whenever the artifact_kind branch landed until
        fixed -- "cannot access local variable 'doc_id' where it is not
        associated with a value". The two sources are exercised back to
        back here specifically because the bug only reproduces when both
        code paths exist in the same module, which every existing test
        above already technically satisfied without ever calling this one."""
        report_source = next(s for s in MODULE.SOURCES if s["label"] == "ghidra_report_html")
        json_source = next(s for s in MODULE.SOURCES if s["label"] == "ghidra")

        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / f"{SHA}_ghidra_report.html").write_bytes(b"report")
            MODULE.scan_source(report_source, root, {})

            (root / f"{SHA}_ghidra.json").write_text('{"sha256": "%s"}' % SHA)
            pending = MODULE.scan_source(json_source, root, {})

        self.assertEqual(len(pending), 1)
        _, _, action = pending[0]
        self.assertEqual(action["_id"], f"ghidra:{SHA}")

    def test_yara_aggregate_file_explodes_into_one_document_per_sample(self):
        """#1103 Category 4: scanner.py writes one results.json covering
        every sample it has ever scanned -- unlike every other JSON source,
        which is already one-document-per-file. This must produce one ES
        action per entry in payload["samples"], all sharing the file's own
        (key, mtime) so a partial bulk failure still retries every sample
        next pass (advance_state_after_bulk's own shared-key contract)."""
        source = next(s for s in MODULE.SOURCES if s["label"] == "yara")

        sha_b = "b" * 64
        report = {
            "version": 1, "scanner": "YARA", "updated_at": "2026-08-11T00:00:00Z",
            "rules_sha256": "deadbeef", "samples": {
                SHA: {"sha256": SHA, "matches": ["susp_string"], "source": "dionaea", "size": 123},
                sha_b: {"sha256": sha_b, "matches": [], "error": "", "source": "cowrie", "size": 45},
            },
            "errors": [],
        }

        import json as jsonlib
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "results.json").write_text(jsonlib.dumps(report))
            pending = MODULE.scan_source(source, root, {})

        self.assertEqual(len(pending), 2)
        ids = {action["_id"] for _, _, action in pending}
        self.assertEqual(ids, {f"yara:{SHA}", f"yara:{sha_b}"})

        keys = {key for key, _, _ in pending}
        self.assertEqual(len(keys), 1, "both samples must share one (key, mtime) -- same source file")

        matched = next(a for _, _, a in pending if a["_id"] == f"yara:{SHA}")
        self.assertEqual(matched["_source"]["yara"]["matches"], ["susp_string"])
        self.assertEqual(matched["_source"]["file"]["hash"]["sha256"], SHA)
        self.assertEqual(matched["_source"]["report"]["rules_sha256"], "deadbeef")
        self.assertNotIn("samples", matched["_source"]["report"], "report context must exclude the (large) samples dict itself")

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


class DispatchBulkTest(unittest.TestCase):
    """#2109: bulk() batches by action count, never by bytes, so a chunked
    artifact's ~11MB documents all rode in ONE HTTP request -- anything
    past ~9 chunks exceeded ES's ~100MB body cap and the identical
    oversized request was rebuilt and rejected every pass, permanently.
    dispatch_bulk() is the seam that fixes it; these tests pin the sizing
    contract without a live Elasticsearch."""

    def _record(self):
        calls = []

        def fake_bulk(es, actions, **kwargs):
            calls.append({"actions": list(actions), "kwargs": kwargs})
            return len(actions), []

        return fake_bulk, calls

    def test_chunked_source_is_dispatched_one_action_per_request(self):
        original = MODULE.bulk
        fake_bulk, calls = self._record()
        MODULE.bulk = fake_bulk
        try:
            source = {"label": "sandbox_export_host_pcap", "chunked": True}
            pending = [
                ("job.pcap", 1.0, {"_id": "job:host_pcap:0"}),
                ("job.pcap", 1.0, {"_id": "job:host_pcap:1"}),
                ("job.pcap", 1.0, {"_id": "job:host_pcap:2"}),
            ]
            ok, errors = MODULE.dispatch_bulk(None, pending, source)
        finally:
            MODULE.bulk = original

        self.assertEqual((ok, errors), (3, []))
        # chunk_size=1 is the whole fix: one ~11MB chunk per request,
        # independent of how many chunks the artifact produced.
        self.assertEqual(calls[0]["kwargs"].get("chunk_size"), 1)
        self.assertEqual(len(calls[0]["actions"]), 3)

    def test_plain_sources_keep_the_default_batching(self):
        original = MODULE.bulk
        fake_bulk, calls = self._record()
        MODULE.bulk = fake_bulk
        try:
            source = {"label": "ghidra"}
            pending = [("a.json", 1.0, {"_id": "ghidra:x"})]
            MODULE.dispatch_bulk(None, pending, source)
        finally:
            MODULE.bulk = original

        self.assertNotIn("chunk_size", calls[0]["kwargs"])

    def test_largest_single_chunk_action_stays_well_under_the_es_body_cap(self):
        """The invariant #2109 leaves standing: with one action per
        request, no request can exceed one chunk's serialized size -- pin
        that even a full CHUNK_BYTES of incompressible data plus its
        envelope sits far below Elasticsearch's ~100MB default."""
        import json as _json
        import tempfile

        source = next(
            s for s in MODULE.SOURCES
            if s["env"] == "SANDBOX_RESULTS_DIR" and s["label"] == "sandbox_export_host_pcap"
        )
        chunk = bytes(range(256)) * (MODULE.CHUNK_BYTES // 256 + 1)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / f"{JOB}.host.pcap").write_bytes(chunk[: MODULE.CHUNK_BYTES])
            pending = MODULE.scan_source(source, root, {})

        self.assertEqual(len(pending), 1)
        largest = max(len(_json.dumps(action).encode()) for _, _, action in pending)
        self.assertLess(largest, MODULE.CHUNK_BYTES * 4 // 3 + 4096)
        self.assertLess(largest, 50 * 1024 * 1024)


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


class ScanSourceSameMtimeRaceTest(unittest.TestCase):
    """#2377 ledger row characterization of the mtime state's known
    equal-resolution race: a file rewritten within the same clock tick the
    filesystem hands out (kernel coarse-grained inode timestamps can make
    two sub-tick writes share one st_mtime) is skipped even though its
    content changed -- mtime equality is the sole change signal; nothing
    backs it up with size or content hashing.

    os.utime forces a genuinely identical st_mtime so this is
    deterministic on every filesystem, not just coarse-clock ones. The
    flip side is also pinned: the skip never becomes permanent loss --
    the next write whose mtime does advance re-imports the CURRENT bytes,
    and since document _ids are deterministic the ES mirror overwrites in
    place."""

    def test_same_tick_rewrite_skipped_then_healed_by_next_real_change(self):
        import os
        import tempfile

        # The plainest live source in this module: doc _id IS the filename
        # (a hash by production convention), arbitrary bytes, no aggregate/
        # chunked machinery -- so nothing here characterizes anything but
        # the mtime gate itself.
        source = next(s for s in MODULE.SOURCES if s["label"] == "cowrie_ttylog")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            f = root / SHA
            f.write_bytes(b"contents v1")
            state = {}

            first = MODULE.scan_source(source, root, state)
            self.assertEqual(len(first), 1, "initial import: no state yet")
            key, mtime, action = first[0]
            self.assertEqual(action["_source"]["shasum"], SHA)
            self.assertEqual(base64.b64decode(action["_source"]["ttylog_base64"]), b"contents v1")

            # Cycle succeeds -> state advances to this file's mtime.
            MODULE.advance_state_after_bulk(first, set(), state)

            # Same-tick rewrite: new bytes, mtime forced back to exactly
            # what was recorded.
            f.write_bytes(b"contents v2 CHANGED")
            os.utime(f, (mtime, mtime))
            self.assertEqual(f.stat().st_mtime, state[key])

            skipped = MODULE.scan_source(source, root, state)
            self.assertEqual(skipped, [], "equal-mtime rewrite is invisible to the scan (the characterized race)")

            # Any later write that actually moves mtime heals the mirror:
            # current bytes get indexed under the same deterministic _id.
            f.write_bytes(b"contents v3 HEALED")
            healed = MODULE.scan_source(source, root, state)
            self.assertEqual(len(healed), 1)
            _, _, heal_action = healed[0]
            self.assertEqual(heal_action["_id"], action["_id"])
            self.assertEqual(
                base64.b64decode(heal_action["_source"]["ttylog_base64"]), b"contents v3 HEALED"
            )


class VerdictProjectionTest(unittest.TestCase):
    """#2047: the ioc-verdicts-v1 projection the importer side-writes --
    raw facts per sample only, with the Rust readers rebuilding their own
    label wording through shared functions. These tests pin extraction
    from each source's emitted document body, the merge rules (replace for
    single-doc sources, never-downgrade-max for sandbox), and the pure
    doc-building core."""

    def ghidra_body(self, family, sha=None):
        return {
            "file": {"hash": {"sha256": sha or SHA}},
            "ghidra": {"ai_triage": {"family_guess": family}},
        }

    def test_extracts_raw_facts_from_each_verdict_source(self):
        ghidra = MODULE.extract_verdict_sample("ghidra", self.ghidra_body("win.lumma"))
        self.assertEqual(ghidra, (SHA, {"ghidra_family": "win.lumma"}))

        github = MODULE.extract_verdict_sample(
            "github_analysis",
            {"file": {"hash": {"sha256": SHA}}, "github_analysis": {"family": "apk.dropper"}},
        )
        self.assertEqual(github, (SHA, {"github_family": "apk.dropper"}))

        revdeck = MODULE.extract_verdict_sample(
            "revdeck",
            {
                "file": {"hash": {"sha256": SHA}},
                "revdeck": {"status": "completed", "answer": "credential stealer"},
            },
        )
        self.assertEqual(revdeck, (SHA, {"revdeck_status": "completed", "revdeck_answer": "credential stealer"}))

        sandbox = MODULE.extract_verdict_sample(
            "sandbox",
            {
                "file": {"hash": {"sha256": SHA}},
                "sandbox": {"risk_level": "high"},
                "risk_level": "high",
            },
        )
        self.assertEqual(sandbox, (SHA, {"_sandbox_level": "high"}))

    def test_non_verdict_sources_and_hashless_docs_yield_nothing(self):
        self.assertIsNone(MODULE.extract_verdict_sample("yara", {"yara": {}}))
        self.assertIsNone(MODULE.extract_verdict_sample("cowrie_ttylog", {"shasum": "x"}))
        # A ghidra document without a resolvable hash can't speak for a
        # sample -- drop it rather than guessing.
        self.assertIsNone(MODULE.extract_verdict_sample("ghidra", {"ghidra": {"ai_triage": {"family_guess": "f"}}}))

    def test_failed_documents_never_reach_the_projection(self):
        pending = [
            ("a_ghidra.json", 1.0, {"_id": f"ghidra:{SHA}", "_source": self.ghidra_body("win.lumma")}),
            ("b_ghidra.json", 2.0, {"_id": "ghidra:" + "b" * 64, "_source": self.ghidra_body("win.redux", sha="b" * 64)}),
        ]
        touched = MODULE.verdict_touched("ghidra", pending, failed_ids={f"ghidra:{SHA}"})
        self.assertEqual(len(touched), 1)
        self.assertEqual(touched[0][0], "b" * 64)

    def test_single_document_sources_replace_only_their_own_keys(self):
        prev = {
            "ghidra_family": "win.old",
            "github_family": "apk.dropper",
            "revdeck_status": "",
            "revdeck_answer": "",
            "sandbox_risk_level": "medium",
        }
        merged = MODULE.merge_verdict_fragments(
            prev, "ghidra", [(SHA, {"ghidra_family": "win.lumma"})]
        )
        self.assertEqual(merged["ghidra_family"], "win.lumma")
        # The analyses this refresh doesn't speak for keep their prior state
        # exactly -- a partial pass must not erase (#2094's rule, applied here).
        self.assertEqual(merged["github_family"], "apk.dropper")
        self.assertEqual(merged["sandbox_risk_level"], "medium")

    def test_sandbox_refresh_never_downgrades_the_best_level(self):
        prev = {"sandbox_risk_level": "critical"}
        merged = MODULE.merge_verdict_fragments(prev, "sandbox", [(SHA, {"_sandbox_level": "low"})])
        self.assertEqual(merged["sandbox_risk_level"], "critical")

        fresh_best = MODULE.merge_verdict_fragments({}, "sandbox", [
            (SHA, {"_sandbox_level": "informational"}),
            (SHA, {"_sandbox_level": "critical"}),
        ])
        self.assertEqual(fresh_best["sandbox_risk_level"], "critical")

        # Sub-threshold-only runs stay out of the projection entirely --
        # real data, but not verdicts (same bar the Rust reader applies).
        quiet = MODULE.merge_verdict_fragments({}, "sandbox", [(SHA, {"_sandbox_level": "informational"})])
        self.assertEqual(quiet["sandbox_risk_level"], "")

    def test_contributing_analyses_lists_present_sources_sorted(self):
        body = {
            "ghidra_family": "",
            "github_family": "apk.dropper",
            "revdeck_status": "completed",
            "revdeck_answer": "stealer",
            "sandbox_risk_level": "high",
        }
        self.assertEqual(MODULE.contributing_analyses(body), ["github_analysis", "revdeck", "sandbox"])

    def test_verdict_docs_for_groups_by_sha_and_merges_prior_state(self):
        existing = {
            SHA: {
                "ghidra_family": "win.old",
                "github_family": "",
                "revdeck_status": "",
                "revdeck_answer": "",
                "sandbox_risk_level": "high",
                "sha256": SHA,
                "contributing_analyses": ["ghidra", "sandbox"],
                "updated": "2026-01-01T00:00:00+00:00",
            }
        }
        actions = MODULE.verdict_docs_for(
            existing, "ghidra", [(SHA, {"ghidra_family": "win.lumma"})], now="2026-08-26T12:00:00+00:00"
        )
        self.assertEqual(len(actions), 1)
        action = actions[0]
        self.assertEqual(action["_index"], "ioc-verdicts-v1")
        self.assertEqual(action["_id"], SHA)
        source = action["_source"]
        self.assertEqual(source["ghidra_family"], "win.lumma")
        self.assertEqual(source["sandbox_risk_level"], "high")
        self.assertEqual(source["contributing_analyses"], ["ghidra", "sandbox"])
        self.assertEqual(source["updated"], "2026-08-26T12:00:00+00:00")


if __name__ == "__main__":
    unittest.main()
