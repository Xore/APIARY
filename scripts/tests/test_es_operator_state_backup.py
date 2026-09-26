#!/usr/bin/env python3
"""Tests for scripts/es-operator-state-backup.py (#3323).

The script's whole value is that a rebuild can get operator-authored state
back into Elasticsearch, so what is under test is the round trip, not the
file format: a stub Elasticsearch stands in for the cluster, the real script
runs against it over a real HTTP client, and the export it writes is restored
into scratch indices and compared document by document. That is the "test it
once into a scratch index" acceptance criterion, run on every CI pass instead
of once by hand.

The stub implements only the endpoints the script uses -- `_mapping`,
`_search` with a scroll cursor, `_search/scroll`, `_refresh`, index create
and `_bulk` -- and answers anything else with 501, so a change that starts
depending on an endpoint neither the script's docstring nor the runbook
mentions fails here instead of on the homeserver.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "es-operator-state-backup.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("es_operator_state_backup", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves annotations through sys.modules[cls.__module__],
    # so the module has to be registered before it is executed.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TOOL = load_tool()
LEDGER = list(TOOL.LEDGER)
DERIVED = list(TOOL.DERIVED)

# What GET _mapping really answers with: the mappings a restore needs, plus
# the server-generated settings a create-index request is not guaranteed to
# accept back.
MAPPING = {
    "dashboard-config-v1": {
        "settings": {"index": {"uuid": "abc", "creation_date": "1750000000000",
                               "provided_name": "dashboard-config-v1",
                               "number_of_shards": "1"}},
        "mappings": {"properties": {"revision": {"type": "long"},
                                    "payload": {"type": "flattened"}}}},
    "dashboard-users-v1": {
        "mappings": {"properties": {"subject": {"type": "keyword"}}}},
    "dashboard-alert-state-v1": {
        "mappings": {"properties": {"Key": {"type": "keyword"},
                                    "Acknowledged": {"type": "boolean"}}}},
    "dashboard-problem-reports-v1": {
        "mappings": {"properties": {"submitted_at": {"type": "date"}}}},
}

PRESENT = ("dashboard-config-v1", "dashboard-users-v1", "dashboard-alert-state-v1",
           "dashboard-problem-reports-v1")


class FakeEs:
    """The slice of Elasticsearch this tool is allowed to use."""

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.documents: dict[str, dict[str, dict]] = {}
        self.indices: dict[str, dict] = {}
        self.cursors: dict[str, list] = {}
        self.calls: list[str] = []
        self.failing: set[str] = set()
        self._next = 0

    def seed(self, index: str, count: int = 1, prefix: str = "") -> None:
        """Replace the index's contents, so a re-seed is a different
        fixture rather than an addition to the previous one."""
        self.indices[index] = MAPPING.get(index, {"mappings": {"properties": {}}})
        self.documents[index] = {}
        for number in range(count):
            doc_id = f"{prefix}doc-{number}"
            self.documents[index][doc_id] = {
                "payload": {"revision": number, "note": f"row {number}"},
            }

    def open_cursor(self, index: str, size: int) -> str:
        self._next += 1
        cursor = f"scroll-{self._next}"
        self.cursors[cursor] = [index, size, 0]
        return cursor

    def page(self, cursor: str) -> dict:
        index, size, offset = self.cursors[cursor]
        documents = self.documents.get(index, {})
        ids = list(documents)[offset:offset + size]
        self.cursors[cursor][2] = offset + len(ids)
        return {
            "_scroll_id": cursor,
            "hits": {
                "total": {"value": len(documents)},
                "hits": [{"_index": index, "_id": doc_id, "_source": documents[doc_id]}
                         for doc_id in ids],
            },
        }

    def scroll(self, cursor: str) -> dict:
        if cursor not in self.cursors:
            return {"error": {"type": "search_context_missing_exception",
                              "reason": f"No search context found for id [{cursor}]"},
                    "status": 404}
        return self.page(cursor)


class Handler(BaseHTTPRequestHandler):
    cluster: FakeEs

    def log_message(self, *args):
        """Silence the stub's request log."""

    # -- plumbing ---------------------------------------------------------
    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _not_implemented(self, path: str) -> None:
        self._send(501, {"error": {"type": "not_implemented",
                                   "reason": f"the stub has no route for {path}"},
                         "status": 501})

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _route(self) -> tuple[str, dict, list[str]]:
        parsed = urlparse(self.path)
        self.cluster.calls.append(f"{self.command} {parsed.path}")
        return parsed.path, parse_qs(parsed.query), [s for s in parsed.path.split("/") if s]

    def _unknown(self, *names: str) -> bool:
        missing = [name for name in names if name not in self.cluster.indices]
        if missing:
            self._send(404, {"error": {"type": "index_not_found_exception",
                                       "reason": f"no such index [{missing[0]}]"},
                             "status": 404})
            return True
        broken = [name for name in names if name in self.cluster.failing]
        if broken:
            self._send(503, {"error": {"type": "search_phase_execution_exception",
                                       "reason": "stubbed failure"}, "status": 503})
            return True
        return False

    # -- routes -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        path, _, segments = self._route()
        if not segments:
            self._send(200, {"version": {"number": "9.5.3"}})
        elif segments[-1] == "_count" and len(segments) == 2:
            if not self._unknown(segments[0]):
                self._send(200, {"count": len(self.cluster.documents.get(segments[0], {}))})
        elif segments[-1] == "_mapping" and len(segments) == 2:
            if not self._unknown(segments[0]):
                self._send(200, {segments[0]: self.cluster.indices[segments[0]]})
        else:
            self._not_implemented(path)

    def do_PUT(self) -> None:  # noqa: N802
        path, _, segments = self._route()
        self._body()
        if len(segments) != 1:
            self._not_implemented(path)
            return
        index = segments[0]
        if index in self.cluster.indices:
            self._send(400, {"error": {"type": "resource_already_exists_exception",
                                       "reason": f"index [{index}] already exists"},
                             "status": 400})
            return
        self.cluster.indices[index] = {}
        self.cluster.documents.setdefault(index, {})
        self._send(200, {"acknowledged": True, "index": index})

    def do_DELETE(self) -> None:  # noqa: N802
        path, _, _ = self._route()
        self._body()
        if path == "/_search/scroll":
            self._send(200, {"succeeded": True, "num_freed": 1})
        else:
            self._not_implemented(path)

    def do_POST(self) -> None:  # noqa: N802
        path, query, segments = self._route()
        body = self._body()
        if segments[-1:] == ["_refresh"]:
            if not self._unknown(*segments[:-1]):
                self._send(200, {"_shards": {"total": 1, "successful": 1, "failed": 0}})
            return
        if segments[-1] == "_search" and len(segments) == 2:
            index = segments[0]
            if self._unknown(index):
                return
            size = int(query.get("size", ["500"])[0])
            self._send(200, self.cluster.page(self.cluster.open_cursor(index, size)))
            return
        if segments == ["_search", "scroll"]:
            request = json.loads(body or b"{}")
            cursor = request.get("scroll_id", "")
            if cursor not in self.cluster.cursors:
                self._send(404, {"error": {"type": "search_context_missing_exception",
                                           "reason": "no such cursor"}, "status": 404})
                return
            self._send(200, self.cluster.scroll(cursor))
            return
        if segments[-1] == "_bulk" and len(segments) == 2:
            self._bulk(segments[0], body)
            return
        self._not_implemented(path)

    def _bulk(self, index: str, body: bytes) -> None:
        if index in self.cluster.failing:
            self._send(200, {"took": 1, "errors": True, "items": [
                {"index": {"_id": "x", "status": 400, "error": {
                    "type": "mapper_parsing_exception", "reason": "stubbed failure"}}}]})
            return
        lines = [line for line in body.decode().splitlines() if line.strip()]
        if len(lines) % 2:
            # What Elasticsearch answers for a body whose last document has
            # no terminating newline -- the shape a truncated file has.
            self._send(400, {"error": {"type": "illegal_argument_exception",
                                       "reason": "the bulk request must be "
                                                 "terminated by a newline\n"},
                             "status": 400})
            return
        self.cluster.indices.setdefault(index, {})
        items = []
        for action, source in zip(lines[0::2], lines[1::2]):
            doc_id = json.loads(action)["index"]["_id"]
            self.cluster.documents.setdefault(index, {})[doc_id] = json.loads(source)
            items.append({"index": {"_id": doc_id, "status": 201}})
        self._send(200, {"took": 1, "errors": False, "items": items})


class Harness(unittest.TestCase):
    cluster: FakeEs
    server: ThreadingHTTPServer
    thread: threading.Thread

    @classmethod
    def setUpClass(cls) -> None:
        cls.cluster = FakeEs()
        handler = type("BoundHandler", (Handler,), {"cluster": cls.cluster})
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self) -> None:
        self.cluster.reset()
        for index, count in (("dashboard-config-v1", 1), ("dashboard-users-v1", 1),
                             ("dashboard-alert-state-v1", 3),
                             ("dashboard-problem-reports-v1", 2)):
            self.cluster.seed(index, count)
        # The rest of the ledger was never created, which is the state a
        # cluster is in for most of it.

    def run_tool(self, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
        environment = dict(os.environ)
        environment.update({"ES_URL": self.base_url, "ES_CURL_BIN": "curl",
                            "ES_CURL_TIMEOUT": "30"})
        environment.update(env or {})
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              capture_output=True, text=True, check=False,
                              env=environment)

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}"

    def export(self, dest: pathlib.Path, env: dict | None = None,
               *extra: str) -> subprocess.CompletedProcess:
        result = self.run_tool("--dest", str(dest), *extra, env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def bulk_pairs(self, path: pathlib.Path) -> list:
        lines = [line for line in path.read_text().splitlines() if line.strip()]
        self.assertEqual(len(lines) % 2, 0,
                         f"{path} is not whole action/document pairs")
        return [(json.loads(action)["index"]["_id"], json.loads(source))
                for action, source in zip(lines[0::2], lines[1::2])]


@unittest.skipUnless(shutil.which("curl"), "curl not installed")
class ExportTests(Harness):

    def test_export_writes_a_mapping_and_a_bulk_body_per_present_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "es-operator-state"
            self.export(dest)
            for index in PRESENT:
                self.assertTrue((dest / f"{index}.mapping.json").is_file(), index)
                self.assertTrue((dest / f"{index}.docs.ndjson").is_file(), index)
            self.assertEqual([doc_id for doc_id, _ in self.bulk_pairs(
                dest / "dashboard-alert-state-v1.docs.ndjson")],
                ["doc-0", "doc-1", "doc-2"])

    def test_the_action_lines_carry_no_index_so_the_documented_post_is_unambiguous(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "out"
            self.export(dest)
            for line in (dest / "dashboard-config-v1.docs.ndjson").read_text().splitlines():
                parsed = json.loads(line)
                if "index" in parsed:
                    self.assertNotIn("_index", parsed["index"])

    def test_the_mapping_export_drops_the_settings_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "out"
            self.export(dest)
            mapping = json.loads(
                (dest / "dashboard-problem-reports-v1.mapping.json").read_text())
            self.assertEqual(list(mapping), ["mappings"],
                             "the file is PUT verbatim as a create-index body, "
                             "so index.uuid/index.creation_date must not be in it")
            self.assertIn("submitted_at", mapping["mappings"]["properties"])

    def test_more_documents_than_one_page_come_through_the_scroll_cursor(self):
        self.cluster.seed("dashboard-alert-state-v1", 7, prefix="many-")
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "out"
            self.export(dest, env={"ES_PAGE_SIZE": "2"})
            pairs = self.bulk_pairs(dest / "dashboard-alert-state-v1.docs.ndjson")
            self.assertEqual(len(pairs), 7)
            calls = " ".join(self.cluster.calls)
            self.assertIn("/_search/scroll", calls)
            self.assertIn("DELETE /_search/scroll", calls,
                          "the cursor has to be released, not left to expire")

    def test_an_index_that_was_never_created_is_reported_not_faked(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "out"
            result = self.export(dest)
            self.assertFalse((dest / "dashboard-canarytokens-v1.docs.ndjson").exists())
            manifest = (dest / "MANIFEST.txt").read_text()
            self.assertIn("absent", manifest)
            for index, _ in LEDGER:
                self.assertIn(index, manifest,
                              f"{index} is unaccounted for in the manifest")
            self.assertIn("4 of 10 indices captured", manifest)

    def test_one_unreadable_index_does_not_cost_the_others(self):
        self.cluster.failing.add("dashboard-users-v1")
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "out"
            self.export(dest)
            self.assertTrue((dest / "dashboard-config-v1.docs.ndjson").is_file())
            self.assertIn("failed", (dest / "MANIFEST.txt").read_text())
            self.assertIn("FAILED", self.export(dest).stderr)

    def test_an_unreachable_cluster_exits_non_zero_and_writes_no_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "out"
            result = self.run_tool("--dest", str(dest), env={
                "ES_URL": "http://127.0.0.1:1", "ES_CURL_TIMEOUT": "2"})
            self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
            self.assertIn("not reachable", result.stderr)
            self.assertFalse((dest / "MANIFEST.txt").exists(),
                             "a manifest here would read as a good backup")

    def test_a_capped_index_is_truncated_between_documents_and_says_so(self):
        self.cluster.seed("dashboard-alert-state-v1", 20, prefix="big-")
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "out"
            # Three documents per page and a cap below a full page's worth,
            # so the cap has to bite partway through the scroll.
            result = self.export(dest, env={"ES_PAGE_SIZE": "3",
                                            "ES_MAX_INDEX_BYTES": "400"})
            pairs = self.bulk_pairs(dest / "dashboard-alert-state-v1.docs.ndjson")
            self.assertGreater(len(pairs), 0)
            self.assertLess(len(pairs), 20)
            self.assertEqual(len(pairs) % 1, 0)
            manifest = (dest / "MANIFEST.txt").read_text()
            self.assertIn("truncated", manifest)
            self.assertIn("ES_MAX_INDEX_BYTES", manifest)


@unittest.skipUnless(shutil.which("curl"), "curl not installed")
class RestoreTests(Harness):
    """The acceptance criterion: export, restore into a scratch index, compare."""

    SCRATCH = "restore-check-{index}"

    def test_a_round_trip_into_a_scratch_index_reproduces_every_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "es-operator-state"
            self.export(dest)
            result = self.run_tool("--restore", str(dest), "--into", self.SCRATCH)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for index in PRESENT:
                target = self.SCRATCH.format(index=index)
                self.assertEqual(self.cluster.documents[target],
                                 self.cluster.documents[index],
                                 f"{index} did not survive the round trip")

    def test_the_restore_creates_its_target_and_reflects_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "out"
            self.export(dest)
            self.assertEqual(self.run_tool("--restore", str(dest), "--into",
                                           self.SCRATCH).returncode, 0)
            self.assertIn(f"PUT /{self.SCRATCH.format(index='dashboard-config-v1')}",
                          self.cluster.calls)
            for index in PRESENT:
                self.assertIn(f"POST /{self.SCRATCH.format(index=index)}/_refresh",
                              self.cluster.calls,
                              "without the refresh a _count right after the "
                              "restore reads zero")

    def test_a_bulk_the_cluster_rejects_fails_the_restore_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "out"
            self.export(dest)
            self.cluster.failing.add(self.SCRATCH.format(index="dashboard-config-v1"))
            result = self.run_tool("--restore", str(dest), "--into", self.SCRATCH)
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn("FAILED", result.stderr)

    def test_a_truncated_bulk_body_is_refused_rather_than_half_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = pathlib.Path(tmp) / "out"
            self.export(dest)
            broken = dest / "dashboard-config-v1.docs.ndjson"
            broken.write_text(broken.read_text() + '{"partial":\n')
            scratch = self.SCRATCH.format(index="dashboard-config-v1")
            result = self.run_tool("--restore", str(dest), "--into", self.SCRATCH,
                                   "--index", "dashboard-config-v1")
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn("not a usable bulk body", result.stderr)
            self.assertNotIn(f"POST /{scratch}/_bulk", self.cluster.calls,
                             "a body that did not parse must never be sent")
            self.assertNotIn(scratch, self.cluster.documents,
                             "a half-restored index is worse than none")

    def test_restoring_a_directory_with_nothing_in_it_is_an_argument_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_tool("--restore", tmp)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)


class LedgerTests(unittest.TestCase):
    """The ledger is the entire scope of the tool; these pin its shape."""

    def test_ledger_indexes_are_distinct_and_look_like_real_indices(self):
        names = [name for name, _ in LEDGER]
        self.assertEqual(len(names), len(set(names)))
        for name in names:
            self.assertRegex(name, r"^dashboard-[a-z0-9-]+-v1$", name)

    def test_every_ledger_entry_carries_a_reason(self):
        for name, why in LEDGER + DERIVED:
            self.assertTrue(why.strip(), f"{name} has no stated reason")

    def test_no_index_is_both_exported_and_excluded(self):
        exported = {name for name, _ in LEDGER}
        self.assertFalse(exported & {name for name, _ in DERIVED})

    def test_an_index_off_the_ledger_is_refused_by_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            environment = dict(os.environ, ES_CURL_BIN="curl", ES_URL="http://127.0.0.1:1")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--dest", tmp,
                 "--index", "dashboard-payload-inventory-v1"],
                capture_output=True, text=True, check=False, env=environment)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("not in the ledger", result.stderr)

    def test_list_prints_both_halves_of_the_scope(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--list"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not exported", result.stdout)
        for name, _ in LEDGER + DERIVED:
            self.assertIn(name, result.stdout)


class DocumentationTests(unittest.TestCase):
    """The runbooks and the tool must not disagree about what is backed up."""

    def runbook(self) -> str:
        return (REPO_ROOT / "docs" / "BACKUP-ESSENTIALS.md").read_text()

    def test_every_exported_index_is_named_in_the_runbook(self):
        text = self.runbook()
        for name, _ in LEDGER:
            self.assertIn(name, text,
                          f"{name} is exported by the tool but absent from "
                          f"docs/BACKUP-ESSENTIALS.md")

    def test_every_excluded_index_is_explained_in_the_runbook_too(self):
        text = self.runbook()
        for name, _ in DERIVED:
            self.assertIn(name, text,
                          f"{name} is excluded by the tool but never justified "
                          f"in the runbook")

    def test_the_settings_runbook_no_longer_claims_a_snapshot_policy_covers_it(self):
        text = (REPO_ROOT / "docs" / "settings-operations.md").read_text()
        # The old §Backup deferred to a cluster-wide policy that has never
        # existed. Nothing may reintroduce that deferral in any wording, so
        # the note recording the fix paraphrases rather than quotes it.
        self.assertNotIn("snapshot/backup policy", text)
        self.assertIn("es-operator-state-backup.py", text)

    def test_both_backup_scripts_export_operator_state(self):
        essentials = (REPO_ROOT / "scripts" / "backup-essentials.sh").read_text()
        onhost = (REPO_ROOT / "analysis" / "backup-honeypot.sh").read_text()
        for name, text in (("scripts/backup-essentials.sh", essentials),
                           ("analysis/backup-honeypot.sh", onhost)):
            self.assertIn("es-operator-state-backup.py", text,
                          f"{name} leaves operator state in no backup at all")

    def test_the_essentials_runbook_does_not_claim_elasticsearch_is_unbacked(self):
        text = self.runbook()
        self.assertIn("es-operator-state/", text)
        self.assertIn("MANIFEST.txt", text)


if __name__ == "__main__":
    unittest.main()
