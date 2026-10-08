#!/usr/bin/env python3
"""arkime-init's composable-templates.js must put a shadowed template back.

GET /_index_template returns system-managed fields (created_date_millis,
modified_date_millis) that Elasticsearch refuses on PUT. Stashing the body
verbatim made every restore fail with HTTP 400 and arkime-init exit 1 (#3549).
Runs the real script's `shadow` and `generate` passes against a fake
Elasticsearch that enforces the same rule.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "arcane" / "home" / "honeypot-init" / "arkime" / "composable-templates.js"
SYSTEM_FIELDS = {"created_date", "created_date_millis", "modified_date", "modified_date_millis"}
CATCH_ALL = {
    "index_patterns": ["*"],
    "priority": 1,
    "template": {"settings": {"index.number_of_replicas": 0}},
}


class FakeElasticsearch(BaseHTTPRequestHandler):
    templates: dict[str, dict] = {}

    def log_message(self, *_args) -> None:
        pass

    def reply(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/_index_template":
            listed = [
                {"name": name, "index_template": body | {"created_date_millis": 1, "modified_date_millis": 2}}
                for name, body in self.templates.items()
            ]
            return self.reply(200, {"index_templates": listed})
        self.reply(404, {})

    def do_PUT(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        if self.path.startswith("/_index_template/"):
            managed = SYSTEM_FIELDS & body.keys()
            if managed:
                return self.reply(400, {"error": f"managed by the system: {sorted(managed)[0]}"})
            self.templates[self.path.rsplit("/", 1)[1]] = body
        self.reply(200, {"acknowledged": True})

    def do_DELETE(self) -> None:
        self.templates.pop(self.path.rsplit("/", 1)[1], None)
        self.reply(200, {"acknowledged": True})

    def do_POST(self) -> None:
        self.reply(404, {})


@unittest.skipUnless(shutil.which("node"), "node is required")
class ArkimeComposableRestoreTest(unittest.TestCase):
    def test_shadowed_catch_all_is_put_back_without_system_fields(self) -> None:
        FakeElasticsearch.templates = {"single-node-replica-default": dict(CATCH_ALL)}
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeElasticsearch)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as temp:
                env = os.environ | {
                    "ARKIME__elasticsearch": f"http://127.0.0.1:{server.server_port}",
                    "SHADOW_FILE": str(Path(temp) / "shadow" / "shadow.json"),
                }
                for mode in ("shadow", "generate"):
                    proc = subprocess.run(
                        ["node", str(SCRIPT), mode], env=env, capture_output=True, text=True, timeout=60
                    )
                    self.assertEqual(proc.returncode, 0, f"{mode}: {proc.stdout}\n{proc.stderr}")
        finally:
            server.shutdown()
        self.assertEqual(FakeElasticsearch.templates.get("single-node-replica-default"), CATCH_ALL)


if __name__ == "__main__":
    unittest.main()
