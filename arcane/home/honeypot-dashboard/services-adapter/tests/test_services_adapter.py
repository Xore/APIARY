#!/usr/bin/env python3
"""#197: allowlist enforcement and response handling for services-adapter.py.

Every test mocks docker_request()/docker_request_raw() -- these tests must
run without a real Docker socket, and more importantly, the allowlist tests
specifically assert the mock is never called at all for a disallowed name,
proving the rejection happens before any Docker API call, not just that the
result looks right.
"""
import importlib.util
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("services_adapter", HERE / "services-adapter.py")
adapter = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(adapter)


def docker_log_frame(stream: int, payload: bytes) -> bytes:
    """Build one Docker log-multiplexing frame (8-byte header + payload)."""
    return bytes([stream, 0, 0, 0]) + len(payload).to_bytes(4, "big") + payload


class AllowlistEnforcementTests(unittest.TestCase):
    def test_perform_action_rejects_disallowed_name_without_calling_docker(self):
        with mock.patch.object(adapter, "docker_request") as mocked:
            status, payload = adapter.perform_action("hp-elasticsearch", "restart")
        self.assertEqual(status, 403)
        self.assertIn("error", payload)
        mocked.assert_not_called()

    def test_perform_action_rejects_unsupported_action_for_an_allowed_name(self):
        with mock.patch.object(adapter, "docker_request") as mocked:
            status, payload = adapter.perform_action("hp-cowrie", "delete")
        self.assertEqual(status, 400)
        mocked.assert_not_called()

    def test_perform_action_succeeds_for_an_allowed_name_and_action(self):
        with mock.patch.object(adapter, "docker_request", return_value=(204, None)) as mocked:
            status, payload = adapter.perform_action("hp-cowrie", "restart")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        mocked.assert_called_once_with("POST", "/containers/hp-cowrie/restart")

    def test_perform_action_passes_through_a_missing_container(self):
        with mock.patch.object(adapter, "docker_request", return_value=(404, None)):
            status, _ = adapter.perform_action("hp-cowrie", "start")
        self.assertEqual(status, 404)

    def test_perform_action_reports_unexpected_docker_status_as_502(self):
        with mock.patch.object(adapter, "docker_request", return_value=(500, None)):
            status, _ = adapter.perform_action("hp-cowrie", "stop")
        self.assertEqual(status, 502)

    def test_fetch_logs_rejects_disallowed_name_without_calling_docker(self):
        with mock.patch.object(adapter, "docker_request_raw") as mocked:
            status, text = adapter.fetch_logs("hp-dashboard", 200)
        self.assertEqual(status, 403)
        self.assertEqual(text, "")
        mocked.assert_not_called()

    def test_fetch_logs_caps_requested_lines(self):
        with mock.patch.object(adapter, "docker_request_raw", return_value=(200, b"")) as mocked:
            adapter.fetch_logs("hp-cowrie", 999999)
        called_path = mocked.call_args.args[1]
        self.assertIn(f"tail={adapter.MAX_LOG_LINES}", called_path)


class ContainerStatusTests(unittest.TestCase):
    def test_missing_container_reports_not_found_not_an_error(self):
        with mock.patch.object(adapter, "docker_request", return_value=(404, None)):
            result = adapter.container_status("hp-cowrie")
        self.assertEqual(result, {"name": "hp-cowrie", "state": "not_found"})

    def test_malformed_response_reports_unknown_rather_than_raising(self):
        with mock.patch.object(adapter, "docker_request", return_value=(200, "not-a-dict")):
            result = adapter.container_status("hp-cowrie")
        self.assertEqual(result["state"], "unknown")

    def test_healthy_running_container_reports_full_fields(self):
        body = {
            "State": {"Status": "running", "ExitCode": 0, "StartedAt": "2026-08-01T00:00:00Z",
                       "Health": {"Status": "healthy"}},
            "RestartCount": 2,
        }
        with mock.patch.object(adapter, "docker_request", return_value=(200, body)):
            result = adapter.container_status("hp-conpot")
        self.assertEqual(result["state"], "running")
        self.assertEqual(result["health"], "healthy")
        self.assertEqual(result["restart_count"], 2)

    def test_list_services_covers_every_allowlisted_container(self):
        with mock.patch.object(adapter, "docker_request", return_value=(404, None)):
            services = adapter.list_services()
        self.assertEqual({s["name"] for s in services}, adapter.ALLOWED_CONTAINERS)

    def test_post_1418_sensor_stacks_are_observable(self):
        # #2089: nine sensor stacks shipped after this allowlist was first
        # written and none of them ever joined it -- /v1/services reported
        # nothing for them at all, and "nothing" reads as healthy from the
        # pane rather than as "not observable". Pinned so the next new stack
        # does not repeat the drift silently.
        for name in (
            "hp-beelzebub",
            "hp-hellpot",
            "hp-wordpot",
            "hp-mailoney",
            "hp-galah",
            "hp-galah-llm-broker",
            "hp-sentrypeer",
            "hp-elasticpot",
            "hp-endlessh",
            "hp-honeyfs-implant",
            "hp-zeek-proxy",
            "hp-canarytokens-redis",
            "hp-canarytokens-frontend",
            "hp-canarytokens-switchboard",
            "hp-canarytokens-http-router",
            "hp-canarytokens-adapter",
        ):
            self.assertIn(name, adapter.ALLOWED_CONTAINERS)


class LogDemuxTests(unittest.TestCase):
    def test_demuxes_stdout_and_stderr_frames_in_order(self):
        raw = docker_log_frame(1, b"stdout line\n") + docker_log_frame(2, b"stderr line\n")
        self.assertEqual(adapter._demux_docker_log_stream(raw), "stdout line\nstderr line\n")

    def test_falls_back_to_raw_decode_when_shorter_than_one_frame_header(self):
        # A buffer under 8 bytes can't contain even one frame header, so the
        # parser can't have produced any frames -- raw decode is the only
        # sane fallback rather than silently returning empty output.
        self.assertEqual(adapter._demux_docker_log_stream(b"short"), "short")


class NameRouteTests(unittest.TestCase):
    def test_matches_a_valid_action_path(self):
        match = adapter.NAME_ROUTE.match("/v1/services/hp-cowrie/restart")
        self.assertIsNotNone(match)
        self.assertEqual(match.groups(), ("hp-cowrie", "restart"))

    def test_rejects_path_traversal_attempts(self):
        self.assertIsNone(adapter.NAME_ROUTE.match("/v1/services/../../etc/passwd/restart"))

    def test_rejects_an_unsupported_verb_segment(self):
        self.assertIsNone(adapter.NAME_ROUTE.match("/v1/services/hp-cowrie/delete"))


if __name__ == "__main__":
    unittest.main()
