#!/usr/bin/env python3
"""#197: allowlist enforcement and response handling for services-adapter.py.

Most tests mock docker_request()/docker_request_raw() -- these must run
without a real Docker socket, and the allowlist ones specifically assert the
mock is never called at all for a disallowed name, proving the rejection
happens before any Docker API call, not just that the result looks right.
FullAdapterPathTests (#2185) goes one layer wider instead: a stub Engine
socket stands in for docker.sock while the real handler serves requests over
a second unix socket, so idempotent-success responses are pinned through the
full adapter path. Still no real Docker anywhere.
"""
import http.client
import importlib.util
import json
import os
import socket
import tempfile
import threading
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

    # #2185: the Engine answers 304 Not Modified when the requested state
    # already holds -- these are idempotent successes, not failures.
    def test_perform_action_start_on_a_running_container_succeeds_with_noop_flag(self):
        with mock.patch.object(adapter, "docker_request", return_value=(304, None)) as mocked:
            status, payload = adapter.perform_action("hp-cowrie", "start")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["noop"])
        self.assertEqual(payload["action"], "start")
        self.assertEqual(payload["name"], "hp-cowrie")
        mocked.assert_called_once_with("POST", "/containers/hp-cowrie/start")

    def test_perform_action_stop_on_a_stopped_container_succeeds_with_noop_flag(self):
        with mock.patch.object(adapter, "docker_request", return_value=(304, None)) as mocked:
            status, payload = adapter.perform_action("hp-dionaea", "stop")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["noop"])
        self.assertEqual(payload["action"], "stop")
        mocked.assert_called_once_with("POST", "/containers/hp-dionaea/stop")

    def test_perform_action_restart_accepts_304_as_idempotent_success(self):
        with mock.patch.object(adapter, "docker_request", return_value=(304, None)):
            status, payload = adapter.perform_action("hp-cowrie", "restart")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])

    def test_502_error_body_carries_no_upstream_numerals(self):
        # #2185: the raw engine status used to leak straight into the body
        # ("docker engine returned 304"); 5xx bodies stay free of upstream
        # numerals even for genuine anomalies.
        for upstream_status in (409, 500, 503):
            with mock.patch.object(adapter, "docker_request", return_value=(upstream_status, None)):
                _, payload = adapter.perform_action("hp-cowrie", "start")
            self.assertEqual(payload["error"], "docker engine returned an error")

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


class _UnixHTTPConnection(http.client.HTTPConnection):
    """Minimal AF_UNIX HTTP client used to drive the real handler end to end."""

    def __init__(self, sock_path: str) -> None:
        super().__init__("localhost", timeout=10)
        self._sock_path = sock_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._sock_path)


class _FakeDockerEngine:
    """Stands in for the Engine socket, answering a fixed status line, so the
    full adapter path (handler -> perform_action -> docker_request) runs
    against an AF_UNIX listener instead of /var/run/docker.sock."""

    def __init__(self) -> None:
        self.status_line = b"HTTP/1.1 304 Not Modified"
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmpdir.name, "docker.sock")
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(self.path)
        listener.listen(8)
        self._listener = listener

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.thread.join(timeout=2)
        self._listener.close()
        self.tmpdir.cleanup()

    def _serve(self) -> None:
        self._listener.settimeout(0.25)
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                conn.settimeout(5)
                conn.recv(65536)
                conn.sendall(self.status_line + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            finally:
                conn.close()


@unittest.skipUnless(hasattr(socket, "AF_UNIX"), "requires an AF_UNIX-capable platform")
class FullAdapterPathTests(unittest.TestCase):
    """#2185 acceptance path: the Engine's 304 becomes a 200 success over the
    real HTTP handler, not only through perform_action() in isolation -- and
    genuine engine failures still surface as 502 through that same path."""

    @classmethod
    def setUpClass(cls):
        cls.engine = _FakeDockerEngine()
        cls.engine.start()
        cls.patcher = mock.patch.object(adapter, "DOCKER_SOCK", cls.engine.path)
        cls.patcher.start()
        cls.server_dir = tempfile.TemporaryDirectory()
        control_path = os.path.join(cls.server_dir.name, "control.sock")
        cls.server = adapter.ServicesServer(control_path, adapter.ServicesHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)
        cls.patcher.stop()
        cls.engine.stop()
        cls.server_dir.cleanup()

    def _post_action(self, name: str, action: str) -> tuple[int, dict]:
        conn = _UnixHTTPConnection(self.server.server_address)
        try:
            conn.request(
                "POST",
                f"/v1/services/{name}/{action}",
                body=b"{}",
                headers={"Host": "services-adapter"},
            )
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, json.loads(raw)
        finally:
            conn.close()

    def test_start_on_a_running_container_returns_success_through_the_handler(self):
        status, payload = self._post_action("hp-cowrie", "start")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["noop"])

    def test_stop_on_a_stopped_container_returns_success_through_the_handler(self):
        status, payload = self._post_action("hp-dionaea", "stop")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["noop"])

    def test_a_genuine_engine_failure_still_surfaces_as_502_without_numerals(self):
        self.engine.status_line = b"HTTP/1.1 503 Service Unavailable"
        try:
            status, payload = self._post_action("hp-cowrie", "start")
        finally:
            self.engine.status_line = b"HTTP/1.1 304 Not Modified"
        self.assertEqual(status, 502)
        self.assertFalse(any(char.isdigit() for char in payload["error"]))


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
