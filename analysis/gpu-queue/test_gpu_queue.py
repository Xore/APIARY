#!/usr/bin/env python3
"""Unit-level regression tests for gpu_queue.py's list_queue() query
construction and its transport selection (#2077) -- no live Elasticsearch or
subprocess needed, just captures of what each call sends and where.

Confirmed live (2026-08-22): gpu-job-queue's status/job_type fields have no
explicit index mapping, so Elasticsearch's dynamic mapping gave them type
"text" (analyzed) with a ".keyword" sub-field, like any other unmapped
string. list_queue()'s term filters targeted the bare (analyzed) field
name, not ".keyword" -- for "ghidra-triage" (hyphenated, so the standard
analyzer tokenizes it into "ghidra"/"triage", neither of which equals the
literal string), that term query could never match, so
gpu-queue-drain.py's `queued = gpu_queue.list_queue(..., job_type=
"ghidra-triage")` silently returned empty on every single tick -- three
real triage jobs sat "queued" for up to 11 days with zero log output
(main() only prints once it has picked up a job).

Usage: analysis/gpu-queue/test_gpu_queue.py
"""
import contextlib
import importlib.util
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("gpu_queue", HERE / "gpu_queue.py")
gpu_queue = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gpu_queue)

fails = []


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        fails.append(label)


def test_list_queue_filters_use_keyword_subfield():
    captured = {}

    def fake_request(es_host, method, path, body=None):
        captured["body"] = body
        return {"hits": {"hits": []}}

    gpu_queue._request = fake_request
    gpu_queue.list_queue("http://es.invalid:9200", status="queued", job_type="ghidra-triage")

    filters = captured["body"]["query"]["bool"]["filter"]
    fields = {list(f["term"].keys())[0] for f in filters}
    check(fields == {"status.keyword", "job_type.keyword"},
          f"list_queue's term filters target the .keyword sub-fields, got {sorted(fields)}")
    check({"status.keyword": "queued"} in [f["term"] for f in filters],
          "status filter value is unaffected by the .keyword fix")
    check({"job_type.keyword": "ghidra-triage"} in [f["term"] for f in filters],
          "job_type filter still carries the hyphenated value verbatim")


def test_list_queue_omits_filters_that_were_not_requested():
    captured = {}

    def fake_request(es_host, method, path, body=None):
        captured["body"] = body
        return {"hits": {"hits": []}}

    gpu_queue._request = fake_request
    gpu_queue.list_queue("http://es.invalid:9200")

    check(captured["body"]["query"] == {"match_all": {}},
          "no status/job_type given -> match_all, not an empty filter list")


def test_requeue_clears_started_at_and_keeps_attempts():
    # #2075: the stale-running sweep ages jobs by started_at, so a requeued
    # job must have it cleared -- otherwise the next sweep pass would see an
    # ancient started_at on the freshly-requeued job. attempts is left to
    # increment_attempts() at pickup, which is what bounds retries.
    captured = {}

    def fake_request(es_host, method, path, body=None):
        captured["path"], captured["body"] = path, body
        return {}

    gpu_queue._request = fake_request
    gpu_queue.requeue("http://es.invalid:9200", "job-1")

    check("/gpu-job-queue/_update/job-1" in captured["path"],
          "requeue targets the job's update endpoint")
    check(captured["body"] == {"doc": {"status": "queued", "started_at": None}},
          "requeue resets status and started_at, touching nothing else")


def test_transport_direct_reaches_a_local_endpoint_without_docker():
    # #2077: host-side _raw_request() routes everything through a throwaway
    # `docker run --network honeynet curlimages/curl` bridge, which can only
    # reach hosts on that Docker network -- never the runner's own loopback.
    # A test (or local debug) stub listening on 127.0.0.1 therefore silently
    # looked like an enqueue failure, and the ghidra worker suite could only
    # ever test the enqueue-fails fallback path, never the queue-success
    # deferral path the deployed default actually uses. GPU_QUEUE_TRANSPORT
    # =direct forces the plain-urllib branch instead; it must honour the same
    # tuple contract as the container branch: (status, raw_body), non-2xx
    # statuses returned rather than raised.
    srv = HTTPServer(("127.0.0.1", 0), _CaptureHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with _patched_environ({"GPU_QUEUE_TRANSPORT": "direct"}):
            status, body = gpu_queue._raw_request(
                f"http://127.0.0.1:{srv.server_port}",
                "PUT", "/gpu-job-queue/_doc/test-job?refresh=true",
                json.dumps({"probe": "payload"}).encode(),
            )
    finally:
        srv.shutdown()

    check(status == 200, f"a reachable endpoint returns its status (got {status})")
    check(json.loads(body) == {"acknowledged": True},
          f"the response body is returned whole (got {body!r})")
    check(_CaptureHandler.seen[-1][0] == "/gpu-job-queue/_doc/test-job?refresh=true",
          "the path arrives verbatim")
    check(_CaptureHandler.seen[-1][1] == '{"probe": "payload"}',
          "the request body arrives verbatim")


class _CaptureHandler(BaseHTTPRequestHandler):
    """Records one request and answers 200 -- just enough ES to stand still."""

    seen: list[tuple[str, str]] = []

    def log_message(self, *a): pass

    def _respond(self):
        self.seen.append((self.path,
                          self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()))
        payload = b'{"acknowledged": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_PUT = _respond
    do_GET = _respond


@contextlib.contextmanager
def _patched_environ(overrides):
    saved = {k: os.environ.get(k) for k in overrides}
    os.environ.update(overrides)
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


if __name__ == "__main__":
    test_list_queue_filters_use_keyword_subfield()
    test_list_queue_omits_filters_that_were_not_requested()
    test_requeue_clears_started_at_and_keeps_attempts()
    test_transport_direct_reaches_a_local_endpoint_without_docker()
    if fails:
        print(f"\n{len(fails)} failure(s)")
        sys.exit(1)
    print("\nall gpu_queue tests passed")
