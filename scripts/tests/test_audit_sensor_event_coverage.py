#!/usr/bin/env python3
"""Exercise audit-sensor-event-coverage.py's local computation: coverage()'s
percent/sort math and main()'s reporting and --fail-under gate.

#1659/#1665 replaced the old Go-source regex audit with an Elasticsearch
aggregation query (docstring in the script explains why -- there is no
per-sensor classifier left to diff against). That means the only thing
worth unit-testing here is the arithmetic and CLI behaviour around a
canned aggregation response; the query itself is an operational audit
against a live cluster, not something CI can exercise.

search() is mocked out so no network or ES is needed, and coverage() is
mocked out for the main() tests so their argument-parsing/threshold logic
is isolated from the aggregation math already covered above.

Usage: python3 -m unittest scripts.tests.test_audit_sensor_event_coverage
   or: python3 scripts/tests/test_audit_sensor_event_coverage.py
"""
from __future__ import annotations

import importlib.util
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parent.parent / "audit-sensor-event-coverage.py"
spec = importlib.util.spec_from_file_location("audit_sensor_event_coverage", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def _bucket(sensor, events, labelled, pipeline_labelled=None, kinds=()):
    return {
        "key": sensor,
        "doc_count": events,
        "labelled": {"doc_count": labelled},
        "pipeline_labelled": {"doc_count": labelled if pipeline_labelled is None else pipeline_labelled},
        "kinds": {"buckets": [{"key": k} for k in kinds]},
    }


def _agg_response(buckets):
    return {"aggregations": {"sensors": {"buckets": buckets}}}


class CoverageTest(unittest.TestCase):
    def test_computes_percent_and_sorts_worst_first(self):
        response = _agg_response([
            _bucket("cowrie", 100, 100, kinds=["telnet"]),
            _bucket("dionaea", 200, 0),
            _bucket("conpot", 50, 25),
        ])
        with mock.patch.object(mod, "search", return_value=response):
            rows = mod.coverage("24h")
        self.assertEqual([r["sensor"] for r in rows], ["dionaea", "conpot", "cowrie"])
        self.assertEqual(rows[0]["percent"], 0)
        self.assertEqual(rows[1]["percent"], 50)
        self.assertEqual(rows[2]["percent"], 100)

    def test_zero_events_does_not_divide_by_zero(self):
        response = _agg_response([_bucket("idle-sensor", 0, 0)])
        with mock.patch.object(mod, "search", return_value=response):
            rows = mod.coverage("24h")
        self.assertEqual(rows[0]["percent"], 0)

    def test_pipeline_category_tracked_separately_from_honeypot_category(self):
        response = _agg_response([_bucket("suricata", 10, 4, pipeline_labelled=10)])
        with mock.patch.object(mod, "search", return_value=response):
            rows = mod.coverage("24h")
        self.assertEqual(rows[0]["labelled"], 4)
        self.assertEqual(rows[0]["pipeline"], 10)


class MainTest(unittest.TestCase):
    def _run_main(self, argv, rows):
        with mock.patch.object(mod, "coverage", return_value=rows), \
             mock.patch.object(sys, "argv", ["audit-sensor-event-coverage.py", *argv]), \
             redirect_stdout(io.StringIO()) as out:
            code = mod.main()
        return code, out.getvalue()

    def test_no_events_short_circuits_clean(self):
        code, out = self._run_main(["--since", "1h"], [])
        self.assertEqual(code, 0)
        self.assertIn("no sensor events", out)

    def test_uncovered_sensor_is_listed(self):
        rows = [{"sensor": "dionaea", "events": 5, "labelled": 0, "percent": 0,
                 "pipeline": 0, "kinds": []}]
        code, out = self._run_main([], rows)
        self.assertEqual(code, 0)
        self.assertIn("label nothing at all", out)
        self.assertIn("dionaea", out)

    def test_fail_under_trips_on_low_coverage(self):
        rows = [{"sensor": "dionaea", "events": 5, "labelled": 1, "percent": 20,
                 "pipeline": 1, "kinds": ["x"]}]
        code, _ = self._run_main(["--fail-under", "50"], rows)
        self.assertEqual(code, 1)

    def test_fail_under_passes_above_threshold(self):
        rows = [{"sensor": "cowrie", "events": 5, "labelled": 5, "percent": 100,
                 "pipeline": 5, "kinds": ["x"]}]
        code, _ = self._run_main(["--fail-under", "50"], rows)
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
