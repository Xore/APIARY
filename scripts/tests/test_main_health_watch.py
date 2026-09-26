"""#3324 main-health-watch: issue lifecycle and untested-head dispatch against a fake gh."""
from __future__ import annotations

import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "main-health-watch.py"
_spec = importlib.util.spec_from_file_location("main_health_watch", SCRIPT)
mhw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mhw)

OLD = "2026-09-25T06:00:00Z"
GREEN_SHA, RED_SHA, HEAD_SHA = "a" * 40, "b" * 40, "c" * 40


def run(sha, conclusion, created, event="push", rid=1):
    return {"databaseId": rid, "headSha": sha, "conclusion": conclusion, "url": f"u/{rid}", "createdAt": created, "event": event}


class FakeGh:
    """Answers the gh calls the script makes; records the mutating ones."""

    def __init__(self, runs, head_sha=GREEN_SHA, head_date=OLD, runs_for_head=True, issue=None):
        self.runs, self.head_sha, self.head_date = runs, head_sha, head_date
        self.runs_for_head, self.issue, self.calls = runs_for_head, issue, []

    def __call__(self, *args):
        a = list(args)
        if a[:2] == ["run", "list"] and "--commit" in a:
            return json.dumps([{"databaseId": 9}] if self.runs_for_head else [])
        if a[:2] == ["run", "list"]:
            return json.dumps(self.runs)
        if a[:2] == ["run", "view"]:
            return json.dumps({"jobs": [{"name": "Dashboard backend-service (Rust)", "conclusion": "failure"}, {"name": "ok", "conclusion": "success"}]})
        if a[0] == "api" and "/compare/" in a[1]:
            return json.dumps({"commits": [{"sha": RED_SHA, "commit": {"message": "chore(deps): bump rand\n\nbody"}}]})
        if a[0] == "api" and "/commits?" in a[1]:
            return json.dumps([{"sha": self.head_sha, "commit": {"committer": {"date": self.head_date}, "message": "x"}}])
        if a[:2] == ["issue", "list"]:
            return json.dumps([self.issue] if self.issue else [])
        self.calls.append(a)
        return ""


class WatchTests(unittest.TestCase):
    def go(self, fake, *argv):
        with mock.patch.object(mhw, "gh", fake), mock.patch.object(mhw.subprocess, "run"), \
                mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "o/r"}):
            return mhw.main(list(argv))

    def red_runs(self):
        return [run(RED_SHA, "failure", "2026-09-25T07:00:00Z", rid=2), run(GREEN_SHA, "success", OLD, rid=1)]

    def test_red_main_opens_one_issue_naming_jobs_and_suspects(self):
        fake = FakeGh(self.red_runs())
        self.assertEqual(self.go(fake), 0)
        [create] = [c for c in fake.calls if c[:2] == ["issue", "create"]]
        body = create[create.index("--body") + 1]
        self.assertIn("Dashboard backend-service (Rust)", body)
        self.assertIn("bump rand", body)
        self.assertIn(f"`{GREEN_SHA[:10]}`", body)
        self.assertIn(mhw.MARKER.format(sha=RED_SHA), body)

    def test_same_red_head_is_not_reported_twice(self):
        issue = {"number": 5, "body": mhw.MARKER.format(sha=RED_SHA), "comments": []}
        fake = FakeGh(self.red_runs(), issue=issue)
        self.go(fake)
        self.assertEqual([c for c in fake.calls if c[0] == "issue"], [])

    def test_new_red_head_appends(self):
        issue = {"number": 5, "body": mhw.MARKER.format(sha=GREEN_SHA), "comments": []}
        fake = FakeGh(self.red_runs(), issue=issue)
        self.go(fake)
        self.assertTrue(any(c[:3] == ["issue", "comment", "5"] for c in fake.calls))

    def test_green_again_closes_the_issue(self):
        issue = {"number": 5, "body": mhw.MARKER.format(sha=RED_SHA), "comments": []}
        fake = FakeGh([run(GREEN_SHA, "success", "2026-09-25T08:00:00Z")], issue=issue)
        self.go(fake)
        self.assertTrue(any(c[:3] == ["issue", "close", "5"] for c in fake.calls))

    def test_cancelled_runs_do_not_decide(self):
        runs = [run(RED_SHA, "cancelled", "2026-09-25T07:00:00Z", rid=2), run(GREEN_SHA, "success", OLD)]
        fake = FakeGh(runs)
        self.go(fake)
        self.assertEqual([c for c in fake.calls if c[0] == "issue"], [])

    def test_untested_head_is_dispatched_not_alarmed(self):
        fake = FakeGh([run(GREEN_SHA, "success", OLD)], head_sha=HEAD_SHA, runs_for_head=False)
        self.go(fake)
        dispatched = [c for c in fake.calls if c[:2] == ["workflow", "run"]]
        self.assertEqual(sorted(c[2] for c in dispatched), sorted(mhw.WORKFLOWS))
        self.assertTrue(all(c[c.index("--ref") + 1] == "main" for c in dispatched))
        self.assertEqual([c for c in fake.calls if c[0] == "issue"], [])

    def test_fresh_head_gets_a_grace_period(self):
        now = mhw.datetime.now(mhw.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        fake = FakeGh([run(GREEN_SHA, "success", OLD)], head_sha=HEAD_SHA, head_date=now, runs_for_head=False)
        self.go(fake)
        self.assertEqual([c for c in fake.calls if c[:2] == ["workflow", "run"]], [])

    def test_dispatched_runs_count_as_main_runs(self):
        runs = [run(HEAD_SHA, "failure", "2026-09-25T09:00:00Z", event="workflow_dispatch", rid=3), run(GREEN_SHA, "success", OLD)]
        fake = FakeGh(runs)
        self.go(fake)
        self.assertTrue(any(c[:2] == ["issue", "create"] for c in fake.calls))


if __name__ == "__main__":
    unittest.main()
