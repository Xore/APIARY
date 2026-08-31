#!/usr/bin/env python3
"""Alarm when workflow runs sit parked in the Actions queue far beyond a
healthy wait (#2499).

2026-08-27 quality's entire pipeline head-of-line blocked for hours: every
run's first job ("Pick CI executor") queues behind the same GitHub-hosted
pool as every matrix, so nothing in any run can start until its router
lands -- and with a merge storm plus a dozen PR pushes the pool never
drained. Measured live that afternoon: 54 runs queued repo-wide while ~5
jobs were in flight and 40-minute dead windows separated brief drains --
delayed-start degradation layered on the structural single-router-per-run
dependency. Either way the observable is the same and the response is the
same: notice, and open a tracking issue instead of silently parking green
PRs behind an invisible queue.

Design, kept honest:

- The threshold (CI_QUEUE_STALL_MINUTES, default 60) is deliberately far
  above ordinary delayed-start noise (GitHub's own incident taxonomy calls
  >5m "delayed"; the 2026-08-26 incident's tail ran 40 minutes). A sweep
  that fires has something real to say.
- "CI heartbeat" canaries are excluded: their queueing while the
  homeserver is offline is the router's designed-for signal (quality.yml
  bounds them with its own decision window and falls back), so they would
  be a standing false alarm, not a stall.
- State lives in a labeled tracking issue, not a file: at most one open
  `ci-queue-stall` issue exists. A sweep finding fresh stalls opens or
  appends; a sweep finding the queue recovered closes the open issue with
  the recovery evidence. Consecutive stalled sweeps update the same issue,
  so a 4-hour stall is one thread, not sixteen.
- The scan REFUSES to read an API failure as a healthy queue: an empty or
  errored result that was supposed to list runs is exactly the failure
  mode an alarm must not have (the first live validation pass of this
  script read a broken gh invocation as "queue healthy" -- that bug class
  is now fatal instead of silent).

Usage (the .github/workflows/ci-queue-watch.yml cron runs the first form):
  scripts/ci-queue-watch.py [--dry-run]
  --dry-run prints the would-be action and exits (no issue writes) -- used
  for the #2499 live validation.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

STALL_MINUTES = int(os.environ.get("CI_QUEUE_STALL_MINUTES", "60"))
LABEL = "ci-queue-stall"
REPO = os.environ.get("GITHUB_REPOSITORY", "")
DRY_RUN = "--dry-run" in sys.argv[1:]
HEARTBEAT_NAME = "CI heartbeat"
SCAN_DAYS = 1


def fail(msg: str) -> "None":
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def gh(*args: str) -> str:
    out = subprocess.run(["gh", *args], capture_output=True, text=True)
    if out.returncode != 0:
        fail(f"gh {' '.join(args[:2])} failed: {out.stderr.strip()}")
    return out.stdout


def gh_json_pages(endpoint: str) -> list[dict]:
    """Fetch all pages, tolerating gh's concatenated multi-document stream.

    --paginate prints each page's raw JSON document back to back, which is
    not one JSON value; decode them sequentially.
    """
    raw = gh("api", endpoint, "--paginate")
    decoder = json.JSONDecoder()
    pages: list[dict] = []
    idx = 0
    while idx < len(raw):
        while idx < len(raw) and raw[idx] in " \t\r\n":
            idx += 1
        if idx >= len(raw):
            break
        value, idx = decoder.raw_decode(raw, idx)
        pages.append(value)
    return pages


def stalled_runs() -> list[dict]:
    if not REPO:
        fail("GITHUB_REPOSITORY must be set")
    scan_since = (datetime.now(timezone.utc) - timedelta(days=SCAN_DAYS)).strftime("%Y-%m-%d")
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=STALL_MINUTES)
    pages = gh_json_pages(
        f"repos/{REPO}/actions/runs?per_page=100&created=>={scan_since}"
    )
    runs = [r for page in pages for r in page.get("workflow_runs", [])]
    if not runs:
        fail(
            "scan returned no runs at all — refusing to read an absent "
            "listing as a healthy queue (does this repo run any workflows?)"
        )
    stale: list[dict] = []
    for run in runs:
        if run.get("status") != "queued":
            continue
        if run.get("name") == HEARTBEAT_NAME:
            continue
        started = run.get("run_started_at")
        if not started:
            continue
        started_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
        if started_dt < cutoff:
            stale.append(
                {
                    "workflow": run.get("name") or "?",
                    "id": run.get("id"),
                    "branch": (run.get("head_branch") or "?")[:40],
                    "url": run.get("html_url") or "",
                    "queued_since": started,
                }
            )
    stale.sort(key=lambda r: r["queued_since"])
    return stale


def open_stall_issue() -> str:
    out = gh(
        "issue", "list", "-R", REPO, "--state", "open",
        "--label", LABEL, "--json", "number", "--jq", ".[0].number // \"\"",
    ).strip()
    return out or ""


def runner_capacity_line() -> str:
    """'X of Y self-hosted runners online (Z busy)', or a note that the
    check itself failed. #2742: two of five runners sat offline for two
    days with no signal in this alarm — a stall report that also says how
    much capacity is actually available would have surfaced that outage
    immediately instead of two days later. Best-effort: a failure here
    must not block the (more important) queue-stall report itself.
    """
    try:
        out = subprocess.run(
            ["gh", "api", f"repos/{REPO}/actions/runners", "--paginate"],
            capture_output=True, text=True,
        )
        if out.returncode != 0:
            return f"Runner capacity: could not query ({out.stderr.strip()[:120]})"
        decoder = json.JSONDecoder()
        runners: list[dict] = []
        raw, idx = out.stdout, 0
        while idx < len(raw):
            while idx < len(raw) and raw[idx] in " \t\r\n":
                idx += 1
            if idx >= len(raw):
                break
            value, idx = decoder.raw_decode(raw, idx)
            runners.extend(value.get("runners", []))
        if not runners:
            return "Runner capacity: no self-hosted runners registered"
        online = [r for r in runners if r.get("status") == "online"]
        busy = [r for r in online if r.get("busy")]
        offline = [r["name"] for r in runners if r.get("status") != "online"]
        line = f"Runner capacity: {len(online)} of {len(runners)} online ({len(busy)} busy)"
        if offline:
            line += f" — offline: {', '.join(offline)}"
        return line
    except Exception as exc:
        # Best-effort per the docstring above: an unanticipated API/JSON
        # shape here must not raise past this function and take out the
        # primary queue-stall report with it.
        return f"Runner capacity: could not query (unexpected error: {exc})"


def main() -> int:
    stale = stalled_runs()

    if not stale:
        print(f"queue healthy: no runs parked beyond {STALL_MINUTES}m")
        if DRY_RUN:
            return 0
        open_issue = open_stall_issue()
        if open_issue:
            now = datetime.now(timezone.utc).strftime("%FT%TZ")
            gh(
                "issue", "close", open_issue, "-R", REPO,
                "--comment",
                f"Queue recovered as of {now}: no runs parked beyond "
                f"{STALL_MINUTES}m. Closing the alarm; the next stalled "
                "sweep reopens.",
            )
            print(f"closed stall issue #{open_issue} (recovered)")
        return 0

    print(f"stall detected: {len(stale)} run(s) parked beyond {STALL_MINUTES}m")
    lines = [
        f"- [{r['workflow']}]({r['url']}) `{r['id']}` on `{r['branch']}`"
        f" — queued since {r['queued_since']}"
        for r in stale
    ]
    print("\n".join(lines))

    now = datetime.now(timezone.utc).strftime("%FT%TZ")
    body = "\n".join(
        [
            f"Sweep at {now}: **{len(stale)}** run(s) queued for more than "
            f"{STALL_MINUTES} minutes.",
            "",
            runner_capacity_line(),
            "",
            "Context: #2499 — the router job every quality matrix waits on shares one",
            "GitHub-hosted pool with all matrices, so repo-wide saturation turns into a",
            "head-of-line block; delayed-start degradation produces the same observable.",
            "Check <https://www.githubstatus.com> for an active Actions incident before",
            "assuming a repo-side cause. Once the queue drains, rerun failed legs",
            "individually (never trust the aggregate) per the house flake rule.",
            "",
            *lines,
        ]
    ) + "\n"

    if DRY_RUN:
        print(f"--- dry run: would open/update {LABEL} issue with the body above")
        return 0

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
        fh.write(body)
        body_path = Path(fh.name)

    # Label creation is best-effort: it exists after the first sweep.
    subprocess.run(
        ["gh", "label", "create", LABEL, "-R", REPO,
         "-d", "CI queue stall alarm (scripts/ci-queue-watch.py)",
         "--color", "D93F0B"],
        capture_output=True, text=True,
    )
    open_issue = open_stall_issue()
    if open_issue:
        gh("issue", "comment", open_issue, "-R", REPO, "--body-file", str(body_path))
        print(f"appended to stall issue #{open_issue}")
    else:
        gh(
            "issue", "create", "-R", REPO, "--title",
            f"CI queue stalled — runs parked beyond {STALL_MINUTES}m (#2499 watch)",
            "--label", LABEL, "--body-file", str(body_path),
        )
        print("opened stall issue")
    body_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
