#!/usr/bin/env python3
"""Audit a window of merged PRs: every issue a PR claims to close via a
GitHub closing keyword must actually be in the `closed` state (#2922).

Why this needs a script and not "the tracker will tell you": GitHub only
auto-closes a linked issue when the PR carrying the closing keyword merges
into the repository's DEFAULT branch. A stacked PR -- one whose base is
another feature branch, not `main` -- can carry a perfectly correct
`Closes #N` line that never fires, because by the time the parent branch
reaches `main`, that line was already consumed by the earlier merge into
the (non-default) parent. #2749 and #2750 both shipped this way: merged,
genuinely fixed, `Closes #N` present and correct in the child PR body, and
still open in the tracker two days later because nothing re-checked. See
docs/CI-CD.md's "Stacked PRs and Closes #N (#2922)" section for the policy
this script enforces the audit half of.

This script does not know or care whether a PR was stacked -- it treats
every merged PR in the window identically: extract every issue number named
by a GitHub closing keyword in the PR body, and flag any that are not
`closed`. A flagged issue means either the auto-close didn't fire (the
stacking failure mode above) or the fix hasn't actually landed as the PR
body claims -- either way it needs a human look, which is the point.

Usage:
    scripts/check-merged-prs-closed-issues.py                  # last 7 days
    scripts/check-merged-prs-closed-issues.py --since 2026-09-01
    scripts/check-merged-prs-closed-issues.py --pr 2798 --pr 2799
    scripts/check-merged-prs-closed-issues.py --repo Xore/APIARY --since 2026-09-01

Exit status: 0 if every claimed issue is closed, 1 if any is still open (or
a lookup failed), 2 for a usage/environment error (e.g. `gh` not installed
or not authenticated).

Requires the `gh` CLI, authenticated for the target repo.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import date, timedelta

# GitHub's own closing-keyword set (case-insensitive), same list GitHub
# itself recognizes in a PR/commit body:
# https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue
CLOSING_KEYWORDS = (
    "close", "closes", "closed",
    "fix", "fixes", "fixed",
    "resolve", "resolves", "resolved",
)

# Matches "Closes #123", "fixes: #45", "Resolved GH-9" -- keyword, optional
# colon, optional owner/repo, #N or GH-N. Deliberately does not match a bare
# "#123" with no keyword: this script audits CLAIMED closes, not every issue
# mention.
CLOSING_RE = re.compile(
    r"\b(?:" + "|".join(CLOSING_KEYWORDS) + r")\b\s*:?\s*"
    r"(?:[\w.-]+/[\w.-]+)?(?:#|GH-)(\d+)",
    re.IGNORECASE,
)


def run_gh(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["gh", *args], capture_output=True, text=True, check=True,
        )
    except FileNotFoundError:
        print("error: `gh` CLI not found on PATH", file=sys.stderr)
        sys.exit(2)
    except subprocess.CalledProcessError as exc:
        print(f"error: `gh {' '.join(args)}` failed:\n{exc.stderr}", file=sys.stderr)
        sys.exit(2)
    return result.stdout


def merged_prs(repo: str, since: str) -> list[dict]:
    out = run_gh([
        "pr", "list", "--repo", repo, "--state", "merged",
        "--search", f"merged:>={since}",
        "--json", "number,title,body,baseRefName,mergedAt",
        "--limit", "200",
    ])
    return json.loads(out)


def pr_by_number(repo: str, number: int) -> dict:
    out = run_gh([
        "pr", "view", str(number), "--repo", repo,
        "--json", "number,title,body,baseRefName,mergedAt,state",
    ])
    return json.loads(out)


def claimed_issues(body: str) -> set[int]:
    return {int(match.group(1)) for match in CLOSING_RE.finditer(body or "")}


def issue_state(repo: str, number: int) -> str | None:
    try:
        out = run_gh(["issue", "view", str(number), "--repo", repo, "--json", "state"])
    except SystemExit:
        return None
    return json.loads(out).get("state")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default="Xore/APIARY", help="owner/repo (default: Xore/APIARY)")
    parser.add_argument("--since", default=None, help="only PRs merged on/after this date (YYYY-MM-DD); default 7 days ago")
    parser.add_argument("--pr", type=int, action="append", default=None, help="check specific PR number(s) instead of a date window; repeatable")
    args = parser.parse_args()

    if args.pr:
        prs = [pr_by_number(args.repo, n) for n in args.pr]
    else:
        since = args.since or (date.today() - timedelta(days=7)).isoformat()
        prs = merged_prs(args.repo, since)

    problems: list[str] = []
    checked_issues = 0

    for pr in prs:
        issues = claimed_issues(pr.get("body", ""))
        if not issues:
            continue
        for number in sorted(issues):
            checked_issues += 1
            state = issue_state(args.repo, number)
            if state is None:
                problems.append(
                    f"PR #{pr['number']} claims to close #{number}, but that "
                    f"issue lookup failed (deleted, transferred, or a typo'd number?)"
                )
            elif state != "CLOSED":
                base = pr.get("baseRefName", "?")
                stacked_note = (
                    f" (base branch: {base} -- if this isn't `main`, this is "
                    f"exactly the stacked-PR Closes-drop #2922 describes)"
                    if base not in ("main", "master") else ""
                )
                problems.append(
                    f"PR #{pr['number']} ({pr.get('title', '')!r}) claims to "
                    f"close #{number}, but it is still {state}{stacked_note}"
                )

    if problems:
        print(f"check-merged-prs-closed-issues: {len(problems)} problem(s) "
              f"found across {len(prs)} merged PR(s), {checked_issues} claimed "
              f"issue(s) checked:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"check-merged-prs-closed-issues: OK -- {len(prs)} merged PR(s), "
          f"{checked_issues} claimed issue(s), all closed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
