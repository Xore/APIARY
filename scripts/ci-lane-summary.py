#!/usr/bin/env python3
"""Render a GitHub Actions run's job results as a Markdown lane table.

#3319: a red Quality run's only evidence was the raw log, and lanes that
were path-filtered or router-skipped looked identical to lanes that ran and
passed. This prints one row per lane into the step summary so "ran",
"skipped and why", and "never had an executor" are three different, readable
outcomes instead of three shades of green.

Reads the `needs` context object (workflow: `${{ toJSON(needs) }}`) as JSON
on stdin, or from --needs-json. Every field it reads is one GitHub documents
as always present: `result` is one of success/failure/cancelled/skipped.

Exits non-zero when any lane failed or was cancelled. A lane that skipped
without any twin passing is ALSO a failure, because "no executor reported
anything" is the exact state that used to read as green. A skip where the
other twin passed is not a failure: a router skipping one twin of a pair
because the other ran is correct operation, and is reported with the leg
that did run.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

# Result strings GitHub Actions reports for a job.
PASS = "success"
FAIL = "failure"
SKIP = "skipped"
CANCEL = "cancelled"

# A pair's fallback twin is the "-cloud" suffix (#2565's routing convention:
# the homeserver twin keeps the canonical check name, the GitHub-hosted
# fallback appends "(GitHub-hosted)"). The homeserver twin's JOB ID is either
# the bare name or, for the go-test loop, the bare name plus "-homeserver".
CLOUD_SUFFIX = "-cloud"
HOMESERVER_SUFFIX = "-homeserver"


def _verdict(result: str) -> tuple[str, str]:
    """Map a job result to (label, emoji) for the report."""
    if result == PASS:
        return ("passed", "✅")
    if result == SKIP:
        return ("skipped", "⏭️")
    if result == CANCEL:
        return ("cancelled", "🚫")
    if result == FAIL:
        return ("failed", "❌")
    return (result or "unknown", "❓")


def _lane(job: str, result: str) -> dict[str, Any]:
    label, emoji = _verdict(result)
    return {"job": job, "result": result, "label": label, "emoji": emoji}


def classify(needs: dict[str, Any]) -> list[dict[str, Any]]:
    """Turn the needs context into one entry per lane.

    A lane is either a single job or an executor PAIR: the bare-named job
    plus its "-cloud" twin (or the "-homeserver"/"-cloud" pair the go-test
    loop uses). Pairs are reported as one lane with a per-leg verdict, since
    exactly one twin is expected to run per execution.
    """
    lanes: list[dict[str, Any]] = []
    handled: set[str] = set()

    # Pairs are discovered from the "-cloud" leg, which is the one job id
    # that is spelled the same way for both families. Its base name is either
    # the homeserver twin's id verbatim (public-safety / public-safety-cloud)
    # or that base with "-homeserver" appended (go-test-homeserver /
    # go-test-cloud, where the loop job could not also take the bare name).
    for job, entry in needs.items():
        if not job.endswith(CLOUD_SUFFIX) or job in handled:
            continue
        base = job[: -len(CLOUD_SUFFIX)]
        home_job = base if base in needs else f"{base}{HOMESERVER_SUFFIX}"
        if home_job not in needs:
            continue
        lanes.append(
            {
                "pair": True,
                "job": home_job,
                "homeserver": _lane(home_job, needs[home_job].get("result", "")),
                "cloud": _lane(job, entry.get("result", "")),
            }
        )
        handled.update({home_job, job})

    # Whatever is left is a single job.
    for job, entry in needs.items():
        if job in handled:
            continue
        lanes.append(_lane(job, entry.get("result", "")))

    # Pairs were discovered from their "-cloud" leg, so the appended order is
    # not workflow order. Sort by where each lane's first job sits in the
    # `needs` object (a pair's homeserver leg, which is the one a reader
    # looks for) and the table reads the way the workflow declares it.
    order = {job: index for index, job in enumerate(needs)}
    lanes.sort(key=lambda lane: order.get(_lane_key(lane), 0))
    return lanes


def _lane_key(lane: dict[str, Any]) -> str:
    return lane["homeserver"]["job"] if lane.get("pair") else lane["job"]


def _pair_cell(lane: dict[str, Any]) -> tuple[str, str, str]:
    """Render one pair as (verdict cell, detail cell, worst result).

    The verdict cell names which leg produced the outcome so a reader sees
    "ran on the homeserver" versus "ran on GitHub-hosted" rather than a bare
    pass. The worst result is the one that decides pass/fail: any failure or
    cancellation, then any leg with no result at all, then a skip.
    """
    hs, cloud = lane["homeserver"], lane["cloud"]
    results = {hs["result"], cloud["result"]}
    detail_parts = [f"{hs['emoji']} homeserver `{hs['job']}`: {hs['label']}",
                    f"{cloud['emoji']} GitHub-hosted `{cloud['job']}`: {cloud['label']}"]

    if FAIL in results or CANCEL in results:
        worst = FAIL if FAIL in results else CANCEL
        verdict = f"{_verdict(worst)[0]}"
    elif PASS in results:
        # Whichever leg passed is the one that actually ran.
        ran_on = "honeypot-ci" if hs["result"] == PASS else "ubuntu-latest"
        verdict = f"ran ({ran_on})"
        worst = PASS
    elif SKIP in results:
        # Every leg skipped: this is the "unavailable" case the issue calls
        # out -- indistinguishable from green in a bare checks list.
        worst = SKIP
        verdict = "skipped"
    else:
        worst = SKIP
        verdict = "no result"

    return verdict, " · ".join(detail_parts), worst


def render(
    needs: dict[str, Any],
    title: str = "CI lanes",
    allow_skips: dict[str, str] | None = None,
) -> str:
    """Build the Markdown report for the step summary."""
    allow_skips = allow_skips or {}
    lanes = classify(needs)
    lines = [f"### {title}", ""]
    if not lanes:
        lines.append("_No lanes reported._")
        return "\n".join(lines) + "\n"

    lines.append("| Lane | Outcome | Detail |")
    lines.append("| --- | --- | --- |")
    problems: list[str] = []
    unavailable = 0

    for lane in lanes:
        if lane.get("pair"):
            verdict, detail, worst = _pair_cell(lane)
            if worst == SKIP:
                unavailable += 1
                problems.append(
                    f"{lane['job']}: neither executor reported a result -- the "
                    f"lane was skipped, not passed"
                )
            elif worst in (FAIL, CANCEL):
                problems.append(f"{lane['job']}: {worst}")
            lines.append(f"| `{lane['job']}` | {verdict} | {detail} |")
        else:
            worst = lane["result"]
            reason = allow_skips.get(lane["job"])
            if worst == SKIP and reason:
                # An accounted skip: still a skip, but carrying the reason the
                # caller already decided, so it is named rather than counted
                # as unaccounted.
                unavailable += 1
                lines.append(
                    f"| `{lane['job']}` | {lane['emoji']} {lane['label']} | {reason} |"
                )
            elif worst == SKIP:
                unavailable += 1
                problems.append(f"{lane['job']}: skipped, with no recorded reason")
                lines.append(f"| `{lane['job']}` | {lane['emoji']} {lane['label']} | |")
            else:
                if worst != PASS:
                    problems.append(f"{lane['job']}: {worst or 'no result'}")
                lines.append(
                    f"| `{lane['job']}` | {lane['emoji']} {lane['label']} | |"
                )

    passed = sum(
        1
        for lane in lanes
        if (not lane.get("pair") and lane["result"] == PASS)
        or (lane.get("pair") and _pair_cell(lane)[2] == PASS)
    )
    lines.append("")
    skipped_note = f"; {unavailable} skipped" if unavailable else ""
    lines.append(f"{passed}/{len(lanes)} lanes ran and passed{skipped_note}.")
    if problems:
        lines.append("")
        lines.append("**Not green:**")
        for problem in problems:
            lines.append(f"- {problem}")
    return "\n".join(lines) + "\n"


def parse_allow_skips(values: list[str]) -> dict[str, str]:
    """Parse repeated --allow-skip "job[:reason]" arguments.

    A lane that is skipped for a reason the caller has already decided is
    legitimate needs one, so the summary says "skipped because <reason>"
    instead of counting it as unaccounted. This is the mechanism that keeps
    pull_request-only checks (ai-attribution, #3329) from being reported as
    a problem on every push-to-main run.
    """
    allowed: dict[str, str] = {}
    for value in values:
        job, _, reason = value.partition(":")
        allowed[job] = reason or "skipped by design"
    return allowed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--needs-json",
        default="-",
        help="file holding the ${{ toJSON(needs) }} object, or - for stdin",
    )
    parser.add_argument("--title", default="CI lanes", help="summary heading")
    parser.add_argument(
        "--allow-skip",
        action="append",
        default=[],
        metavar="JOB[:REASON]",
        help="a lane whose skip is expected; repeated, and reported with the reason",
    )
    args = parser.parse_args(argv)
    allow_skips = parse_allow_skips(args.allow_skip)

    if args.needs_json == "-":
        raw = sys.stdin.read()
    else:
        with open(args.needs_json, encoding="utf-8") as handle:
            raw = handle.read()

    needs = json.loads(raw)
    report = render(needs, args.title, allow_skips)
    print(report, end="")

    # The guard: every lane must have produced a passing result, or a skip
    # the caller has already accounted for. Failure, cancellation, and a skip
    # with nothing behind it are the states a reader must not be able to
    # mistake for green, and each still fails the run.
    for lane in classify(needs):
        if lane.get("pair"):
            hs, cloud = lane["homeserver"], lane["cloud"]
            ran = PASS in (hs["result"], cloud["result"])
        else:
            ran = lane["result"] == PASS or (
                lane["result"] == SKIP and lane["job"] in allow_skips
            )
        if not ran:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
