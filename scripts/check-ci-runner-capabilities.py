#!/usr/bin/env python3
"""Fail CI when a self-hosted-eligible job needs a capability the runner lacks.

#2223: frontend-next's Docker lockfile step carried the same workflow_dispatch
opt-in `runs-on:` as the toolchain-only jobs, back when the self-hosted runner
deliberately had no Docker -- a dispatched opt-in run paid checkout+setup+cache
on the homeserver only to die on `docker: command not found`. #2565 later
retired that no-docker design and granted the runner user docker-group
membership (scripts/github-ci-runner/install-ci-runner.sh) specifically so
Docker-bound checks like this one could route there. That fixed today's file,
but nothing stopped the same class of drift from recurring the next time a
step is added to a self-hosted-eligible job/row -- this pins the invariant in
code instead of trusting review to keep catching it.

Two rules, checked only inside `run:` step bodies (comment lines stripped, so
prose that merely mentions "sudo" or "docker" in an explanation does not
trigger a false positive):

1. No self-hosted-eligible step may invoke `sudo` unconditionally. The runner
   user has no sudo BY DESIGN (quality.yml's own routing-comment header says
   so) -- the only sanctioned shape is the existing
   `command -v <tool> >/dev/null 2>&1 || { sudo apt-get ... }` fallback idiom,
   which only actually shells out to sudo when the tool is missing, and every
   tool it guards is preinstalled on the runner host (#2565's host-provision
   list) so that branch is provably dead there.
2. No self-hosted-eligible step may invoke `docker` unless
   install-ci-runner.sh still grants the runner user docker-group membership
   -- ties the workflow's assumption to the actual provisioning script, so a
   future revert of that grant fails this check instead of failing silently
   on the next dispatched run.

"Self-hosted-eligible" means: a plain job whose `runs-on:` is the literal
`[self-hosted, linux, x64, honeypot-ci]` list, or a scripts-and-compose
matrix row carrying `home: true` (its `runs-on:` is a ternary that only
resolves to the same list).

Honest limitation, same shallow-parsing tradeoff as check-zeek-pin-parity.py:
this is regex-based text scanning, not a YAML+shell parser. It is accurate
for the flat `run: |` blocks this repo actually writes.

Usage: python scripts/check-ci-runner-capabilities.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
QUALITY = ROOT / ".github" / "workflows" / "quality.yml"
INSTALL_CI_RUNNER = ROOT / "scripts" / "github-ci-runner" / "install-ci-runner.sh"

JOB_HEADER_RE = re.compile(r"(?m)^  ([A-Za-z][\w-]*):[ \t]*$")
ROW_HEADER_RE = re.compile(r"(?m)^          - name:")
INCLUDE_END_RE = re.compile(r"(?m)^    steps:[ \t]*$")
SELF_HOSTED_RUNS_ON_RE = re.compile(
    r"runs-on:\s*\[self-hosted,\s*linux,\s*x64,\s*honeypot-ci\]"
)
HOME_TRUE_RE = re.compile(r"(?m)^            home:\s*true\s*$")
ROW_NAME_RE = re.compile(r"- name:\s*(.+)")

BARE_SUDO_RE = re.compile(r"\bsudo\b")
GUARDED_SUDO_RE = re.compile(
    r"command -v \S+[^\n]*\|\|\s*\{[^}]*\bsudo\b[^}]*\}", re.DOTALL
)
DOCKER_RE = re.compile(r"(?<![\w-])docker(?![\w-])")


def strip_comment_lines(text: str) -> str:
    """Drop lines that are pure comments (YAML `#...` or bash `#...`).

    Uniform rule for both: any line whose stripped content starts with `#`.
    Keeps `sudo`/`docker` mentioned only in prose from tripping the checks
    below.
    """
    return "\n".join(
        line for line in text.splitlines() if not line.strip().startswith("#")
    )


def job_bodies(text: str) -> dict[str, str]:
    marker = "\njobs:\n"
    jobs_start = text.index(marker) + len(marker)
    body = text[jobs_start:]
    headers = list(JOB_HEADER_RE.finditer(body))
    out: dict[str, str] = {}
    for i, m in enumerate(headers):
        start = m.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(body)
        out[m.group(1)] = body[start:end]
    return out


def matrix_rows(job_body: str) -> list[str]:
    end_marker = INCLUDE_END_RE.search(job_body)
    include_body = job_body[: end_marker.start()] if end_marker else job_body
    headers = list(ROW_HEADER_RE.finditer(include_body))
    rows = []
    for i, m in enumerate(headers):
        start = m.start()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(include_body)
        rows.append(include_body[start:end])
    return rows


def eligible_blocks(quality_text: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    for name, body in job_bodies(quality_text).items():
        if name == "scripts-and-compose":
            for row in matrix_rows(body):
                if HOME_TRUE_RE.search(row):
                    row_name_m = ROW_NAME_RE.search(row)
                    row_name = row_name_m.group(1).strip() if row_name_m else "?"
                    blocks.append((f"scripts-and-compose[{row_name}]", row))
        elif SELF_HOSTED_RUNS_ON_RE.search(body):
            blocks.append((name, body))
    return blocks


def bare_sudo_violations(code: str) -> list[str]:
    guarded_spans = [g.span() for g in GUARDED_SUDO_RE.finditer(code)]
    violations = []
    for m in BARE_SUDO_RE.finditer(code):
        if any(start <= m.start() < end for start, end in guarded_spans):
            continue
        line = code[: m.start()].count("\n")
        offending = code.splitlines()[line].strip()
        violations.append(f"unconditional sudo: {offending}")
    return violations


def main() -> int:
    quality_text = QUALITY.read_text(encoding="utf-8")
    install_text = INSTALL_CI_RUNNER.read_text(encoding="utf-8")
    docker_granted = "usermod -aG docker" in install_text

    failures: list[str] = []
    blocks = eligible_blocks(quality_text)

    for label, raw in blocks:
        code = strip_comment_lines(raw)
        for violation in bare_sudo_violations(code):
            failures.append(f"{label}: {violation}")
        if DOCKER_RE.search(code) and not docker_granted:
            failures.append(
                f"{label}: step invokes docker, but "
                f"{INSTALL_CI_RUNNER.relative_to(ROOT)} no longer grants the "
                "runner user docker-group membership -- the self-hosted "
                "runner cannot run this job's docker step (#2223)"
            )

    if failures:
        print("CI runner capability check FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print(
            "\nEvery job/matrix-row whose runs-on carries the self-hosted "
            "opt-in must only require capabilities the runner actually has "
            f"(docker: {'granted' if docker_granted else 'NOT granted'} via "
            f"{INSTALL_CI_RUNNER.relative_to(ROOT)}; sudo: never, by design). "
            "Route the job to ubuntu-latest instead, or guard the capability "
            "behind a `command -v ... || { ... }` presence check the way the "
            "shellcheck/redis-server rows do.",
            file=sys.stderr,
        )
        return 1

    print(
        f"{len(blocks)} self-hosted-eligible job(s)/row(s) checked -- no "
        f"capability mismatch (docker granted={docker_granted}, no "
        "unconditional sudo)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
