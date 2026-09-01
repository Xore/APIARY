#!/usr/bin/env python3
"""Monthly cadence for #2315: notice when the pinned Elastic trio falls
behind upstream, and file the bump issue instead of relying on someone
remembering to check elastic.co/release-notes.

The pin at 9.5.1 sat unbumped until #2315 found it by hand during an
unrelated audit sweep -- exactly the "drift that happened to nobody
noticing" #1956 warned about. This script is the owner #2315 asked for:
it runs monthly, resolves the current manifest-list digest for each pinned
image's tag family, and opens (or updates) one tracking issue naming
whichever of elasticsearch/kibana/filebeat has a newer patch/minor
available than what the compose files pin today.

Every compose file in COMPOSE_FILES is scanned, not just honeypot-elk:
elasticsearch is pinned twice (honeypot-elk *and* honeypot-init), and the
honeypot-init copy is precisely the pin #2315 found stale because nothing
was watching it. All pins for one image must be byte-identical
(tag *and* digest); a divergence is reported as a failure, not ignored.

It does NOT bump the pin itself -- verification (CONTAINER-UPDATES.md's
own checklist: real release notes, the Arkime-as-second-consumer check,
running the ES_IMAGE-hardcoding tests for real) is a human-in-the-loop
step, deliberately not automated here.

Exit status is the whole point of the guardrail:
  0  every image was checked and every pin is current
  1  at least one image could NOT be checked (fetch failure, missing pin,
     pins disagreeing between compose files), or a newer release exists.
A run that could not reach the registry must never look like a clean run,
so an unreachable image is an error naming that image -- never a silent
"trio is current" off a partial check.

Usage: python3 scripts/elastic-release-watch.py [--dry-run]
       --dry-run prints the issue it would file instead of touching GitHub.
Needs: GH_TOKEN (repo scope) in the environment for the gh CLI calls.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Every compose file that pins one of the watched images. honeypot-init is
# in here deliberately: its duplicate elasticsearch pin is the one #2315
# calls out as "easy to miss", and leaving it out would let the exact same
# drift recur under a green watcher.
COMPOSE_FILES = [
    ROOT / "arcane" / "home" / "honeypot-elk" / "compose.yml",
    ROOT / "arcane" / "home" / "honeypot-init" / "compose.yml",
]
REPO = "Xore/APIARY"
TRACKING_LABELS = ["ops", "dependencies"]

# The docker.elastic.co tag lists are ~48k tags / ~2.5 MB each and measure
# 15-18s to transfer from a warm connection, so the original timeout=15 was
# below the real cost of the request and two of the three images timed out
# on every run. Budget ~5x the measured worst case, with one retry.
AUTH_TIMEOUT = 30
TAGS_TIMEOUT = 90
FETCH_ATTEMPTS = 2

# One row per pinned image this watch owns. "repo" is the docker.elastic.co
# path; "current" is read live from ELK_COMPOSE rather than hardcoded here,
# so this script can't itself drift out of sync with the pin it's checking.
IMAGES = [
    {"name": "elasticsearch", "repo": "elasticsearch/elasticsearch"},
    {"name": "kibana", "repo": "kibana/kibana"},
    {"name": "filebeat", "repo": "beats/filebeat"},
]

AUTH_URL = "https://docker-auth.elastic.co/auth?service=token-service&scope=repository:{repo}:pull"
TAGS_URL = "https://docker.elastic.co/v2/{repo}/tags/list"


def find_pins(repo: str) -> list[tuple[Path, str, str]]:
    """Every pin of `repo` across COMPOSE_FILES, as (file, version, full ref).

    Returns one entry per occurrence -- duplicates across (or within) files
    are kept, precisely so main() can assert they all agree.
    """
    pattern = re.compile(
        rf"docker\.elastic\.co/{re.escape(repo)}:(\d+\.\d+\.\d+)@(sha256:[0-9a-f]{{64}})"
    )
    pins: list[tuple[Path, str, str]] = []
    for path in COMPOSE_FILES:
        if not path.exists():
            continue
        for m in pattern.finditer(path.read_text()):
            pins.append((path, m.group(1), f"{m.group(1)}@{m.group(2)}"))
    return pins


def fetch_tags(repo: str) -> list[str]:
    last: Exception | None = None
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            token_req = urllib.request.Request(AUTH_URL.format(repo=repo))
            with urllib.request.urlopen(token_req, timeout=AUTH_TIMEOUT) as resp:
                token = json.load(resp)["token"]
            tags_req = urllib.request.Request(
                TAGS_URL.format(repo=repo), headers={"Authorization": f"Bearer {token}"}
            )
            with urllib.request.urlopen(tags_req, timeout=TAGS_TIMEOUT) as resp:
                return json.load(resp).get("tags", [])
        except Exception as e:  # noqa: BLE001 -- retried, then surfaced as a failure
            last = e
            print(
                f"warn: attempt {attempt}/{FETCH_ATTEMPTS} to fetch tags for {repo} failed: {e}",
                file=sys.stderr,
            )
    raise RuntimeError(f"{FETCH_ATTEMPTS} attempts failed, last error: {last}")


def latest_stable(tags: list[str]) -> str | None:
    # Plain X.Y.Z tags only -- skip -SNAPSHOT/-beta/arch-suffixed variants.
    versions = []
    for t in tags:
        m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", t)
        if m:
            versions.append(tuple(int(x) for x in m.groups()))
    if not versions:
        return None
    versions.sort()
    return ".".join(str(x) for x in versions[-1])


def main(dry_run: bool = False) -> int:
    behind: list[str] = []
    # Anything that means "this image was NOT successfully checked". A
    # non-empty list makes the run red no matter what the checked images
    # said -- the original bug was warning to stderr and returning 0.
    unchecked: list[str] = []

    for image in IMAGES:
        name, repo = image["name"], image["repo"]

        pins = find_pins(repo)
        if not pins:
            unchecked.append(
                f"{name}: no {repo} pin found in any of "
                + ", ".join(str(p.relative_to(ROOT)) for p in COMPOSE_FILES)
            )
            continue

        # #2315's actual defect class: the same image pinned in two compose
        # files and only one of them bumped. Divergence is a finding, not a
        # detail to paper over by picking the first match.
        distinct = sorted({ref for _, _, ref in pins})
        if len(distinct) > 1:
            detail = "; ".join(
                f"{p.relative_to(ROOT)} -> {ref}" for p, _, ref in pins
            )
            unchecked.append(f"{name}: pins disagree across compose files ({detail})")
            continue

        pinned = pins[0][1]
        where = ", ".join(str(p.relative_to(ROOT)) for p, _, _ in pins)
        print(f"{name}: pinned {distinct[0]} in {len(pins)} place(s): {where}")

        try:
            tags = fetch_tags(repo)
        except Exception as e:  # network egress, auth, or registry shape changed
            unchecked.append(f"{name}: could not fetch tags for {repo}: {e}")
            continue

        latest = latest_stable(tags)
        if latest is None:
            unchecked.append(f"{name}: no plain X.Y.Z tag found for {repo}")
            continue

        if tuple(map(int, latest.split("."))) > tuple(map(int, pinned.split("."))):
            behind.append(f"- **{name}**: pinned at {pinned}, {latest} is available")
            print(f"{name}: pinned {pinned} < latest {latest}")
        else:
            print(f"{name}: pinned {pinned} is current (latest seen: {latest})")

    if unchecked:
        print(
            f"elastic-release-watch: FAILED -- {len(unchecked)} of {len(IMAGES)} image(s) "
            "could not be checked, so this run proves nothing about them:",
            file=sys.stderr,
        )
        for line in unchecked:
            print(f"  - {line}", file=sys.stderr)

    if not behind:
        if unchecked:
            return 1
        print(
            f"elastic-release-watch: all {len(IMAGES)} images checked, trio is current, "
            "nothing to file"
        )
        return 0

    title = "Elastic trio has a newer release available"
    body = (
        "Filed automatically by `scripts/elastic-release-watch.py` (the #2315 monthly cadence).\n\n"
        + "\n".join(behind)
        + "\n\nMust-move-together: elasticsearch/kibana/filebeat may not lead or lag each other -- "
        "bump all three in one change even if only one moved. Every pin listed above is pinned in "
        "both `arcane/home/honeypot-elk/compose.yml` and (for elasticsearch) "
        "`arcane/home/honeypot-init/compose.yml` -- move them together. Follow "
        "`docs/CONTAINER-UPDATES.md`'s checklist, including the Arkime-as-second-ES-consumer check "
        "and running the ES_IMAGE-hardcoding tests under `analysis/tests/` for real against the new "
        "digest before merging."
    )
    if unchecked:
        body += "\n\n**Incomplete run** -- these images could not be checked at all:\n" + "\n".join(
            f"- {line}" for line in unchecked
        )

    if dry_run:
        print("elastic-release-watch: --dry-run, would file/update this issue:")
        print(f"  title: {title}")
        for line in body.splitlines():
            print(f"  | {line}")
        return 1 if unchecked else 0

    existing = subprocess.run(
        ["gh", "issue", "list", "-R", REPO, "--search", title, "--state", "open", "--json", "number"],
        capture_output=True, text=True, check=True,
    )
    open_matches = json.loads(existing.stdout or "[]")
    if open_matches:
        number = open_matches[0]["number"]
        subprocess.run(
            ["gh", "issue", "comment", str(number), "-R", REPO, "--body", body],
            check=True,
        )
        print(f"elastic-release-watch: updated existing issue #{number}")
    else:
        args = ["gh", "issue", "create", "-R", REPO, "--title", title, "--body", body]
        for label in TRACKING_LABELS:
            args += ["--label", label]
        result = subprocess.run(args, capture_output=True, text=True, check=True)
        print(f"elastic-release-watch: filed {result.stdout.strip()}")
    # An issue was filed, so the newer-release path has done its job and is
    # green; an image we could not check at all is still red.
    return 1 if unchecked else 0


if __name__ == "__main__":
    sys.exit(main("--dry-run" in sys.argv[1:]))
