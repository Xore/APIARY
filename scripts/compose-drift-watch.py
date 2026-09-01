#!/usr/bin/env python3
"""Alarm when a compose-defined, always-on service has no container at all
while its project siblings are actually running (#2747).

2026-08-31: a `systemctl restart docker` (#2743) surfaced four services
across three Dockge/Arcane stacks (`honeypot-elk`'s elasticsearch and
kibana, `honeypot-keycloak`'s postgres, `ghosts`'s ghosts-postgres) that had
**no container at all** -- not even a stopped one -- while their dependent
app containers kept running against a backing store that did not exist.
None of the four had a `docker events` destroy/die entry in the recent
history checked, so `restart: unless-stopped` never got a chance to save
them: a container that was never created has nothing to restart. Elasticsearch
sat in this state long enough that its absence was the standing condition,
not a blip -- with no alarm anywhere. This is a dedicated fleet-wide sweep
for exactly that shape, in the spirit of `disk-usage-watch.py` (#2743) and
the runner-capacity report (#2744), following `ci-queue-watch.py`'s (#2499)
proven de-dup design rather than inventing a new one.

What counts as drift:

- A service is "expected to persist" if its resolved `restart` policy is
  anything other than `no`/unset. This is a structural signal, not a
  hardcoded exclusion list: `honeypot-init`'s six one-shot setup jobs
  (arkime-init, elasticsearch-setup, honeypot-kibana-setup, log-init,
  persona-apply, snare-clone) all declare `restart: no` and are legitimately
  expected to reach zero containers once they've run -- they resolve out of
  the "expected to persist" set on their own, with no special-casing of the
  project name. A profile-gated service not in the compose file's active
  profile set does not appear in `docker compose config` output at all, so
  it is never considered either.
- "No container at all" means zero containers in any state (`docker compose
  ps -a`), not "not currently running" -- a stopped-but-existing container
  is a different, already-visible problem (`docker ps -a` shows it).
- The alarm only fires when at least one *other* service in the same
  project has a container in the `running` state. This is the "while
  dependants run" half of the issue title: it is what makes a missing
  sidecar dangerous (something is actively serving traffic against a
  backing store that silently isn't there) rather than "the whole stack was
  never started," which is a different, self-evident condition.

Design mirrors ci-queue-watch.py's proven shape:
- A single open `compose-drift-alarm`-labeled issue at a time: a sweep that
  finds continued drift appends to it; a sweep that finds it resolved closes
  it with the recovery evidence.
- Refuses to read a broken scan as a healthy fleet: zero project directories
  found, or `docker compose config`/`ps` failing on *every* project, is
  fatal rather than silently reported as "nothing wrong." A single project's
  `config`/`ps` failure (e.g. a missing required env var) is reported
  separately as "could not resolve" and does not block the rest of the
  sweep or get silently swallowed.
- Runs directly on the host being swept (no separate SSH credential or
  network path to the thing being measured), same reasoning
  disk-usage-watch.py and ci-queue-watch.py both give for their own designs.

Usage (the .github/workflows/compose-drift-watch.yml cron runs the first
form, on the homeserver-backed self-hosted runner):
  scripts/compose-drift-watch.py [--dry-run] [--stacks-root /var/dockge/stacks]
  --dry-run prints the would-be action and exits (no issue writes).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

LABEL = "compose-drift-alarm"
REPO = os.environ.get("GITHUB_REPOSITORY", "")
PERSISTENT_RESTART_POLICIES = {"unless-stopped", "always", "on-failure"}


def fail(msg: str) -> "None":
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def gh(*args: str) -> str:
    out = subprocess.run(["gh", *args], capture_output=True, text=True)
    if out.returncode != 0:
        fail(f"gh {' '.join(args[:2])} failed: {out.stderr.strip()}")
    return out.stdout


def project_dirs(stacks_root: Path) -> list[Path]:
    if not stacks_root.is_dir():
        fail(f"{stacks_root} is not a directory -- refusing to read an absent fleet as healthy")
    dirs = sorted(
        d for d in stacks_root.iterdir()
        if d.is_dir() and (d / "compose.yml").is_file()
    )
    if not dirs:
        fail(f"no compose.yml found under {stacks_root} -- refusing to read this as a healthy fleet")
    return dirs


# #2764: fixed deployed path, not this checkout's sibling file -- the
# sudoers NOPASSWD grant (scripts/github-ci-runner/install-ci-runner.sh)
# matches this exact interpreter + script path, and a self-hosted runner's
# checkout directory is not guaranteed stable the way this root-owned
# install location is. scripts/compose-project-state.py is that same file's
# source of truth -- re-run install-ci-runner.sh after changing it.
PRIVILEGED_HELPER = "/opt/github-ci-runner-helpers/compose-project-state.py"


def resolved_services(project: Path) -> dict[str, str] | None:
    """service name -> resolved restart policy. None on resolution failure."""
    out = subprocess.run(
        ["docker", "compose", "-f", "compose.yml", "config", "--format", "json"],
        cwd=project, capture_output=True, text=True,
    )
    if out.returncode != 0:
        return None
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError:
        return None
    return {
        name: (svc.get("restart") or "")
        for name, svc in data.get("services", {}).items()
    }


def actual_containers(project: Path) -> list[dict] | None:
    """[{Service, State}, ...] for every container docker knows about
    (any state), belonging to this project. None on resolution failure."""
    out = subprocess.run(
        ["docker", "compose", "-f", "compose.yml", "ps", "-a", "--format", "json"],
        cwd=project, capture_output=True, text=True,
    )
    if out.returncode != 0:
        return None
    containers = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            containers.append(json.loads(line))
        except json.JSONDecodeError:
            return None
    return containers


def privileged_project_state(project: Path) -> tuple[dict[str, str], list[dict]] | None:
    """Same two answers, obtained through the narrow root-run helper.

    #2764: a handful of stacks' .env files aren't readable by whichever
    unprivileged user runs this sweep (root/deploy-runner-owned, 600/640).
    `docker compose config` AND `docker compose ps` both fail on those with
    permission denied -- `ps` has to load the project too, so patching only
    the config half leaves the stack just as unresolved as before. Hence one
    helper call that returns both halves, and one place that can fail.

    The helper resolves everything as root but only ever prints
    {"services": {name: restart}, "containers": [{Service, State}]} -- never
    a secret value, an image, a label or a command line. Silently absent
    (not installed, or the sudoers grant isn't there) just means this
    fallback fails too and the project stays "unresolved", same as before
    #2764 -- this can never make a resolution failure look like a clean
    pass.
    """
    out = subprocess.run(
        ["sudo", "-n", "/usr/bin/python3", PRIVILEGED_HELPER, str(project)],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        return None
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError:
        return None
    services = data.get("services")
    containers = data.get("containers")
    if not isinstance(services, dict) or not isinstance(containers, list):
        return None
    return services, containers


def project_state(project: Path) -> tuple[dict[str, str], list[dict]] | None:
    """(resolved services, existing containers), or None if this project
    can't be resolved at all. Tries unprivileged first and only reaches for
    the root helper when either half fails -- so an ordinary run stays
    entirely unprivileged, and the four .env-locked stacks resolve through
    exactly one sudo call instead of two half-fixes."""
    services = resolved_services(project)
    containers = actual_containers(project) if services is not None else None
    if services is not None and containers is not None:
        return services, containers
    return privileged_project_state(project)


def sweep(stacks_root: Path) -> tuple[list[dict], list[str]]:
    """Returns (drift findings, project names that failed to resolve)."""
    findings: list[dict] = []
    unresolved: list[str] = []

    for project in project_dirs(stacks_root):
        name = project.name
        state = project_state(project)
        if state is None:
            unresolved.append(name)
            continue
        services, containers = state

        has_any_container = {c["Service"] for c in containers}
        has_running_container = {
            c["Service"] for c in containers if c.get("State") == "running"
        }

        expected_persistent = {
            svc for svc, restart in services.items()
            if restart in PERSISTENT_RESTART_POLICIES
        }
        missing = expected_persistent - has_any_container
        if not missing:
            continue

        # Only an alarm if a sibling is genuinely up -- otherwise this is
        # "the whole stack isn't deployed," a different and self-evident
        # condition, not silent drift.
        siblings_running = has_running_container - missing
        if not siblings_running:
            continue

        for svc in sorted(missing):
            findings.append({
                "project": name,
                "service": svc,
                "siblings_running": sorted(siblings_running),
            })

    return findings, unresolved


def open_alarm_issue() -> str:
    out = gh(
        "issue", "list", "-R", REPO, "--state", "open",
        "--label", LABEL, "--json", "number", "--jq", ".[0].number // \"\"",
    ).strip()
    return out or ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stacks-root", default="/var/dockge/stacks")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    stacks_root = Path(args.stacks_root)
    findings, unresolved = sweep(stacks_root)
    host = os.environ.get("RUNNER_NAME") or os.uname().nodename

    if unresolved:
        print(
            f"note: {len(unresolved)} project(s) could not be resolved and "
            f"were skipped (not read as healthy): {', '.join(unresolved)}",
            file=sys.stderr,
        )

    if not findings:
        print(f"healthy on {host}: no always-on service is missing all its containers "
              "while a sibling runs")
        if args.dry_run:
            return 0
        if not REPO:
            fail("GITHUB_REPOSITORY must be set")
        open_issue = open_alarm_issue()
        if open_issue:
            now = datetime.now(timezone.utc).strftime("%FT%TZ")
            gh(
                "issue", "close", open_issue, "-R", REPO,
                "--comment",
                f"Recovered as of {now}: sweep on {host} found no drifted "
                "service. Closing; the next sweep that finds drift reopens.",
            )
            print(f"closed compose-drift-alarm issue #{open_issue} (recovered)")
        return 0

    print(f"DRIFT: {len(findings)} service(s) missing all containers while a sibling runs")
    lines = [
        f"- `{f['project']}` / **{f['service']}** — zero containers "
        f"(running siblings: {', '.join(f['siblings_running'])})"
        for f in findings
    ]
    print("\n".join(lines))

    now = datetime.now(timezone.utc).strftime("%FT%TZ")
    body = "\n".join(
        [
            f"Sweep at {now} on `{host}`: **{len(findings)}** compose-defined, "
            "always-on service(s) have no container at all (not even stopped) "
            "while another service in the same project is running.",
            "",
            "Context: #2747 — this is exactly the shape that let a live "
            "Elasticsearch cluster and two other DB sidecars silently not "
            "exist while their dependent app containers ran regardless, "
            "with no alarm anywhere. Bring the missing service up against "
            "its **existing** data volume "
            "(`docker compose -f compose.yml up -d <service>`, run from the "
            "project directory) — never `docker volume prune`/`rm`, and "
            "never recreate a volume without first confirming it's actually "
            "empty. Check Arcane's gitops-sync history for the project "
            "around when this likely started.",
            "",
            *lines,
            "",
            (
                f"Also unresolved this sweep (skipped, not counted as "
                f"healthy): {', '.join(unresolved)}"
                if unresolved else ""
            ),
        ]
    ).strip() + "\n"

    if args.dry_run:
        print(f"--- dry run: would open/update {LABEL} issue with the body above")
        return 0
    if not REPO:
        fail("GITHUB_REPOSITORY must be set")

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
        fh.write(body)
        body_path = Path(fh.name)

    subprocess.run(
        ["gh", "label", "create", LABEL, "-R", REPO,
         "-d", "Compose-defined service missing all containers while a sibling runs (scripts/compose-drift-watch.py)",
         "--color", "D93F0B"],
        capture_output=True, text=True,
    )
    open_issue = open_alarm_issue()
    if open_issue:
        gh("issue", "comment", open_issue, "-R", REPO, "--body-file", str(body_path))
        print(f"appended to compose-drift-alarm issue #{open_issue}")
    else:
        gh(
            "issue", "create", "-R", REPO, "--title",
            f"ops: {len(findings)} compose service(s) drifted out of existence (#2747 watch)",
            "--label", LABEL, "--body-file", str(body_path),
        )
        print("opened compose-drift-alarm issue")
    body_path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
