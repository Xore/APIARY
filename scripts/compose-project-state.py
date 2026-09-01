#!/usr/bin/env python3
"""Narrow root-run helper for compose-drift-watch.py (#2764).

Both halves of the sweep have to read a project's `.env`: `docker compose
config` needs it to interpolate `${...}` values, and `docker compose ps`
needs it to even load the project. Four stacks under `/var/dockge/stacks/`
(honeypot-arcane, honeypot-galah, honeypot-keycloak, honeypot-wordpot) have
`.env` files the `github-ci-runner` system user can't read at all (owner
`root`/`github-deploy-runner`:`deploy-runner`, mode 600/640) -- confirmed
live, permission denied regardless of the 600/640 split, and for `ps` just
as much as for `config`.

The issue named two shapes to fix this: widen `github-ci-runner`'s group
membership (broadest, simplest, and a real blast-radius increase -- a
scheduled CI job would gain read access to Keycloak admin credentials, DB
passwords, every secret any of these `.env` files hold), or give the sweep
a narrower privilege that can never leak a secret value back to the
CI-runner-owned process. This is the second shape: root reads and resolves
the project (secrets included, transiently, in this short-lived root
process only), but the ONLY thing that ever leaves this process **on
stdout** is

    {"services":   {service_name: restart_policy, ...},
     "containers": [{"Service": ..., "State": ...}, ...]}

-- structural metadata, and nothing else. Not one environment value, image
name, digest, label, command line or file path from inside the resolved
config or the `ps` output crosses the boundary, even though both raw
outputs are full of them (`ps --format json` alone carries Image, Command
and the whole `Labels` string). Anything this helper writes to *stderr* is
a diagnostic from a failed docker invocation, deliberately excluded from
that guarantee; compose-drift-watch.py captures and discards it.

Both halves are returned by a single invocation on purpose: one sudo call,
one output schema to audit, and no way for a future caller to pick up the
privileged path for one half and silently keep failing on the other (which
is exactly how #2764's first attempt left all four stacks unresolved).

The output-schema boundary is what keeps secrets in; the host's own
permissions are what keep a hostile compose file out. A compose file placed
under an allowed root with `restart: "${SOME_SECRET}"` could carry a value
out through the one field this helper does emit -- that is closed by the
fact that the stacks roots are not writable by the calling user
(`/var/dockge/stacks` is `drwxrwsr-x root:deploy-runner`, and
`github-ci-runner` is in neither), not by anything this script does. If a
stacks root ever becomes writable by the sweep's user, this guarantee has
to be re-derived.

Granted to `github-ci-runner` via a sudoers NOPASSWD entry restricted to
this exact script path (see scripts/github-ci-runner/install-ci-runner.sh),
not a general root shell or group membership -- the sudoers wildcard that
allows a trailing project-path argument is safe specifically because this
script's own validation (below), not sudoers, is the actual boundary: any
argument that isn't a clean absolute path under a known stacks root is
rejected before docker ever runs.

Usage (normally invoked by compose-drift-watch.py via `sudo -n`, not by
hand):
  sudo python3 scripts/compose-project-state.py <project-dir>
Exit 0 on success, 1 on a docker/compose failure, 2 on a rejected argument.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

# Real deploy roots only -- matches compose-drift-watch.py's own
# --stacks-root default and the VPS/homeserver's actual layout. A path
# outside these is refused before touching the filesystem at all, so this
# root-run helper can't be pointed at an arbitrary root-owned file elsewhere
# on the host even though sudoers itself allows any trailing argument.
ALLOWED_ROOTS = (Path("/var/dockge/stacks"), Path("/opt/stacks"))


def compose(project: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", "compose.yml", *args],
        cwd=project, capture_output=True, text=True,
    )


def parse_ps(stdout: str) -> list[dict] | None:
    """`ps --format json` is newline-delimited objects on the fleet's compose
    (v5.5.0, verified live); some versions emit a single array instead.
    Accept either, and keep ONLY Service/State -- the raw records also carry
    Image, Command and a flattened Labels blob, none of which may cross the
    privilege boundary."""
    stdout = stdout.strip()
    if not stdout:
        return []
    records: list[dict]
    if stdout.startswith("["):
        try:
            records = json.loads(stdout)
        except json.JSONDecodeError:
            return None
    else:
        records = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                return None
    return [
        {"Service": r.get("Service", ""), "State": r.get("State", "")}
        for r in records
    ]


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: compose-project-state.py <project-dir>", file=sys.stderr)
        return 2

    try:
        project = Path(sys.argv[1]).resolve(strict=True)
    except OSError as e:
        print(f"refusing: cannot resolve {sys.argv[1]!r}: {e}", file=sys.stderr)
        return 2

    if not any(root == project or root in project.parents for root in ALLOWED_ROOTS):
        print(f"refusing: {project} is outside the known stacks roots {ALLOWED_ROOTS}", file=sys.stderr)
        return 2

    compose_file = project / "compose.yml"
    if not compose_file.is_file():
        print(f"refusing: no compose.yml under {project}", file=sys.stderr)
        return 2

    cfg = compose(project, "config", "--format", "json")
    if cfg.returncode != 0:
        print(cfg.stderr, file=sys.stderr)
        return 1
    try:
        data = json.loads(cfg.stdout)
    except json.JSONDecodeError as e:
        print(f"docker compose config produced non-JSON output: {e}", file=sys.stderr)
        return 1

    ps = compose(project, "ps", "-a", "--format", "json")
    if ps.returncode != 0:
        print(ps.stderr, file=sys.stderr)
        return 1
    containers = parse_ps(ps.stdout)
    if containers is None:
        print("docker compose ps produced non-JSON output", file=sys.stderr)
        return 1

    # The only line that leaves this root process: service names + restart
    # policies, and container service names + states. Nothing from
    # `environment:`, `secrets:`, `build:`, `image:`, `Labels` or any other
    # key either command resolved along the way.
    print(json.dumps({
        "services": {
            name: (svc.get("restart") or "")
            for name, svc in data.get("services", {}).items()
        },
        "containers": containers,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
