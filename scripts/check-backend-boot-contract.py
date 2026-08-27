#!/usr/bin/env python3
"""Fail CI when a compose service consumes WORKER_LOOPS but does not carry
the apiary-backend image's full auth-posture pair (#2320).

Every service listed under a WORKER_LOOPS env item -- serving tier or
loop-only replica alike -- boots through the same apiary-backend entrypoint
whose startup gate (#2183) refuses an empty SERVICE_TOKEN unless
APIARY_ALLOW_UNAUTH_DEV carries exactly "1". Those two arrive as
per-container environment, so each role forwards its own copy: #2320
shipped because four loop services carried only the token half and kept
crash-looping on [E-SERVICE-TOKEN] for hours on an empty-token deployment
while their serving siblings right next to them booted fine. Same class,
one var over, would reintroduce silently stale charts with no error
anywhere either side of the split -- this check is the mechanical version
of reviewing every WORKER_LOOPS consumer against the boot gate's inputs.

If a future backend change adds a third variable to the gate, it belongs
in AUTH_VARS below; this inventory is deliberately explicit so that edit
is reviewable next to the gate itself.

Scope: arcane/home/*/compose.yml, where the apiary-backend roles live.
Comment-aware and indentation-based rather than YAML-parsed -- stdlib
only, matching check-compose-env-docs.py (#1982); every compose file in
this repo uses one uniform layout style.

Usage: python scripts/check-backend-boot-contract.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOME = ROOT / "arcane" / "home"

# The #2183 boot-contract inputs, as they must appear as environment item
# keys on any role of the image.
AUTH_VARS = ("SERVICE_TOKEN", "APIARY_ALLOW_UNAUTH_DEV")

SERVICE_HEADER = re.compile(r"^([A-Za-z0-9_-]+):\s*$")
ENV_ITEM = re.compile(r"^\s*-\s+([A-Za-z_][A-Za-z0-9_]*)=")


def services_with_env(compose_text: str) -> dict[str, set[str]]:
    """service name -> keys of its environment: block items.

    Comments skipped throughout; a service header is a two-space-indented
    plain key once the top-level `services:` mapping starts, and any line
    dedenting back out ends both that service and any open env block.
    """
    services: dict[str, set[str]] = {}
    current: str | None = None
    in_services = False
    env_indent: int | None = None

    for raw in compose_text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()

        if indent == 0:
            if stripped == "services:":
                in_services = True
                current = None
                env_indent = None
            else:
                in_services = False
            continue
        if not in_services:
            continue

        if indent == 2 and not stripped.startswith("- "):
            header = SERVICE_HEADER.match(stripped)
            if header:
                current = header.group(1)
                services.setdefault(current, set())
                env_indent = None
                continue

        if current is None:
            continue

        if re.match(r"^environment:\s*$", stripped):
            env_indent = indent
            continue
        if env_indent is not None and indent <= env_indent:
            env_indent = None
        elif env_indent is not None:
            item = ENV_ITEM.match(raw)
            if item:
                services[current].add(item.group(1))
    return services


def main() -> int:
    failures: list[str] = []
    checked: list[str] = []

    for stack in sorted(HOME.iterdir()):
        compose = stack / "compose.yml"
        if not stack.is_dir() or not compose.is_file():
            continue
        rel_compose = str(compose.relative_to(ROOT))
        compose_text = compose.read_text(errors="replace")

        for name, keys in sorted(services_with_env(compose_text).items()):
            if "WORKER_LOOPS" not in keys:
                continue
            checked.append(f"{rel_compose}:{name}")
            missing = [var for var in AUTH_VARS if var not in keys]
            if missing:
                failures.append(
                    f"{rel_compose}: '{name}' consumes WORKER_LOOPS but does "
                    f"not forward {', '.join(missing)} -- the apiary-backend "
                    f"[E-SERVICE-TOKEN] boot gate (#2183) reads both halves "
                    f"(see #2320)"
                )

    if failures:
        print(f"{len(failures)} apiary-backend boot-contract failure(s):")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(
        f"apiary-backend boot contract holds ({len(checked)} WORKER_LOOPS "
        f"service(s): {', '.join(checked)})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
