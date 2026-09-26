#!/usr/bin/env python3
"""deploy-profile-sizing.py — the declared-resource arithmetic behind
docs/deploy-profiles/README.md's sizing table (#3328).

Issue #3328 asked for "measured resource sizing per role (VPS vs
homeserver) to go with the deploy profiles", and the certificate half of it
was already merged (#3352) without this half. What is measurable from the
repository itself is not the *usage* of a running deployment -- that needs the
live hosts, and the one-off measurements that do exist are recorded as prose in
other docs, not as data this script can read. What is exactly reproducible, and
is the part that actually determines whether a host is big enough, is the sum
of the ceilings every container's compose file declares: a container is
OOM-killed at its `memory` limit, so a host with less RAM than the sum of the
profile's limits runs that profile *into* OOM kills. This script sums those
declarations, per profile and per role, straight out of the compose files so
the documented numbers cannot drift away from the trees they describe.

Three things it deliberately does not pretend to be:

  * a usage measurement. Nothing here observes a running container; it reads
    `deploy.resources.limits` (and the older non-swarm `mem_limit`) as written.
  * a reservation. `cpus`/`memory` limits are ceilings, so their sum is what
    the deployment is *allowed* to consume, not what it will consume, and not
    a lower bound on anything except host RAM (see above).
  * a complete total. Services with no declared limit count as zero, so every
    figure is a lower bound; the script reports how many services that was, and
    which, rather than quietly reporting a smaller number.

Usage:
  scripts/deploy-profile-sizing.py               # human-readable summary
  scripts/deploy-profile-sizing.py --format md   # the doc's table rows
  scripts/deploy-profile-sizing.py --profile deploy-profiles/full.txt --verbose
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - CI installs pyyaml for this step
    sys.exit(
        "deploy-profile-sizing.py needs PyYAML to read the compose files.\n"
        "  pip install pyyaml"
    )

ROOT = Path(__file__).resolve().parents[1]
PROFILE_DIR = ROOT / "deploy-profiles"
HOME_DIR = ROOT / "arcane" / "home"
VPS_COMPOSE = ROOT / "vps" / "docker-compose.yml"

# Docker compose accepts a decimal value plus an optional binary-ish unit
# suffix. Everything in these trees is `128M` / `1G` / `12G` / `2GB`; sizes
# are normalised to bytes here so the sums are arithmetic, not string
# concatenation.
_SUFFIX = re.compile(r"^\s*([0-9]*\.?[0-9]+)\s*([a-zA-Z]*)\s*$")
_UNITS = {"": 1, "b": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}


def memory_bytes(value) -> int:
    """Parse a compose memory limit into bytes. Docker's own suffixes, binary
    multiples (`m`/`M` is MiB, not MB) -- see scripts/compose-drift-watch.py's
    _compose_memory_bytes(), which normalises the same way."""
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    match = _SUFFIX.match(str(value))
    if not match:
        raise ValueError(f"unparseable memory limit: {value!r}")
    number, suffix = match.group(1), match.group(2).lower()
    if len(suffix) > 1 and suffix.endswith("b"):  # 2GB, 1Gb
        suffix = suffix[:-1]
    if suffix not in _UNITS:
        raise ValueError(f"unknown memory unit in {value!r}")
    return int(float(number) * _UNITS[suffix])


def service_limits(compose: Path) -> dict[str, dict]:
    """service name -> {"cpus": float|None, "memory": int|None, "path": str}

    A service with no declared limit gets None for that field, never 0-as-if-
    it-were-declared, so the caller can count what is missing. YAML merge keys
    (`<<: *anchor`) are resolved by PyYAML's loader, which matters for the VPS
    compose's six `oidc-*` services."""
    document = yaml.safe_load(compose.read_text(encoding="utf-8")) or {}
    out: dict[str, dict] = {}
    for name, service in (document.get("services") or {}).items():
        if not isinstance(service, dict):
            continue
        resources = ((service.get("deploy") or {}).get("resources") or {})
        limits = resources.get("limits") or {}
        # analysis/ghidra's revdeck service still uses the pre-swarm spelling.
        memory = limits.get("memory", service.get("mem_limit"))
        cpus = limits.get("cpus")
        out[name] = {
            "cpus": float(cpus) if cpus is not None else None,
            "memory": memory_bytes(memory) if memory is not None else None,
            "path": f"{compose.relative_to(ROOT)}",
        }
    return out


def stack_compose(stack: str) -> Path:
    return HOME_DIR / f"honeypot-{stack}" / "compose.yml"


def profile_stacks(profile: Path) -> list[str]:
    """One stack name per line, `#` comments and blank lines ignored -- the
    format docs/deploy-profiles/README.md documents and
    scripts/validate-deploy-profile.sh parses."""
    names = []
    for line in profile.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            names.append(line)
    return names


def role_totals(services: dict[str, dict]) -> dict:
    cpus = sum(s["cpus"] or 0.0 for s in services.values())
    memory = sum(s["memory"] or 0 for s in services.values())
    undeclared = sorted(
        name
        for name, s in services.items()
        if s["cpus"] is None or s["memory"] is None
    )
    return {
        "cpus": cpus,
        "memory": memory,
        "services": len(services),
        "undeclared": undeclared,
    }


def profile_totals(profile: Path) -> dict:
    per_stack = {}
    for stack in profile_stacks(profile):
        services = service_limits(stack_compose(stack))
        per_stack[stack] = {"services": services, "totals": role_totals(services)}
    combined: dict[str, dict] = {}
    for entry in per_stack.values():
        combined.update(entry["services"])
    return {
        "profile": profile,
        "stacks": profile_stacks(profile),
        "per_stack": per_stack,
        "totals": role_totals(combined),
    }


def human_memory(num: int) -> str:
    return f"{num / 1024 ** 3:.1f} GiB"


def report_text(profiles: list[dict], vps: dict) -> str:
    out = ["# home role -- declared container ceilings per profile", ""]
    header = f"{'profile':24s} {'stacks':>7s} {'services':>10s} {'cpus':>8s} {'memory':>10s} {'no limits':>10s}"
    out.append(header)
    out.append("-" * len(header))
    for p in profiles:
        t = p["totals"]
        out.append(
            f"{p['profile'].name:24s} {len(p['stacks']):7d} {t['services']:10d} "
            f"{t['cpus']:8.1f} {human_memory(t['memory']):>10s} {len(t['undeclared']):10d}"
        )
    out += ["", "per stack, largest declared memory first:", ""]
    for p in profiles:
        out.append(f"{p['profile'].name}:")
        for stack, entry in sorted(
            p["per_stack"].items(),
            key=lambda kv: (-kv[1]["totals"]["memory"], kv[0]),
        ):
            t = entry["totals"]
            out.append(
                f"  {stack:24s} {t['services']:3d} svc  {t['cpus']:5.1f} cpu  "
                f"{human_memory(t['memory']):>10s}"
                + (f"  (no limits: {', '.join(t['undeclared'])})" if t["undeclared"] else "")
            )
        out.append("")
    t = vps["totals"]
    out += [
        "# vps role -- declared container ceilings (vps/docker-compose.yml)",
        "",
        f"  {t['services']:3d} svc  {t['cpus']:5.1f} cpu  {human_memory(t['memory']):>10s}"
        f"  ({len(t['undeclared'])} services declare no limit and count as 0)",
    ]
    return "\n".join(out)


def report_markdown(profiles: list[dict], vps: dict) -> str:
    """The exact table rows docs/deploy-profiles/README.md embeds, so
    tests/docs/test_3328_profile_sizing_matches_compose.py can hold the doc to
    the compose files instead of to a hand-copied number."""
    rows = []
    for p in profiles:
        t = p["totals"]
        rows.append(
            f"| `{p['profile'].name}` | {len(p['stacks'])} | {t['services']} | "
            f"{t['cpus']:.1f} | {human_memory(t['memory'])} | {len(t['undeclared'])} |"
        )
    t = vps["totals"]
    rows.append(
        f"| `vps/` (whole role) | — | {t['services']} | "
        f"{t['cpus']:.1f} | {human_memory(t['memory'])} | {len(t['undeclared'])} |"
    )
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--format", choices=("text", "md"), default="text",
        help="text: the full summary; md: just the doc's table rows (#3328)",
    )
    parser.add_argument(
        "--profile", action="append", metavar="PATH",
        help="only this profile (repeatable); defaults to every deploy-profiles/*.txt",
    )
    args = parser.parse_args(argv)

    if args.profile:
        profiles = [profile_totals(Path(p).resolve()) for p in args.profile]
    else:
        profiles = [
            profile_totals(p) for p in sorted(PROFILE_DIR.glob("*.txt"))
        ]
    vps = {"totals": role_totals(service_limits(VPS_COMPOSE))}

    if args.format == "md":
        print(report_markdown(profiles, vps))
    else:
        print(report_text(profiles, vps))
    return 0


if __name__ == "__main__":
    sys.exit(main())
