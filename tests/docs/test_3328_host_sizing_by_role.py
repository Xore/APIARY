#!/usr/bin/env python3
"""Regression test for #3328's per-role host sizing.

The issue asked for "measured resource sizing per role (VPS vs homeserver)"
next to the deploy profiles. docs/deploy-profiles/README.md now publishes
that sizing, and this test is what keeps it true.

The failure it guards against is the ordinary one for a number written in
prose: the number was correct when written, a compose limit moved, and the
doc kept asserting the old figure. Nothing in the tree would notice --
unlike the ES heap, which the runtime itself enforces. So this test
recomputes every published figure from the compose files it claims to
describe and compares.

Three things are asserted:

1. The sizing section exists, names both roles, and keeps the two
   distinctions it exists to draw: a hard floor (pinned, real minimum)
   versus a declared ceiling (what a limit permits, not what a host
   needs). A doc that blurred those into one "requirement" number would be
   the same bug as having no doc at all.
2. The published figures still match the tree -- per-profile service
   counts and ceiling sums, the VPS always-on totals, and the
   Elasticsearch heap/limit that the whole home floor rests on.
3. docs/SENSORS.md's runtime budget agrees with the same compose file. It
   had drifted: it said 8 GiB with a 4 GiB heap, while
   arcane/home/honeypot-elk/compose.yml has pinned 6g since before the
   #258 split and now caps the container at 12G. That understated the one
   number in the repository that is a hard floor by 2 GiB.
"""
import pathlib
import re
import sys

import pytest
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PROFILES_README = REPO_ROOT / "docs/deploy-profiles/README.md"
SENSORS_DOC = REPO_ROOT / "docs/SENSORS.md"
ELK_COMPOSE = REPO_ROOT / "arcane/home/honeypot-elk/compose.yml"
VPS_COMPOSE = REPO_ROOT / "vps/docker-compose.yml"
PROFILE_DIR = REPO_ROOT / "deploy-profiles"


# ── measurement helpers, mirroring how the doc's numbers were derived ──


def _mib(value):
    """Compose memory value -> MiB. Accepts '12G', '1024M', bare bytes."""
    if value is None:
        return 0.0
    text = str(value).strip()
    match = re.match(r"^([0-9.]+)\s*([kKmMgG])[bB]?$", text)
    if match:
        return float(match.group(1)) * {"k": 1 / 1024, "m": 1, "g": 1024}[
            match.group(2).lower()
        ]
    return float(text) / (1024 * 1024)


def _limits(service):
    return (
        (((service or {}).get("deploy") or {}).get("resources") or {}).get("limits")
        or {}
    )


def _mem(limits):
    return limits.get("mem_limit", limits.get("memory"))


def _profile_stacks(path):
    stacks = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        if line:
            stacks.append(line)
    return stacks


def _stack_totals(stack):
    """(services, vCPU, MiB) of one home stack's declared ceilings."""
    compose = yaml.safe_load(
        (REPO_ROOT / f"arcane/home/honeypot-{stack}/compose.yml").read_text(encoding="utf-8")
    ) or {}
    services = 0
    cpus = mib = 0.0
    for service in (compose.get("services") or {}).values():
        if not isinstance(service, dict):
            continue
        services += 1
        limits = _limits(service)
        cpus += float(limits.get("cpus") or 0)
        mib += _mib(_mem(limits))
    return services, cpus, mib


def _profile_totals(profile_path):
    """(stacks, services, services-with-a-limit, vCPU, MiB) for one profile.

    The count is of services *declared* in the profile's compose files,
    which includes one-shot bootstrap jobs (honeypot-elk's
    arkime-pcap-init is the only such service carrying no limit) -- the doc
    says "services", not "containers running", and this measures the same
    thing the doc counted.
    """
    stacks = _profile_stacks(profile_path)
    services = limited = 0
    cpus = mib = 0.0
    for stack in stacks:
        compose = REPO_ROOT / f"arcane/home/honeypot-{stack}/compose.yml"
        for service in (yaml.safe_load(compose.read_text(encoding="utf-8")) or {}).get(
            "services", {}
        ).values():
            if not isinstance(service, dict):
                continue
            services += 1
            limits = _limits(service)
            cpu, mem = limits.get("cpus"), _mem(limits)
            if cpu is not None or mem is not None:
                limited += 1
                cpus += float(cpu) if cpu is not None else 0.0
                mib += _mib(mem)
    return len(stacks), services, limited, cpus, mib


def _vps_totals():
    compose = yaml.safe_load(VPS_COMPOSE.read_text(encoding="utf-8")) or {}
    always_on = [
        service
        for service in compose.get("services", {}).values()
        if isinstance(service, dict) and service.get("restart") in ("unless-stopped", "always")
    ]
    cpus = sum(float(_limits(s).get("cpus") or 0) for s in always_on)
    mib = sum(_mib(_mem(_limits(s))) for s in always_on)
    limited = sum(1 for s in always_on if _limits(s))
    return len(compose.get("services", {})), len(always_on), limited, cpus, mib


# ── 1. the section exists and keeps the distinction it exists to draw ──


@pytest.fixture(scope="module")
def profiles_doc():
    return PROFILES_README.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def flat_profiles_doc(profiles_doc):
    """The same document with every whitespace run collapsed to one space.

    Prose assertions below match sentences that wrap across lines. Matching
    the raw text would make a reflow of the paragraph a test failure, which
    is not what any of these are checking -- they check the *numbers* and
    the claims, so reflow has to be invisible to them.
    """
    return re.sub(r"\s+", " ", profiles_doc)


def test_sizing_section_exists(profiles_doc):
    assert "## Host sizing by role" in profiles_doc, (
        "docs/deploy-profiles/README.md lost its per-role sizing section -- that "
        "section is the whole of #3328's deliverable on this side"
    )


def test_sizing_section_names_both_roles(profiles_doc):
    for role in ("### Role: VPS", "### Role: home server"):
        assert role in profiles_doc, f"missing the {role!r} block"


def test_sizing_keeps_floor_and_ceiling_distinct(profiles_doc):
    # A "minimum sizing" doc that quietly published ceiling sums as
    # requirements would be the same failure as no doc: the full profile
    # declares 120.50 vCPU, which is not a host size.
    assert "ceiling is not a reservation" in profiles_doc.lower(), (
        "the sizing section must say plainly that declared ceilings are not "
        "reservations, or the ceiling columns read as host requirements"
    )
    assert "no per-role load test in this repository" in profiles_doc, (
        "the section must keep stating that the reference-host figures are the "
        "only measured data -- one host per role, not a load test"
    )


def test_sizing_table_cross_references_the_roles(profiles_doc):
    assert "#host-sizing-by-role" in profiles_doc, (
        "the 'Not covered here' paragraph must point at the sizing section now "
        "that it covers VPS host sizing, so the two do not read as contradicting"
    )


# ── 2. the published figures still match the tree ──


@pytest.mark.parametrize(
    "profile", ["full.txt", "ics-focused.txt", "minimal-web.txt"]
)
def test_profile_row_matches_its_compose_files(profiles_doc, profile):
    stacks, services, limited, cpus, mib = _profile_totals(PROFILE_DIR / profile)
    # One table row per profile: | `name.txt` | stacks | services | limited | vCPU | GiB |
    row = re.search(
        rf"\|\s*\[`{re.escape(profile)}`\][^|]*\|\s*(\d+)\s*\|\s*(\d+)\s*\|"
        rf"\s*(\d+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|",
        profiles_doc,
    )
    assert row, f"no sizing table row found for {profile}"
    assert int(row.group(1)) == stacks, (
        f"{profile} resolves to {stacks} stacks, the doc says {row.group(1)}"
    )
    assert int(row.group(2)) == services, (
        f"{profile} declares {services} services in arcane/home/*/compose.yml, "
        f"the doc says {row.group(2)}"
    )
    assert int(row.group(3)) == limited, (
        f"{profile} has {limited} services carrying a deploy.resources limit, "
        f"the doc says {row.group(3)}"
    )
    assert float(row.group(4)) == pytest.approx(cpus, abs=0.01), (
        f"{profile} declares {cpus:.2f} vCPU of ceilings, the doc says {row.group(4)}"
    )
    assert float(row.group(5)) == pytest.approx(mib / 1024, abs=0.01), (
        f"{profile} declares {mib / 1024:.2f} GiB of ceilings, the doc says {row.group(5)}"
    )


def test_vps_figures_match_the_vps_compose(profiles_doc):
    total, always_on, limited, cpus, mib = _vps_totals()
    assert f"{total} services, {always_on} always-on" in profiles_doc, (
        f"vps/docker-compose.yml declares {total} services, {always_on} of them "
        "always-on; the sizing section must state that count"
    )
    assert f"{limited} that carry limits sum to" in profiles_doc, (
        f"{limited} always-on VPS services carry a limit; the doc must say so, and "
        "must not imply the sum covers the rest"
    )
    assert f"**{cpus:.2f} vCPU / {mib / 1024:.2f} GiB**" in profiles_doc, (
        f"VPS always-on ceilings sum to {cpus:.2f} vCPU / {mib / 1024:.2f} GiB"
    )
    unlimited = always_on - limited
    assert f"other {unlimited}" in profiles_doc, (
        f"{unlimited} always-on VPS services carry no limit at all; the doc must "
        "count them, since a ceiling sum that silently omits them is an undercount"
    )


def test_elasticsearch_heap_is_published_as_the_hard_floor(profiles_doc):
    compose = yaml.safe_load(ELK_COMPOSE.read_text(encoding="utf-8"))
    elasticsearch = compose["services"]["elasticsearch"]
    entry = [e for e in elasticsearch["environment"] if e.startswith("ES_JAVA_OPTS")][0]
    heap = entry.split("=", 1)[1]
    heap_gib = _mib(re.search(r"-Xms([0-9.]+[gGmM])", heap).group(1)) / 1024
    assert heap == "-Xms6g -Xmx6g", f"unexpected heap pin: {heap!r}"
    # mlock is what makes the heap a floor rather than a ceiling: a host under
    # pressure cannot reclaim a locked heap by swapping.
    assert "bootstrap.memory_lock=true" in elasticsearch["environment"], (
        "the sizing section's hard floor rests on memory_lock; without it the "
        "heap is a recoverable reservation, not a floor"
    )
    assert elasticsearch["ulimits"]["memlock"] == {"soft": -1, "hard": -1}
    assert f"**{heap_gib:.0f} GiB of permanently resident, unswappable RAM" in profiles_doc, (
        f"the home hard floor must be the {heap_gib:.0f} GiB heap this compose pins"
    )
    limit = _mem(_limits(elasticsearch))
    assert f"`memory: {limit}`" in profiles_doc, (
        f"Elasticsearch's container ceiling is {limit}; the doc must quote it"
    )
    assert f"exactly 2x the heap" in profiles_doc, (
        f"{limit} is exactly twice {heap}; the doc should say what that ratio is"
    )


def test_pcap_bounds_are_quoted_from_the_files_that_enforce_them(profiles_doc):
    # The VPS bound is Suricata's own pcap-log rotation; the home bound is
    # pcap-sync's PCAP_MAX_GB. Neither is enforced by a cleanup script, so
    # both numbers have to come from the file that actually enforces them.
    suricata = (REPO_ROOT / "vps/suricata/suricata.yaml").read_text(encoding="utf-8")
    assert "max-files: 12500" in suricata
    assert "`limit: 4mb` with `max-files: 12500`" in profiles_doc
    assert f"`PCAP_MAX_GB`, default 200" in profiles_doc
    installer = (REPO_ROOT / "scripts/install-homeserver.sh").read_text(encoding="utf-8")
    assert '"defaultMinFreeSpace": "100GB"' in installer
    assert "**100 GB free on `/var`**" in profiles_doc, (
        "install-homeserver.sh enforces a 100 GB buildkit GC floor on /var; the "
        "sizing section must carry it, because an advisory number is not a floor"
    )


def test_backbone_not_sensors_dominates_the_home_ceilings(flat_profiles_doc):
    # The actionable claim in the section: narrowing the sensor list barely
    # moves the total, because the biggest single contributor is elk, which
    # every profile carries. If that ever stops being true the doc's advice
    # ("a narrow profile is not a proportionally smaller host") inverts.
    assert all(
        "elk" in _profile_stacks(PROFILE_DIR / name)
        for name in ("full.txt", "ics-focused.txt", "minimal-web.txt")
    ), "elk is no longer in every profile; the shared-floor claim needs rewriting"
    _, elk_cpu, elk_mib = _stack_totals("elk")
    full_stacks, _, _, full_cpu, _ = _profile_totals(PROFILE_DIR / "full.txt")
    ics_stacks, _, _, ics_cpu, _ = _profile_totals(PROFILE_DIR / "ics-focused.txt")
    assert (
        f"`elk` alone declares {elk_cpu:.2f} vCPU and {elk_mib / 1024:.2f} GiB"
        in flat_profiles_doc
    ), (
        f"elk declares {elk_cpu:.2f} vCPU / {elk_mib / 1024:.2f} GiB of ceilings; "
        "the doc must quote it"
    )
    dropped = full_stacks - ics_stacks
    delta = full_cpu - ics_cpu
    assert f"Dropping {dropped} of `full`'s {full_stacks} stacks" in flat_profiles_doc
    assert f"takes {delta:.2f} vCPU off {full_cpu:.2f}" in flat_profiles_doc


def test_narrower_is_not_always_lighter(flat_profiles_doc):
    # minimal-web and ics-focused list the same number of stacks, so the
    # intuitive "fewer stacks, smaller host" reading is wrong here: tanner
    # declares more than conpot+dnp3 combined.
    web_stacks, _, _, web_cpu, _ = _profile_totals(PROFILE_DIR / "minimal-web.txt")
    ics_stacks, _, _, ics_cpu, _ = _profile_totals(PROFILE_DIR / "ics-focused.txt")
    assert web_stacks == ics_stacks, (
        f"the doc compares the two as equal-width ({ics_stacks} stacks each); "
        f"they are now {ics_stacks} and {web_stacks}"
    )
    tanner_svc, tanner_cpu, _ = _stack_totals("tanner")
    conpot_svc, conpot_cpu, _ = _stack_totals("conpot")
    dnp3_svc, dnp3_cpu, _ = _stack_totals("dnp3")
    assert (
        f"`tanner` alone is {tanner_svc} services and {tanner_cpu:.2f} vCPU"
        in flat_profiles_doc
    )
    assert (
        f"which outweighs `conpot` ({conpot_svc} services, {conpot_cpu:.2f}) plus "
        f"`dnp3` ({dnp3_svc} service, {dnp3_cpu:.2f})" in flat_profiles_doc
    ), (
        f"tanner {tanner_svc}svc/{tanner_cpu:.2f} vs conpot {conpot_svc}svc/"
        f"{conpot_cpu:.2f} + dnp3 {dnp3_svc}svc/{dnp3_cpu:.2f}"
    )
    assert web_cpu > ics_cpu, "minimal-web no longer declares more than ics-focused"


# ── 3. the two docs must not contradict each other ──


def test_sensors_budget_agrees_with_the_elk_compose():
    sensors = SENSORS_DOC.read_text(encoding="utf-8")
    compose = yaml.safe_load(ELK_COMPOSE.read_text(encoding="utf-8"))
    elasticsearch = compose["services"]["elasticsearch"]
    limit_gib = _mib(_mem(_limits(elasticsearch))) / 1024
    assert f"Elasticsearch gets {limit_gib:.0f} GiB with a 6 GiB heap" in sensors, (
        "docs/SENSORS.md's runtime budget must quote the heap and limit the "
        f"compose actually declares ({limit_gib:.0f} GiB / 6 GiB); it drifted to "
        "8 GiB / 4 GiB and understated the one hard floor in the tree by 2 GiB"
    )
    assert "8 GiB with a 4 GiB heap" not in sensors, (
        "the pre-#258 monolith figures are still in docs/SENSORS.md"
    )
    assert "deploy-profiles/README.md#host-sizing-by-role" in sensors, (
        "docs/SENSORS.md's budget paragraph must link the sizing section, so a "
        "reader who lands on the ceilings learns they are not a host size"
    )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
