#!/usr/bin/env python3
"""The shard budget assertion #3283 was missing: every index family bounded
individually is not the same thing as the *total* fitting on one node.

`tests/docs/test_3283_fix.py` pins that `arkime_sessions3-*` has a delete
phase, and `elasticsearch-setup.sh` now gives nearly every family one. What
neither file checks is the sum. On 2026-09-21 the single node reached
`cluster.max_shards_per_node`'s 1000 default and every subsequent index
creation was refused:

    validation_exception: this action would add [1] shards, but this cluster
    currently has [1000]/[1000] maximum normal shards open

which sent every sensor's events to `dead-letter-honeypot` (1.73 B documents by
2026-09-24) and took the fleet silent for three days. Nothing was wrong with
any one family. 84 Zeek log types x one index a day is 84 new primary shards
a day, and nothing anywhere added those up.

So this file computes the steady state from the repo's own two
index-creating layers and asserts it:

  * `analysis/filebeat.yml`'s `output.elasticsearch.indices` -- the routing
    rules that name every index Filebeat creates, and therefore the cadence
    and cardinality of each family.
  * `analysis/elasticsearch-setup.sh` -- the index template that resolves each
    family to an ILM policy, and the policy's `delete.min_age`, which is what
    stops the family accumulating.

Retained-indices-in-flight is `age_days` for a daily family and
`age_days / 30.44` for a monthly one, times the family's cardinality. A
regression is then a number, not a three-day outage.

Two properties make the number trustworthy rather than self-confirming:

* the check reads the routing rules and the policy ages out of the repo, so
  adding a family, flipping a cadence, or changing `HONEYPOT_RETENTION_DAYS`
  moves the projection;
* `test_the_budget_check_rejects_the_pre_3283_cadence` runs the same function
  over the shape #3362 removed (Zeek back to one index per day) and requires it
  to blow the ceiling. If that ever stops being true the budget number has
  stopped meaning anything and every other test here is decoration.

The ceiling is Elasticsearch's 1000 default and stays that way. The live
cluster ran at 1500 from 2026-09-24 as a reversible unblock to restart ingest,
and `test_3283_fix.py` asserts that number is not pinned in the repo on
purpose: moving the ceiling would hide a recurrence instead of fixing it. This
file is the other half of that bargain -- it is what lets the default stand.

Dependency-free on purpose: quality.yml's tests/docs row installs only pytest,
so filebeat.yml is read as text, not parsed as YAML.
"""
from __future__ import annotations

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FILEBEAT = REPO_ROOT / "arcane/home/honeypot-elk/analysis/filebeat.yml"
SETUP = REPO_ROOT / "arcane/home/honeypot-init/analysis/elasticsearch-setup.sh"
SURICATA = REPO_ROOT / "vps/suricata/suricata.yaml"

# cluster.max_shards_per_node's default, and the number every family has to fit
# under. Not configurable: see the module docstring and test_3283_fix.py's
# test_the_shard_cap_is_not_pinned_in_the_repo.
CEILING = 1000

# "Approaching the limit" is a range, not a point, so the assertion is a
# fraction of the ceiling rather than the ceiling itself. 0.75 leaves room for
# a family or two to be added without a red build, and still fails long before
# the node is refusing index creations -- at 1500/2000 the failure mode is a
# dead-letter flood, not a slow creep.
BUDGET_FRACTION = 0.75

DAYS_PER_MONTH = 30.44

# The number of Zeek log types is not statically knowable from the repo: Zeek
# enables its log set from `@load packages` in vps/zeek/local.zeek, so the
# authoritative list lives in the Zeek distribution, not here. What is knowable
# is that it is a two-digit number that moves slowly, and the budget below holds
# with a wide margin around it -- so this is deliberately generous, and the
# assertion is written to survive it growing.
#
# Provenance: measured live on the homeserver on 2026-09-25, when 90 new
# indices appeared in one day and 84 of them were zeek-v1-*/zeek-proxy-v1-*.
# filebeat.yml's own #3283 comment records the same 84.
ZEEK_LOG_TYPES = 84


# --------------------------------------------------------------------------
# The two layers, read out of the repo
# --------------------------------------------------------------------------


def routing_rules(text: str) -> list[tuple[str, str | None]]:
    """Filebeat's `output.elasticsearch.indices` rules, as (pattern, logset).

    The slice stops at the end of the `indices:` list so a `- index:` line
    anywhere else in the file cannot be mistaken for a routing rule.
    """
    start = text.index("output.elasticsearch:")
    block = text[start:]
    end = block.index("non_indexable_policy")
    block = block[:end]
    rules = []
    for match in re.finditer(r'^\s*- index:\s*"([^"]+)"\s*$', block, re.M):
        # The logset is the `when.equals` guard of this same list item, i.e.
        # whatever precedes the next `- index:` line.
        tail = block[match.end():]
        nxt = re.search(r"^\s*- index:", tail, re.M)
        item = tail[: nxt.start()] if nxt else tail
        logset = re.search(r'logset:\s*"([^"]+)"', item)
        rules.append((match.group(1), logset.group(1) if logset else None))
    assert rules, "no output.elasticsearch.indices rules were found; the parser is broken"
    return rules


def cadence(pattern: str) -> str:
    """`daily`, `monthly`, or `none` -- how often this rule mints an index.

    `%{+yyyy.MM.dd}` is a new index every day. `%{+yyyy.MM}.01` is a new index
    once a month, the literal `.01` being what #3362 chose so every consumer's
    `yyyy.MM.dd` regex and `family-*` pattern still matches. A rule with no
    date token mints exactly one index and is therefore not a shard risk at
    all, but `none` is still returned explicitly so a missing date is a
    readable outcome rather than a silent zero.
    """
    if re.search(r"%\{\+yyyy\.MM\}\.01$", pattern):
        return "monthly"
    if re.search(r"%\{\+yyyy\.MM\.dd\}$", pattern):
        return "daily"
    if re.search(r"%\{\+yyyy", pattern):
        return "unknown"
    return "none"


def cardinality(pattern: str, suricata_types: int) -> int:
    """How many distinct index names one rule can produce.

    A `%{[field]}` segment is the only source of multiplication here, and the
    two that exist are both countable from the repo: Suricata's event types are
    declared in vps/suricata/suricata.yaml's eve-log `types:`, and Zeek's log
    types are the declared constant above.
    """
    fields = re.findall(r"%\{\[([^\]]+)\]\}", pattern)
    total = 1
    for field in fields:
        if field == "suricata.eve.event_type":
            total *= suricata_types
        elif field == "zeek_log":
            total *= ZEEK_LOG_TYPES
        else:
            raise AssertionError(
                f"routing rule {pattern!r} multiplies by an index name field the "
                f"budget cannot count: {field!r}. Add its cardinality to "
                "cardinality() or this projection is quietly an underestimate."
            )
    return total


def suricata_event_types(text: str) -> int:
    """The event types Suricata's eve-log is configured to emit."""
    lines = text.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if line.strip() == "types:" and "eve-log" in "\n".join(lines[max(0, i - 60):i])),
        None,
    )
    assert start is not None, "no eve-log types: block in vps/suricata/suricata.yaml"
    indent = len(lines[start]) - len(lines[start].lstrip())
    found = []
    for line in lines[start + 1:]:
        if not line.strip():
            continue
        pad = len(line) - len(line.lstrip())
        if pad <= indent:
            break
        head = re.match(r"\s*-\s*([A-Za-z0-9_]+)\s*:", line)
        if head and pad == indent + 2:
            found.append(head.group(1))
    assert found, "eve-log types: block parsed to nothing; the parser is broken"
    return len(found)


def templates(text: str) -> list[tuple[str, tuple[str, ...], str | None, int]]:
    """Every `PUT _index_template/<name>` as (name, patterns, lifecycle, priority).

    Splitting on the URL is enough and stays readable; each chunk is the
    template's own heredoc or single-quoted body. `index_patterns` is kept as a
    tuple rather than joined, because one template legitimately covers two
    families -- `zeek-events` matches `["zeek-v1-*", "zeek-proxy-v1-*"]` -- and
    matching a joined string as if it were a single glob silently fails to match
    anything.

    Priority is part of the tuple because it is how Elasticsearch picks between
    two templates that both match: `zeek-proxy-events` (480) must beat
    `zeek-events` (470) for a `zeek-proxy-v1-*` name, or every proxy index
    would be budgeted against the wrong policy's delete age.
    """
    out = []
    for chunk in text.split("_index_template/")[1:]:
        name = re.split(r'["\'\s]', chunk, maxsplit=1)[0].strip(" \\")
        patterns = re.search(r'"index_patterns":\s*\[(.*?)\]', chunk[:3000], re.S)
        if not patterns:
            continue
        lifecycle = re.search(r'"index\.lifecycle\.name":\s*"([^"]+)"', chunk[:3000])
        priority = re.search(r'"priority":\s*(\d+)', chunk[:3000])
        out.append((
            name,
            tuple(re.findall(r'"([^"]+)"', patterns.group(1))),
            lifecycle.group(1) if lifecycle else None,
            int(priority.group(1)) if priority else 0,
        ))
    assert out, "no index templates parsed out of elasticsearch-setup.sh"
    return out


def policy_ages(text: str, retention_days: int) -> dict[str, int]:
    """ILM policy name -> delete.min_age in days, for one retention setting.

    The ages are shell arithmetic, not literals, because #2193 made every window
    derive from HONEYPOT_RETENTION_DAYS. Evaluating them here rather than
    reading a hardcoded table is the point: change the knob and the projection
    moves with it. The four forms that appear are handled explicitly instead of
    `eval`, so this stays a parser and not a code-execution hole.
    """
    suricata_days = max(1, retention_days * 7 // 30)
    ages: dict[str, int] = {}
    loop = re.search(r"for spec in\s+(.*?); do", text, re.S).group(1)
    for name, expr in re.findall(r'"([a-z0-9\-]+):([^"]+)"', loop):
        ages[name] = _evaluate_age(expr, retention_days, suricata_days)
    # honeypot-30d is defined outside the loop because its hot phase is a real
    # rollover rather than delete-only. Its delete age is still the knob.
    rollover = re.search(r'_ilm/policy/honeypot-30d.*?\\"min_age\\":\\"\$(\{retention_days\})d\\"', text, re.S)
    assert rollover, "honeypot-30d's delete.min_age is no longer the retention knob"
    ages["honeypot-30d"] = _evaluate_age("${retention_days}d", retention_days, suricata_days)
    return ages


def _evaluate_age(expr: str, retention_days: int, suricata_days: int) -> int:
    multipliers = {
        "${retention_days}d": retention_days,
        "$(( retention_days * 2 ))d": retention_days * 2,
        "$(( retention_days * 6 ))d": retention_days * 6,
        "${suricata_days}d": suricata_days,
    }
    if expr not in multipliers:
        raise AssertionError(
            f"unrecognised ILM min_age expression {expr!r}. Add it to the table "
            "rather than letting this projection silently skip the policy."
        )
    return multipliers[expr]


def _family(pattern: str) -> str:
    """The index name with every variable and date token collapsed to a probe.

    Only used for matching against a template's `index_patterns`, so the probe
    value just has to be something no real log type is called.
    """
    name = re.sub(r"%\{\[[^\]]+\]\}", "probe", pattern)
    name = re.sub(r"%\{\+[^}]+\}(\.01)?", "", name)
    return name


def _matches(family: str, index_pattern: str) -> bool:
    rx = "^" + re.escape(index_pattern).replace(r"\*", ".*") + "$"
    return re.match(rx, family) is not None


def _covers(family: str, patterns: tuple[str, ...]) -> bool:
    return any(_matches(family, p) for p in patterns)


def resolve(family: str, tpls, ages):
    """(policy, age_days) for one family, honouring template priority.

    Mirrors how Elasticsearch picks: the highest-priority matching composable
    template wins. `zeek-proxy-events` (480) therefore decides `zeek-proxy-*`
    rather than `zeek-events` (470), which is what the live cluster does.
    Returns (None, None) when nothing matches, and (policy, None) when the
    winning template names no policy -- the two failures the caller reports
    differently.
    """
    hits = [t for t in tpls if _covers(family, t[1])]
    if not hits:
        return None, None
    policy = max(hits, key=lambda t: t[3])[2]
    if policy is None:
        return None, None
    return policy, ages.get(policy)


def project(retention_days: int, filebeat_text: str | None = None) -> dict:
    """The steady-state primary-shard count, broken down by family.

    `filebeat_text` exists so a test can project an alternative routing config
    through this exact arithmetic instead of duplicating it. It defaults to the
    repo's own file; nothing here writes to it.
    """
    fb = filebeat_text if filebeat_text is not None else FILEBEAT.read_text(encoding="utf-8")
    sh = SETUP.read_text(encoding="utf-8")
    rules = routing_rules(fb)
    tpls = templates(sh)
    ages = policy_ages(sh, retention_days)
    types = suricata_event_types(SURICATA.read_text(encoding="utf-8"))

    per_family: dict[str, int] = {}
    unbounded: list[str] = []
    unresolved: list[str] = []
    for pattern, _logset in rules:
        family = _family(pattern)
        kind = cadence(pattern)
        if kind == "none":
            # One index, one shard, forever: not a shard-growth term.
            continue
        if kind == "unknown":
            unbounded.append(pattern)
            continue
        policy, age = resolve(family, tpls, ages)
        if policy is None or age is None:
            unresolved.append(f"{pattern} -> {policy}")
            continue
        in_flight = age if kind == "daily" else age / DAYS_PER_MONTH
        shards = cardinality(pattern, types) * in_flight
        # dashboard-backend-v1 is routed by two logsets onto one family, so the
        # family is keyed, not the rule: a second rule for the same index names
        # must not be counted as a second copy of the same shards.
        per_family[family] = max(per_family.get(family, 0), shards)

    # Fixed-name families: the singleton indices this repo installs. Each is one
    # index for the life of the stack, so one shard each.
    singletons = sum(
        1 for _name, patterns, _lc, _prio in tpls
        if not any("*" in p for p in patterns) and not any("dead-letter" in p for p in patterns)
    )
    # The families this repo does not own and cannot bound: Kibana's saved
    # objects, Elasticsearch's own .internal/monitoring indices, Arkime's
    # configuration indices, and filebeat's monitoring index. Measured live on
    # 2026-09-27: 38 such indices. Rounded up, because the projection's job is
    # to be pessimistic about the ceiling it has to fit under.
    platform = 40

    dynamic = sum(per_family.values())
    return {
        "per_family": per_family,
        "unbounded": unbounded,
        "unresolved": unresolved,
        "singletons": singletons,
        "platform": platform,
        "total": dynamic + singletons + platform,
    }


# --------------------------------------------------------------------------
# The assertion
# --------------------------------------------------------------------------


def test_every_routing_rule_rolls_over_on_a_bounded_cadence():
    """No index family may mint a fresh index on an unbounded schedule.

    The cheapest possible form of the #3283 bug: a routing rule whose date
    token is neither the daily nor the monthly shape parses as `unknown` rather
    than being counted, so it has to fail here instead of quietly dropping out
    of the projection below.
    """
    fb = FILEBEAT.read_text(encoding="utf-8")
    unknown = [p for p, _ in routing_rules(fb) if cadence(p) == "unknown"]
    assert not unknown, (
        f"routing rules with an unrecognised date cadence: {unknown}. A rule "
        "this test cannot read is a family whose shard count it cannot budget "
        "(#3283)."
    )


def test_no_routing_rule_writes_to_a_dateless_index():
    """Every family Filebeat writes to is date-partitioned.

    Found by mutation-testing this file: a rule whose name carries no date at
    all, `- index: "traefik-v1"`, passes both checks above and is still wrong,
    in a way specific to #3283. It is not a shard-count problem -- one index is
    one shard -- but it is a retention one, and worse than an unbounded family:

      * its name does not match its own template's `traefik-v1-*` pattern, so it
        resolves to the priority-1 `single-node-replica-default` catch-all,
        which sets replicas and nothing else. The family gets no ILM policy at
        all, which is the same defect #3283 found in `arkime_sessions3-*`; and
      * giving it a policy would not help. A delete-only policy on an
        unpartitioned index deletes the *whole* index when min_age is reached,
        so the data is lost rather than rotated.

    So a dateless rule is a routing mistake either way, and neither the shard
    budget nor the delete-phase check can see it. This can.
    """
    dateless = [p for p, _ in routing_rules(FILEBEAT.read_text(encoding="utf-8")) if cadence(p) == "none"]
    assert not dateless, (
        f"routing rules writing to a dateless index: {dateless}. Every family "
        "here is date-partitioned; a name with no date token stops matching its "
        "own index template, so the family silently loses its ILM policy, and "
        "attaching a delete-only policy to it would delete the whole index "
        "rather than rotate it (#3283)."
    )


def test_every_routing_family_resolves_to_a_policy_that_deletes():
    """A family with no delete phase is the arkime_sessions3-* bug (#3283).

    Live, that family was the only one with no retention: it added one index a
    day, forever, and its 12 existing indices were never going to expire. This
    asserts the general form of that check, so the next unbounded family fails
    here by name rather than three days later as a dead-letter flood.
    """
    sh = SETUP.read_text(encoding="utf-8")
    fb = FILEBEAT.read_text(encoding="utf-8")
    tpls = templates(sh)
    ages = policy_ages(sh, 30)
    orphans = []
    for pattern, logset in routing_rules(fb):
        if cadence(pattern) == "none":
            continue
        family = _family(pattern)
        policy, age = resolve(family, tpls, ages)
        if policy is None:
            orphans.append(f"{family} (no index.lifecycle.name on any matching template)")
        elif age is None:
            orphans.append(f"{family} -> {policy} (no delete.min_age)")
    assert not orphans, (
        f"routing families with no ILM delete phase: {orphans}. Each adds a new "
        "index per rollover and never ages one out, which is how the node "
        "reached 1000/1000 and dead-lettered every sensor (#3283)."
    )


def test_the_steady_state_fits_under_the_default_shard_ceiling():
    """THE check. The whole stack's projected shard count, asserted.

    Not a warning, and not a log line: an assertion with a number on it. The
    ceiling is Elasticsearch's own 1000 default because the repo deliberately
    does not raise it (test_3283_fix.py asserts the raised 1500 is absent), so
    this is the test that makes leaving the default at 1000 safe.
    """
    budget = project(30)
    assert not budget["unbounded"], f"unbudgeted routing rules: {budget['unbounded']}"
    assert not budget["unresolved"], f"routing families with no deletable policy: {budget['unresolved']}"
    limit = int(CEILING * BUDGET_FRACTION)
    assert budget["total"] <= limit, (
        f"projected steady state is {budget['total']:.0f} primary shards against a "
        f"{limit} budget ({BUDGET_FRACTION:.0%} of cluster.max_shards_per_node's "
        f"{CEILING} default). Per family: "
        + ", ".join(f"{k}={v:.0f}" for k, v in sorted(budget["per_family"].items(), key=lambda kv: -kv[1]))
        + f", singletons={budget['singletons']}, platform={budget['platform']}. "
        "On the 2026-09-21 live cluster this is what filled the node and turned "
        "every new index creation into a dead-letter (#3283)."
    )


def shipped_retention_values() -> list[int]:
    """Every HONEYPOT_RETENTION_DAYS a stack in this repo actually ships."""
    values = set()
    for path in REPO_ROOT.rglob("*.env.example"):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("HONEYPOT_RETENTION_DAYS="):
                values.add(int(line.split("=", 1)[1]))
    assert values, "no HONEYPOT_RETENTION_DAYS found in any .env.example"
    return sorted(values)


def test_every_shipped_retention_value_fits_the_ceiling():
    """The knob's real settings, not a range that includes impossible ones.

    #2193 made every window derive from HONEYPOT_RETENTION_DAYS, so the budget
    is a function of the knob. This asserts it for the values the stacks
    actually ship -- 21 (homeserver) and 30 (VPS) -- read out of the
    `.env.example` files rather than hardcoded, so a stack changing its own
    default is covered automatically.

    It deliberately does *not* claim an arbitrary retention fits. At 90 days the
    same arithmetic projects ~1,860 shards: past a point this knob is bounded by
    the node, not by the operator's intent, and the honest thing for a check to
    say is that the shipped values fit and larger ones are a decision (more
    nodes, or coarser rollover), not something to paper over. See
    test_the_projection_reports_a_retention_value_that_cannot_fit, which pins
    that the projection is capable of saying so.
    """
    for retention in shipped_retention_values():
        budget = project(retention)
        assert budget["total"] <= int(CEILING * BUDGET_FRACTION), (
            f"a shipped HONEYPOT_RETENTION_DAYS={retention} projects "
            f"{budget['total']:.0f} primary shards, over the "
            f"{int(CEILING * BUDGET_FRACTION)} budget (#3283)"
        )


def test_the_projection_reports_a_retention_value_that_cannot_fit():
    """A check that cannot go red is not a check.

    The knob is operator-facing and nothing stops someone setting it to 180.
    Rather than assert that impossible (it does not fit -- see the test above),
    this asserts the projection is monotonic in the knob and does exceed the
    ceiling at a large enough value. If the arithmetic were quietly dropping
    terms, the shipped-value test would keep passing while the model had stopped
    describing the cluster.
    """
    totals = [project(days)["total"] for days in (7, 21, 30, 60, 90, 180)]
    assert totals == sorted(totals), (
        f"the projection is not monotonic in HONEYPOT_RETENTION_DAYS: {totals}"
    )
    assert totals[-1] > CEILING, (
        f"a 180-day retention still projects {totals[-1]:.0f} shards, under the "
        f"{CEILING} cap. Either the model has lost a term or the stack really "
        f"does fit; one of those is wrong (#3283)"
    )


def test_the_budget_check_rejects_the_pre_3283_cadence():
    """The teeth. The same projection, over the shape that caused the outage.

    #3362 changed Zeek from one index per log type per day to one per month.
    Feeding the pre-fix daily shape back through `project()` must blow the
    ceiling by a wide margin. If this ever passes, the projection is not
    measuring anything and the assertion above is decoration.
    """
    monthly = FILEBEAT.read_text(encoding="utf-8")
    pre_fix = monthly.replace("%{+yyyy.MM}.01", "%{+yyyy.MM.dd}")
    assert pre_fix != monthly, "the Zeek monthly cadence is gone; this test no longer proves anything"

    limit = int(CEILING * BUDGET_FRACTION)
    # The same project() and the same arithmetic, fed the pre-fix routing text
    # as a string. Nothing is written to the repo, and there is exactly one
    # implementation of the projection for both configurations to go through.
    budget = project(30, filebeat_text=pre_fix)

    assert budget["total"] > limit, (
        f"one index per Zeek log type per day now projects only "
        f"{budget['total']:.0f} shards, under the {limit} budget. That is the "
        f"configuration that reached 1000/1000 and dead-lettered every sensor on "
        f"2026-09-21 (#3283), so the projection has stopped seeing it and "
        f"test_the_steady_state_fits_under_the_default_shard_ceiling cannot be "
        f"trusted."
    )
    # And the margin it failed by, so the test says which bug it is guarding.
    assert budget["total"] > 2 * CEILING, (
        f"pre-fix projection is {budget['total']:.0f}; expected it to exceed "
        f"{2 * CEILING}, i.e. to reproduce 2026-09-21 rather than merely edge "
        f"past the budget"
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
