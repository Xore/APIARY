#!/usr/bin/env python3
"""#154 phase 2 (second half): "Correlate events across sensors into one
campaign timeline using stable IDs and time windows."

Distinct from decode_correlate.py's ChunkCorrelator, which reassembles one
multi-part *message* (several sensor events that are fragments of a single
payload). This module correlates separate, complete events into one
*campaign* -- the actual motivating gap #154 opens with: "isolated
low-signal events were detected but not escalated with the right
criticality" because nothing grouped them together in the first place.

Union-find over shared stable identifiers (session ID, source IP, and a
C2 channel ID recovered from free-text fields), gated by a time window.
No ML, no fuzzy matching -- deterministic, same posture as
decode_correlate.py's bounded_decode ("deterministic rules own decoding...
and critical alert gates").
"""
from __future__ import annotations

import dataclasses
import re
from datetime import datetime, timedelta

_CHANNEL_RE = re.compile(r"channel=([A-Za-z0-9]+)")

# Actor names that identify a *named*, legitimate participant rather than
# an anonymous/compromised one -- confirmed directly against every
# dashboard-audit/ci-workflow event in corpus.jsonl that carries an
# "actor" field. When one of these owns a "host" value, that host is
# real shared infrastructure (an operator, an automation account, the
# stack's own maintenance service) an unrelated event can legitimately
# also mention -- not a signal that two events share an actor identity.
# "unknown", by contrast, is this corpus's own explicit stand-in for "no
# named actor could be attributed" (see corpus-019/020/022's own raw
# fields) -- exactly the anonymous-compromised-workload case where a
# shared host value *is* real identity evidence.
_NAMED_ACTORS = {"admin", "system", "hp-autoheal", "dependabot[bot]", "github-actions[bot]"}


def extract_identifiers(raw: dict) -> set[str]:
    """Pulls every stable identifier this event's raw sensor data carries.
    Deliberately narrow: only signals confirmed (against every event shape
    in corpus.jsonl) to actually indicate shared actor/session/channel
    identity, not "any two events that happen to mention the same
    string" -- see the docstring above on why dest_ip and a
    named-actor's host are excluded."""
    ids: set[str] = set()

    session = raw.get("session")
    if session:
        ids.add(f"session:{session}")

    src_ip = raw.get("src_ip")
    if src_ip:
        ids.add(f"ip:{src_ip}")

    # host counts as an identity signal only when nothing else in this
    # event claims a named actor for it -- see _NAMED_ACTORS above.
    host = raw.get("host")
    actor = raw.get("actor")
    if host and actor not in _NAMED_ACTORS:
        ids.add(f"ip:{host}")

    # The campaign's own message-protocol channel ID, recovered from
    # whichever free-text field carries it (cowrie's "input", Suricata's
    # "payload_printable", or a DNS "rrname" label) -- the one identifier
    # in this corpus that bridges otherwise-unconnected actor identities
    # (see tests/test_campaign_correlator.py's own end-to-end proof).
    for field in ("input", "payload_printable"):
        text = raw.get(field, "")
        m = _CHANNEL_RE.search(text)
        if m:
            ids.add(f"channel:{m.group(1)}")

    # No channel extraction from raw["dns"]["rrname"]: DNS labels can't
    # carry '=', so the campaign's own channel ID isn't literally embedded
    # there the way it is in the HTTP/cowrie cases -- corpus-018's own
    # notes confirm only a *data fragment* travels over DNS, not the
    # protocol's control fields. Noted here so a future reader doesn't
    # wonder whether this was simply forgotten.

    return ids


@dataclasses.dataclass
class Campaign:
    event_ids: list[str]
    identifiers: set[str]
    start: str
    end: str


class _UnionFind:
    def __init__(self, items):
        self._parent = {i: i for i in items}

    def find(self, x):
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self._parent[ra] = rb


def _parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")


def correlate_campaigns(events: list[dict], window: timedelta = timedelta(hours=72)) -> list[Campaign]:
    """Groups events sharing a stable identifier (session, source IP, or
    C2 channel) into campaigns, within `window` of each other. Two events
    with a shared identifier more than `window` apart are NOT unioned --
    #154's own "time windows" requirement -- even a real campaign's own
    reused infrastructure (a channel ID, a compromised host) stops being
    good correlation evidence once enough time separates two sightings of
    it that they're more plausibly unrelated reuse than one continuous
    incident. Events sharing no identifier with anything else become
    their own singleton campaign -- a real, expected outcome for an event
    with nothing else in the corpus to link it to, not a bug (see
    corpus-026's own case in the test suite)."""
    by_id = {e["event_id"]: e for e in events}
    ids = list(by_id)
    uf = _UnionFind(ids)

    # identifier -> [(event_id, timestamp), ...], so pairwise time-window
    # comparisons only happen within one identifier's own bucket rather
    # than the full O(n^2) event set.
    buckets: dict[str, list[tuple[str, datetime]]] = {}
    for eid, e in by_id.items():
        ts = _parse_ts(e["timestamp"])
        for ident in extract_identifiers(e["raw"]):
            buckets.setdefault(ident, []).append((eid, ts))

    for members in buckets.values():
        members.sort(key=lambda pair: pair[1])
        for i in range(len(members) - 1):
            eid_a, ts_a = members[i]
            eid_b, ts_b = members[i + 1]
            if ts_b - ts_a <= window:
                uf.union(eid_a, eid_b)

    clusters: dict[str, list[str]] = {}
    for eid in ids:
        clusters.setdefault(uf.find(eid), []).append(eid)

    campaigns = []
    for members in clusters.values():
        members_sorted = sorted(members, key=lambda eid: by_id[eid]["timestamp"])
        cluster_ids: set[str] = set()
        for eid in members_sorted:
            cluster_ids |= extract_identifiers(by_id[eid]["raw"])
        campaigns.append(Campaign(
            event_ids=members_sorted,
            identifiers=cluster_ids,
            start=by_id[members_sorted[0]]["timestamp"],
            end=by_id[members_sorted[-1]]["timestamp"],
        ))
    campaigns.sort(key=lambda c: c.start)
    return campaigns
