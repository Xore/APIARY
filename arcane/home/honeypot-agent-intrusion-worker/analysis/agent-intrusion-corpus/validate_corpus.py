#!/usr/bin/env python3
"""Validates corpus.jsonl against schema.json plus the safety constraints
JSON Schema can't express (#154's own corpus requirement: "Do not copy live
indicators, credentials, hostnames, or weaponized payloads").

No third-party dependencies (matches analysis/ghidra/models/*.py's own
stated philosophy, cited directly in docs/agent-intrusion-threat-model.md
item 8's supply-chain discussion) -- schema validation is hand-rolled rather
than pulling in `jsonschema`, since this file's own schema subset (required
fields, enums, string patterns, nested objects) doesn't need the full spec.

Run directly: python3 validate_corpus.py
Or import: from validate_corpus import load_corpus, validate_event
"""
from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS_PATH = HERE / "corpus.jsonl"
SCHEMA_PATH = HERE / "schema.json"

EVENT_ID_RE = re.compile(r"^corpus-[0-9]{3}$")
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

REQUIRED_FIELDS = (
    "event_id", "timestamp", "phase", "trust_boundary", "sensor",
    "encoding_layer", "is_benign", "raw", "expected_findings", "notes",
)
PHASES = {
    "recon", "secret_discovery", "encoded_dropper_c2", "exfiltration",
    "persistence_self_migration", "cloud_k8s_identity_probe",
    "internal_network_pivot", "source_control_ci_probe", "benign",
}
ENCODING_LAYERS = {"none", "base64", "gzip+base64", "chunked+xor+gzip+base64", "jinja2-template"}
REQUIRED_PHASES = PHASES - {"benign"}

# RFC 5737 documentation ranges -- the only address space this corpus may
# use. Real WireGuard tunnel range (10.8.0.0/24, APIARY's own real
# production range per docs/honeypot-network-isolation.md) is intentionally
# ALSO allowed: corpus-007's benign WireGuard-handshake baseline event
# names the stack's real tunnel peer address on purpose, to give phase 3's
# criticality rules a genuine "known good" contrast against corpus-023's
# unexpected mesh client -- it is not attacker-controlled or secret, so it
# carries none of the risk the TEST-NET-only rule below exists to prevent.
TEST_NET_RANGES = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
ALLOWED_NON_TEST_NET_IPS = {
    "10.8.0.1",  # corpus-007: APIARY's own real WireGuard tunnel peer -- see above.
    "169.254.169.254",  # corpus-021: the well-known cloud metadata link-local address itself,
    # named as the *destination* of a synthetic probe attempt -- a real, public,
    # non-secret constant (RFC 3927 link-local), not an indicator specific to
    # any deployment. Never appears here as a source or a stand-in for real
    # infrastructure.
    "127.0.0.1",  # corpus-023: a local SOCKS5 proxy bind address inside process_args,
    # not a real network endpoint anything connects to.
}

IP_KEYS = {"src_ip", "dest_ip", "dst_ip", "peer", "host"}


def _find_ips(value) -> list[str]:
    """Recursively pulls every string under an IP-shaped key, plus every
    bare dotted-quad found anywhere else in the structure (covers dns.rrname
    labels, process_args, and other free-text fields the fixed key list
    above wouldn't catch)."""
    found: list[str] = []
    ip_literal_re = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

    def walk(v, key=None):
        if isinstance(v, dict):
            for k, sub in v.items():
                walk(sub, k)
        elif isinstance(v, list):
            for sub in v:
                walk(sub, key)
        elif isinstance(v, str):
            if key in IP_KEYS:
                found.append(v)
            for m in ip_literal_re.findall(v):
                found.append(m)

    walk(value)
    return found


def validate_event(event: dict, index: int) -> list[str]:
    errors = []

    for field in REQUIRED_FIELDS:
        if field not in event:
            errors.append(f"event {index}: missing required field {field!r}")
    if errors:
        return errors  # further checks assume these fields exist

    if not EVENT_ID_RE.match(event["event_id"]):
        errors.append(f"event {index}: event_id {event['event_id']!r} doesn't match ^corpus-[0-9]{{3}}$")
    if not TIMESTAMP_RE.match(event["timestamp"]):
        errors.append(f"event {index}: timestamp {event['timestamp']!r} isn't a bare UTC ISO-8601 (YYYY-MM-DDTHH:MM:SSZ)")
    if event["phase"] not in PHASES:
        errors.append(f"event {index}: phase {event['phase']!r} not in {sorted(PHASES)}")
    if not isinstance(event["trust_boundary"], str) or not event["trust_boundary"].strip():
        errors.append(f"event {index}: trust_boundary must be a non-empty string")
    if not isinstance(event["sensor"], str) or not event["sensor"].strip():
        errors.append(f"event {index}: sensor must be a non-empty string")
    if event["encoding_layer"] not in ENCODING_LAYERS:
        errors.append(f"event {index}: encoding_layer {event['encoding_layer']!r} not in {sorted(ENCODING_LAYERS)}")
    if not isinstance(event["is_benign"], bool):
        errors.append(f"event {index}: is_benign must be a bool")
    if not isinstance(event["raw"], dict):
        errors.append(f"event {index}: raw must be an object")
    if not isinstance(event["notes"], str) or not event["notes"].strip():
        errors.append(f"event {index}: notes must be a non-empty string")

    ef = event["expected_findings"]
    if not isinstance(ef, dict):
        errors.append(f"event {index}: expected_findings must be an object")
    else:
        for f in ("should_escalate", "decoded_summary", "matched_rule"):
            if f not in ef:
                errors.append(f"event {index}: expected_findings missing {f!r}")
        if "should_escalate" in ef and not isinstance(ef["should_escalate"], bool):
            errors.append(f"event {index}: expected_findings.should_escalate must be a bool")
        if event.get("is_benign") and ef.get("should_escalate"):
            errors.append(f"event {index}: is_benign=true but expected_findings.should_escalate=true (contradiction -- #154 requires benign near-neighbors to never be the reason to escalate)")

    # Safety constraint: TEST-NET-only addressing (#154: "Do not copy live
    # indicators... All replay input must be synthetic and non-routable").
    for ip in _find_ips(event.get("raw", {})):
        if ip in ALLOWED_NON_TEST_NET_IPS:
            continue
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue  # not actually an IP literal (a version string, a hash fragment, etc.)
        if not any(addr in net for net in TEST_NET_RANGES):
            errors.append(
                f"event {index} ({event['event_id']}): address {ip!r} is not in a TEST-NET range "
                f"(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and not on the allowed-exceptions list"
            )

    return errors


def load_corpus(path: Path = CORPUS_PATH) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"corpus.jsonl line {line_no}: invalid JSON ({exc})") from exc
    return events


def validate_corpus(events: list[dict]) -> list[str]:
    errors = []
    for i, event in enumerate(events, start=1):
        errors.extend(validate_event(event, i))

    # Ordering: the corpus's own event_id sequence must match its timestamp
    # order -- corpus.jsonl is meant to be read top-to-bottom as the
    # timeline, and a mismatch here would mean either the file was hand-edited
    # out of order or a note's cross-reference to another event_id no longer
    # points at the event it once did.
    ids = [e.get("event_id") for e in events]
    expected_ids = [f"corpus-{i:03d}" for i in range(1, len(events) + 1)]
    if ids != expected_ids:
        errors.append(f"event_id sequence doesn't match position order: got {ids[:5]}..., want {expected_ids[:5]}...")

    timestamps = [e.get("timestamp", "") for e in events]
    if timestamps != sorted(timestamps):
        errors.append("timestamps are not in strictly ascending order")
    if len(set(timestamps)) != len(timestamps):
        errors.append("duplicate timestamps found (every event should be independently orderable)")

    # Coverage: #154 requires all 8 named phases present, plus at least one
    # benign near-neighbor overall.
    phases_present = {e.get("phase") for e in events}
    missing_phases = REQUIRED_PHASES - phases_present
    if missing_phases:
        errors.append(f"missing required phase(s): {sorted(missing_phases)}")
    if not any(e.get("is_benign") for e in events):
        errors.append("no benign near-neighbor events found (#154 requires at least one, to measure false positives)")

    # Every non-benign event_id referenced by name inside another event's
    # own notes field must actually exist -- catches a stale cross-reference
    # left behind by a future edit (see build script's own comment on why
    # this class of bug is easy to introduce silently).
    all_ids = set(ids)
    ref_re = re.compile(r"\bcorpus-[0-9]{3}\b")
    for e in events:
        for ref in ref_re.findall(e.get("notes", "")):
            if ref not in all_ids:
                errors.append(f"{e.get('event_id')}: notes references {ref!r}, which doesn't exist in this corpus")

    return errors


def main() -> int:
    if not SCHEMA_PATH.exists():
        print(f"error: {SCHEMA_PATH} not found", file=sys.stderr)
        return 2
    json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))  # just confirms it's valid JSON

    try:
        events = load_corpus()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    errors = validate_corpus(events)
    if errors:
        print(f"FAIL: {len(errors)} problem(s) in corpus.jsonl ({len(events)} events read)", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print(f"OK: {len(events)} events, all required phases present, all addresses TEST-NET-safe")
    return 0


if __name__ == "__main__":
    sys.exit(main())
