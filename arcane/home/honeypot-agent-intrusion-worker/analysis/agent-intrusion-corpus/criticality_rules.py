#!/usr/bin/env python3
"""#154 phase 3: "Escalate independently of an LLM when combinations cross
trust boundaries... Treat model output as advisory; deterministic rules
own decoding, schema validation, and critical alert gates."

Every rule here inspects an event's raw sensor-shaped structure directly
(command text, alert fields, audit-event shape) -- never the corpus's own
`phase`/`is_benign`/`expected_findings` metadata, which is fixture-only
ground truth a live sensor event will never carry. corpus.jsonl's
expected_findings.should_escalate is used exclusively as the *test
oracle* in tests/test_criticality_rules.py, to prove these structural
rules reach the same verdict the corpus's own authors intended -- never
as an input to the rules themselves. Getting that distinction backwards
(reading should_escalate as if it were live data) would make this whole
module a no-op that only ever "detects" its own fixture.

Each rule is independent and stateless; evaluate_event() returns every
rule that matched, not just the first -- an event tripping multiple
trust-boundary categories at once is itself part of the signal (see
campaign_severity() below, which counts *distinct* rule categories across
a campaign, not just whether escalation happened at all).
"""
from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import ipaddress
import re

import decode_correlate as dc

_SENSITIVE_PATHS = (
    "/proc/self/environ",
    "/proc/1/environ",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
)

# Actors this repo's own fixtures/workflows treat as named and legitimate
# -- see campaign_correlator.py's _NAMED_ACTORS for the identical
# rationale (a named actor's ordinary activity is not itself suspicious,
# regardless of what it superficially resembles).
_NAMED_ACTORS = {"admin", "system", "hp-autoheal", "dependabot[bot]", "github-actions[bot]"}

METADATA_SERVICE_IP = "169.254.169.254"

# #1427 item 2/3/4: planted breadcrumb hostnames (cowrie/honeyfs's own
# /etc/hosts and ~mwagner/internal-services.txt) mapped to the real sensor
# each one's real, portbridge-forwarded port actually reaches -- see
# internal-services.txt's own NAT-portmap framing for why this is a real,
# not aspirational, reachable target rather than a DNS-resolution trick
# (confirmed against cowrie's own vendored ping.py/ssh.py: neither performs
# real hostname resolution, both just MD5-hash whatever string was typed --
# so the only actually-reachable version of "this hostname points
# somewhere real" is naming another sensor's own real public port on the
# same shared VPS IP, which is what these five names do).
BREADCRUMB_TARGETS = {
    "bastion02": "beelzebub",
    "dc01": "beelzebub",
    "agent-gateway-01": "beelzebub",
    "cms-legacy-01": "beelzebub",
    "analytics-es-04": "elasticpot",
}


@dataclasses.dataclass(frozen=True)
class RuleMatch:
    rule: str
    reason: str
    # #154 phase 5's own required field ("decoded-artifact hashes") -- only
    # populated by rules that actually perform a decode (encoded-execution,
    # encoded-egress-external); every other rule leaves this empty, since
    # attaching a hash chain to, say, a privileged-container-create match
    # would be fabricating provenance for something that was never decoded.
    # dc.DecodeStep entries, not a re-derived shape -- worker.py serializes
    # these straight through (dataclasses.asdict) rather than this module
    # inventing its own parallel hash-record format.
    decode_chain: tuple = ()


def _cowrie_input(raw: dict) -> str:
    return raw.get("input", "") if raw.get("eventid", "").startswith("cowrie.") else ""


def rule_sensitive_path_read(raw: dict) -> RuleMatch | None:
    """#154's own item 3/#88's finding: a read of /proc/*/environ or a
    projected workload-identity token is a real trust-boundary crossing
    regardless of whether it succeeds -- the HDF5 Vector 1 / Kubernetes
    service-account-token analogs from the source campaign."""
    text = _cowrie_input(raw)
    for path in _SENSITIVE_PATHS:
        if path in text:
            return RuleMatch("sensitive-path-read", f"command references {path}")
    return None


def rule_chunked_c2_protocol(raw: dict) -> RuleMatch | None:
    """The campaign's own type=/channel=/seq=/chk= message-protocol shape
    is unusual enough on its own -- a legitimate command essentially never
    carries this exact structure -- that a single chunk is worth
    escalating even before decode_correlate.ChunkCorrelator can reassemble
    the full message (which may need chunks this event alone doesn't
    have). Matches on structure only, never claims to have decoded
    anything -- see rule_encoded_execution below for that distinct claim."""
    text = raw.get("input", "") or raw.get("payload_printable", "")
    msg = dc.parse_chunk_message(text)
    if msg is not None:
        return RuleMatch("chunked-c2-protocol", f"type={msg.msg_type} channel={msg.channel} seq={msg.seq}")
    return None


def rule_encoded_execution(raw: dict) -> RuleMatch | None:
    """A single-shot command that both contains an execution primitive
    (exec/eval alongside a decode call -- the campaign's own quoted
    gzip.decompress(base64.b64decode(...)) convention) *and* actually,
    verifiably decodes (via bounded_decode, not just "looks like
    base64") is real, confirmed evidence of an encoded payload about to
    run -- stronger than rule_chunked_c2_protocol's structural-only
    match, since this one is backed by a successful, checksummed decode."""
    text = _cowrie_input(raw)
    if not text or not re.search(r"\bexec\s*\(|\beval\s*\(", text):
        return None
    blob = dc.extract_candidate_blob(text)
    if not blob:
        return None
    result = dc.bounded_decode(blob.encode())
    if result.ok:
        return RuleMatch("encoded-execution", f"verified decode: {result.output[:60]!r}", tuple(result.chain))
    return None


# Deliberately *relative* (same /24 as the source), not an absolute
# RFC1918-membership check. Tried that first and it doesn't work against
# this corpus: ipaddress.ip_address(...).is_private returns True for every
# RFC 5737 TEST-NET range too (192.0.2.0/24, 198.51.100.0/24,
# 203.0.113.0/24), which Python's stdlib bundles in with real private
# space -- and corpus.jsonl's own addresses, both the "internal workload"
# and "external dead-drop" ones, all have to be TEST-NET by the corpus's
# own safety constraint (no real routable indicators). An absolute
# RFC1918-only check (excluding TEST-NET from "internal") does fix that,
# but breaks the other direction instead: confirmed live, corpus-008's
# benign same-segment telemetry (192.0.2.60 -> 192.0.2.61, deliberately
# meant to represent "stayed inside one network") then reads as external
# too, since neither address is real RFC1918 either. A same-/24 check
# sidesteps the whole problem and is arguably more correct for real
# traffic anyway: two hosts on the same operational network segment
# staying "internal" to each other doesn't actually depend on which
# global address range they happen to sit in.
def _same_segment(src: str, dest: str) -> bool:
    try:
        src_addr, dest_addr = ipaddress.ip_address(src), ipaddress.ip_address(dest)
    except ValueError:
        return False
    if dest_addr.is_loopback or dest_addr.is_link_local:
        return True
    return ipaddress.ip_network(f"{src}/24", strict=False) == ipaddress.ip_network(f"{dest}/24", strict=False) \
        or src_addr == dest_addr


def rule_encoded_egress_external(raw: dict) -> RuleMatch | None:
    """A verifiably-decodable payload (confirmed via bounded_decode -- not
    just alphabet-matching, #2087) leaving toward a destination outside the
    source's own network segment -- the exfiltration-over-ordinary-web-
    service shape #154 names directly. Checked against both an HTTP-shaped
    payload field and a DNS query label (the campaign's own two
    interchangeable exfil transports).

    Each transport certifies its payload before matching, with rigor
    matched to its encoding: the HTTP candidate goes through
    bounded_decode itself and requires result.ok -- the same bar
    rule_encoded_execution applies -- so a JWT segment, long hex hash, or
    cloud key-id toward an external host (alphabet-matching but not
    actually encoded) does NOT fire; every match's decode_chain records a
    transform that really ran. DNS labels are base32 rather than base64 --
    bounded_decode doesn't try base32 -- so they get the equivalent
    treatment directly: real base32-decode of the first label, then the
    same looks-like-text gate applied to the DECODED bytes, never the
    label; padded to a multiple of 8 the way tests/test_decode_correlate.py's
    own corpus-018 check does."""
    src = raw.get("src_ip")
    dest = raw.get("dest_ip")
    if not dest or not src or _same_segment(src, dest):
        return None

    if raw.get("payload_printable"):
        blob = dc.extract_candidate_blob(raw["payload_printable"])
        if blob:
            result = dc.bounded_decode(blob.encode())
            # #2087: result.ok means either a checksummed gzip/zlib/xor
            # layer verified the payload or its final layer is real text --
            # actual evidence. An unverified alphabet-match is neither, and
            # no longer escalates.
            if result.ok:
                return RuleMatch("encoded-egress-external", f"decodable payload toward external {dest}", tuple(result.chain))

    dns = raw.get("dns")
    if isinstance(dns, dict) and dns.get("rrname"):
        label = dns["rrname"].split(".")[0]
        try:
            data = base64.b32decode(label.upper() + "=" * ((8 - len(label) % 8) % 8))
        except (binascii.Error, ValueError):
            return None
        if data and dc.looks_like_text(data):
            step = dc.DecodeStep(
                "base32",
                hashlib.sha256(label.encode()).hexdigest(),
                hashlib.sha256(data).hexdigest(),
                len(data),
            )
            return RuleMatch("encoded-egress-external", f"decodable payload toward external {dest}", (step,))
    return None


def rule_metadata_service_probe(raw: dict) -> RuleMatch | None:
    """169.254.169.254 (the well-known cloud metadata link-local address)
    has no legitimate reason to be addressed by anything in this stack --
    see docs/agent-intrusion-threat-model.md item 4: the *attempt* is
    signal regardless of whether the underlying infrastructure exists to
    make it succeed."""
    if raw.get("dest_ip") == METADATA_SERVICE_IP:
        return RuleMatch("metadata-service-probe", "destination is the cloud metadata link-local address")
    return None


def rule_privileged_container_create(raw: dict) -> RuleMatch | None:
    """A --privileged container with the host filesystem bind-mounted is
    root-equivalent host access -- the campaign's own "bare privileged pod
    with host filesystem mounted" step, in this stack's Docker-Compose
    terms."""
    if raw.get("event") != "container_create":
        return None
    flags = raw.get("flags", [])
    if "--privileged" in flags:
        return RuleMatch("privileged-container-create", f"flags={flags}")
    return None


def rule_broad_scope_identity_token(raw: dict) -> RuleMatch | None:
    """A workload-identity token minted with an admin-shaped scope, a long
    TTL, or by an actor this rule doesn't recognize as named/legitimate is
    the forged-24-hour-service-account-token shape from the campaign's own
    Day 3 credential abuse -- contrast with a narrow-scope, short-TTL,
    named-operator request (this repo's own real settings-introspection
    token flow), which should never match."""
    if raw.get("event") not in ("token_mint", "token_mint_attempt"):
        return None
    scope = str(raw.get("requested_scope", ""))
    ttl = raw.get("requested_ttl_hours", 0)
    actor = raw.get("actor")
    suspicious_scope = "admin" in scope.lower()
    long_lived = isinstance(ttl, (int, float)) and ttl > 4
    unnamed_actor = actor not in _NAMED_ACTORS
    if (suspicious_scope or long_lived) and unnamed_actor:
        return RuleMatch("broad-scope-identity-token", f"scope={scope!r} ttl={ttl}h actor={actor!r}")
    return None


def rule_covert_mesh_enrollment(raw: dict) -> RuleMatch | None:
    """Flag shapes the campaign's own writeup quotes verbatim
    (--state=mem:, --no-logs-no-support) for running a mesh-VPN client in
    memory-only, telemetry-suppressed userspace mode -- or a Suricata
    signature explicitly naming unexpected mesh/VPN enrollment."""
    args = " ".join(raw.get("process_args", []))
    if "--no-logs" in args or "state=mem" in args:
        return RuleMatch("covert-mesh-enrollment", f"process_args={raw.get('process_args')}")
    signature = raw.get("alert", {}).get("signature", "") if isinstance(raw.get("alert"), dict) else ""
    if "mesh" in signature.lower() and "vpn" in signature.lower():
        return RuleMatch("covert-mesh-enrollment", f"alert signature: {signature!r}")
    return None


def rule_internal_connector_enumeration(raw: dict) -> RuleMatch | None:
    """An internal service-connector/broker catalog request from an actor
    this rule doesn't recognize as named -- the "single request returned
    the broker's full destination catalog" step from the campaign's own
    Day 3 internal-connector exploitation."""
    if raw.get("event") != "api_request":
        return None
    endpoint = raw.get("endpoint", "")
    if "connector" in endpoint and raw.get("actor") not in _NAMED_ACTORS:
        return RuleMatch("internal-connector-enumeration", f"endpoint={endpoint!r} actor={raw.get('actor')!r}")
    return None


def rule_scm_write_unexpected_actor(raw: dict) -> RuleMatch | None:
    """Source-control write-capable events (an installation-token mint, or
    a PR shaped to auto-trigger CI) from an actor this rule doesn't
    recognize as named. Mirrors dependabot-auto-merge.yml's own real
    `github.actor == 'dependabot[bot]'` guard -- the actor check IS the
    control here, same as it is for that real workflow, not the scope or
    PR title, both of which a legitimate automated update also has."""
    event = raw.get("event")
    actor = raw.get("actor")
    if event == "github_app_token_mint" and actor not in _NAMED_ACTORS:
        return RuleMatch("scm-write-unexpected-actor", f"github_app_token_mint by actor={actor!r}")
    if event == "pull_request_opened" and raw.get("triggers_workflow") and actor not in _NAMED_ACTORS:
        return RuleMatch("scm-write-unexpected-actor", f"pull_request_opened by actor={actor!r}, triggers CI")
    return None


def rule_staged_payload_reference(raw: dict) -> RuleMatch | None:
    """A command inventorying a known malware-staging directory
    convention (/tmp/staged) -- narrower and more heuristic than the other
    rules here (a real defender would tune this per-environment), included
    anyway since it's exactly the campaign's own last meaningful action
    (Day 5: list staged binary, hostname, date) before response cut its
    access -- the kind of low-effort "is anything still there" check
    worth flagging on its own path convention alone."""
    text = _cowrie_input(raw)
    if "/tmp/staged" in text:
        return RuleMatch("staged-payload-reference", "command references a known staging-directory path")
    return None


def rule_breadcrumb_reference(raw: dict) -> RuleMatch | None:
    """#1427 item 2/3: a cowrie command referencing one of the planted
    internal-asset breadcrumb names (BREADCRUMB_TARGETS above -- cowrie's
    own /etc/hosts and ~mwagner/internal-services.txt). Weak signal alone
    -- an attacker who merely `cat`s /etc/hosts sees every name without
    acting on any of them -- campaign_breadcrumb_followed below is the
    actual "did they act on it" claim."""
    text = _cowrie_input(raw)
    for name in BREADCRUMB_TARGETS:
        if name in text:
            return RuleMatch("breadcrumb-reference", f"command references planted breadcrumb {name!r}")
    return None


ALL_RULES = (
    rule_sensitive_path_read,
    rule_chunked_c2_protocol,
    rule_encoded_execution,
    rule_encoded_egress_external,
    rule_metadata_service_probe,
    rule_privileged_container_create,
    rule_broad_scope_identity_token,
    rule_covert_mesh_enrollment,
    rule_internal_connector_enumeration,
    rule_scm_write_unexpected_actor,
    rule_staged_payload_reference,
    rule_breadcrumb_reference,
)


def evaluate_event(raw: dict) -> list[RuleMatch]:
    """Runs every rule against one event's raw sensor data, returns every
    match (not just the first) -- an event tripping several categories at
    once is itself signal, not redundant noise to dedupe away."""
    return [m for rule in ALL_RULES if (m := rule(raw)) is not None]


# #154 phase 5's own required field ("the trust boundary crossed"). Kept as
# a lookup table rather than folded into each RuleMatch directly, since the
# boundary crossed is a property of *which rule* matched, not of any one
# event's own data -- matches this module's own per-category framing
# (campaign_severity groups by rule name for the identical reason).
TRUST_BOUNDARIES = {
    "sensitive-path-read": "process/container -> host secret material",
    "chunked-c2-protocol": "honeypot session -> external C2 channel",
    "encoded-execution": "honeypot session -> local code execution",
    "encoded-egress-external": "internal workload -> external network segment",
    "metadata-service-probe": "workload -> cloud identity/metadata service",
    "privileged-container-create": "workload -> host (root-equivalent)",
    "broad-scope-identity-token": "workload -> orchestrator identity",
    "covert-mesh-enrollment": "workload -> internal mesh/VPN",
    "internal-connector-enumeration": "mesh identity -> internal service catalog",
    "scm-write-unexpected-actor": "workload/mesh identity -> source control",
    "staged-payload-reference": "honeypot session -> local filesystem (staged artifacts)",
    "breadcrumb-reference": "honeypot session -> named internal decoy asset (unconfirmed)",
    "breadcrumb-followed": "honeypot session -> named internal decoy asset -> real target sensor (confirmed)",
}


def campaign_severity(matched_rules_per_event: dict) -> tuple[str, set]:
    """Given {event_id: [RuleMatch, ...]} for one campaign, counts the
    *distinct* rule categories that fired anywhere in it (not the raw
    match count -- two events both tripping sensitive-path-read is one
    category, not two) and derives an overall severity. This is the
    actual point of correlating first (campaign_correlator.py) and only
    then evaluating rules: #154's own motivating finding is that
    individually-reasonable-severity signals combining across a campaign
    is what the LLM-based stack missed, not that any one signal was
    itself insufficiently alarming."""
    categories: set[str] = set()
    for matches in matched_rules_per_event.values():
        categories |= {m.rule for m in matches}
    if len(categories) >= 3:
        return "critical", categories
    if len(categories) >= 1:
        return "high", categories
    return "low", categories


def campaign_breadcrumb_followed(campaign_event_ids: list, events_by_id: dict, matches_per_event: dict) -> tuple | None:
    """#1427 item 4: the real "followed the breadcrumb" claim, distinct
    from rule_breadcrumb_reference's per-event "the name was read" match.
    Requires BOTH, in order: some event in this campaign matched
    breadcrumb-reference naming an asset, AND a chronologically *later*
    event in the same campaign was actually served by that asset's real
    target sensor (BREADCRUMB_TARGETS). campaign_event_ids is already
    timestamp-sorted (campaign_correlator.py's own Campaign.event_ids), so
    one forward pass is sufficient -- no re-sorting needed here.

    Returns (event_id, RuleMatch): event_id is the LATER "reached the
    target" event, not the earlier reference -- worker.py attaches the
    match there so agent_campaigns.html's evidence timeline shows it
    against the actual arrival, not the passive read that merely named
    it. Returns None if no campaign event ever reaches a referenced
    target (the common case: most breadcrumb reads are never acted on).
    """
    referenced_targets: set = set()
    for eid in campaign_event_ids:
        for m in matches_per_event.get(eid, ()):
            if m.rule == "breadcrumb-reference":
                for name, target in BREADCRUMB_TARGETS.items():
                    if name in m.reason:
                        referenced_targets.add(target)
        sensor = events_by_id[eid]["raw"].get("sensor")
        if sensor in referenced_targets:
            return eid, RuleMatch(
                "breadcrumb-followed",
                f"referenced a breadcrumb pointing at {sensor!r}, then {sensor!r} was actually reached",
            )
    return None
