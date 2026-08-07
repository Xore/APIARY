# Agent-intrusion synthetic replay corpus + decode/correlate pipeline (#154 phases 1-2)

A versioned, fully synthetic corpus of ordered events representing the
July 2026 agent-intrusion campaign's own phase structure, replayed in
APIARY's own sensor/event vocabulary (phase 1: "Sanitized replay corpus"),
plus the bounded, non-executing decoder and chunk correlator phase 2 asks
for ("Decode and correlate before LLM analysis"), proven against that
corpus rather than hand-built fixtures alone. The prerequisite research
(mapping the campaign to APIARY's actual trust boundaries) is
[`docs/agent-intrusion-threat-model.md`](../../docs/agent-intrusion-threat-model.md),
already done. Phase 3 (deterministic criticality rules) is the next piece
this decode/correlate output is meant to feed.

## What's here

- **`corpus.jsonl`** — the corpus itself. One JSON object per line, in
  strict timestamp order; `event_id` (`corpus-001`, `corpus-002`, ...)
  matches that order exactly.
- **`schema.json`** — JSON Schema for one event's shape.
- **`validate_corpus.py`** — validates the corpus against the schema plus
  safety constraints JSON Schema can't express (TEST-NET-only addressing,
  no benign/escalate contradictions, cross-reference integrity). No
  third-party dependencies — hand-rolled, matching
  `analysis/ghidra/models/*.py`'s own stated "one less supply-chain
  surface" philosophy. Run directly: `python3 validate_corpus.py`.
- **`tests/test_corpus.py`** — `unittest`-based tests (same convention as
  every other `analysis/tests/*.py` in this repo — no `pytest` dependency).
  Proves the corpus validates clean *and* that the validator actually
  catches deliberately-broken input, not just that today's corpus happens
  to pass.
- **`decode_correlate.py`** — phase 2's decoder (`bounded_decode`: bounded,
  non-executing base64/gzip/zlib decode, with a single-byte-XOR brute-force
  fallback, full provenance chain, depth/size caps) and chunk correlator
  (`ChunkCorrelator`: reassembles the campaign's own type/channel/sequence/
  checksum message protocol before a multi-part payload is even decodable).
  No third-party dependencies, same reasoning as `validate_corpus.py`.
- **`tests/test_decode_correlate.py`** — unit tests against hand-built
  fixtures (including the decoder's own bounds: depth cap, size cap,
  malformed/adversarial input never raising) *and* end-to-end tests that
  run the real corpus's encoded events through the pipeline and confirm
  the recovered plaintext actually matches what each event's own
  `expected_findings.decoded_summary` claims — cashing in the corpus's own
  "ground truth" contract for real, not just trusting the prose.
- **`campaign_correlator.py`** — phase 2's other half ("Correlate events
  across sensors into one campaign timeline using stable IDs and time
  windows"). Distinct from `decode_correlate.py`'s `ChunkCorrelator`,
  which reassembles fragments of *one message*; this correlates separate,
  already-complete *events* into one campaign, union-find style over
  shared session/source-IP/C2-channel identifiers within a time window.
  No ML, no fuzzy matching — deterministic, same posture as
  `bounded_decode`.
- **`tests/test_campaign_correlator.py`** — unit tests plus an end-to-end
  proof against the real corpus of the actual motivating case #154 opens
  with: a C2 channel ID reused across a "stage" and an "exfil" message
  bridges two events sharing *no* session or IP of their own into one
  8-event campaign. Also asserts two real, deliberate scope limits this
  identifier-only approach doesn't solve (fleet siblings on different
  hosts; an actor's IP changing across a mesh/NAT pivot) rather than
  leaving them as silent gaps.

## Design

Each event carries:

| Field | Meaning |
|---|---|
| `event_id` | `corpus-NNN`, matches position in the file |
| `timestamp` | ISO 8601 UTC, strictly ascending across the whole corpus |
| `phase` | One of the 8 phases #154 required, or `benign` |
| `trust_boundary` | The boundary this event's technique crosses, in APIARY's own terms |
| `sensor` | Which real APIARY sensor/source `raw` is shaped like (cowrie, suricata, dashboard-audit, ci-workflow) |
| `encoding_layer` | What a decoder needs to peel back (`none`, `base64`, `gzip+base64`, `chunked+xor+gzip+base64`, `jinja2-template`) |
| `is_benign` | True for near-neighbor control events — same surface shape, not part of the attack chain |
| `raw` | A realistic, sensor-shaped JSON blob — what phase 2's decoder would actually receive in production |
| `expected_findings` | Ground truth: `should_escalate` (for phase 3), `decoded_summary` (for phase 2), `matched_rule` (placeholder — phase 3 doesn't define real rule IDs yet) |
| `notes` | What real campaign step this is an analog of, and why — every event is annotated, this is a reviewable artifact, not just machine input |

### Why sensor-shaped `raw`, not an abstract description

Phase 2's decoder will consume real sensor output (cowrie JSON lines,
Suricata `eve.json` alerts, etc.). A corpus that only *described* what
should happen ("attacker exfiltrates data") would be useless as a fixture
for testing an actual decoder. Every `raw` field here is built to look like
what that sensor really emits, so a future decoder can be pointed at this
file's `raw` values directly.

### The 8 required phases, and how each maps onto APIARY

Per `docs/agent-intrusion-threat-model.md`, APIARY has no real Kubernetes,
cloud IAM, or metadata service — three of the campaign's own techniques
(K8s service-account tokens, cloud metadata credential replay, forged
workload-identity tokens) have nothing to escalate into *here*. Those
events are included anyway (`cloud_k8s_identity_probe`, and the K8s-token
event under `secret_discovery`) because the corpus's job is testing
whether a correlation engine recognizes the *signature* of a technique
class — an attacker's toolkit doesn't know or care that a target lacks
Kubernetes, and a honeypot session attempting `cat
/var/run/secrets/kubernetes.io/serviceaccount/token` is real signal about
that attacker regardless of whether the path resolves to anything. Each
such event's own `notes` field says so explicitly.

`internal_network_pivot` and `source_control_ci_probe`, by contrast, map
onto real APIARY trust boundaries almost exactly: this stack has a real
WireGuard mesh (VPS↔homeserver) and a real GitHub App-adjacent write path
(`dependabot-auto-merge.yml`'s `contents:write`/`pull-requests:write`
scopes). Those phases' benign near-neighbors (corpus-004, corpus-007) are
deliberately APIARY's own *real* good-case events (an actual Dependabot
PR shape, the actual WireGuard tunnel peer address), not generic
placeholders — the sharpest possible contrast against the attack-chain
version.

### Benign near-neighbors

#154 requires them explicitly ("Include benign near-neighbors to measure
false positives"). Each one shares its attack-chain counterpart's surface
shape (same sensor, same rough technique category) but differs in the
property that should actually matter — actor identity, destination
boundary, token scope/TTL, or simply "this is the real, known-good
version of the same kind of event." `expected_findings.should_escalate`
is `false` for every benign event by construction;
`validate_corpus.py`/the tests enforce that as a hard contradiction check.

## Safety constraints (#154: "must never... expose secrets... Do not copy
live indicators, credentials, hostnames, or weaponized payloads")

- Every address is TEST-NET (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`), checked by `validate_corpus.py` against every
  IP-shaped field *and* every bare dotted-quad found anywhere in an
  event's `raw` blob. A short, individually-commented allowlist exists for
  three real, non-secret constants that are meaningful specifically
  *because* they're real: APIARY's own WireGuard tunnel peer
  (`10.8.0.1`), the well-known cloud metadata link-local address
  (`169.254.169.254`, itself the point of the event it appears in), and a
  loopback SOCKS5 bind address (`127.0.0.1`).
- Every password/token value is the literal placeholder `fake-not-real`
  or an explanatory string — never a real-shaped secret.
  `test_no_obviously_real_looking_secrets` greps every event for real
  credential-prefix shapes (`AKIA`, `ghp_`, `tskey-auth-`, etc.) as a
  backstop against a future hand-edit pasting something real in.
- The encoded/C2 technique itself is expressed via the campaign's own real
  command *shapes* (`gzip.decompress(base64.b64decode(...))`, the
  message-protocol type/channel/seq/checksum fields, `--state=mem:
  --no-logs-no-support`), since that shape is what a decoder/correlator
  needs to recognize — but every payload those commands act on is an
  inert, synthetic placeholder, never a working dropper.
- No real hostnames, campaign infrastructure names, or IOCs from the
  source campaign are copied — every identifier (`corpus-example.test`,
  `corpus-fleet-01`, session IDs) is obviously fixture-shaped.

## Regenerating

`corpus.jsonl` is hand-reviewed data, not generated at build time — there
is no script in this directory that produces it. It was originally built
with a one-off Python script (events defined in final chronological order
so each event's own cross-references to other `event_id`s by name stay
correct without a renumbering pass) that was discarded after review, by
design: a corpus meant to be read and reasoned about by a person should be
edited directly, not regenerated from a generator that could silently
change reviewed content. To extend the corpus, add events directly to
`corpus.jsonl`, keep `event_id`/timestamp order consistent, and run
`validate_corpus.py` (or `tests/test_corpus.py`) before committing.

## Versioning

`corpus.jsonl` is not itself schema-versioned (no top-level `version`
field) — the file's own git history is the version record, matching how
this repo treats `analysis/yara/` and other reviewed-fixture directories.
A future breaking change to `schema.json` (a required field added/removed,
an enum value changed) should bump `schema.json`'s own `$id` and add a
note here, not silently reinterpret old corpus rows under a new meaning.

## What this directory does *not* do

`decode_correlate.py` and `campaign_correlator.py` decode, reassemble, and
group; neither scores or escalates anything — no criticality rules, no
severity, no alerting. That's phase 3's job, which this directory's
decoded+correlated output is meant to feed once built. `matched_rule` in
every corpus event is still either `null` or a descriptive placeholder
string, not a real rule identifier, since phase 3's rule set doesn't exist
yet. Both modules are also standalone Python, not yet wired into the
dashboard/analysis-worker pipeline production code would actually run
against live sensor data — that integration is separate follow-up work
once phase 3 defines what a decoded+correlated campaign should trigger.
`campaign_correlator.py` itself has two deliberate, tested scope limits
(see `tests/test_campaign_correlator.py`'s own "documented gap" tests):
it correlates on shared *identifiers*, not repeated-technique similarity
across different infrastructure, and it has no way to link an actor's
identity across a NAT/mesh boundary where its own address changes.
