# Research: Cisco Secure FMC inert management persona — fidelity, isolation and provenance requirements (#3214)

Records what an **optional, non-vulnerable** Cisco Secure Firewall Management
Center persona would have to satisfy before anyone builds it, and what is
explicitly out of scope. This is the F3 decision row of [#3180](https://github.com/Xore/APIARY/issues/3180)
("Make a scoped decision on an inert FMC persona"), not the F4 row
([#3215](https://github.com/Xore/APIARY/issues/3215), separately authorized
management-audit ingestion).

Written 2026-09-27 against `45f41effadc8c797701927b648969adf950bf6dc` on
`oc/3214-decision`. The vendor-side facts are taken from #3180's corrected
claim-verification matrix (2026-09-17, snapshot
`00593d1d693cc7fe792beb7d24724dca5f55b2b8`); the fleet-side facts are derived
here by reading the tree. Nothing was probed, built, deployed, or run.

**Scope, per the operator decision recorded on #3214:** analysis and contract
only. No sensor, no compose entry, no port publication, no decoy, no test, and
no change to Conpot, Dionaea, or the Cisco ASA decoy's behaviour. A negative
verdict later is an acceptable outcome, so this note deliberately does not
argue for a build and does not pre-commit to one.

## 1. Product identity: FMC is not the ASA persona, and the repo already treats it that way

Cisco Secure Firewall Management Center (FMC) is the **centralized
management console** for Cisco Secure Firewall — the plane an administrator
logs into to manage many firewalls. The fleet's existing Cisco decoy
(`cisco-asa-honeypot`, [`docs/SENSORS.md`](../SENSORS.md)) is a **Cisco ASA
WebVPN/IKE data-plane** decoy. Per #3180's verified matrix, ASA is not the
affected FMC product, and neither are FDM or FTD: "Secure FMC Software" is the
named product, and the note's own instruction is to *preserve these product
distinctions*. #3180's executive finding says the same about the fleet: "A
Cisco ASA WebVPN decoy is not FMC."

The distinction is not a naming preference. It is load-bearing three times
over, and the tree already enforces two of them:

1. **Bait credentials must not cross products.** Both decoys' credential
   indicator sets refuse a Cisco vendor default-credential list, and say so in
   terms that name this decision:
   [`arcane/home/honeypot-cisco-asa-honeypot/cisco-asa-honeypot/credentials.go`](../../arcane/home/honeypot-cisco-asa-honeypot/cisco-asa-honeypot/credentials.go)
   ("#3180's research proposed flagging 'known default creds for Cisco FMC'.
   This fleet runs no FMC instance, has never had one to test a list
   against…") and the same passage in
   [`arcane/home/honeypot-http/http-honeypot/credentials.go`](../../arcane/home/honeypot-http/http-honeypot/credentials.go).
   The ASA's own bait is the fleet's invented `nexusai-asa-vpn` product, not a
   Cisco claim.
2. **A regression test already forbids the two identities merging.**
   [`tests/docs/test_3213_fix.py`](../../tests/docs/test_3213_fix.py) asserts
   that the literal `fmc` (and `cisco`, `cisco123`, `asa/`) never appears in
   either decoy's indicator set, and that the bait stays scoped to the
   fleet's own `nexusai-*` persona. That assertion is the repo's current
   expression of "an ASA event stays an ASA event" and it must keep passing
   whatever an FMC persona eventually looks like.
3. **The credential scrubber is scoped by sensor name, and a new sensor is out
   of scope for it.** `CREDENTIAL_SENSORS` in
   [`arcane/home/honeypot-dashboard/backend-service/src/secrets_boundary.rs`](../../arcane/home/honeypot-dashboard/backend-service/src/secrets_boundary.rs)
   is exactly `["http-honeypot", "cisco-asa-honeypot"]`, and the same file
   asserts that scope in a test. Widening it is a **separate, reviewed change
   with its own proof obligation** (already-indexed documents are not fixed by
   redacting at the sensor) — it is not something an FMC persona inherits by
   existing.

**Requirement F-1 (identity).** Any future FMC persona carries its own sensor
name, its own `persona_id`, and its own asset identity. It never reuses
`cisco-asa-honeypot`'s sensor name, its `nexusai-asa-vpn` product, or its
event vocabulary; and an existing ASA fixture stays ASA. Concretely, the ASA
fixtures already in the tree — the credential-presence case in
[`events.rs`](../../arcane/home/honeypot-dashboard/backend-service/src/events.rs)
(`{"event": {"sensor": "cisco-asa-honeypot"}}` with `credential_status:
"unknown"`) and the canonical-dispatch row in
[`ip_enrichment/canonical.rs`](../../arcane/home/honeypot-dashboard/backend-service/src/ip_enrichment/canonical.rs)
— must keep their existing identity, and a record that merely *looks* like
another persona must not fall through to that persona's rules.

**Requirement F-2 (no product borrowing).** Sharing a management port, a
vendor name, a TLS profile, or a page template with the ASA decoy never
changes an event's product identity. Port sharing is permitted only if the
sensor name on the event is what decides the identity — which is how this
fleet already dispatches (`canonical.rs`'s per-sensor arms, `topology.rs`'s
per-sensor registration).

## 2. Static surface inventory

Static by construction: this is a table of what the tree would have to say,
read from the tree, with **no live probe of any kind** — no connection, no
scan, no banner grab, no port check. The vendor's own default port set for
FMC is **not asserted here**; #3180's proposed detector watches 443/8443, and
that is a hypothesis about where a management console would be published, not
a claim about this product's defaults. Confirming a real appliance's defaults
would need a separately authorized asset, which this issue does not have.

### 2.1 Today: there is no FMC surface anywhere in this stack

| check | result |
|---|---|
| `git grep -i -l -E "fmc\|firepower\|firesight"` over tracked files | **no sensor, compose, dashboard or pipeline hit.** The matches are the two `credentials.go` comments declining to ship FMC vendor claims, `tests/docs/test_3213_fix.py`'s ban on the literal, a compiled `http-honeypot` binary and the reporter's `go.sum` (coincidental), and this note's own three doc references |
| `docs/SENSORS.md`'s sensor table | no FMC row; the only Cisco-branded row is `cisco-asa-honeypot` (ASA WebVPN + IKE) |
| portbridge `RULES` (`vps/docker-compose.yml`) | no FMC management publication; `tcp:8443:10.8.0.2:8443:pp` and `udp:500:10.8.0.2:500` are the ASA's |
| `vps/honeypot-firewall.sh` `TCP_PORTS`/`UDP_PORTS` | the same two Cisco ports, nothing management-console shaped |
| `personas/personas.json` | no management-plane persona at all |

So: nothing to patch, nothing to audit, and no fleet exposure to defend. The
question this note answers is purely "would adding one be worth it, and under
what contract".

### 2.2 The three-layer separation a future persona must declare

The fleet's routing has three distinct layers, and a persona that conflates
them is the failure mode the #1509 firewall-drift postmortem in
[`vps/honeypot-firewall.sh`](../../vps/honeypot-firewall.sh) exists to prevent (a
sensor had a portbridge rule and no firewall rule, so it was fully
unreachable despite being wired everywhere else). Any future FMC persona
declares all three, in one place, and the numbers must be equal:

| Layer | What it is | Where it lives | ASA's value, for comparison |
|---|---|---|---|
| **Internal listening port** | the port the process binds inside its container | the sensor's own env var + its README | `HTTPS_LISTEN_ADDR=:8443`, `IKE_LISTEN_ADDR=:500` |
| **Host publication** | the port bound on `HP_BIND` (the WireGuard tunnel address), in `compose.yml`'s `ports:` | `arcane/home/<stack>/compose.yml` | `${HP_BIND:-10.8.0.2}:8443:8443`, `:500:500/udp` |
| **Intended public routing** | the port the world may reach, via the VPS | portbridge `RULES` in [`vps/docker-compose.yml`](../../vps/docker-compose.yml) **and** the firewall list in `vps/honeypot-firewall.sh` | `tcp:8443:10.8.0.2:8443:pp` (PROXY-aware), `udp:500:10.8.0.2:500` |

Constraints a future persona inherits from today's state, all checkable
without a probe:

- **443 is not available as a public publication.** Traefik already binds
  `443:443` and `80:80` on the VPS. A management console is the one decoy
  family whose obvious port number is therefore unusable, which is a real
  design input, not an obstacle to route around.
- **8443 is the ASA's** WebVPN publication, and 8080, 8081, 8543, 8880, 8888,
  8889, 9201 are all taken by other sensors. A new public port must be absent
  from both `RULES` and the firewall list, and `vps/check-firewall-portbridge-sync.sh`
  is the static check that the two stay in agreement.
- **Internal port and published port are allowed to differ** — the fleet does
  it deliberately (citrix raw 4443 → container 443; sonicwall raw 8543 →
  container 8443; endlessh public 2022 → container 19024). But the offset must
  be stated in the persona's README, not left for an auditor to infer.
- **A management port must not be published "because it is what FMC uses".**
  #3180's disposition says it plainly: "Avoid blanket public
  management-port exposure." An FMC persona's public port is a *deception
  budget* decision, and it gets its own authorization (see §7).
- **Attribution is a property of the routing choice, not an afterthought.**
  PROXY-protocol fronted (`RULES` with the `:pp` flag, `PROXY_PROTOCOL=1` in
  the sensor) is the PROXY-aware tier in
  [`docs/PIPELINES.md`](../PIPELINES.md); without it the sensor is
  tunnel-blind and depends on the portbridge `CONN_LOG` `via_port` join, and
  an FMC event with an unattributable source IP is much weaker evidence. A
  management-plane persona should take the PROXY-aware tier.

## 3. Coverage map: what an FMC-shaped probe actually hits today

This is the part that decides whether the persona is worth anything, so it is
derived rather than assumed. The finding is that the fleet already collects
the interesting bytes generically, and none of it knows or claims the product.

| Traffic | Where it lands today | What is captured | What is *not* claimed |
|---|---|---|---|
| A Java-serialized stream in an HTTP body | `http-honeypot` / `api-honeypot` (same binary) | `payload_class = "serialized-object"`, matched on the `rO0AB` base64 prefix or the raw `AC ED 00 05` magic in `main.go`'s `classifyPayload`; request bodies are read under a 64 KiB cap (`bodyReadCap` in `credentials.go`) and the raw bytes reach the classifier before redaction | It is not parsed, deserialized, or verified as exploitable; it names no CVE and no actor. The classifier is ordered, so an earlier branch can take precedence, and the 64 KiB cap plus JSON encoding mean the stored body is not byte-for-byte evidence for arbitrary binary |
| An FMC-shaped login POST | `http-honeypot`, and the ASA's WebVPN side | #3213's vocabulary: `credential_status` ∈ {absent, present_unparsed, extracted, unknown}, `credential_present` as a nullable pointer, `auth_outcome` ∈ {simulated, real, unknown} — with a regression test asserting no outcome is ever derived from a status code | `200` on a canned page is **not** an authentication. #3180: "This is not authentication success… Treating missing fields as absence makes false bypass alerts inevitable." |
| A request that looks like it targets a management console | `cisco-asa-honeypot` (ASA WebVPN 8443) and `citrix-honeypot` | Unconditional per-request logging of path, headers, UA, and the CVE-2018-0101 / CVE-2019-19781 shapes each was built for; both terminate their own TLS | Neither impersonates FMC. The ASA decoy's `main.go` header states it is "a Cisco ASA WebVPN decoy for CVE-2018-0101" — a different product and a different vulnerability class |
| ICS/SCADA or malware-capture traffic | Conpot ×6, DNP3, Dionaea | Protocol decoding, bistream retention, incident records | Neither presents an HTTP management console; per #3180, Conpot's internal port-80 listener and Dionaea's `roots/www` directory are not evidence of FMC fidelity |
| Network metadata | `vps/suricata/suricata.yaml` on the VPS's public NIC | `tls`/JA3/JA4 records, flow | No request bodies. And the decoys are raw-tunnelled TLS that the decoy itself terminates, so a rule that matches a path or body can never fire on them — #2977 established this for the citrix decoy and #3011 for the SonicWall one |

**Requirement F-3 (no false precision).** A future persona may classify the
*surface* it presents (`fmc_*_surface_probe`-shaped, one classification per
recognised route family), but it must not name a CVE in an event type unless
the literal request shape is confirmed against a primary source. This is
#2919's confirm-before-classify discipline, restated for a third management
persona: #2977 added seven path literals taken from signatures already loaded
on this fleet's own IDS, and declined to guess a CVE-2026-19490 path for
exactly this reason. #3180's proposed detectors are explicitly "unvalidated
hypotheses, not demonstrated coverage."

**Requirement F-4 (byte safety).** Captured bytes stay bytes. No layer
deserializes, decodes, inflates, or executes them; no layer follows a URL,
path, or callback the request contains; and any storage path must record
length, truncation, and read-error rather than presenting a partial read as
complete. The honest form of the capture is "generic serialized content was
received", never "exploit succeeded".

## 4. Isolation requirements

These are not aspirations — each one is an existing, enforced invariant that
a new stack either satisfies or is visibly exempted from.

| ID | Requirement | Where it is enforced today |
|---|---|---|
| **I-1** | Its own single-member Docker network, shared with nothing | `docs/honeypot-network-isolation.md` §3; the ASA's is `cisco_asa_honeypot_net` |
| **I-2** | `internal: true` on that network — a management persona has no design reason to make an outbound request, unlike Cowrie/Dionaea/TANNER, which need egress to capture fetched malware | `docs/persona-design.md` §1 names exactly this: sensors with no reason to reach the internet are the ones an operator should be able to air-gap, and its `*_AIR_GAPPED` pattern is the established way to do it. **An FMC persona should be internal-only, not merely "allowed by default"** |
| **I-3** | `cap_drop: [ALL]` + `security_opt: no-new-privileges:true` + `read_only: true` | Every hardened decoy; `scripts/isolation-audit.sh` is the standing audit |
| **I-4** | Never mounts `/var/run/docker.sock`, never `privileged` | `docs/honeypot-network-isolation.md` §3: "a container that has it has the host" |
| **I-5** | Explicit CPU + memory + `json-file` log budget, sized by measurement not guess | `docs/SENSORS.md`'s runtime budget section; the ASA's measured 1.0 CPU / 256 MiB |
| **I-6** | A healthcheck plus the `autoheal=true` label, wired as a pair | `scripts/check-autoheal-labels.py` (CI) |
| **I-7** | Log output only to a bind-mounted host log dir, shipped by Filebeat under `honeypot.*`, retention parity with every other sink | `scripts/check-json-sink-retention-parity.py` (#2892's ledger) |
| **I-8** | Bounded, time-limited request handling: a body read cap *and* the server-level timeouts, so neither a slow-dripped body nor an idle keep-alive can hold a goroutine or socket open | the sibling decoy's own `http.Server` sets `ReadHeaderTimeout: 5s`, `ReadTimeout: 10s`, `WriteTimeout: 120s`, `IdleTimeout: 60s` with a comment (#881) recording that header timeouts alone leave the body and keep-alive unbounded; the 64 KiB `bodyReadCap` is the size half |
| **I-9** | No third-party code execution, no subprocess on the request path, no template or expression evaluation, no deserialization library reachable from request bytes | the fleet's posture for the Go decoys. **TANNER is the documented exception** — it does emulate SQLi/LFI/XSS/command-execution/object-injection/XXE/CRLF/template-injection, and earns that only on its own `tanner_local` network with a disposable nested Docker on tmpfs rather than a host socket mount. An FMC persona acquires no such emulator and therefore no such boundary |
| **I-10** | Its own compose stack under `arcane/home/honeypot-<name>/` with a per-stack `.env.example` | `scripts/check-compose-env-docs.py` (CI) requires every interpolated `${VAR}` to be documented in that stack's own template |

**Requirement I-11 (deployment is a separate authorization).** Nothing in this
note authorizes a deployment, a port publication, or a firewall change. A
future PR that builds a persona lands it dark (compose file, docs, tests,
fixtures) with no `RULES` entry, no firewall line, and no Traefik hostname;
exposure is a second, separately reviewed change that names the owner, the
port, and the rollback.

## 5. Provenance requirements

| ID | Requirement | Rationale |
|---|---|---|
| **P-1** | The persona joins `personas/personas.json` as a fictional organization/site/asset, and passes `personas/validate_personas.py` | `docs/personas/README.md`: "Never use a real organization, clone a live website, or seed real credentials or customer data." A management console that names a real customer is a liability, not a decoy |
| **P-2** | No real credentials, real certificate keys, real hostnames, or production device names anywhere in the persona | Same rule; also `scripts/check-public-leaks.py` (CI) as the standing gate |
| **P-3** | Any synthetic management action is a **simulation with no side effects**: it is logged, it changes no firewall, access policy, rule, or object anywhere, and it cannot reach a device because there is no device | The fleet has no managed-firewall estate for a persona to affect, and must not acquire one. A decoy that can actually change a policy is a real control plane with a public IP |
| **P-4** | Every FMC-origin event carries simulation provenance: the persona/asset identity, and `auth_outcome = "simulated"` (never `real`) | #3213's vocabulary already has the value; §3's own guidance is that real success needs trusted audit evidence, which a honeypot by definition never has |
| **P-5** | No Cisco vendor default-credential list, and no credential list of any kind sourced from exploit material | #3180's own correction: CVE-2026-20316 concerns a hard-coded **low-privileged** account, "not evidence of a publicly documented default administrator password", and "No actual credential list was verified or is supplied. Do not collect one from exploit material or test it on a system." The existing `credentials.go` comments and `test_3213_fix.py` already encode this |
| **P-6** | The persona's identity is stable in the event stream: `persona_id`, `site_id`, `asset_id`, `organization`, so the dashboard's existing pivots work | `docs/personas/README.md`; Filebeat enrichment under `honeypot.*` |
| **P-7** | The design doc names what the persona is *for* (attraction and product context) and what it is *not* (bypass detection, policy-change evidence) in the same breath | §9 |

## 6. Maintenance cost

The cost is the reason this decision is worth recording before it is made.
A new management persona is a genuine new-service build, not a config change,
and it touches every layer that has to agree:

| Surface | What must change | Gate that fails if it does not |
|---|---|---|
| Sensor | New Go service (or a sibling of the citrix/sonicwall/ASA decoys) with its own Dockerfile, module, and tests | Go build/test/fmt rows in CI |
| Compose | a new stack dir under `arcane/home/honeypot-<name>/` (named after the sensor) holding its own `compose.yml` + `.env.example` | `scripts/check-compose-env-docs.py` |
| Hardening | network, caps, read-only, budgets, healthcheck, autoheal | `scripts/check-autoheal-labels.py`, `scripts/isolation-audit.sh` |
| Publication | `RULES` in `vps/docker-compose.yml` **and** the port list in `vps/honeypot-firewall.sh` | `vps/check-firewall-portbridge-sync.sh` |
| Enrichment | Filebeat persona fields under `honeypot.*` | Filebeat/dashboard ingestion checks |
| Dashboard | registration in `topology.rs` (sensor → stack → containers), the protocol arm in `sensors.rs`, a detail arm in `event_detail.rs`, canonical-field promotion in `ip_enrichment/`, and frontend protocol mapping | Go + frontend test rows |
| Credential boundary | **only if** the persona ever carries credentials — a reviewed scope change to `CREDENTIAL_SENSORS` with its own proof, since already-indexed documents are not repaired by sensor-side redaction | `secrets_boundary.rs` tests |
| Retention | JSON sink registered in the retention-parity check | `scripts/check-json-sink-retention-parity.py` |
| Docs | `docs/SENSORS.md` row, `docs/NETWORK.md` routing table, `docs/PIPELINES.md` attribution tier, `docs/persona-design.md` outbound table, `docs/STACK-REBUILD.md` stack list, `docs/CGNAT-DEPLOYMENT.md` standalone-honeypot list, `docs/personas/README.md` inventory, `docs/DECEPTION-EXTENSIONS.md` row | `scripts/check-doc-paths-exist.py`, `scripts/check-docs-reachable.py` |
| Steady state | a new decoy is also a new thing to patch, budget, and retire | — |

The steady-state row is the one that decides a P2 decision. Every existing
edge decoy in this fleet exists because a specific CVE made it worth its
running cost; an FMC persona has no equivalent forcing function, and the
fleet has already retired one decoy for exactly this reason
([`docs/DECEPTION-EXTENSIONS.md`](../DECEPTION-EXTENSIONS.md)'s WordPot row:
attacker-facing runtime, noise-floor traffic, and a duty already covered by a
sibling).

## 7. Out of scope, explicitly

Not deferred — **out of scope for this issue and for any persona built under
this contract**:

1. **Authentication bypass.** No code path may authenticate an attacker, no
   credential may be accepted, and no response may be shaped to read as a
   successful login. A bypass *emulator* is exactly the thing #3180's
   disposition forbids ("do not replace them or map an exploit chain").
2. **Object deserialization.** No `ObjectInputStream`, no gadget chain, no
   reflective instantiation, no decoding of any serialization format from
   request bytes. The fleet recognizes serialization *headers* to classify
   bytes; that is the entire permitted depth.
3. **Command execution.** No shell, no `exec`, no subprocess, no template or
   expression evaluation, no file write from request content.
4. **Network callbacks.** No outbound request-following — no SSRF relay, no
   fetch of an attacker-supplied URL, no webhook, no DNS resolution of
   attacker-supplied names, no link-local or metadata-service reach. The
   SonicWall decoy's `AMC_RELAY_URL` is a *fixed, non-attacker-steerable*
   hop and is the only outbound-request precedent in the fleet; a management
   persona needs none, and `internal: true` (I-2) removes the route entirely.
5. **A vulnerable FMC image.** No vendor appliance image, no deliberately
   unpatched build, no "vulnerable staging box" of any kind.
6. **Touching Conpot, Dionaea, or the ASA decoy.** Their behaviour, event
   vocabulary, ports, and files stay byte-identical.
7. **FMC vendor default-credential research** beyond what's already recorded
   in #3180's corrected matrix, and no testing of any credential anywhere.
8. **Managed-appliance audit ingestion.** That is #3215, gated on separately
   authorized inputs, and is a different subsystem (schema + normalization
   over real audit exports, with synthetic fixtures first) — not a decoy.
9. **Suricata rules for FMC paths.** Per §3, a self-terminated-TLS decoy makes
   such a rule structurally dead; and no FMC rule was established from
   repository evidence. The sensor's own classifier is the only detection
   point that works on this surface, and it names the surface, not the CVE.
10. **Any deployment, publication, or firewall change** (I-11).

## 8. Why the prohibitions above are structural, not policy

The three most tempting items — deserialization, bypass, execution — are
tempting precisely because the CVEs behind them are real (#3180 verified
CVE-2026-20131 as insecure Java byte-stream deserialization to unauthenticated
root RCE, and CVE-2026-20079 as a web-interface authentication bypass, both
CVSS 10.0 and both in CISA KEV; CVE-2026-20316 as static low-privileged
credentials, CVSS 5.3 Medium with Cisco SIR High, also in KEV). Reproducing
any of them inside a public-facing container converts a sensor into a
vulnerability with the honeypot's own IP reputation, on a host whose entire
value is that it can be attacked freely. The decoy's job is to *survive* the
attempt and record it. A persona that can be exploited has stopped being a
decoy and started being the vulnerability, and the fleet has no authorization
to run one.

The same logic makes the "simulation" framing load-bearing rather than
diplomatic: an FMC-shaped `POST` that *appears* to push a policy, with no
firewall behind it, is an inert record. The moment it can move a real object,
it is a management console on a public IP, and this issue authorizes neither.

## 9. Coverage: what an FMC persona would and would not add

Stated as a property of the design, not as a recommendation.

**Would close (attraction and context):**

- A real attacker probing a Cisco management console would find something
  that looks like one, and the request would arrive with its real path,
  headers, and body intact under a product-specific persona instead of being
  flattened into generic HTTP telemetry.
- Product-context pivot: an operator asking "what did we see aimed at network
  security management?" would get an answer from an event stream, rather than
  inferring intent from a path string on a generic decoy.
- A surface-level classification vocabulary (F-3) for management-console route
  families, which is legitimate coverage of *which surface was probed* —
  confirmable without any CVE claim.

**Cannot close, and this is the load-bearing half:**

- **Real bypass success.** A decoy cannot authenticate anyone, so no event
  from it is ever evidence that CVE-2026-20079 worked. #3180's assessment of
  that proposed detector: "Not reliably feasible… 20079 may bypass normal login
  entirely."
- **Actual policy changes, new admins, certificate imports.** These are
  management-state transitions. A decoy can log the *request*; only a
  trusted audit stream from a real appliance can establish the *outcome* —
  and that stream is #3215's separately authorized scope, with its own schema
  work. #3180: "URI matching does not establish a completed operation."
- **Exploit validation.** Nothing here confirms that a payload would have
  worked, that a deserialization sink exists, or that a CVE applies to any
  version. The persona is a recording surface, not an oracle.
- **Fleet exposure reduction.** There is no FMC in this fleet to reduce
  exposure for (§2.1).
- **Java-stream body fidelity.** The generic HTTP decoy's 64 KiB cap and JSON
  encoding already limit byte-for-byte evidence for binary bodies; a new
  persona would not fix that by existing (F-4 keeps the limit).

The asymmetry is the decision input. The "would close" column is
attraction/context — real, but the same class of value the generic HTTP
decoy already provides. The "cannot close" column is every class a reader
would most want from a management persona. That is a fact about the design;
whether it justifies a new running service is the open question this note
leaves open.

## 10. Acceptance criteria for any future PR

Offline, inert fixtures only. No exploitation, no credential testing, no
appliance access, no deployment, no live probe.

1. The PR's own design section reproduces this document's fidelity, isolation
   and provenance requirements (§1, §4, §5), states which §6 maintenance
   surfaces it touches, and records per requirement why any of them does not
   apply.
2. An existing ASA fixture is still an ASA fixture: the
   `cisco-asa-honeypot` cases in `events.rs` and
   `ip_enrichment/canonical.rs` pass unchanged, and no new code path maps an
   FMC-shaped record onto ASA rules.
3. The `fmc`/vendor-credential ban in
   [`tests/docs/test_3213_fix.py`](../../tests/docs/test_3213_fix.py) still
   passes, and the new persona's bait credentials, if any, are this fleet's
   own fictional ones.
4. Every event the persona emits carries persona/asset identity and
   `auth_outcome = "simulated"`; a fixture asserts a simulated action changes
   no state, because there is no state to change.
5. Offline tests cover: classification of each recognised route family from a
   fixture request; refusal to deserialize/execute/follow (a fixture
   serialization-marker body must produce a classification and nothing else);
   the body read cap **and** the truncation/read-error reporting F-4 requires
   — which the sibling decoy's bounded read does *not* provide today, its read
   error being discarded, so this is new work rather than a copied
   assertion; `credential_status`/`unknown` reaching every state; and the
   absence of any CVE-named event type without a cited primary source.
6. The persona is dark: no `RULES` entry, no firewall line, no Traefik
   hostname, no DNS record — with the exposure change filed separately.
7. All standing gates pass unchanged: `check-compose-env-docs`,
   `check-autoheal-labels`, `check-json-sink-retention-parity`,
   `check-doc-paths-exist`, `check-docs-reachable`, `check-doc-stale-paths`,
   `isolation-audit.sh`, and the full `tests/docs/` suite. No existing test is
   weakened, skipped, deleted, or allowlisted to accommodate the new sensor;
   no new Suricata or zizmor finding is allowlisted; any new GitHub Action is
   pinned to a full commit SHA.

## 11. What was not verified

- **FMC's own product surface** (default ports, wizard endpoints, API
  prefixes, page titles, version strings) was not verified. #3180's
  `/webui/`, `/api/`, 443 and 8443 references are issue hypotheses about where
  to look, not confirmed vendor facts; nothing was probed to check them. Any
  build must source each literal from a primary Cisco document first, under
  #2919's confirm-before-classify rule.
- **Live exposure** was not checked: no container was inspected, no index was
  queried, no ruleset was read from the running VPS. §2.1 is a statement about
  the tracked tree at `45f41eff`, and §3 about the code as written.
- **Whether a real FMC would be fingerprinted as one by a real scanner** was
  not tested. #2977's Citrix finding is the relevant warning: a scanner that
  fingerprints the decoy as the wrong product class never sends the traffic in
  the first place, and no amount of later classification recovers it. The same
  risk applies to any persona that presents Cisco branding without Cisco
  management-console structure.
- **Attraction uplift was not measured.** No traffic baseline was taken, so
  the "would close" column in §9 is a design argument, not a forecast.
- The vendor claims inherited from #3180 carry #3180's own status labels
  (CONFIRMED / UNVERIFIED / CONTRADICTED), including Interlock attribution
  confirmed for CVE-2026-20131 only and UNVERIFIED for the other two. Nothing
  in this note upgrades a status.

## 12. Bottom line

**The requirements are recorded; the build is not decided, and this note does
not recommend one.** There is no FMC surface in this stack today, so nothing
is exposed and nothing needs patching — the question was never "is this a
gap in our defences", it is "would another decoy add enough to be worth a
permanent new service". What this fleet already collects generically (the
`serialized-object` classification, #3213's honest credential and auth
vocabulary, unconditional per-request capture on the ASA and citrix decoys)
covers the bytes; what an FMC persona would add is product context and
attraction, and it structurally cannot add bypass-success or policy-change
evidence.

If a future reader takes the bait and builds one anyway, the contract is
above and it is the floor, not the ceiling: inert only, no bypass, no
deserialization, no execution, no callbacks, no vulnerable image, its own
persona and network, no sharing of the ASA's identity, and no exposure without
a separate authorization. A negative verdict remains an acceptable outcome
for #3214, and this note is written so that arriving at one costs an hour of
reading rather than a week of re-deriving.
