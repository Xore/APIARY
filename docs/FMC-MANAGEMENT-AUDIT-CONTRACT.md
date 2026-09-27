# FMC management-audit ingestion contract (#3215)

[← back to README](README.md) · [Sensors](SENSORS.md) ·
[Pipelines](PIPELINES.md) · [Deception extensions](DECEPTION-EXTENSIONS.md)

The shape an **authorized Cisco Secure Firewall Management Center
management-audit export** would be reduced to, and the invariants that hold
however such an export turns out to be shaped. This is the F4 row of
[#3180](https://github.com/Xore/APIARY/issues/3180)'s disposition. It is a
**doc only** — deliberately **not implemented**: no normalizer, no connector, no
reader of a live audit stream, and no index is created. Nothing in this document
describes software that exists.

Written 2026-09-27 against `3ac9703fb87f7e1c2d11ac35b4617504547c0534` on
`oc/3215-contract`. Every fleet-side fact below was derived by reading the tree.
No appliance was reached, no export was obtained, no probe of any kind was run —
and none is authorized: #3215 is **blocked** pending an authorized audit source,
and tracking it does not authorize obtaining one.

**The honest summary, up front:** the target shape and every safety invariant
below can be specified now, because they depend on this fleet's own conventions
and not on what an FMC export looks like. The *bindings* — which vendor field
feeds which of these fields, what the timestamps mean, whether a completed
change is provable from the export at all — cannot be specified without reading
a real export, so they are named as open questions with the evidence that would
settle each one, and left open. Writing plausible field names for a source nobody
has read would turn this into fiction, and a reader cannot tell fiction from
specification once it is in a table.

## The one distinction everything else follows from

A decoy HTTP log and an appliance audit stream are different classes of
evidence, and the difference is not a matter of degree.

| | **Decoy HTTP log** | **Authorized audit export** |
|---|---|---|
| Produced by | this fleet's own sensors, on purpose, to be attacked | a real management console, about its own state |
| Records | that a **request** arrived, with its path, headers and body | that an **operation** was attempted, and — sometimes, and only if the source says so — that it **completed** |
| Can establish | that someone aimed something at a management console, and what they sent | who changed what, under which role, when, and with what result |
| Cannot establish | whether anything happened | anything about an *attacker's* infrastructure — there is no attacker in this stream; it is full of the operator's own authorized activity |
| In this fleet | `honeypot-v2-*`, via [PIPELINES.md](PIPELINES.md) §1 | nowhere. No index, no reader, no connector exists |

The asymmetry is why mixing them is the failure mode to design against.
#3213 already fixed the small version of this inside the decoys: a `200` on a
canned login page is not an authentication, which is why `auth_outcome` is a
three-value vocabulary rather than a boolean. The large version is the same
mistake one level up, and it is the one that pages an operator at 3am.

> A request-shaped record must never become a completed-change event. A
> simulated or fixture-shaped record must never become a real audit event. A
> missing principal or result must stay unknown, never acquire a default.

Three further consequences, stated here because they are what a reader
mistakes for optional detail:

- **A management-API `2xx` is not a completed change.** A response code is the
  console's opinion of its own HTTP layer, and a decoy that returns `200` proves
  nothing whatsoever. Only a source that says the operation landed may set
  `change.state = completed`.
- **Audit volume is the operator, not the attacker.** Every real administrator
  logs in. Naive volume, rarity or "unusual principal" heuristics tuned on
  decoy data produce nothing but the operator's own routine, and a contract that
  invites them is a contract that trains its readers to ignore the index.
- **The two streams must never share a correlation key.** If an audit row and a
  decoy row could be joined on a common field, the join itself would manufacture
  the claim this document exists to prevent — an attacker's request appearing to
  have caused an operator's authorized change.

## The normalized record

One document per source audit record. Its own namespace, its own index family
(proposed: `fmc-audit-events-v1` — a proposal, not a commitment), and its own
allowlist. It is **not** written in the flattened decoy `honeypot` namespace and
it is **not** a sensor event: the decoy stream's fingerprint promotion, GeoIP
pass and source-health pivots all assume the document describes something an
attacker touched, and an audit row describes the opposite.

That is not a new pattern for this tree. The precedent is
`auth-events-worker`, which already normalizes a *non-attacker* source (the
fleet's own failed logins) with an explicit field allowlist, its own index, its
own mapping, and the source's stable event id used as the Elasticsearch document
id so that re-ingesting a row overwrites it rather than duplicating it. This
contract copies that discipline and changes nothing else.

Read the five columns as: the field, its type, what it may carry, **what it may
never carry**, and what a missing value means. The fourth column is the
boundary; the fifth is where a careless refactor loses the truth.

| Field | Type | May carry | Never carries | When absent |
|---|---|---|---|---|
| `evidence.class` | keyword | which kind of evidence produced this row: `fmc_audit_export`, `fmc_audit_fixture`, or `decoy_http` | never an `fmc_audit_export` value on a row that did not come from an authorized export | `unknown`. Absence is never read as export |
| `evidence.source_id` | keyword | the source record's own stable identifier, verbatim | never a surrogate key this fleet generated, and never a digest standing in for a real one | `unknown`. A row with no source id is not deduplicable and is quarantined, not ingested |
| `evidence.contract_version` | keyword | the version of this contract that shaped the row | never the ingesting binary's version, which would silently re-shape already-indexed rows | `unknown` |
| `appliance.product` | keyword | `cisco_secure_fmc`, as the source identifies itself | never a Cisco ASA value, and never the fleet's own invented `nexusai-asa-vpn` product | `unknown`, and the row is then not an FMC audit row at all |
| `appliance.ref` | keyword | a fleet-local surrogate for the appliance, stable across every row from it | never the appliance's real hostname, FQDN, serial number, or management address — the real value lives in a local ingest-time mapping that is not indexed | `unknown`. Rows are not correlated to each other without it |
| `appliance.version` | keyword | the product version string the appliance reports | never a version this fleet inferred, and never an implied CVE applicability | `unknown` |
| `principal.name` | keyword | the account name exactly as the audit stream gives it | never a password, token, or key, and never a value recovered from a request body | `unknown`. An absent principal is never filled in from a User-Agent, a session cookie, or a neighbouring row |
| `principal.id` | keyword | the appliance's own stable account identifier | never an email address or any other real-person identifier | `unknown` |
| `principal.role` | keyword | the role or permission tier the audit stream attributes **at the time of the operation** | never a role this fleet assigned, and never a role inferred from the account's name | `unknown` |
| `session.id` | keyword | the appliance's own session or transaction identifier | never a session cookie, bearer token, or `Authorization` value — the identifier that names a session, never the credential that proved it | `unknown`. An unattributable row is not attributed to a session |
| `operation.name` | keyword | the operation as the source names it, kept verbatim | never a normalized verb this fleet invented, and never a CVE-named operation | `unknown` |
| `operation.target_type` | keyword | the class of object acted on — policy, user, certificate, rule, and so on | never a class inferred from a URL path or a path substring | `unknown` |
| `object.id` | keyword | the source's own object identifier, verbatim | never a resolved path into a real filesystem, and never a live API path this fleet could fetch | `unknown` |
| `object.type` | keyword | the object class as the source states it | never inferred from a path substring, which is the inference §Maintenance context exists to reject | `unknown` |
| `result` | keyword | `success`, `failure`, or `unknown` — the outcome the audit stream states | never derived from an HTTP status code, a response length, a redirect, or the mere absence of an error field | `unknown`. `unknown` is never rounded to `success` |
| `timestamp.event` | date | the appliance's own clock reading for the operation | never replaced by the collector's clock, and never back-dated from arrival order | `unknown`. Also not trusted for ordering until the open question in §Not specified, and why is settled |
| `timestamp.ingested` | date | this fleet's clock at normalization time | never used as the event time, and never presented as one | always set |
| `timestamp.trusted` | boolean | whether the source's clock semantics have actually been verified | never `true` by default or by optimism | `false` until verified, and a future change to `true` is a reviewed act with its own evidence |
| `change.state` | keyword | `completed`, `attempted`, or `unknown` — whether the source asserts the change landed | never promoted from a requests-only record, and never from a `2xx` on a management API | `unknown` |
| `change.before` | object, allowlisted keys only | the before-values of keys on the explicit allowlist, and only those | never a value, blob, certificate, key, token or secret, and never a key outside the allowlist | `unknown`. A missing side is never an empty object, and never a zero |
| `change.after` | object, allowlisted keys only | the after-values of allowlisted keys, and only those | never a value, blob, certificate, key, token or secret, and never a key outside the allowlist | `unknown`. A missing side is never an empty object, and never a zero |
| `asset.context` | object | the `organization`, `site_id`, `asset_id` and `role` keys that [`personas/personas.json`](../personas/personas.json) already defines, so the dashboard's existing pivots work | never a real customer's asset identifiers, and never a persona entry invented for an appliance this fleet does not own | `unknown`. A row is never attached to a persona by hostname match |
| `maintenance.context` | object | `maintenance.ticket`, `maintenance.window_start`, `maintenance.window_end`, `maintenance.declared_by`, set only from an operator-declared change record | never inferred from a path substring, a job name, a user-agent, or a time-of-day heuristic | `unknown`. Absent context means *not declared*, never *not maintenance* |

**Why `change.before` / `change.after` is an allowlist and not a filter.** This
is the only field in the shape where a secret would plausibly arrive, and it
arrives as whatever the vendor chose to put in a before/after diff — which for
a certificate object is a certificate, and for a user object may be a credential
field. A value-level filter cannot police that: it cannot tell a truncated PEM
from an opaque token, cannot know which key names are sensitive until it has read
every vendor version, and fails open on the one field nobody reviewed. So the
boundary is structural — the normalizer copies **allowlisted keys only** and
never copies a value it was not told to copy. A key that is not on the list is
dropped, not truncated and not blanked, and the list is versioned with the
contract so a widening is a reviewable diff rather than a silent change.

**Identity resolution is a join, never a field.** The mapping from
`appliance.ref` to a real appliance is deliberately not part of the indexed
record, for the same reason the fleet already redacts at the sensor rather than
at read time: an indexed document is already copied, already replicated and
already exportable, and "we will remove it later" is not a control over data
that has already spread. Anyone needing the real name joins at read time
against a local mapping that never leaves the ingest host.

## Promotions that must never happen

Three conversions, each of which the issue names and each of which is
individually invisible in review and catastrophic in aggregate. They are stated
as prohibitions, not as cautions, and a future implementation is expected to
assert each one against a fixture.

1. **A requests-only record never becomes a completed change.** A record whose
   source asserts only that a request arrived — a decoy HTTP log, a
   request-shaped audit entry with no completion assertion, a `2xx` — may set
   `change.state` to `attempted` or `unknown`, and never to `completed`. #3214
   puts the same boundary from the decoy side: a decoy can log the *request*,
   and only a trusted audit stream can establish the *outcome*.
2. **A simulated or fixture record never becomes a real audit event.** Anything
   with `evidence.class = fmc_audit_fixture` is a test artifact and is
   quarantined, never indexed into the audit family. The mirror of this on the
   decoy side is #3214's P-4: every synthetic management action carries
   `auth_outcome = simulated`, never `real`.
3. **A missing principal or result stays `unknown`.** Never defaulted, never
   inherited from the nearest row that had one, never inferred from the object
   type or the operation name. #3213's `unknown` exists for exactly this and its
   loss is the easiest mistake in the whole vocabulary to make.

**Duplicates and out-of-order arrival.** `evidence.source_id` is the natural key
and becomes the document id, so re-ingesting a row overwrites it rather than
producing a second completed action. A high-water checkpoint on
`timestamp.event` is *not* sufficient on its own — it drops everything that
arrives late — so a future implementation would need the overlap-then-dedupe
shape `auth-events-worker` already documents for the same reason, and would keep
the source id on every row so the deduplication is auditable after the fact.

**Correlation happens last, and only between trustworthy rows.** Not before
proving the source and its timestamp semantics, exactly as the issue requires.
Until `timestamp.trusted` is `true`, correlation windows are advisory and every
derived conclusion carries that caveat.

## Maintenance context

The issue's criterion is specific and worth restating verbatim in intent: a
**scheduled certificate renewal must be separated from an unexpected admin
creation by explicit maintenance context, not by path substrings.**

The two are frequently indistinguishable in the record itself. A renewal and an
intrusion both touch a certificate object; both carry a plausible path; both
happen at a plausible hour. A rule that reads the path, the job name, the
user-agent or the time of day is therefore not a weaker version of the right
rule — it is a rule that will eventually classify a real intrusion as routine and
file it under the next renewal, which is silent, self-erasing, and the worst
outcome available to a detection index.

So maintenance context is **declared**, not derived, and it lives in the
operator's own change record: `maintenance.ticket`,
`maintenance.window_start`, `maintenance.window_end`,
`maintenance.declared_by`. It is attached to a row at ingest time from a
declaration the operator authored, which means the human who authorized the work
is the one asserting it, and the assertion is auditable as a separate fact.

Three properties that follow, each of which a future implementation must preserve:

- **A maintenance-flagged row stays in the index, with its flag set.** It is
  never dropped and never hidden. Suppression as deletion would be a second,
  undocumented mechanism for losing evidence, and it would make the index's
  contents depend on a declaration that can be edited. Maintenance context is a
  *triage hint* — it changes how a row is presented, never whether it exists.
- **The hint is a hint.** A declared window never mutes an operation outside its
  own scope: a `maintenance.ticket` covering a certificate renewal does not
  explain a new administrator created three minutes later, and the contract
  requires that such a row remain fully alertable regardless of any window.
- **An absent declaration means undeclared.** `maintenance.context` absent is
  `unknown`, never `not-maintenance` and never `maintenance`.

## Out of scope, explicitly

Not deferred — **out of scope for this contract and for anything built under it**.
Each item is excluded for a stated reason, because the reason is what makes the
next boundary case decidable instead of arbitrary.

1. **Certificate material.** The certificate body itself — the PEM-armoured text
   or the DER bytes, and any base64 of either — never enters a normalized record.
   The certificate *is* the credential: it is what an attacker presents to
   impersonate the appliance, so a corpus of them in a long-retained,
   dashboard-served, exportable index is a credential store wearing a detection
   index's clothes. What is permitted about a certificate object is a SHA-256
   fingerprint of it, which is one-way and is already how this fleet's
   `fingerprint.kind` / `fingerprint.value` envelope represents a stable
   identity — plus the fact that an import or rotation was attempted.
2. **Private keys.** No private key material in any encoding, at any nesting
   depth, under any field, ever. This is not a redaction question but a
   structural one: a key is unbounded in sensitivity and bounded in usefulness
   to an analyst, and a normalizer that copies values it was not told to copy
   will eventually copy one. The contract's allowlist (§The normalized record)
   is what makes the guarantee checkable, because a key cannot be copied by a
   mapper that only copies named fields.
3. **Passwords.** No account password, shared secret, or passphrase, in the
   record or in any `change.before` / `change.after` diff. #3213 already
   established that removing a field is not removing a leak, and that the
   scrub has to run over every channel; the same reasoning applies to a vendor
   before/after diff, and this contract goes one step further by never copying
   the value in the first place rather than scrubbing it afterwards.
4. **Tokens.** No bearer token, API key, session cookie, `Authorization` value,
   or reset link — the identifier is kept, the credential that proved it is
   never kept. Every one of these is replayable for as long as it is valid, and
   an indexed row survives the incident-response window that would have
   rotated it.

Also out of scope, and for the same "would need its own authorization" reason:

- **A live audit reader.** No connector, no poller, no scheduled fetch, no
  appliance API client. The issue authorizes no appliance access, and
  `auth-events-worker` is the shape such a reader would take *if* an authorized
  source ever exists — a separate, reviewed change.
- **An index, a template, or a mapping.** No `fmc-audit-events-v1` index is
  created by this document. The name above is a proposal for whoever builds it.
- **Decoding, parsing, or interpreting a certificate.** Fingerprinting a blob is
  permitted; parsing one to extract a subject, a serial or a validity window is
  a decision nobody has made, and it is the first step toward handling key
  material.
- **Any detection, alert, or correlation rule.** A contract that also ships
  thresholds has pre-committed to a build, and thresholds tuned without a source
  are guesses with an operational cost.
- **Retention.** Not set here. An audit export can carry regulated personal data
  under someone else's governance, and that is a question for the operator who
  owns the data, not a default this doc can pick.
- **Anything that changes `cisco-asa-honeypot`, Conpot, Dionaea, or any other
  sensor.** Their behaviour, vocabulary, ports and files stay byte-identical.

## FMC is not the ASA persona

**This section defers; it does not restate.** The product-identity decision is
[#3214](https://github.com/Xore/APIARY/issues/3214)'s — the *inert management
persona* note — and a second, slightly different copy of a product boundary is
how two documents drift into contradicting each other. What belongs here is only
what this contract must not do to it.

- Cisco Secure FMC is the **centralized management console** for Cisco Secure
  Firewall. This fleet's Cisco decoy, `cisco-asa-honeypot`, is a **WebVPN/IKE
  data-plane** decoy. Different product, different plane, different vulnerability
  class; #3214 records that distinction and its consequences, including a
  regression test that keeps the two identities from merging.
- **No FMC sensor exists in this stack, and this document does not create one.**
  No sensor name, no compose entry, no port publication, no decoy, no persona
  entry. An audit record is evidence *about* an appliance; a decoy is a thing
  that *pretends* to be one, and this contract is only ever the former.
- **No audit row ever sets `event.sensor` to a decoy's sensor name.** The decoy
  stream's sensor field is how this fleet dispatches per-product rules
  (`canonical.rs`'s per-sensor arms, `topology.rs`'s per-sensor registration);
  borrowing it would route a management-console audit row through ASA rules that
  know nothing about principals, roles, or results. `appliance.product` is the
  discriminator here, and it lives in this contract's own namespace.
- **The existing ASA fixtures stay ASA.** A record that merely looks like
  another product must not fall through to that product's rules — #3214's F-1,
  enforced today by a test that must keep passing.
- **No vendor claim is introduced here.** No default-credential list, no
  CVE-named operation, no port or endpoint presented as this product's default.
  Per #3214's F-3, each such literal must come from a primary Cisco document
  before anyone uses it, and per #2919's confirm-before-classify rule a contract
  is the last place to guess one.

## Not specified, and why

#3215 is **blocked** on an authorized audit source, and the honest consequence
is that the *bindings* are open. Each row below names a question, why it cannot
be answered from the tree, and the specific artefact that would settle it. A
future reader should treat every one of these as a gate on the implementation,
not as a detail to be filled in during the build.

| Open question | Why it cannot be answered here | What would settle it |
|---|---|---|
| Which vendor field feeds each field above | Nobody has read an FMC export. Guessing produces a table that looks authoritative and binds nothing | a redacted sample export, or Cisco's own published schema for the audit view |
| Timestamp semantics — device clock or collector clock, timezone, precision, ordering guarantees, and whether clock skew is bounded | The whole contract leans on it. Ordering, deduplication and every correlation window are unfounded without it, which is why `timestamp.trusted` defaults to `false` and `timestamp.ingested` is kept separate | the export's own header or manifest, plus one export containing two events whose arrival order is known to differ from their order in the file |
| The `result` vocabulary in practice | `success` / `failure` / `unknown` is the contract's own vocabulary; whether the source distinguishes *denied* from *failed* from *not attempted* is unknown | an export containing at least one genuine failure and one genuine denial, from an authorized system |
| Whether `change.before` / `change.after` are emitted at all, and under what key names | Vendor-specific, and the allowlist in §The normalized record cannot be written without knowing the real key set | one authorized export of a policy change, a user change and a certificate import, with its key names intact |
| Whether a completed change is provable from the export alone | If the source records attempts only, then `change.state` can never legitimately be `completed`, and the central claim this contract exists for is unavailable | an authorized export plus the vendor's own statement of what its audit view is authoritative for |
| Whether object identifiers are stable across exports, versions and reinstalls | Deduplication and correlation both assume stability; a per-export synthetic id would silently break both | two exports of the same system taken on different days, compared |
| Whether the export is complete or paginated, and whether it can be silently truncated | `auth-events-worker` found exactly this in a different admin API — a capped page returns `200` with fewer rows and no marker, and a permanent one-page fetch drops everything after the cap | a documented or observed pagination contract, and an export whose row count can be reconciled against an independent total |
| What governance applies to a customer's audit data | An audit stream can carry regulated personal data, and retention and residency are the data owner's call | the operator's own data-handling decision, recorded before any export is accepted — not a schema question |
| Whether a second source is required to corroborate a change | "Correlate only after proving a trustworthy source" implies the possibility that one source is not enough, and the threshold is unstated | an operator decision on single-source versus corroborated attribution, recorded as policy |

**The source-independent half is what this document delivers**, and it is not
small: the record shape, the never-carry column, the three prohibited
promotions, the declared-maintenance rule, the exclusion list, and the identity
boundary all hold regardless of what an export looks like, and they are the parts
that are expensive to retrofit. What a reader should take from the table above is
not "these are loose ends to tidy during the build" but **"the first eight
questions are gates, and a build that starts before they are answered is
building against a guess."**

## Acceptance criteria for any future implementation

Offline and inert. Fixtures only: no exploitation, no credential testing, no
appliance access, no deployment, no live probe. The issue authorizes none of
these, and tracking the proposal does not authorize obtaining access.

1. The implementation's own design section reproduces this contract's field
   table, its never-carry column, its three prohibited promotions and its
   exclusion list, and records for each open question in §Not specified, and why
   the build is proceeding without it — or does not proceed.
2. Offline fixtures distinguish a successful, a failed and an unknown result, a
   user creation and a certificate import, **without changing any real system** —
   asserted, not assumed: a fixture that changed a real system could not be run
   in CI at all.
3. A requests-only fixture cannot become a completed-change event; a simulated
   or fixture fixture cannot become a real audit event. Both are asserted as
   negative tests, so a future refactor that promotes either one fails loudly
   rather than quietly.
4. Duplicate and out-of-order fixtures retain their `evidence.source_id` and
   produce no duplicate completed action; a missing principal or result stays
   `unknown` and is asserted to stay `unknown`.
5. A declared maintenance window separates a scheduled fictional certificate
   renewal from an unexpected admin creation by explicit context — and the test
   asserts the separation is *not* reproducible from a path substring, which is
   the property that actually matters.
6. A produced record contains no certificate contents, no private keys, no raw
   secrets and no real infrastructure identifiers, asserted over the emitted
   document rather than over the normalizer's source code.
7. An existing ASA fixture is still an ASA fixture: #3214's identity regression
   test still passes, and no new code path maps an audit record onto ASA rules.
8. All standing gates pass unchanged — `check-doc-paths-exist`,
   `check-docs-reachable`, `check-doc-stale-paths`, `check-public-leaks`,
   `check-compose-env-docs`, `scripts/isolation-audit.sh`, and the full
   `tests/docs/` suite. No existing test is weakened, skipped, deleted, or
   allowlisted to accommodate this; no new Suricata or zizmor finding is
   allowlisted; any new GitHub Action is pinned to a full commit SHA.

## What was not verified

- **FMC's audit export format.** Field names, value encodings, completeness
  guarantees, timestamp semantics: none of it was read, because no authorized
  export exists. Every binding in the field table is therefore a *contract slot*,
  not a mapping, and the table above says so.
- **FMC's product surface** — ports, endpoints, version strings — was not
  verified, and is not asserted anywhere in this document. #3214 records the
  same absence for the decoy side and the same rule for filling it in.
- **Whether a real FMC would be distinguishable in an audit stream at all.** The
  risk #3214 flags applies with the sign flipped: a decoy that is fingerprinted
  as the wrong product never receives the traffic, and by the same token a
  normalizer bound to the wrong field names will silently ingest nothing rather
  than fail. Nothing here was tested against a real export.
- **No index was queried, no container inspected, no running host read.** Every
  fleet-side statement is about the tracked tree at `3ac9703f`, and every
  reference to a deploy-time value is a description of the code as written.
- **The maintenance model is untested against a real operator's change
  management.** It is specified as a declaration the operator authors, which is
  a design decision, not a validated process.
- **No detection value is claimed.** Nothing here says an audit stream would
  find anything. It says what such a finding would have to look like to be
  honest.

## Bottom line

**The contract is specified; the build is not decided, and this document does
not recommend one.** What is delivered is the source-independent half: the
normalized shape, the never-carry boundary, the three prohibited promotions, the
declared-maintenance rule, the exclusion list with its reasons, and the identity
line that keeps FMC distinct from the ASA decoy. Those are the parts that are
expensive to retrofit, and they are recorded now while the decision is still
cheap.

What is deliberately left open is everything that needs a real export: the
bindings, the timestamp semantics, the result vocabulary, the before/after key
set, and whether a completed change is provable from one source at all. #3215
stays **blocked** on an authorized audit source, and obtaining that source is
not authorized here.

So the recommendation is explicit, and it is a negative one: **do not build this
yet.** A negative verdict remains an acceptable outcome for #3215 — including
the verdict that an audit stream is not worth ingesting at all for a honeypot
fleet, which is a real possibility given that the stream is the operator's own
authorized activity rather than an attacker's. If a future reader takes the bait
anyway, the contract above is the floor and not the ceiling, and the open
questions are gates rather than loose ends.
