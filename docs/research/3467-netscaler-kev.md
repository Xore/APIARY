# Research: CVE-2026-88771 / CVE-2026-88772 — Citrix NetScaler ADC/Gateway zero-day RCE pair — citrix-honeypot coverage (#3467)

**Verdict: this ships KEV-metadata-driven coverage, not exploit detection.**
That is the honest ceiling for this pair today, and the reasoning is in
§2. It is a complete answer to the issue, not a partial one — but it is a
narrower one than the issue's Signal A/B/C sketch, and §6 says which
parts were dropped and why.

Gathered and re-verified 2026-09-28 against primary sources, against
`origin/main` at `9bca6c81`.

## 1. Sources, and what each one actually says

| source | what it establishes | what it does **not** contain |
|---|---|---|
| CISA KEV feed, catalog `2026.09.27`, released 2026-09-27T21:30:35Z, 1728 entries | both CVEs present; `dateAdded` 2026-09-27; `dueDate` 2026-09-30; `forensicTriage` Yes; `knownRansomwareCampaignUse` Unknown | no CVSS, no request shape, no payload |
| Citrix **CTX697096** (Changelog: 2026-09-27 Initial Publication) | per-CVE preconditions, CVSS v4.0 vectors, CWE ids, fixed builds, and per-CVE ns.conf regexes for checking a customer's *own* config | no attack traffic, no exploit shape, no IoC bytes |
| watchTowr Rapid Reaction, 2026-09-27 | discovery timeline; 88773–88778 "Not reported" exploited; where the IOCs actually live | no request shape either |

Reproduced from CTX697096, which is the vendor's own classification of its
own CVEs and therefore the authority here:

| CVE | CVSS v4.0 | CWE | Precondition (verbatim) |
|---|---|---|---|
| CVE-2026-88771 | 9.5 `AV:N/AC:L/AT:P/PR:N/UI:N/…` | CWE-20 | "All NetScaler ADC and NetScaler Gateway deployments (Default configuration / No additional feature required)" |
| CVE-2026-88772 | 9.5 `AV:N/AC:H/AT:N/PR:N/UI:N/…` | CWE-119 | "DTLS configuration enabled on NetScaler ADC or NetScaler Gateway (Note: Enabled by default on VPN vServer)" |

Fixed builds: 14.1-73.37, 13.1-64.23, 13.1-37.279 (FIPS/NDcPP).

Two discrepancies worth recording rather than silently resolving:

- **KEV lists `cwes: ["CWE-119"]` for both entries**, which contradicts
  CTX697096's CWE-20 for 88771 and looks like the catalog copying 88772's
  row. The code uses CTX697096's CWE and notes this in a comment.
- **88771 is CWE-20 (Improper Input Validation), not CWE-78 (OS Command
  Injection).** Citrix did not characterise it as command injection. The
  distinction is load-bearing for detection — see §3.

## 2. Why there is no payload signature to ship

Four things are true, and together they close off the obvious approach:

1. **No request shape is published.** Neither CTX697096 nor KEV nor
   watchTowr gives a path, method, header, parameter, body field or byte
   sequence for either CVE. CTX697096 is a precondition/upgrade table plus
   regexes for reading a customer's own `ns.conf`.
2. **88771 has no network-observable precondition to filter on.** Its
   precondition is *every* deployment. A decoy standing in for the product
   is affected by definition, so there is nothing to test.
3. **The published IOCs are not wire patterns.** KEV and CTX697096 both
   point at an IOC scan. Per watchTowr it is "an IOC scan on the NetScaler
   Console Security Advisory page (version 14.1-73.36 or later, telemetry
   enabled)", or requestable from Citrix Support — appliance-console
   artifacts gated on a build this decoy does not run. A network decoy
   cannot match them even in principle.
4. **The vendor says the IoCs are incomplete.** Citrix's own caveat, quoted
   by watchTowr: the IOCs "do not cover every technique", so "a clean
   result is not proof." That argues against over-reading *any* single
   signal — including a classifier this change adds.

Inventing a magic string here would produce detection events an analyst
trusts and that correspond to nothing. That is a worse outcome than no
coverage, so the honest deliverable is metadata-driven.

## 3. What shipped

`arcane/home/honeypot-citrix-honeypot/citrix-honeypot/cve_2026_88771.go`,
classified through the existing `log2` path with no new logging mechanism
and no new fields on the shared `event` struct.

**Metadata half — `netscaler_kev_exposure`, once per process start.** One
event per CVE carrying the verified metadata above, plus
`decoy_exercises_precondition`. The CVE id goes in `path` so
`path: "CVE-2026-88771"` is a working query. The 88772 row records its
gap as data (`precondition_gap=…`), not as a comment nobody triages on.
Emitted once next to `listening`, not per request: this is deployment
metadata, and repeating it per request would inflate the stream for
nothing.

**Classifier half — `netscaler_cmd_metachar_shape_inferred`.** An
inference, and labelled as one in the event name itself:

- **Documented:** the primitive. CTX697096 — "an unauthenticated attacker
  to execute arbitrary commands"; KEV agrees.
- **Inferred:** that the unvalidated input lands in the path, query or
  body. No source says where it lands; it could equally be a header, a
  cookie or a typed field.

Two tiers, because the cheap version of this classifier is a lie detector
in the other direction:

- *high-conviction* (fire alone): `` ` `` `$(` `${` LF CR — no legitimate
  client emits these into a decoded request target.
- *low-conviction* (need two **distinct**): `&&` `||` `;` `|` `>` `<` `&` —
  each has a real benign use. `&` is the query separator; `;` is the
  Jetty/Tomcat matrix-parameter form. A bare `/vpn/;id` deliberately does
  **not** classify: it is indistinguishable from `/store;jsessionid=…` by
  shape alone. That is a real miss, stated in a comment rather than
  discovered later.

The scan is left-to-right with longest-match-first, which is load-bearing:
an earlier draft used per-token `strings.Contains`, which made `a=1&&b=2`
match both `&` and `&&` as two distinct tokens and fired on the exact
sloppy-encoder artifact the low tier exists to tolerate. Mutant-tested
below; `TestShellShapeTokenScanIsNonOverlapping` pins it.

`queryForShape` unescapes `r.URL.RawQuery`, because `RawQuery` is the raw
wire form (`%60id%60` stays encoded) while `r.URL.Path` is decoded by
`net/http` before the handler runs. The POST body is deliberately **not**
decoded — inventing a form parser would mean guessing the attacker's
content type, and a body carrying the literal byte is caught either way.
Percent-encoded bodies are a known miss.

**Naming.** The event is named for the observable, not the CVE, and keeps
`inferred` in its name. `authSurfaceEvent`'s comment already records why:
a CVE-numbered event name produces "a classifier that looks like real
detection coverage in the dashboard while never having been checked
against a real request", and this package already declined to add a
`cve_2026_19490` event for exactly that reason. The CVE association rides
on `netscaler_kev_exposure` and this file instead.

## 4. Tests, and proof they can fail

`cve_2026_88771_test.go`. Every classifier has both a CAN-fire and a
does-not-fire test; the benign corpus is traffic this decoy actually
serves (SAML `wctx`/`SAMLRequest` base64, JWT bearer, `a=1&b=2`,
`/store;jsessionid=`, the `newbm.pl` capture path, a normal credential
POST), not strings chosen to be obviously clean.

Four mutants, each reverted after watching it go red:

| mutant | result |
|---|---|
| empty the high-conviction tier | 7 CAN-fire cases fail |
| revert to per-token `Contains` | 5 benign cases fail (`;jsessionid`, `a=1&b=2`, `a=1&&b=2`, …) |
| move the classifier after the early-returning auth block | `…FiresOnAnAuthSurfacePath` fails |
| bolt a fabricated `payload=NS-ICCV-88771-EXEC-V1` into the KEV metadata | `…ClaimsNoPayloadSignature` fails on both CVEs |

That last one is the important one. It is a standing guard against the
exact failure this change is written to avoid, and its comment says to
delete it deliberately, in the commit that cites a real source.

## 5. What was not verified

- **No live detection rate, and none is claimable.** Nothing was deployed;
  the change is repo-only. An Arcane build + redeploy is needed before any
  new event kind can appear in ES, and the first real hit must be verified
  on a document indexed *after* that deploy.
- **The Citrix "Indicators of Compromise" blog section could not be read** —
  `community.citrix.com` returned HTTP 403 to every attempt, via fetch and
  via a browser-UA curl. Its IoC list is therefore unverified. The
  conclusion in §2 rests on watchTowr's description of where those IOCs
  live (console-side, build-gated), not on having read the list. If that
  section turns out to publish wire-level indicators, §2 needs revisiting
  and this becomes a payload-signature change.
- **No live Suricata ruleset check** (the 2977 doc's `grep -ci citrix`
  audit). The fleet's ET Open rules were not re-counted for this change, so
  this doc does not claim anything about rule coverage.
- **No traffic was sent anywhere.** All fixtures are inert strings in unit
  tests. No exploitation, no docker, no Elasticsearch, no model load.
- **The false-positive path is reasoned about, not measured.** A benign
  query that percent-encodes shell punctuation (`q=a%20%3E%20b%20%3C%20c`)
  decodes into two low-conviction tokens and will classify. Acceptable
  because a decoy attracts no organic search box, the event says
  `inferred`, and the alternative — missing every encoded payload — is the
  worse error. Unverified against real traffic.
- **13.1-64.24 is not asserted** as vendor guidance. watchTowr documents
  it for appliances where `show ns variable` returns anything (reboot
  loop); CTX697096 does not mention it.

## 6. Out of scope, deliberately

- **CVE-2026-88773** (HTTP request smuggling, CWE-444, 9.3, "HTTP
  Configuration enabled") is a real request-shape CVE and the
  contradictory-framing classifier the issue sketches would match it. Not
  reported exploited (watchTowr's table), outside the "88771 + 88772"
  scope of this change, and `http-honeypot` already has Content-Length
  handling to sit alongside. Belongs in the per-CVE file work (#3464).
- **CVE-2026-88774 through 88778.** Configuration-dependent, not reported
  exploited, and 88778 is fixed by enabling Enhanced ISN Generation rather
  than by upgrade alone.
- **CVE-2026-88772 needs a UDP/DTLS listener** before it is detectable at
  all (§2, and the `precondition_gap` field). A new exposed transport is a
  deception-design change with its own review — the same call #3032 (a)
  recorded for the AAA/SAML surface. Its own issue.
- **A "probe with no preceding session-establishment request" classifier**
  (issue Signal A bullet 1) needs per-source connection state, which no
  classifier in this package holds today.
- **Fingerprint divergence** (issue Signal C) is already largely covered:
  `ja3.go`/`ja4.go` put `x-ja3`/`x-ja4` on every event, and
  `canonical.rs` promotes them to a fingerprint. Nothing to add.

## 7. Bottom line

The right product for this pair is **KEV-metadata-driven coverage**: the
sensor declares which KEV entries it impersonates, with the preconditions
and the fixed builds, and adds one clearly-labelled inference for the
documented command-execution primitive. The exploit payloads are not
public, and **this ships no fabricated IoC** — every pattern is either
transcribed from CTX697096/KEV or marked `inferred` in the code comment,
the event name and the test name.

CVE-2026-88772 has no classifier at all, because its DTLS precondition is
structurally unobservable on a TCP-only decoy, and that gap is recorded
as queryable data rather than papered over with a guess.
