# Research: CVE-2026-20131 / 20079 / 20316 — the Interlock claims and what APIARY can honestly observe

Documentation-only deliverable for [#3180](https://github.com/Xore/APIARY/issues/3180).
No detector, classifier, sensor, or signature was added. The three CVEs are real;
the "one Interlock campaign, three critical flaws, since January" sentence the
issue was opened with is not, and the correction is the substance of this note.

Written 2026-09-29 against `origin/main` at `43061f27`. The vendor facts are
taken from the issue's own corrected claim-verification matrix (posted
2026-09-17, repository snapshot `00593d1d693cc7fe792beb7d24724dca5f55b2b8`).
The fleet facts are derived by reading the tree. Nothing was probed, built,
executed, deployed, or fetched live; no credential was tested; no exploit was
run.

## Finding

Three real vulnerabilities in Cisco Secure Firewall Management Center (FMC) web
management. Two are CVSS 10.0 Critical. **One is CVSS 5.3 Medium with a Cisco SIR
High rating** — the issue's original table called all three Critical, and that is
wrong.

| CVE | Severity | Exploited? | Interlock / January 26 attribution | Precondition |
|---|---|---|---|---|
| CVE-2026-20131 | **CVSS v3.1 10.0 Critical** (`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`) | Yes. Cisco PSIRT aware of attempted exploitation in March 2026; CISA KEV addition 2026-03-19 | **Supported, and only here.** Amazon's research report attributes the artifacts to Interlock; eSentire and Help Net Security corroborate the published attribution. Exploitation from **January 26, 2026** is given for this CVE | Unauthenticated. Insecure deserialization of a user-supplied Java byte stream in the web-based management interface → remote code execution as root |
| CVE-2026-20079 | **CVSS v3.1 10.0 Critical** (same vector as 20131) | Yes. Cisco PSIRT aware of active exploitation in **August 2026**; KEV addition 2026-09-09 | **Not supported.** The vendor advisories do not name Interlock. KEV records ransomware use as `Unknown`. Do not transfer 20131's attribution across the row | Crafted HTTP requests against an improper system process created at boot, executing commands for OS root access. The issue's "authentication bypass" framing is an incomplete description |
| CVE-2026-20316 | **CVSS v3.1 5.3 Medium** (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`), **Cisco SIR High** — deliberately not Critical, because it combines with other FMC issues for privilege elevation | Yes. Cisco PSIRT aware of active exploitation in **July 2026**; KEV addition 2026-07-29 | **Not supported.** KEV records ransomware use as `Known`, which identifies no group | Hard-coded/static credentials for a **low-privileged** account, granting access to sensitive data. **Not** a publicly documented default administrator password, and no credential values are reproduced here |

Three further corrections from the same matrix, because each one changes what a
detector would look for:

- **Affected product is Secure FMC software**, regardless of configuration, and
  for 20079 also SCC Firewall Management. FDM, ASA and FTD are not the affected
  product, and the similarly named SCC/former Defense Orchestrator is on the
  not-affected list. A Cisco ASA decoy is not FMC.
- **Dates mean different things.** First publication, vendor awareness of
  exploitation, and KEV addition are three separate facts. Cisco first published
  both 20131 and 20079 on 2026-03-04; 20316 on 2026-07-29. Awareness-of-
  exploitation is March (20131, attempted), August (20079), July (20316).
- **Cyware's September 7, 2026 briefing is UNVERIFIED** and is not cited as
  corroboration here. A candidate URL returned HTTP 404, which is not evidence
  that no such briefing exists.
- The eSentire page is dated **March 19, 2026** and reports that Amazon
  published on March 18. The issue conflates the two dates.

## Why this matters for APIARY

**There is no FMC in this fleet, and no sensor that presents one.** FMC appears
nowhere in the sensor tree, in any compose file, or in the portbridge and
firewall publications. The only Cisco-branded decoy is
`cisco-asa-honeypot` — ASA **WebVPN/IKE**, a data-plane persona built for
CVE-2018-0101 — and it is a different product. Conpot speaks ICS protocols
(S7, Modbus, BACnet, IPMI, ENEP, IEC 104, and friends) and publishes no
management console; Dionaea publishes no HTTP management listener and has no
demonstrated Java-deserialization handler. So there is no FMC exposure here to
patch, audit, or reduce, and this is a coverage question rather than a defence
gap.

What is already there is generic HTTP collection, and it is worth more than the
issue assumed:

- `http-honeypot` / `api-honeypot` classify a request body carrying Java
  serialization markers as `payload_class = "serialized-object"` — matched on
  the base64 `rO0AB` prefix or the raw `AC ED 00 05` magic, ordered
  first-match-wins so an earlier class can take precedence. It is deliberately
  **not** shared with a new class per language, so a Java-specific `java_marker`
  field carries the narrower observation instead (`"stream-magic"` for raw magic
  at offset 0, `"stream-magic-base64"` for the encoded form).
- Capture is described rather than implied: `body_capture_state`
  (`complete` / `truncated` / `unknown`), `body_captured_bytes`,
  `body_read_error`, `body_b64`, `body_sha256` with an explicit
  `body_sha256_scope`, and `body_declared_bytes`. A 40-byte body and a
  truncated 4 MB one are no longer the same record.
- Credentials and authentication are separated by #3213: `credential_status`
  ∈ {absent, present_unparsed, extracted, unknown}, `credential_present` as a
  nullable pointer, and `auth_outcome` ∈ {simulated, real, unknown} which is
  never derived from an HTTP status. A `200` on a canned login page is not an
  authentication.

The honest ceiling, then: **an FMC-shaped probe aimed at this fleet lands as
generic HTTP telemetry with a serialization marker on it.** That is real
evidence that bytes of that shape arrived. It is not evidence of CVE-2026-20131,
not evidence of a successful bypass, and not evidence of Interlock.

## Proposed detection

**The issue's four proposed detectors are unvalidated hypotheses, not
demonstrated coverage.** Nothing below has been tested against traffic. Two of
them cannot be built honestly on this surface at all, and saying so is more
useful than a query that returns confident nonsense.

| Issue's proposal | Feasibility here | What is missing |
|---|---|---|
| 1. Java serialization magic (`AC ED 00 05`) in POST bodies to `/webui/` or `/api/` | **Partly available already**, via the existing `payload_class` / `java_marker` classification. Scoping by method and path is possible as a hunt | The `/webui/` and `/api/` paths are the issue's hypothesis about where to look, not a vendor-published request shape; nothing here establishes them. Legitimate Java serialization, PHP sharing the same class, scanner tests, and a coincidental short `rO0AB` prefix are all false-positive sources. The path must be sourced from a primary Cisco document before it is a rule |
| 2. Successful login without credentials at 443/8443 | **Not reliably feasible.** A status code is not an authentication, and `auth_outcome` is `simulated` by design. 20079's described mechanism bypasses normal login entirely, so a login-shaped detector would not see it | Auth outcome, session correlation, principal/role, and a protected-resource decision. Treating "field absent" as "no credential" manufactures false bypass alerts |
| 3. Known/default FMC credentials | **Only generic credential-attempt collection exists.** 20316 is a hard-coded **low-privileged** account, which is not a default administrator password. This fleet's bait indicators are its own fictional `nexusai-*` values, and a regression test pins that no Cisco vendor credential string appears in either sensor's indicator set | A vendor-approved credential indicator reference with product/account scope, plus restricted handling. No credential list is verified or supplied, and none should be collected from exploit material or tested against a system |
| 4. Post-exploitation: policy changes, new admins, certificate imports | **Not supported as actual changes.** A decoy can record the *request*; only a trusted audit stream from a real appliance can establish the *outcome* | Appliance audit/syslog ingestion, actor/role/session, operation, object, outcome, and before/after state. That is a different subsystem and a separately authorized scope — see [`FMC-MANAGEMENT-AUDIT-CONTRACT.md`](../FMC-MANAGEMENT-AUDIT-CONTRACT.md) (#3215) |

The one hunt that is defensible today, using **real indexed field names** from
the tree rather than invented ones:

```
honeypot-v2-*   where honeypot.payload_class = "serialized-object"
               | where honeypot.java_marker   = "stream-magic"          # narrower, Java-only
  group by honeypot.sensor, honeypot.path, honeypot.method
```

Every field in that query is one this pipeline already writes
(`arcane/home/honeypot-elk/analysis/filebeat.yml`'s `honeypot-json` input
namespaces sensor JSON under `honeypot.*` into `honeypot-v2-*`;
`backend-service/src/events.rs` reads `honeypot.payload_class` off the
document). The result must be labelled **generic serialized content received**.
It must not be renamed "CVE-2026-20131 success" or "Interlock detected".
**No query was executed against a live index**, and mapping behaviour should be
checked before this is saved as a stored query.

For a sensor that does not emit `payload_class` at all — `cisco-asa-honeypot`
keeps bounded POST data in `honeypot.data` and has no serialization
classification — the field names to be mapped to the real schema are simply the
`honeypot.*` equivalents above, and until they exist no query should name them.

## Severity

**For the affected product: Critical for CVE-2026-20131 and CVE-2026-20079
(CVSS 10.0, in CISA KEV, exploited), Medium-plus-chain for CVE-2026-20316
(CVSS 5.3 with Cisco SIR High, in KEV, exploited as a low-privileged static
credential).** Two of the three are unauthenticated root-level issues on a
management plane, which is the worst place for them to be.

**For APIARY: informational, and no work is implied by this document.** This
fleet has no FMC, so there is no exposure to reduce. The realistic value of
these three CVEs to this project is (a) the reminder that the generic HTTP
sensors already capture serialization markers and describe their own capture
completeness, which is the coverage that matters, and (b) the product-identity
discipline FMC forced: the ASA decoy stays an ASA decoy, and #3214's
requirements for any *optional* inert FMC persona are recorded separately
([`3214-fmc-inert-persona.md`](3214-fmc-inert-persona.md)).

## References

All URLs are the ones named in the issue body or its corrected matrix. The
Cyware item is excluded — it is UNVERIFIED, and a 404 on a guessed slug is not
a source.

- Cisco Security Advisory, CVE-2026-20131 —
  <https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-rce-NKhnULJh>
- Cisco Security Advisory, CVE-2026-20079 —
  <https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-onprem-fmc-authbypass-5JPp45V2>
- Cisco Security Advisory, CVE-2026-20316 —
  <https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-static-cred-BET3Cjh>
- CVE records: <https://cveawg.mitre.org/api/cve/CVE-2026-20131>,
  <https://cveawg.mitre.org/api/cve/CVE-2026-20079>,
  <https://cveawg.mitre.org/api/cve/CVE-2026-20316>
- CISA KEV catalog —
  <https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json>
  (retrieved release `2026-09-16T18:47:50.6796Z`)
- Amazon Security / MadPot research report, Interlock targeting enterprise
  firewalls — <https://aws.amazon.com/blogs/security/amazon-threat-intelligence-teams-identify-interlock-ransomware-campaign-targeting-enterprise-firewalls/>
- eSentire advisory, "Cisco Vulnerability CVE-2026-20131 Exploited by Interlock"
  (page dated 2026-03-19) —
  <https://www.esentire.com/security-advisories/cisco-vulnerability-cve-2026-20131-exploited-by-interlock>
- Help Net Security, 2026-07-30, on CVE-2026-20316 —
  <https://www.helpnetsecurity.com/2026/07/30/cisco-fmc-cve-2026-20316-exploited/>
- This repo's own analysis, corrected 2026-09-17:
  <https://github.com/Xore/APIARY/issues/3180#issuecomment-5706550262>

## Veracity note

**Single-vendor for the vulnerabilities, independently attributed for exactly
one of them.** Cisco's own advisories and CNA records are the authority for what
each CVE is and how it is scored; CISA KEV is the authority for the exploit-in-
the-wild and due-date facts. Those are primary vendor sources, not independent
verification of exploitability.

**The Interlock attribution is one research report plus two write-ups of it.**
Amazon's MadPot report is first-party research attributing recovered artifacts
to Interlock on convergent technical and operational indicators. eSentire and
Help Net Security corroborate the *published attribution*; neither is an
independent reproduction. Cisco confirms attempted exploitation of 20131 without
naming an actor. No exploit was reproduced here, and none should be.

**Not confirmed, and not to be inferred:**

- **Interlock exploited CVE-2026-20079 or CVE-2026-20316.** No retrieved vendor
  advisory names Interlock for either. KEV's `Known` ransomware-use value for
  20316 identifies no group.
- **Exploitation of 20079 or 20316 in January 2026.** Cisco's July and August
  awareness dates neither establish nor rule out earlier exploitation. The
  January 26, 2026 date belongs to 20131 alone.
- **Any request shape, payload, or path for any of the three.** None of the
  cited sources publishes one. The issue's `/webui/`, `/api/`, 443 and 8443
  references are hypotheses about where to look.
- **A public default FMC administrator credential.** 20316 concerns a
  hard-coded low-privileged account. No credential value is asserted here and
  none was collected.
- **That a live hit on `serialized-object` is an attack on this fleet.** It is
  evidence of bytes of that shape. Nothing in the fleet establishes that they
  targeted FMC, exploited anything, or came from Interlock.
- **The Cyware daily briefing.** UNVERIFIED, and not cited as corroboration.

**Method limits.** This is a static review of the tracked tree plus the issue's
recorded research. No container was inspected, no index was queried, no
ruleset was read from a running host, no traffic was sent anywhere, and no
credential was tested. The fleet-side claims are statements about the tree at
`43061f27`, not about live exposure or about the deployed sensors' behaviour
under attack.
