# #3189 — CVE-2026-63077 JetBrains TeamCity deserialization RCE: what APIARY actually detects

Scope: the shipped `teamcity-agent-deserialization` payload class in the
`http-honeypot` sensor, read from `origin/main` at `43061f27`. **No new
detector was written for this document and none is proposed here** — the
classifier already exists and is on main. This records what it is, and says
plainly where it is narrower than the issue asked for.

The issue body's STATUS block claims "Implementation PRs are OPEN and awaiting
merge." **That is stale.** The work shipped in #3444 (`5545607a`, "feat(http-honeypot):
classify CVE-2026-63077 TeamCity agent deserialization") and the classifier
survived #3464's move of the cases out of `main.go` into one file per CVE
(`2b64e57a`). The dispatch line in `classify.go` is not behind a PR.

## Finding

Everything in this table is transcribed from the issue's own research record
(`gh issue view 3189`, comment 2026-09-17, "Primary-source verification
matrix"), which cites the sources in `## References`. **Nothing here was
re-derived from a vendor page for this document, and no value is supplied from
model memory** — see `## Veracity note` for what that costs.

| Field | Value | Verdict in the issue's matrix |
|---|---|---|
| CVE | CVE-2026-63077 | CONFIRMED — JetBrains CNA record, `state: PUBLISHED`, publication date 2026-07-27 |
| Product | JetBrains TeamCity On-Premises | CONFIRMED; the follow-up advisory says TeamCity Cloud mitigations are already applied |
| Class | CWE-502, deserialization of untrusted data | CONFIRMED — named by both the CNA record and CISA KEV |
| CVSS | **3.1**, 9.8, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | CONFIRMED as the *published* score. Not independently calculated, and not a CVSS 4.0 score |
| In CISA KEV | Yes, `dateAdded` 2026-08-05 | CONFIRMED — the saved KEV feed entry for this exact CVE |
| Fixed builds | TeamCity 2025.11.7 and 2026.1.3 | CONFIRMED from the original advisory |
| Precondition | None reachable from a decoy. The CNA record names the mechanism as deserialization reached *through the agent polling protocol*, so the vector's `PR:N` is a property of the protocol, not of a credential guess. The request goes to whatever endpoint the application's own dispatch resolves | CONFIRMED for the mechanism; the "unauthenticated" half is what makes this sensor's approach possible at all |
| Consequence as described by the vendor | Command execution with the TeamCity server process's own privileges; successful exploitation could expose TeamCity data, configurations and stored credentials, **depending on those privileges** | CONFIRMED, conditional. The advisory does not establish which credentials any particular server holds |

**Excluded from the table above, deliberately.** The original issue also
claimed that attackers can pull server backups containing AWS IAM keys and
then retrieve S3 files, that Cadence is in this CVE's product scope, and that
JetBrains advises treating all execution inputs/outputs as untrusted. The
issue's own research marked all three **UNVERIFIED** — no supporting statement
was found in the CNA record, the KEV feed, or either JetBrains advisory, and
Cadence is not identified. They are not restated here as fact, and **nothing
in the shipped detector depends on any of them.** The "treat inputs/outputs
as untrusted" phrasing specifically was not located; the follow-up advisory's
actual recommendations (trusted-network access, least OS privilege, separating
servers from agents) are not a substitute for a quotation that was not found.

## Why this matters for APIARY

The `PR:N` in the vector is the whole reason a decoy can be useful here at all.
A CVE that needs a valid credential is a CVE a passive decoy mostly cannot
name: the attempt and the ordinary traffic look the same. An unauthenticated
deserialization sink does not have that problem — the request that probes for
it is the request that exploits it, and its *bytes* are the evidence, which is
exactly what an HTTP sensor records.

Three consequences, all of which the shipped code is built around:

1. **The protocol shape is the product half, not a path.** There is no bait
   path to serve and no endpoint to point at. The signal is the shape of what
   an agent poll carries, so this is a byte classifier on the existing
   `http-honeypot` sensor and not a new listener, route or decoy.
2. **The container and the product must be seen together.** Every TeamCity
   server on earth has agents polling it, and a serialized object on an HTTP
   port is routinely somebody else's finding — this sensor serves its own
   WordPress XML-RPC bait and buckets `xmlrpc` paths as `wordpress`
   (`main.go:707`), so containers arrive on that transport constantly and are
   not TeamCity's. Either half alone is fleet background noise; the classifier
   that fires on it is worse than no classifier.
3. **A decoy must not be the thing that gets deserialized.** See
   `## Known gaps` — the class reports an *attempt*, and the design refuses to
   grow past that.

## Coverage as implemented

Read from the source, not from the issue's proposal.

### The entry point and its position in the dispatch

`arcane/home/honeypot-http/http-honeypot/classify.go:78`:

```go
{"teamcity-agent-deserialization", teamcityAgentDeserialization},
```

It is **second in the dispatch**, behind `roundcube-virtuser-query-sqli`
(`classify.go:73`) and **ahead of the generic `serialized-object` case at
`classify.go:169`**. That position is the whole reason the class exists rather
than being redundant: `serializedObject` (`classify_generic.go:197`) matches
`rO0AB` at the *start* of a body or the raw header *anywhere* in one, and would
otherwise claim the raw forms while leaving the base64-in-XML and
container-in-query forms unlabelled. Placing the case below the generic one
would make it dead code.

The order is not a convention here, it is an asserted invariant:
`wantPayloadClassOrder` in `classify_order_3464_test.go:422` pins this class at
position 2, and `TestPayloadClassOrderIsPinned` (`classify_order_3464_test.go:461`)
compares the dispatch against that list position by position.

### The predicate

`classify_teamcity.go:49` — a conjunction, and both halves are required:

```go
func teamcityAgentDeserialization(c classifyInput) bool {
	if !javaSerializationContainer(c) {
		return false
	}
	return teamcityAgentProtocol(c.Q, c.B)
}
```

**Half one — the serialization container** (`classify_teamcity.go:135`,
`javaSerializationContainer`). Three marks, in the order they are worth
matching:

| Mark | Where matched | Anchor |
|---|---|---|
| Raw Java stream header `AC ED 00 05` (`classify_teamcity.go:66`) | `strings.Contains` over **raw** `Query`/`Body` | Containment, not prefix — the same four bytes arrive in a form field, an XML element, or a query string |
| Base64 form `rO0AB` (`classify_teamcity.go:77`) | `base64TokenHasPrefix` (`classify_teamcity.go:165`), **case-sensitive** | Anchored to the start of a base64 token: a match is only accepted at index 0 or where the preceding byte is not in `isBase64Char` (`classify_teamcity.go:185`). Padding `=` is excluded from that set on purpose, because `data=rO0AB…` must match |
| Gadget class name (`javaGadgetClasses`, `classify_teamcity.go:97`) | `containsAny` over the **lowered** `Q`/`B` | commons-collections 3/4 functors, `com.sun.rowset.jdbcrowsetimpl`, `beancomparator`, `annotationinvocationhandler`, `TemplatesImpl`, the xbean JNDI converter, `com.ysoserial` |

The raw-vs-lowered split is load-bearing, not tidiness, and the file says so at
`classify_teamcity.go:32-40`: `strings.ToLower` replaces every non-UTF-8 byte
with U+FFFD, so the lowered copy of a raw `AC ED 00 05` header is replacement
characters and the signature is gone. The container is therefore read from the
raw strings and the ASCII product names from the lowered copies the caller has
already built, so the hot path allocates nothing.

**Half two — TeamCity's agent-protocol shape** (`classify_teamcity.go:245`,
`teamcityAgentProtocol`). Two ways in, cheap one first:

- A product-qualified marker as a substring, against
  `teamcityProtocolMarkers` (`classify_teamcity.go:222`):
  `teamcity.server.message`, `org.jetbrains.teamcity`, `jetbrains.buildserver`,
  `buildserver.action`. These are package-qualified internals, so a substring
  match is right. The `teamcity.*` namespace at large is **deliberately
  excluded** — an agent's property bag is full of `teamcity.agent.jvm.os.name`
  and neighbours, and that bag is what a normal poll looks like
  (`classify_teamcity.go:218-221`).
- A call name as a **whole value** from `teamcityAgentCallNames`
  (`classify_teamcity.go:198`): the five `xmlrpc/*` registration calls, the
  generic `xmlrpc/remote` envelope, and `agentUnload`/`agentUnload2`. Whole
  value rather than substring because the transport is not TeamCity's alone —
  `xmlrpc/remote` is an XML-RPC convention. The name is *extracted* rather than
  substring-matched, from `methodName`/`method` parameters
  (`classify_teamcity.go:259-268`) and from the XML-RPC `<methodName>` element
  (`xmlrpcMethodName`, `classify_teamcity.go:295`).

`url.ParseQuery` is used to split parameters, and `xmlrpcMethodName` is two
index searches. **Neither is told what to do with what it found, and no decoder
is imported anywhere on this path.**

### What it deliberately does not match, and why

Each of these is a pinned negative, not an oversight:

| Not matched | Why | Pin |
|---|---|---|
| An ordinary agent registration poll — same call name, same product, ordinary parameters, no container | Every TeamCity server has agents doing this forever. Flagging it puts the class on the fleet's background traffic | `teamcity_deser_test.go:118` |
| The product's own `teamcity.*` parameters with no magic bytes | The property bag is not a container | `teamcity_deser_test.go:126` |
| Plain text naming the product, in body or in query | A CI log line or an error page. A mention is not an aim | `teamcity_deser_test.go:134`, `teamcity_deser_test.go:140` |
| **WordPress XML-RPC carrying the identical container** | The one that matters in production: same bytes, different product, on a transport this sensor serves itself. The attribution would be worse than having no class | `teamcity_deser_test.go:159` |
| A gadget class name alone | A string in a request is a string. The class does not guess that somebody meant to hand it to a deserializer elsewhere | `teamcity_deser_test.go:194` |
| A neighbouring call name, `xmlrpc/allowRegistrationAndPing` | TeamCity is not the only product with an XML-RPC agent channel, which is why the gate is whole-value | `teamcity_deser_test.go:202` |

The WordPress negative is the boundary the ordering decision turns on, and it
is pinned from both sides: with no product half the same bytes keep the generic
`serialized-object` label (`teamcity_deser_test.go:169`, `:177`, `:185`).

### What the class reaches

`teamcity_deser_test.go:297` — `TestTeamcityDeserializationReachesTheEvent` —
drives `ServeHTTP` end to end and asserts four things about the emitted event:

- `payload_class` is `teamcity-agent-deserialization` on the event;
- `credential_status` is `absent` and `auth_outcome` is `unknown` — the class
  does not require a login to have happened first, because the CVE does not;
- the container signature (`rO0AB`) survives the #3213 redaction, or an analyst
  could not read the payload out of the event that was classified;
- **no persona**: the decoy still answers its generic 404 and the path category
  stays the generic `wordpress`. This assertion is a standing guard against
  somebody later growing the CVE reading into a TeamCity persona.

`TestTeamcityDeserializationMatchesBytesWithoutDecoding`
(`teamcity_deser_test.go:234`) pins the no-decoder rule with fixtures a
decoder-based implementation could not pass: a container whose tail is not
valid base64 still classifies, a header truncated to the four raw bytes still
classifies, and valid base64 decoding to harmless text does not.

**Field names.** The event field is the real one: `payload_class` on the
`event` struct (`main.go:125`), read by the dashboard at
`arcane/home/honeypot-dashboard/backend-service/src/events.rs:206`. The sensor
log is shipped by Filebeat into `honeypot-v2-*` with parsed fields nested under
`honeypot.*` (`arcane/home/honeypot-elk/analysis/filebeat.yml:84,617`), so the
queryable path is `honeypot.payload_class`. **Elasticsearch field names beyond
that — index templates, any `keyword`/`text` mapping, Kibana saved-object or
data-view naming — are not mapped here and are to be mapped to the real schema
before any dashboard or alert work is built on this class.**

### Tests that pin it

- `arcane/home/honeypot-http/http-honeypot/teamcity_deser_test.go` — 3 test
  functions, 18 subtests: 5 positive cases and **10** negatives in
  `TestTeamcityAgentDeserialization` (15), 3 no-decode cases in
  `TestTeamcityDeserializationMatchesBytesWithoutDecoding`, and the end-to-end
  event assertion in `TestTeamcityDeserializationReachesTheEvent`. The whole
  `http-honeypot` package passes on this branch.

  The count is 10 negatives rather than the 7 quoted in #3444's commit message
  because #3464's rebase added three: WordPress XML-RPC with a raw stream, a
  bare container with no product shape, and a base64 container at offset zero.
  All three assert `serialized-object` — they are the "keeps the generic class"
  side of the ordering boundary, and they are why the generic case is provably
  untouched outside the gate.
- `arcane/home/honeypot-http/http-honeypot/classify_order_3464_test.go` —
  `TestPayloadClassOrderIsPinned` (`:461`) pins the position of this class in
  the dispatch; `TestClassifyPayloadCorpusCoversEveryDispatchClass` (`:519`)
  fails if a class is added to the dispatch and left without a corpus row;
  `classifyOrderCorpus` (`:88`) carries one representative TeamCity payload.
- `arcane/home/honeypot-http/http-honeypot/payload_test.go` — the pinned
  30-day fleet corpus. **It contains no TeamCity entry**, which is itself the
  measurement: no event of this shape has been seen on the fleet. No
  false-positive rate against live traffic is claimed anywhere.

`tests/docs/` has **no** test for this class. The docs gate did not change
because of this document.

## Known gaps

Stated plainly, because the issue asked for more than shipped and the
difference is the deliverable.

- **The class labels an attempt, not an exploitation.** It reports that a
  request carried the marks of a deserialization attempt on a named product's
  protocol. It does not establish that the object graph was well-formed, that a
  sink existed, or that anything executed (`classify_teamcity.go:42-48`). Only
  that claim is available from the bytes a sensor receives.
- **The whole AWS/S3/backup post-exploitation chain is absent, and was
  verified absent from the primary sources before it was left out.** No
  canary AWS credential is issued, provisioned, or monitored; no S3 access is
  detected; no backup is served. The issue's own research also records that the
  dashboard's canary token allowlist does not include AWS keys. This is a
  deliberate omission, not an oversight: the chain underneath it is UNVERIFIED.
- **No Cadence coverage**, and no basis in the cited sources for any.
- **No TeamCity persona, no bait endpoint, no path category, no new route or
  port.** The decoy answers its generic 404. A product persona would need a
  cited benign basis; a guessed path is not one.
- **Only the agent polling protocol is recognised.** The `teamcityAgentCallNames`
  and `teamcityProtocolMarkers` lists are the recognition surface. A
  deserialization path through some other TeamCity entry point, or a
  protocol-qualified name not on those two lists, is **not** detected by this
  class and will fall through to `serialized-object` or stay unlabelled.
- **Container-in-query works, percent-encoded containers do not.** The
  query channel is percent-decoded once before the lowered copy is built
  (`classify.go:221-225`); a body that is itself percent-encoded is not
  decoded, so a double-encoded body is a known miss.
- **The 64 KiB body read cap** (`bodyReadCap`, `credentials.go:201`) bounds the
  container half. A payload whose container sits past the cap is a miss.
- **No live validation of any kind.** Nothing was deployed, no traffic was
  sent anywhere, no exploit was reproduced, and the fleet's `honeypot-v2-*`
  indices were not reachable from here. **No event count, detection rate, or
  false-positive rate is claimable**, and the absence of one in the pinned
  corpus is consistent with either "no campaign" or "no coverage yet".
- **The #3213 redaction contract is asserted, not audited.** The test proves
  the container signature survives redaction for one fixture; it does not
  establish that every shape of this payload survives it.

## Severity

**Of the CVE: 9.8 published (CVSS 3.1), in CISA KEV since 2026-08-05.** That is
the vendor's/CISA's assessment as recorded in the issue's research matrix, not
a score calculated here. This repo has been burned by a severity correction
before (#3180, 2026-09-17), so it is stated with its source and not upgraded,
downgraded, or restated as "critical" on our own authority.

**Of the coverage:** the class is a narrow, low-false-positive, high-precision
detector for a narrow shape — an unauthenticated deserialization attempt whose
bytes are visible on an HTTP port. It contributes one well-attributed
`payload_class` to an existing sensor and no new attack surface. It is not
exploit confirmation, not post-exploitation detection, and not a KEV-driven
alert. It should be read as "this shape was aimed at us and recorded," which
is a real but partial answer to the issue.

## References

All from the issue body's own source list. No URL was added from memory, and
none is cited for something it does not establish.

- JetBrains CNA record (CVE-2026-63077, `state: PUBLISHED`, CVSS 3.1 vector,
  CWE-502, publication date) — https://cveawg.mitre.org/api/cve/CVE-2026-63077
- CISA KEV feed (`dateAdded: 2026-08-05`) —
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- CISA KEV catalog entry referenced by the CNA record —
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-63077
- JetBrains original advisory (fixed builds 2025.11.7 and 2026.1.3; command
  execution with the server process's privileges) —
  https://blog.jetbrains.com/teamcity/2026/07/cve-2026-63077/
- JetBrains follow-up advisory (later exploitation reports; trusted-network
  access, least OS privilege, separating servers from agents) —
  https://blog.jetbrains.com/teamcity/2026/08/cve-2026-63077-update/

**Excluded:** https://www.jetbrains.com/privacy-security/issues-fixed/2026-q3/
returned HTTP 404 when the issue's research saved it. It is listed here so a
future reader does not re-derive it as a citation, and it is **not** evidence
for anything in this document.

## Veracity note

**Confirmed against primary sources, on 2026-09-17 by the issue's research
run, and transcribed here rather than re-verified:** the CVE identifier, its
PUBLISHED state, the CVSS 3.1 score and vector, CWE-502, TeamCity On-Premises
as the affected product, the fixed builds, the KEV `dateAdded` date, the
mechanism (deserialization reached through the agent polling protocol), and the
vendor's description of the consequence. These are the vendor's and CISA's
characterisations of their own records. No exploit was reproduced.

**Vendor-reported, and treated as such:** the command-execution and
credential-exposure consequences are the advisory's description of impact. The
advisory ties credential exposure to the server process's privileges and does
not establish which credentials any particular deployment holds.

**Unverified, and absent from this document as fact:** the backup/AWS IAM
key/S3 chain, the Cadence product connection, the attributed "treat all
execution inputs/outputs as untrusted" JetBrains advice, and the premise that
an actually unpatched runtime is required to obtain useful detection. The
first three were marked UNVERIFIED in the issue's own matrix; the fourth is a
design choice, not a finding. **No conclusion here rests on any of them.**

**Read from source, in this document, and therefore the strongest claims here:**
everything in `## Coverage as implemented`. Every behaviour stated there is
anchored to a `file:line` in the classifier, its test file, or the pinned
dispatch order, and the cited tests were run on this branch.

**Not validated at all:** live detection rate, false-positive rate against
fleet traffic, and whether a real campaign produces this exact shape. The
pinned corpus has no entry of this class, so there is no measurement to quote —
and its absence is not evidence of absence. The Elasticsearch/Kibana field
mapping beyond `honeypot.payload_class` is likewise unmapped, and is flagged
as such rather than guessed.
