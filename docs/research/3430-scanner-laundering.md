# #3430 — scanner-laundering: the umbrella, and what the layers actually cover

Scope: this is the index for `#3430` and the work that came out of it — the two
implementation issues (`#3443`, `#3447`) and the one adjacent bug filed from the
same work (`#3446`, dead-drop sanitisation, which is *not* coverage for this
technique). It records which layers exist, which are proposals, and which are
unmeasurable on this surface. It deliberately does **not** re-derive layer C —
that is
[`3447-scanner-laundering-layer-c.md`](3447-scanner-laundering-layer-c.md), and
the design reasoning, bounds, mutation sweep and rollout notes live there. Read
that for how; read this for how much of the issue is actually covered.

Re-verified 2026-09-29 against `origin/main` at `43061f27`. Code claims carry
`file:line`. Every count below was re-run while writing this, not copied.

## Finding

`#3430` describes agent-driven scanner-laundering: a constrained agent that
routes around a GET-only limitation by abusing public web services as
relays, double-encodes to slip a method/path filter, and exfiltrates results
back through a URL. The umbrella answer is **partial, and the part that is
built is the part that was cheap**:

| technique | covered? | by what |
|---|---|---|
| double-encoding a method/path filter | **yes, twice** | `odata-double-encode-probe` (query/body, in-request) and `odata-path-encoded-bypass` (path, two-request pair) |
| relay abuse | **no detector; only a design constraint** | the correlation key is deliberately not the source address (`laundering.go:944-959`); the two classes key on request bytes, which a relay does not change |
| URL exfil | **no** | nothing in the dispatch names a self-submitting or outbound-carrying form |

There is no capture behind any of this. `#3430` is a research note citing a
public third-party investigation; the positives in the test suite follow
*published shapes*, not observed fleet traffic
(`odata_double_encode_test.go:9-12`). That constraint is load-bearing for every
coverage number in this document and is restated in *Veracity note*.

## Why this matters for APIARY

Three things, in descending order of how much they are actually worth.

1. **A relay is not a defence, and the code now says so in the one place it
   mattered.** A per-IP rule sees one request from a public scanner and stops
   — that is `#3430`'s own technique-2 observation, and it is why the stateful
   layer's key is a header-set hash (`laundering.go:944-959`, header list at
   `laundering.go:975`) with `X-Forwarded-For` excluded on purpose so the key
   cannot be partitioned by forging it. This is defence-in-depth on a decoy,
   not a fix for anything.
2. **Two laundering classes now exist and they are easy to conflate.** Both
   concern double-encoding, both mention OData, and they write into the same
   field. `TestLaunderingClassIsNotA3430Layer`
   (`scanner_laundering_3430_test.go:281-307`) asserts the two classes are
   unreachable from each other's inputs *in both directions*, precisely because
   the confusion is easy.
3. **The cost side is real and is the side that bites first.** Both classes
   gained a gate only after an ungated version was measured claiming real
   traffic. A class that fires on ordinary traffic is worse than no class
   (`classify.go:209-210`).

None of this remediates a vulnerability. There is no CVE here and none is
claimed.

## Layers

`#3430`'s layer letters are used **inconsistently across this repo**, which is
worth recording before anything else, because an index document that silently
picks one reading will be wrong. Three different readings are live in the tree
today:

- `scanner_laundering_3430_test.go:94` calls the ungated OData-option rule
  "`#3430`'s layer-A signature".
- `classify_odata.go:3` calls the shipped query/body class "`#3430`'s class,
  layer C".
- `laundering.go:3` calls `#3447` "layer C of `#3430`'s scanner-laundering
  classification", and `3447-scanner-laundering-layer-c.md:164-168` explicitly
  disowns that: *"`#3430`'s layer C … and `#3447`'s 'layer C' are different
  things under the same name."*

For the rest of this document, **"layer" below means the capability, not the
letter**: *in-request double-encoding*, *path-borne double-encoding*,
*per-source history*, *cross-source window*. The letter mapping is left as the
repo has it, because changing it is a code-comment change outside this
document's remit.

### What exists

| capability | class / component | decided from | code |
|---|---|---|---|
| in-request double-encoding (query **or** body) | `odata-double-encode-probe` | one request: an OData system option whose key or value still holds a percent-escape after `url.ParseQuery`'s single decode | `classify_odata.go:43-75`; dispatch entry `classify.go:133` |
| path-borne double-encoding, two-request pair | `odata-path-encoded-bypass` | two requests from one client fingerprint against one collection path | `laundering.go:97`, `laundering.go:284-356`, `laundering.go:715-717` |
| relay resistance | *(not a class)* | the fingerprint and the in-request gate both key on bytes a relay cannot change | `laundering.go:944-978` |

Two properties of the stateful half that matter for the umbrella, because they
are what keep layer C from contaminating the other 33 dispatch classes:

- The escape half is read from the **decoded path** and the query is not
  (`laundering.go:703-717`). That separation *is* the layer.
- The label is written only into an empty `PayloadClass`
  (`laundering.go:620`), so `#3443`'s most-identifying-first ordering still
  decides who wins. Accordingly `odata-path-encoded-bypass` is deliberately
  **absent** from the pinned dispatch order at
  `classify_order_3464_test.go:420-455` — it is not a dispatch class, and its
  absence there is correct, not an oversight.

The pair is one-shot (`laundering.go:353`) and structurally cannot fire within a
single request (`laundering.go:332`, `laundering.go:342-344`), which is what
keeps the over-match trap `#3447` names impossible rather than merely avoided.
Bounded by `launderMaxEntries` 512, `launderPerFingerprint` 8, `launderTTL`
10 min (`laundering.go:108`, `:114`, `:122`), each overridable via
`LAUNDER_MAX_ENTRIES` / `LAUNDER_PER_FINGERPRINT` / `LAUNDER_TTL_SECONDS`, with
`HTTP_LAUNDERING=0` as the off switch (`main.go:1215-1224`).

### What is proposed only, or not implementable here

Both of these are pinned as negatives, not merely absent —
`TestScannerLaunderingLayersNotImplementable`
(`scanner_laundering_3430_test.go:200-269`) logs them at lines 246-249 and
asserts at 263-268 that the in-request class still works and that an OData
option on the root still does not qualify.

- **Per-source history** (monotonic growth in distinct attempted field names on
  one resource; a rejected request retried with a single byte-level mutation).
  **Unimplementable in-request**, and this is not a missing feature but the
  finding: it is defined across requests from one source, and
  `launderingState` is deliberately not keyed on the source address. The
  counter-example is in the code comment at
  `scanner_laundering_3430_test.go:211-216` — under relay laundering a
  per-source rule is blind by construction, and the parts of the signature
  that need history are exactly the parts laundering hides.
- **Cross-source header-fingerprint clustering over an event window** (many
  distinct paths sharing one fingerprint). **Unimplementable in this binary.**
  A bounded map keyed by `(fingerprint, resource)` is a pairing over one client
  and one collection, not a window over the fleet. This distinction is stated
  in three places and is the single most likely thing to be got wrong:
  `laundering.go:3` vs. `3447-…-layer-c.md:164-168`,
  `scanner_laundering_3430_test.go:258-262`, and
  `scanner_laundering_3430_test.go:271-275`.

  A window *is* available — Elasticsearch can window the event log after the
  fact (`laundering.go:43-44`) — but that is a backend query, not this binary,
  and no such query ships. It is listed under *Known gaps* as unbuilt, not
  as done.
- **Layer A's path shapes read by `classifyPayload`.** Not implementable
  without handing `classifyPayload` the path, which would be a real change to
  the package's purity invariant — the one asserted at
  `laundering_purity_test.go:24-50`, which calls it over the whole pinned
  corpus before and after the stateful detector has run and requires both
  answer sets to agree.

## Coverage as implemented

Measured against the **pinned 31-entry fixture**, re-run on `43061f27` with
`go test -run 'TestLayerCCorpusMeasurement|TestScannerLaundering3430CorpusMeasurement' -v`:

```
corpus entries:                          31
ungated OData system option claims:      0 []
ungated residual-escape claims:          3 [php-cgi argument injection double-encoded
                                            real: pagename double-encoded traversal
                                            real: pagename backslash variant]
gated class claims:                      0 []
published shapes: 14 caught, 0 missed []
layer C claims, 2 passes:                0 []        (laundering_test.go:964)
```

What each number is and is not:

- **The 0s are the false-positive control**, and the ungated 3 is why the gates
  exist. All three ungated claims are real traffic already correctly labelled
  by more specific classes; the gate's job is to leave them alone. The ungated
  count is *asserted* at `scanner_laundering_3430_test.go:173-176`, not logged,
  so a future corpus sample that changes it fails the test rather than letting
  the number drift.
- **14/14 is coverage of the published shapes**, i.e. a regression guard on
  what the issue described. It is not a detection rate, and there is no fleet
  data behind it.
- **0 for layer C over two passes is a purity/no-false-positive result**, not a
  claim that the pair never fires. The positive side is
  `TestLayerCCatchesThePublishedPathBorneBypass`, which does fire on the
  two-request shape.

Package state on this commit: `go test ./...` passes; 129 top-level tests, 422
including subtests (`go test -v` PASS counts). This is larger than the 97/154
`#3447` recorded, because `#3464` and `#3449` have since landed in the same
package.

### What "not measured" covers, explicitly

**No count in this document is measured against the fleet corpus.** The
`honeypot-v2-*` indices and the deployed sensor are not reachable from a PR —
`3447-scanner-laundering-layer-c.md:269-272` says so, and nothing found in this
pass contradicts it. The 31-entry fixture is a sample of the fleet's 30-day
window (`#1888`: 11,139 requests carrying a body or query, 583 distinct values
between them, `classify.go:180-182`), mirrored entry-for-entry from
`payload_test.go`. The fleet window is large and the distinct-value set is
small, and the sample is a sample. **Unmeasured stays labelled unmeasured.**

One throughput figure exists and is worth carrying with its caveat: the
creation-order eviction ring replaced an inline oldest-entry scan measured at
79 µs against a full 512-entry map versus 0.9 µs otherwise
(`laundering.go:192-197`). The numbers are recorded in the code comment; the
benchmark itself lives in PR `#3447`'s body and **is not in this repo**, so
this document does not treat it as independently reproducible.

## Known gaps

Ordered by how much they would change an operator's reading of the coverage.

1. **Zero fleet evidence for either class.** Not one of these labels has been
   observed on a real document, because the fleet has not been queried. First
   real hit must be verified on a document indexed *after* a redeploy.
2. **No alert surface.** Both classes land in the existing `payload_class`
   field — `main.go:125` (`json:"payload_class,omitempty"`), read by the
   backend at `events.rs:141` and rendered at `events.tsx:40`. **No new field,
   so no mapping or `openapi.json` change.** But no saved view, dashboard panel
   or detection rule ships for either class. Whether `payload_class` is the
   right place to look, and over what index pattern, is a question about a
   deployed index and is not answered here.
3. **The stateful layer's miss mode is a deliberate trade, not a bug.** A
   campaign that probes one collection and exploits another, or rotates its
   client stack between the two requests, is missed by the `(fingerprint,
   resource)` binding (`3447-…-layer-c.md:273-278`). The relay-laundering
   technique makes rotation *cheap*, so this is the gap most likely to matter
   against a real campaign.
4. **URL exfil is uncovered, and is a separate problem.** No class names a
   self-submitting or outbound-carrying form — that shape is pinned to
   unlabelled at `scanner_laundering_3430_test.go:90`. The adjacent thing that
   *did* ship is `#3446` (dead-drop sanitisation: attacker-controlled values
   echoed into dead-drop content), which is a hygiene fix in the echo path and
   **is not coverage for this technique**. Don't read it as one.
5. **The 10-minute TTL has no measured cadence behind it**
   (`laundering.go:116-122`; `3447-…-layer-c.md:279-281`). It is configurable
   for that reason.
6. **Saturation is observable but untested against load.** `evicted` is counted
   and reported on stderr every 1000 (`laundering.go:73-78`,
   `laundering.go:142-144`), which is the right shape — a detector at its cap
   has void coverage and an operator who cannot see that reads the absence of
   alerts as the absence of attacks. No run has shown what the fleet's traffic
   actually does to the cap.
7. **A naming collision still in the tree.** `classify_odata.go:3` says "The
   other two layers are in `laundering.go`", and only one is.
   `scanner_laundering_3430_test.go:94` and `classify_odata.go:3` also disagree
   with each other on which letter names the shipped query-side class. Comments
   only — no behaviour — and fixing them is a code change outside this
   document's remit. Recorded here so the next reader does not resolve it by
   picking a letter.

## Severity

**Low as a security control; the honest value is analytical, not protective.**

- No CVE, no vulnerable product, no remediation. `#3430` is a research note and
  the classes are patterns on a decoy that impersonates an OData-style surface.
  Nothing here prevents an attack; it labels one.
- **The realistic near-term cost is a false positive, not a missed attack.** The
  gated classes claim 0 of 31 pinned corpus entries, and the ungated versions
  that *did* claim real traffic are the reason the gates exist. A
  `odata-double-encode-probe` or `odata-path-encoded-bypass` event on ordinary
  traffic would cost analyst trust in every other class, which is the failure
  mode `classify.go:209-210` warns about.
- If a real laundering campaign is ever seen against this surface, these two
  classes are the part of the signature that survives a relay — the request
  bytes are what a relay cannot rewrite. That is the reason they exist and it
  is worth having, at this severity.

## References

Issues:

- `#3430` — this umbrella. Research note citing a public third-party
  investigation. The current body is the `#3443` status revision; the original
  layer/technique prose is not recoverable from the API, so the layer structure
  cited above is reconstructed from the repo (see *Veracity note*).
- `#3443` — in-request double-encoding classifier. **Closed.**
- `#3447` — stateful path-borne pair. **Closed.** The design writeup is
  [`3447-scanner-laundering-layer-c.md`](3447-scanner-laundering-layer-c.md);
  it is the authority on anything below the umbrella level.
- `#3446` — dead-drop sanitisation. **Closed**, and out of scope here.
- `#3464` — classifier-order pinning. **Closed**; the reason
  `classify_order_3464_test.go` exists.
- `#1888` — the fleet's 30-day window, the origin of the pinned corpus.

Code:

- `arcane/home/honeypot-http/http-honeypot/classify_odata.go` — the in-request
  class and its two-halves gate.
- `arcane/home/honeypot-http/http-honeypot/laundering.go` — the stateful
  component, its bounds and its `ServeHTTP` seam.
- `arcane/home/honeypot-http/http-honeypot/scanner_laundering_3430_test.go` —
  the coverage measurement and the not-implementable pins.
- `arcane/home/honeypot-http/http-honeypot/odata_double_encode_test.go` — the
  `#3443` pins.
- `arcane/home/honeypot-http/http-honeypot/laundering_purity_test.go` — the
  purity invariant, asserted.
- `arcane/home/honeypot-http/http-honeypot/classify_order_3464_test.go` — the
  pinned dispatch order.
- `arcane/home/honeypot-dashboard/backend-service/src/events.rs`,
  `frontend-next/src/routes/events.tsx` — where `payload_class` is read and
  rendered.

## Veracity note

- **No number here is invented, and no number is a fleet measurement.** Every
  count in *Coverage as implemented* is reproducible by re-running the two named
  tests on `43061f27`; the layer-C figure additionally appears in the test's own
  output at `laundering_test.go:964`. The 79 µs / 0.9 µs figure is quoted from
  a code comment and is explicitly *not* independently reproducible from this
  repo.
- **The positives follow published shapes, not captures.** `#3430` is a
  research note. Every positive case in the suite is a transcription of a
  described technique, and both `odata_double_encode_test.go:9-12` and
  `3447-…-layer-c.md:273-278` say so. A layer that has never fired on real
  traffic is a hypothesis with a regression guard, and the two classes should
  be read that way until a deployed sensor produces a document.
- **The proposed-but-unbuilt detectors are unvalidated hypotheses, and are
  labelled as such above.** The per-source-history and cross-source-window
  shapes have no threshold, no measured base rate, and no precision estimate.
  They are pinned as negatives because a thing this binary cannot do is worth
  recording, not because they are a plan.
- **`#3430`'s original prose was not readable.** The issue body has been
  rewritten to a `#3443` status note; GitHub's API does not retain body-edit
  history. Every layer and technique statement in this document is therefore
  sourced from the current body, the issue title, and — principally — the
  repo's own comments and tests, cited inline. Where the repo's two accounts
  disagree (the layer letters, *Known gaps* item 7) this document records the
  disagreement instead of picking a winner.
- **No CVE data is asserted.** `#3430` is not a CVE and none is cited here.
  Nothing in this document was taken from memory about any product or
  vulnerability.
- **Nothing was executed against a live surface.** All fixtures are inert
  strings in unit tests. No live endpoint, no attack traffic, no docker, no
  production Elasticsearch, no model load.
