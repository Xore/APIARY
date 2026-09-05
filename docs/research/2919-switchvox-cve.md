# Research: CVE-2026-9586 — Sangoma Switchvox unauth SQLi/RCE — VoIP/PBX decoy coverage (#2919)

Checks whether this fleet runs the affected software, whether its existing
generic HTTP decoy would recognize the campaign's own signature as anything
more specific than generic noise, and what a scoped fix costs. Gathered
2026-09-04.

**Scope, per this batch's house rules (established in #2861/#2891/#2903):**
analysis plus one small, additive classifier change — not a new honeypot
service, not a new exposed port, not a persona build-out. The distinction
matters here specifically: #2861's Artifactory finding needed a whole new
decoy capability to get any signal at all; this one does not, because the
signal already exists in two separate places once actually checked.

## 1. Does this fleet run self-hosted Switchvox anywhere?

**No.**

```
$ git grep -i -l -E "switchvox|sangoma" origin/main -- .
(no output)
```

No compose stack, Dockerfile, or vendored image anywhere in the repo
references Switchvox or Sangoma. Nothing to patch or audit for the CVE
itself.

## 2. Would a Switchvox-shaped scan even be recognized as one?

**Partially already, in two independent ways — checked by reading the
actual classifier, not assumed:**

`arcane/home/honeypot-http/http-honeypot/main.go` runs two independent
classifiers on every request (`main.go:736-737`), not just one:

```go
Category:     classify(r.URL.Path),
PayloadClass: classifyPayload(r.URL.RawQuery, string(body)),
```

- **`classifyPayload`** already has a generic, path-independent SQLi
  bucket (`main.go:407`): `union select`, `or 1=1`, `' or '`, `sleep(`,
  `benchmark(`, `waitfor delay` in the request body all return
  `"sqli"` regardless of what path they arrived on. The issue's own
  proposed detection query — "any request... where a field value contains
  `) UNION SELECT`" — is a subset of what this bucket already matches. A
  Switchvox-campaign payload against this fleet's existing generic decoy
  would already be flagged `PayloadClass: "sqli"`, not silently bucketed
  as noise. This is the opposite finding from #2861 (Artifactory), where
  neither classifier had any matching bucket at all.
- **`classify`** (path-only) had no bucket for `/pa` before this change —
  it would have landed in the undifferentiated `"scan"` category, same gap
  #2861 found for Artifactory's own paths. Fixed below.

## 3. What was actually missing, and what closing it costs

The gap was narrow: **path-level attribution**, not payload detection. A
hit is already visible as `sqli` via `classifyPayload`; what was missing
was the ability to say "this specific sqli hit is the Switchvox campaign"
rather than one more generic `union select` scan, the same distinction
`classify()` already draws for two named WordPress CVEs
(`wordpress-cve-2020-11738`, `wordpress-cve-2020-25213`, added under #573)
instead of collapsing them into the generic `wordpress` bucket.

Unlike #2861, this was a **one-`case` addition to an existing switch**, not
a new decoy capability requiring new infrastructure, a new exposed port, or
new response content to build and review — so it was made directly rather
than filed separately:

```go
case p == "/pa":
    return "switchvox-cve-2026-9586"
```

Exact match, not `Contains` — `/pa` is short enough that a substring match
would false-positive on unrelated paths (`/api/params`, `/pathfinder/...`).
Placed alongside the existing named-CVE cases, same ordering convention
(specific CVE cases before generic fallbacks).

## 4. What I did not do, and why

- **Did not add a dedicated Switchvox response body** (fake `/pa` XML
  error, admin-token-mint-style bait content). `http-honeypot` presents as
  a generic nginx box; building a convincing Switchvox-specific response
  is a real content-authoring task with its own review surface, and the
  category label alone already gives the dashboard the attribution the
  issue asked for (distinguishing this campaign from background noise).
  If xore wants a higher-fidelity bait (an actual `/pa` endpoint that
  returns a plausible XML parse error and captures the full payload
  shape, which the request body already does verbatim via `body` on every
  event regardless of category), that is a follow-up worth its own issue
  with a mockup of the expected response — filed as #2973.
- **Did not expose a new port or stand up a dedicated VoIP/PBX decoy
  service.** The issue's framing ("nothing in the stack emulates a PBX web
  management surface") is accurate for a *purpose-built* VoIP decoy, but
  the mass-exploitation campaign this CVE describes targets a generic
  unauthenticated HTTP endpoint on whatever port a scanner finds
  listening — exactly the surface `http-honeypot` already is. Standing up
  a second, VoIP-specific service to catch the same mass internet-wide
  scan traffic `http-honeypot` already receives would duplicate exposure
  for no additional signal; SentryPeer remains the right home for actual
  SIP-protocol abuse, which this CVE is not (it's an HTTP endpoint, not
  SIP).
- **Did not independently re-verify the advisory's own numbers** (~4,000
  Shodan-exposed instances, the specific callback port 39323, the exact
  fix version 8.4.0.2) against a primary source — the fleet-exposure and
  classifier questions don't depend on those figures being exact.

## 5. Bottom line

**This fleet has no Switchvox exposure to defend, and its existing generic
decoy already flags this campaign's SQLi payload shape via the pre-existing
`classifyPayload` bucket.** The one real gap — no path-level attribution to
this specific campaign — is closed by a single additive `classify()` case,
made directly in this pass rather than filed separately, since it carries
none of #2861's new-capability cost. A higher-fidelity dedicated `/pa`
response is a genuine, separately-scoped follow-up, filed as #2973 rather
than built here.
