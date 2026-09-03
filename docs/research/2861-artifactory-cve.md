# Research: CVE-2026-82329 — JFrog Artifactory unauth admin-token mint — fleet exposure and decoy coverage (#2861)

Checks whether this fleet runs the affected software, and if not, whether
the existing decoy classification would recognize an Artifactory-probe
request as anything more specific than generic noise. Gathered 2026-09-03.

**Scope, per the issue and this batch's house rules:** analysis only. No
sensor was built, no persona classification was added, and nothing was
deployed.

## 1. Does this fleet run self-hosted Artifactory anywhere?

**No — confirmed by grep over every tracked file, not assumed from the
stack list.**

```
$ git grep -i -l -E "artifactory|jfrog" origin/main -- .
sandbox/ghosts/vendor/ghosts-src/Ghosts.Api/config/usernames.txt
$ ls arcane/home/ | grep -i "registry\|artifact\|jfrog"
(no output)
```

The single hit is an incidental substring in a vendored GHOSTS username
wordlist — not a deployment, not a configuration, not a dependency. (An
earlier draft ran this restricted to `*.yml,*.md,*.go,*.py,Dockerfile*`,
which could not see `*.json` manifests, `*.sh`, `*.rs` or `*.ts`; the
unrestricted form above is what the word "confirmed" needs to rest on, and
it returns the same answer.)

No compose stack, Dockerfile, or vendored image anywhere in the repo
references Artifactory or JFrog. This fleet has no self-hosted Artifactory
instance, lab-adjacent or otherwise — the issue's ask (1), "audit for
anomalous admin tokens" on any self-hosted Artifactory this fleet runs, has
no target: there is nothing to audit.

## 2. Would an Artifactory-probe request even be recognized as one?

The fleet's generic HTTP decoy (`arcane/home/honeypot-http/http-honeypot`,
serving both the `http-honeypot` and `api-honeypot` personas from the same
binary per `docs/SENSORS.md`) classifies every incoming request path into a
named persona bucket for aggregation. Read the classifier directly
(`main.go`'s `classify()` switch, lines 633–684) rather than assuming
`/artifactory/`-shaped traffic lands anywhere meaningful:

```go
case strings.HasPrefix(p, "/api/v1/"), strings.HasPrefix(p, "/apis/"), p == "/version":
    return "kubernetes-api"
case strings.HasPrefix(p, "/v1/models"), strings.HasPrefix(p, "/v1/chat"),
    strings.Contains(p, "openai"):
    return "llm-api"
case p == "/v2/" || strings.Contains(p, "docker"):
    return "container-registry"
case strings.Contains(p, "jenkins"), strings.Contains(p, "grafana"),
    strings.Contains(p, "actuator"):
    return "devops-admin"
default:
    return "scan"
```

None of these buckets match `/artifactory/`, `/api/system/ping`, or
`/ui/api/v1/...` — the issue's own named probe paths. `/api/system/ping`
does not start with `/api/v1/`, so it does not even accidentally fall into
`kubernetes-api`. **Any Artifactory-shaped probe against this fleet's
generic HTTP decoy today is recorded, but bucketed into the undifferentiated
`scan` persona alongside every other unrecognized path** — there is no
per-technique signal, no admin-token-mint-sequence detection, and nothing
that would distinguish "someone is running the CVE-2026-82329 PoC against
us" from routine internet background scanning.

This matches `docs/SENSORS.md`'s own description of `api-honeypot`
("cloud metadata, Kubernetes, registry, DevOps and LLM API probes") — the
existing `container-registry` bucket is a **Docker** registry classifier
(`/v2/`, the string `docker`), not an Artifactory one; the two products
share the word "registry" but not a matching URL shape.

## 3. Relevance to APIARY, re-assessed against §1–§2

The issue's three "Relevance" points, checked against what actually exists
rather than restated:

1. *"Fleet sweep... if any lab-adjacent or monitored assets run self-hosted
   Artifactory"* — none do (§1). Nothing to sweep.
2. *"Detection pattern for our sensors... version-probe or auth-bypass
   attempt observed against a decoy is actionable"* — not today. §2 shows
   the existing classifier has no bucket for it; any such traffic already
   lands as generic `scan`, indistinguishable from noise in the dashboard's
   current aggregation.
3. *"Honeypot-as-discovery... decoy artifacts/metadata (fake package
   registries) could serve as an early-warning surface"* — this fleet
   already has exactly one decoy in that shape (`container-registry`, a
   Docker registry v2 API bait, `main.go:824-825`), which is architecturally
   the same idea the issue gestures at, just for a different product. Adding
   an equivalent Artifactory-shaped bait (a `/artifactory/api/system/ping`
   route, a fake admin-token-mint response) is a real, buildable extension
   of that existing pattern — but it is **new decoy capability**, not a
   config or detection-query change achievable within this research row's
   scope (matching #2777's and #2824's precedent of filing new-capability
   asks separately rather than building them inline).

## 4. What I did not verify

- Did not independently re-check the advisory's own numbers (CVSS 9.8,
  affected/fixed version matrix, the 3-day time-to-wild-exploitation claim)
  against a primary source (NVD/JFrog's own advisory) — this pass's time
  budget went to the fleet-side question, which the advisory's exact
  parameters don't change: this software isn't run here regardless of
  whether the CVSS is 9.8 or 9.1.
- Did not check whether any *other* fleet component (e.g. a CI runner, a
  build tool) talks to a **third-party** hosted Artifactory instance as a
  client (as opposed to running one) — that would be a different exposure
  shape (credential theft against an external service) than what the issue
  describes (auditing a self-hosted instance we run), and grepping for
  outbound Artifactory usage in CI config found nothing, but was not an
  exhaustive audit of every workflow's external dependencies.

## 5. Bottom line

**Not applicable — this fleet runs no self-hosted Artifactory, so there is
nothing to patch, sweep, or protect (#2836's "disproved premise" pattern).**
The one real, scoped follow-on is a new decoy capability (an
Artifactory-shaped bait added to the existing HTTP persona classifier,
mirroring the already-working `container-registry` bucket) — worth a future
enhancement issue if operators want deliberate CVE-2026-82329-shaped bait,
but out of scope for this research row per house rule 3 ("don't change any
sensor's configuration as part of a research row — file the change"). Not
filed as a new issue here: it is a nice-to-have decoy idea with no urgency
(no Artifactory exposure exists to make it defensive), not a gap this
assessment found reason to prioritize.
