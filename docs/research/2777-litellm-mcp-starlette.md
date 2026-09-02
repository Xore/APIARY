# Research: Wiz AI-infrastructure honeypot telemetry — LiteLLM MCP RCE chain (CVE-2026-42271 / CVE-2026-48710) — APIARY sensor and detection coverage (#2777)

Verifies every CVE/technique claim in #2777 against primary sources (vendor
advisories, CISA KEV, a third-party attack-chain writeup, and the Wiz
research blog itself), then assesses it against what this repo actually
deploys — the `beelzebub` MCP sensor (epic #1992, previously read in detail
for `docs/research/2737-mcp-spec-attack-surfaces.md`, commit `bcd83687`),
Suricata, and the ingest pipeline — by reading code and config, not by
assuming the report's gap description applies. Gathered 2026-09-02.

**Scope, per the issue and per #2737's precedent:** analysis only. No
sensor was built, no Suricata rule was written or deployed, no ES query was
added to the dashboard, and no live config (`CANARYTOKENS_*` or otherwise)
was touched.

## 0. Which of the two components this fleet actually runs

Before assessing detection coverage, the more basic question: is anything
in this fleet actually running the affected software? The answer differs
per CVE, and only one half of it is "no".

**Correction (2026-09-02).** An earlier draft of this section claimed *both*
components were absent, on the strength of this grep:

```
$ grep -rl "litellm\|starlette\|fastapi\|uvicorn" --include="*.txt" \
      --include="*.py" --include="Dockerfile*" .
(no output)
```

That command is wrong twice over: it is **case-sensitive** (so it cannot see
`FastAPI`) and its `--include` list **excludes compose files** (so it cannot
see a `uvicorn` invocation in a `command:`). Re-run without either
restriction it does not return nothing:

```
$ grep -rniE "litellm|starlette|fastapi|uvicorn" --exclude-dir=.git .
arcane/home/honeypot-canarytokens/compose.yml:108:  command: bash -c "cd frontend;
    uv run --no-sync python -m uvicorn app:app --host 0.0.0.0 --port 8082"
analysis/ghidra/worker/ghidra-worker.py:535:  ... The service is FastAPI
docs/analysis/ghidra/IMPLEMENTATION_PLAN.md:168: ... The service is FastAPI; ...
```

### 0.1 LiteLLM — absent, confirmed

No LiteLLM anywhere: the case-insensitive repo-wide grep above returns no
`litellm` hit outside this document itself. The one LLM-adjacent service,
`llm-worker`, talks to a locally-run Ollama over plain HTTP — read from its
own code, not from operator notes: `llm-worker/worker.py:208` reads
`OLLAMA_URL` (default `http://ollama:11434`), and `worker.py:278-292`
*refuses to start* unless that endpoint passes `endpoint_is_local(...)`, so
it cannot even be pointed at a hosted proxy. There is no LiteLLM proxy, no
`/mcp-rest/test/*` surface, and nothing for CVE-2026-42271 or
CVE-2026-59822 to land on. **This half of the original claim stands.**

### 0.2 Starlette — present, at an affected version, and internet-reachable

`hp-canarytokens-frontend` and `hp-canarytokens-switchboard` are live
`uvicorn`/FastAPI (hence Starlette) services, both from the same image
(`sha256:95df46c3a9d2…`), built from `thinkst/canarytokens` pinned at
`CANARYTOKENS_REF=dd92bf29bd0f6d1b446fb41e3b8114c6fc7a6205`
(`arcane/home/honeypot-canarytokens/canarytokens/Dockerfile:36`). Measured
inside the running containers on the homeserver, 2026-09-02:

```
$ docker exec hp-canarytokens-frontend \
    find /srv/.venv/lib -maxdepth 3 -name '*.dist-info'
starlette-0.50.0.dist-info
fastapi-0.125.0.dist-info
uvicorn-0.17.6.dist-info
# identical output from hp-canarytokens-switchboard (same image digest)
```

**Starlette 0.50.0 is inside CVE-2026-48710's affected range (0.8.3 through
1.0.0, fixed in 1.0.1; §1.2).** So the vulnerable library *is* deployed
here, on a service that is deliberately internet-reachable — the VPS Traefik
router `honeypot-canarytokens` (`vps/traefik/dynamic.yml:346`) forwards a
wildcard host under the apex domain to it, unauthenticated by design
(`dynamic.yml:308`), because it is a decoy.

### 0.3 What that does and does not mean for exposure

Having the vulnerable version is not the same as having the vulnerability's
*impact*. CVE-2026-48710's primitive is a divergence between
`request.url.path` (rebuilt from the attacker-controlled `Host` header) and
the raw ASGI scope path that routing actually uses — it matters only where
something **authorizes** on `request.url`. Grepping the whole application
source inside the running container (excluding its own `.venv`) finds
exactly two relevant call sites:

```
$ docker exec hp-canarytokens-frontend sh -lc \
    "cd /srv && grep -rn 'request.url\|add_middleware\|BaseHTTPMiddleware\|TrustedHost' \
       --include=*.py . | grep -v '/.venv/'"
./frontend/app.py:314:    if request.url.path not in ["/", "/nest"]:
./frontend/app.py:374:    app.add_middleware(SentryAsgiMiddleware)
```

`app.py:314` uses `request.url.path` to decide whether to attach an
`X-Robots-Tag: noindex, nofollow` header — a crawler hint, not an
authorization boundary. `SentryAsgiMiddleware` is telemetry. There is no
`TrustedHostMiddleware`, no `BaseHTTPMiddleware` subclass, and no
path-based auth middleware anywhere in the app for the bypass to defeat.

So the honest statement, with each half separated as §"read the producer"
discipline requires: **the affected version is deployed and reachable
(observed), and this particular application contains no consumer of the
bypass primitive (observed), so no privilege boundary in it is currently
known to be crossable by CVE-2026-48710 (inferred).** That inference covers
only APIARY's own use of the library; it is not a claim that Starlette
0.50.0 is safe, and the pinned upstream ref should still be moved to a
build that ships Starlette ≥ 1.0.1. That is tracked separately rather than
buried here — filed as **#2866**, see §7.

### 0.4 The `analysis/ghidra` "FastAPI" strings are stale, not a second ASGI service

The other two grep hits are documentation, not code. `analysis/ghidra`'s
live service is `python3 /opt/service/server.py`, whose own module
docstring says it is a **"Deliberately stdlib-only"** drop-in replacement
for the upstream `biniamfd/ghidra-headless-rest` container (#245) — and
that *upstream* service is the FastAPI one the docstring at
`ghidra-worker.py:535` is describing. Measured on the live containers:

```
$ docker exec ghidra-ghidra-1 sh -lc \
    'find / -name "starlette-*.dist-info" -o -name "fastapi-*.dist-info"'
(no output; same for ghidra-statictools-1)
```

No ASGI framework is installed in either. The strings are a description of
software this repo *replaced*, so they are worth correcting in their own
files but they do not add exposure.

### 0.5 How to read the rest of this document

Everything from §2 onward is about whether our MCP **decoy** would notice an
attacker running these TTPs against it. That framing is unchanged by the
above — the LiteLLM CVEs still have no target here. What changed is that
§0 no longer forecloses the Starlette question: it was a live question, it
has now been measured, and the measurement is in §0.2–§0.3.

## 1. The CVEs, re-verified against primary/near-primary sources

The issue's own description turns out to conflate two adjacent CVEs. Both
are real and both were observed by Wiz, but not in the combination the
issue states.

### 1.1 CVE-2026-42271 — confirmed, CVSS corrected

- **Primary sources:** [Snyk](https://security.snyk.io/vuln/SNYK-PYTHON-LITELLM-16119122), [GitLab Advisory DB](https://advisories.gitlab.com/pypi/litellm/CVE-2026-42271/), [The Hacker News](https://thehackernews.com/2026/06/litellm-flaw-cve-2026-42271-exploited.html), [Horizon3.ai's chain analysis](https://horizon3.ai/attack-research/vulnerabilities/cve-2026-42271-chained-with-cve-2026-48710/).
- **Confirmed:** command injection in two MCP preview endpoints —
  `POST /mcp-rest/test/connection` and `POST /mcp-rest/test/tools/list` —
  which accept a full stdio-transport server configuration (`command`,
  `args`, `env`) and pass `command` directly to subprocess execution with
  no validation. **Affected: LiteLLM 1.74.2 up to (not including) 1.83.7.**
  Added to CISA KEV 2026-06-08 for active exploitation.
- **Correction to the issue's severity claim.** The issue states "CVSS:
  9.8 (Critical)" for this CVE. Every source found gives the *standalone*
  CVE-2026-42271 a CVSS of **8.7** (it requires a valid, if low-privileged,
  proxy API key — it is a privilege-escalation/authorization-boundary bug on
  its own, not unauthenticated). **The 10.0 figure belongs to the *chained*
  attack** (42271 + 48710 together, achieving unauthenticated RCE) per
  Horizon3.ai's own writeup — the issue appears to have picked up the
  chain's score and attributed it to the single CVE. This is exactly the
  kind of "secondary aggregator inflates a number" pattern #2824 (this
  round's other research row) independently flags for a different CVE —
  worth noting as a repeated pattern across this batch's research issues,
  not a one-off.
- **Correction to the issue's endpoint description.** The issue says
  "`/test` endpoint" (singular, generic). The actual surface is two named
  endpoints under `/mcp-rest/test/*`, both requiring the request body to
  carry a full MCP server config — precise enough to matter for a detection
  signature (a bare substring match on `/test` would both over- and
  under-fire relative to the real path).

### 1.2 CVE-2026-48710 — confirmed as "BadHost," but not the mechanism the issue implies

- **Primary sources:** [GitLab Advisory DB](https://advisories.gitlab.com/pypi/starlette/CVE-2026-48710/), [IONIX](https://www.ionix.io/threat-center/cve-2026-48710/), [CSO Online](https://www.csoonline.com/article/4177711/fastapi-based-ai-tools-exposed-to-authentication-bypass-by-flaw-in-starlette-framework.html), and the dedicated tracker at [badhost.org](https://badhost.org/).
- **Confirmed mechanism:** Starlette never validated the `Host` header
  before using it to reconstruct `request.url`. Because routing decisions
  are made against the raw ASGI scope path while `request.url` (what
  path-based security middleware actually inspects) is rebuilt from the
  attacker-controlled `Host` header, a single malformed byte in `Host` can
  make `request.url.path` diverge from the path actually routed —
  bypassing any middleware that authorizes on `request.url` rather than the
  raw scope path. **Affected: Starlette 0.8.3 through 1.0.0. Fixed in
  1.0.1.**
- **Correction to the issue's mechanism claim.** The issue describes this
  CVE as what lets an attacker reach internal MCP endpoints "unauthenticated
  or with a single-character `Bearer x`" — folding the header-confusion bug
  and the single-character-Bearer-token bypass into one CVE. **They are two
  different bugs.** Per Wiz's own blog (fetched directly, quoted below),
  the single-character `Bearer x` bypass is a *separate*, third CVE the
  issue never names: **CVE-2026-59822**, a LiteLLM MCP-gateway
  authentication defect where token validation failure returns an empty,
  unrestricted `UserAPIKeyAuth()` object instead of rejecting the request —
  *"Any Bearer token (even just a single character, e.g., `x`) grants full
  MCP access."* CVE-2026-48710 (Starlette) is what Horizon3.ai's chain
  analysis pairs with 42271 for unauthenticated RCE — a Host-header
  confusion bug, not a Bearer-token bug. **The issue's proposed Suricata
  rule ("Alert on `Authorization: Bearer [a-zA-Z0-9]` length ≤ 2 paired
  with MCP endpoint paths") is real and worth having, but it detects
  CVE-2026-59822, not CVE-2026-48710 as titled** — the rule itself is sound,
  the CVE attribution in the issue is wrong.

### 1.3 Fileless execution and memory-resident credential theft — confirmed, with a technique-level correction

Fetched the Wiz blog directly rather than trusting the issue's paraphrase.
Confirmed via direct quote: the observed fileless-execution technique used
`start_new_session=True` to detach the malicious process, then
`shutil.rmtree()`'d the staging directory *while the running process kept
the binary's inode open* — a classic delete-while-running self-cleanup, not
literally `memfd_create` (in-memory anonymous file execution with no
on-disk artifact at any point). The issue's summary names `memfd_create`
specifically; the primary source I could reach describes a related but
distinct fileless pattern (briefly on-disk, then unlinked while still
running) rather than never-touches-disk `memfd_create` execution. Both are
real fileless techniques in the wild and both defeat the same class of
naive "scan the filesystem" detection, but a detector built narrowly around
`memfd_create` syscalls specifically would miss the technique Wiz actually
documented. Memory-resident credential theft via runtime introspection
(`python3 -c "import litellm; print(litellm.api_key)"`-shaped) is confirmed
as described.

### 1.4 Covert exfiltration via `tools/list` description injection — confirmed

Direct quote from the Wiz blog: command output was *"sent back through the
MCP protocol itself, embedded in the description field of a fake tool in
the `tools/list` response."* This matches the issue's description exactly.

## 2. What `beelzebub`'s MCP sensor actually captures, re-read from the pinned source

Repeated #2737's method rather than assuming its conclusions still apply
unchanged: cloned `github.com/mariocandela/beelzebub` at the pinned commit
(`39242822af79a59a6b8d0139adc4a8ccf2edec0c`, `arcane/home/honeypot-beelzebub/beelzebub/Dockerfile`)
and re-read `internal/protocols/strategies/MCP/mcp.go` directly — the same
89 lines #2737 already fully quoted, unchanged since. Everything #2737
established about the `Command`/`Status`/`ID` fields still holds; two more
findings specific to this issue's attack shapes:

- **`tools/list` requests are never traced at all.** The only
  `tr.TraceEvent(...)` call in this file lives inside the closure passed to
  `mcpServer.AddTool` (`mcp.go:70-86`), which fires **only when a tool is
  actually invoked** (a `tools/call` request). `tools/list` — the request
  that would return tool metadata, including any `description` field an
  attacker might have poisoned — is served entirely by the vendored
  `mark3labs/mcp-go` library's `NewStreamableHTTPServer`/`NewMCPServer`
  internals (`mcp.go:22-26`, `89-96`), and none of that path calls into the
  tracer. **The sensor cannot observe §1.4's exfiltration channel at all**,
  not because the data is discarded, but because the request that would
  carry it is never routed through the one place this sensor logs anything.
  This is a stronger negative than #2737's finding for MCP Apps (§2 there
  found no UI-resource *support*, i.e. nothing to attack); here the
  capability the honeypot already exposes — `tools/list`, which any MCP
  client calls as a matter of course before calling a tool — produces zero
  log lines under this sensor's current code, attack or no attack.
- **No `Authorization` header of any kind is captured.** `mcp.go`'s
  `WithHTTPContextFunc` (`mcp.go:92-94`) — confirmed unchanged from #2737's
  reading — threads only `r.RemoteAddr` into context. `Bearer x` or any
  other Authorization value never reaches the `Event` struct via this code
  path. Consistent with #2737's finding that the `Mcp-Session-Id` header was
  never captured either: this sensor's HTTP context bridge is single-purpose
  (source address only) and has never read any other header, for either
  session tracking or authentication signal.
- **The decoy config has no `/mcp-rest/test/*`-shaped bait.** `mcp-8000.yaml`
  defines two tools (`tool:user-account-manager`, `tool:system-log`) served
  over the standard MCP JSON-RPC `tools/call` mechanism at a single address
  (`:8000`). There is no HTTP route resembling LiteLLM's
  `/mcp-rest/test/connection` or `/mcp-rest/test/tools/list` REST-shaped
  preview endpoints — those are LiteLLM's own proxy-management surface, not
  part of the MCP protocol itself, and this decoy doesn't (and structurally
  can't, since it's a bare `mcp-go` server, not a LiteLLM proxy) present
  anything at those paths. An attacker running the exact CVE-2026-42271
  request against this sensor would get a 404 from the underlying HTTP
  router, generating **no MCP-strategy trace event at all** (that code path
  is never reached) — only whatever, if anything, the outer beelzebub HTTP
  server logs for an unmatched route. I did not trace that fallback path;
  flagged as unverified below.

## 3. Reachability: is this decoy even where an internet attacker would find it?

Confirmed from `vps/docker-compose.yml:559`'s portbridge `RULES` string:
`tcp:8000:10.8.0.2:8000` (no `:pp` suffix) — port 8000 on the VPS's public
interface forwards in cleartext, without the PROXY-protocol wrapper, to the
homeserver's `hp-beelzebub` container. This matches
`arcane/home/honeypot-beelzebub/compose.yml`'s own documented reasoning (no
Traefik routing, no PROXY-protocol support in the vendored binary) — the
service is real-attacker-reachable over the open internet at the VPS's port
8000, and because it's forwarded without PROXY protocol, **VPS-side
Suricata sees the plaintext HTTP request** (JSON-RPC body, any headers, all
of it) as it transits the VPS network interface, independent of whether
`beelzebub` itself logs anything about it.

## 4. The issue's proposed detection queries, checked against the real field shape

**Both proposed ES queries use field paths that do not exist in this
stack's indices, and would silently return zero results.**

- `event.dataset: "suricata.eve" AND http.url: (*mcp* OR *litellm*) AND http.http_method: "POST"`
  — Read `arcane/home/honeypot-elk/analysis/filebeat.yml:314-329` directly:
  the Suricata EVE ingest pipeline nests the entire raw EVE record under
  **`suricata.eve.*`** (`target: "suricata.eve"`), explicitly documented in
  the file's own comment as "the layout EveBox reads in `--ecs` mode... the
  only consumer of this shape; queries elsewhere use the promoted ECS
  fields (`source.ip`, `destination.ip`, `network.transport`)." Neither
  `event.dataset` nor a bare `http.url` matches this ingest's actual output
  — the correct path would be `suricata.eve.event_type: http AND
  suricata.eve.http.url: (*mcp* OR *litellm*) AND
  suricata.eve.http.http_method: "POST"`, or the promoted-ECS equivalent if
  one of those fields has actually been promoted (I did not find `http.url`
  in the promoted-field list quoted in the file's own comments, and stopped
  short of tracing the full geoip-honeypot pipeline to confirm — flagged
  below as unverified). This is the exact trap the batch's own plan
  document warns about: a query against a field the data does not use
  returns nothing and reads exactly like "no attacks."
- The `tools/list` anomalous-payload query has no field to check at all,
  per §2 above — `beelzebub`'s MCP strategy never logs a `tools/list`
  response, so there is no document in any index this query could match
  regardless of field-path correctness.
- The Suricata rule pattern for `*/test*`/`*/mcp*` with shell metacharacters
  is directionally sound as a rule *shape* (Suricata `content`/`pcre`
  matching against `http.uri`/`http_client_body` is a normal pattern here —
  `vps/suricata/rules/honeypot-web.rules` already does comparable HTTP
  content matching), but was not checked against this repo's actual rule
  file syntax/variable conventions (`$HOME_NET`, existing `sid` numbering)
  since building the rule is explicitly out of scope for this issue.

## 5. What would and wouldn't be seen, by attack stage

| Stage | Would APIARY see it? | Where | Gap, if any |
|---|---|---|---|
| CVE-2026-42271 request against a *real* LiteLLM instance | N/A — no LiteLLM instance exists in this fleet (§0.1) | — | Not applicable; nothing to protect |
| CVE-2026-48710 (`Host`-header confusion) against `hp-canarytokens-frontend`/`-switchboard` | **No** | — | These *do* run an affected Starlette (0.50.0, §0.2) and are internet-reachable via the VPS Traefik router. Nothing inspects the `Host` header for anomalies at any layer: Traefik routes on it rather than validating it, and no Suricata rule covers malformed `Host` on the canarytokens path. The app has no path-based auth for the bypass to cross (§0.3), so today this is an unmonitored-but-unexploitable surface — a version bump, not a detection gap |
| Same request pattern against the `beelzebub` MCP decoy | **No** | — | The decoy has no `/mcp-rest/test/*` route; the request 404s outside any traced code path (§2) |
| `Bearer x` / malformed-auth probe against the MCP decoy | **No** | — | `WithHTTPContextFunc` never reads `Authorization` (§2, confirms #2737) |
| A genuine `tools/call` invocation against either of the two real decoy tools | **Yes** | `honeypot-v2-*` via the beelzebub log path, `Command`/`CommandOutput`/`SourceIp` fields (#2737 already established this) | None — this is the one path the sensor actually instruments |
| `tools/list` enumeration, poisoned-description exfiltration attempt | **No** | — | Never routed through the tracer at all (§2) — a stronger gap than "logs it badly," it logs nothing |
| Raw HTTP transiting the VPS to port 8000 (headers, body, method) | **Potentially, at the network layer** | Suricata EVE via `suricata.eve.*` — *if* a rule exists to alert on it | No rule currently deployed for this traffic shape (rule-writing is out of scope here); the issue's own proposed ES query to *find* such an alert uses the wrong field path (§4) even if the rule existed |
| Memory-resident credential theft / fileless (`memfd`-family) execution inside any container on the fleet | **No** | — | No host-level syscall monitoring exists anywhere in this repository — confirmed by grep (`auditd`, `falco`, `ebpf` all return zero hits across `.yml`/`.md`). A signature over a stream nobody collects is not coverage; this is a structural gap, not a beelzebub-specific one |

## 6. What I could not verify

- Whether `suricata.eve.http.url` (or an ECS-promoted equivalent) is
  actually populated for HTTP flows in this deployment's live index today —
  I read the ingest pipeline's declared field structure but did not query a
  live Elasticsearch index to confirm a real document exists at that path
  for port-8000 traffic specifically (would require live-cluster access;
  #2820/#2774/#2823's disk-pressure incident makes new-index creation
  unreliable right now, per this round's own environment note, and querying
  an *existing* index wasn't attempted given this is a docs-only research
  deliverable).
- What beelzebub's outer HTTP server (outside the MCP strategy's own
  tracer call) logs, if anything, for a request to an unmatched route like
  `/mcp-rest/test/connection` — I read only the MCP strategy file, not the
  full vendored HTTP server/router setup, since chasing that further felt
  like drifting from "what does this sensor capture" into "audit the entire
  vendored binary," which #2737 also stopped short of for the same sensor's
  own transport layer.
- Whether any *other* container in the fleet ships an affected Starlette.
  §0.2's measurement covered the two canarytokens services (the only
  `uvicorn` invocation in the repo) and §0.4 cleared the two ghidra
  containers; it was not run against every running container image on
  either host. A fleet-wide `dist-info` sweep is the obvious next step and
  is ask (2) of **#2866**.
- Whether the pinned `thinkst/canarytokens` ref has an upstream build that
  carries Starlette ≥ 1.0.1. §0.3 states the version we run and that it is
  in range; it does not establish that a drop-in newer pin exists, which is
  an upstream-compatibility question, not a measurement.
- Independent confirmation of the exact byte sequence Wiz used for the
  malformed `Host` header exploiting CVE-2026-48710 — none of the sources
  fetched (including Horizon3.ai's dedicated chain writeup) states it
  precisely; both describe the vulnerability mechanism but not a literal
  PoC header value.

## 7. Bottom line

**The one action item this assessment produced.** `hp-canarytokens-frontend`
and `hp-canarytokens-switchboard` run Starlette 0.50.0, inside
CVE-2026-48710's affected range, on an internet-reachable service (§0.2).
No privilege boundary in that application consumes the bypass primitive
(§0.3), so this is not an incident — but running a known-affected library on
a reachable service is a version-hygiene defect regardless, and the
"no consumer today" finding is only true of the code as it stands. Moving
the pinned `CANARYTOKENS_REF` to a build carrying Starlette ≥ 1.0.1, plus
the fleet-wide `dist-info` sweep §6 names, is filed as **#2866** rather
than left in this document.

Building MCP `/test`-endpoint bait or a `tools/list` interpretation layer
into `beelzebub`'s decoy configuration is real, scoped follow-on work — but
it is **new sensor capability**, not something achievable by wiring up
existing log fields, matching #2737's precedent for its own Surfaces 2 and
3. The two ES queries in the issue's body should not be adopted verbatim
(§4); a corrected version exists in this document for whichever follow-on
issue eventually builds the rule. No code, sensor, or live config changed
as part of this assessment.
