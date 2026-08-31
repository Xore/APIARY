# Research: MCP 2026-07-28 spec change — attack-surface claims verified against primary sources (#2737)

Verifies the three attack-surface claims from [Backslash Security's write-up](https://backslash.security/blog/new-mcp-spec-opens-new-attack-surfaces) of the MCP `2026-07-28` specification revision against the actual spec, and establishes what `honeypot-beelzebub`'s MCP sensor (epic #1992) currently captures, by reading its code — not by assuming the blog's gap description applies. Gathered 2026-08-31.

**Scope, per the issue:** analysis plus, at most, instrumentation proposals. No new sensor was built, no exploit code was written, and `honeypot-beelzebub`'s deployed configuration was not touched.

## 1. What the spec actually says

### 1.1 Handle-based identity replaces `Mcp-Session-Id` — confirmed, with the mechanism precisely stated

Primary source: [`blog.modelcontextprotocol.io/posts/2026-07-28/`](https://blog.modelcontextprotocol.io/posts/2026-07-28/), the protocol maintainers' own announcement (I could not reach the raw spec diff/changelog page directly through the tooling available in this session — noted as a residual gap in §4, not papered over).

Exact quote: *"we've officially retired the `initialize`/`initialized` exchange along with the `Mcp-Session-Id` header."* And on the replacement mechanism: *"If your server needs to carry state across calls, mint an explicit handle from a tool and have the model pass it back as an argument. We found this works better than session state hidden in the transport — the model can see the handle and thread it between tools."*

This confirms the issue's core claim precisely: session identity moves from an HTTP header (visible to a network intermediary without parsing the JSON-RPC body) into a JSON-RPC tool argument (only visible by parsing the body). The issue's characterization — *"the handle is in the JSON body, not the header"* — matches the primary source's own framing exactly.

### 1.2 `Roots` is deprecated — confirmed, but the issue's framing needs a correction

Primary source: [`modelcontextprotocol.io/specification/2026-07-28/client/roots`](https://modelcontextprotocol.io/specification/2026-07-28/client/roots) — the actual spec page, not the blog.

Confirmed deprecated, via `SEP-2577`, as of protocol version `2026-07-28`. Exact wording: *"New implementations **SHOULD NOT** adopt it; existing implementations **SHOULD** migrate to passing directories or files via tool parameters, resource URIs, or server configuration."* It remains in the spec for at least twelve months post-deprecation under the feature lifecycle policy.

**Correction to the issue's premise:** the issue frames the gap as something the deprecation *creates* — a server can "declare 'I have no filesystem' and then be granted arbitrary paths by the host." Reading the spec directly shows this framing overstates what changed. The very same page states, describing `Roots` as it has always worked, not as a new consequence of deprecation: *"They are informational guidance rather than an access-control mechanism. The protocol does not enforce that servers stay within roots."* Roots was **never** an enforced filesystem boundary — it was always advisory, and the protocol has always relied entirely on client-side/host-side enforcement, never on the wire format. What `2026-07-28` actually changes is narrower and, in one sense, worse for long-term visibility: it discourages new implementations from even sending the (always-advisory, never-enforced) signal at all. The security-relevant fact isn't "deprecation opened a gap" — it's "the gap was always there, and the one weak, informational signal that existed is now being phased out." I'm stating this as a correction because the distinction matters for how a detector should be framed (§3.2): there is no "before" state where `Roots` meaningfully constrained anything to regress from.

### 1.3 SEP-1865 (MCP Apps) exists and does substantially what the issue describes — confirmed, with a dating correction

Primary source: [`modelcontextprotocol.io/seps/1865-mcp-apps-interactive-user-interfaces-for-mcp`](https://modelcontextprotocol.io/seps/1865-mcp-apps-interactive-user-interfaces-for-mcp), Status: **Final**, Extensions Track.

Confirmed: servers declare HTML UI resources via a `ui://` URI scheme (content type `text/html;profile=mcp-app`), predeclared and associated with tools via metadata, rendered by the host, communicating back over the same JSON-RPC channel as everything else.

**Dating correction:** SEP-1865 was created **2025-11-21** and reached Final status around **2026-01-26** — both dates precede the `2026-07-28` spec revision by months. It did not open with `2026-07-28`; the `2026-07-28` release folded it (per the blog: *"a proper extensions framework"*) into the formal extension mechanism alongside Tasks, but the capability itself predates that release. The issue's title framing ("2026-07-28 MCP spec change opens 3 attack surfaces") is accurate for surfaces 1 and 2, but not literally accurate for surface 3 — worth being precise about, since a reader tracing "when did this become possible" would be misled by a strict reading of the title.

**The spec's own threat model is more developed than the issue implies.** The SEP has a dedicated Security Implications section, quoted in full because it directly bears on how a detector should be scoped: *"Hosting interactive UI content from potentially untrusted MCP servers requires careful security consideration."* Stated mitigations: mandatory iframe sandboxing, predeclared/host-reviewable templates, all UI-to-host communication routed through auditable JSON-RPC, and host-enforced user consent for UI-initiated tool calls. The issue's framing (*"HTML in the IDE iframe is below the gateway's OSI layer entirely"*) is true of a **network** gateway specifically — it says nothing about host-level mitigations, which the spec does define. A detection design that ignores the spec's own consent/audit hooks would be redundant with controls MCP Apps already specifies; §3.3 below is scoped around what those hooks do *not* cover (the rendering-layer visual deception itself), not around a bare, unmitigated primitive.

## 2. What `honeypot-beelzebub`'s MCP sensor actually captures — read from the code, not assumed

The MCP decoy service is `arcane/home/honeypot-beelzebub/beelzebub/configurations/services/mcp-8000.yaml` — a **configuration file** for two decoy tools (`tool:user-account-manager`, `tool:system-log`), consumed by a vendored upstream binary. `arcane/home/honeypot-beelzebub/beelzebub/Dockerfile` builds `github.com/mariocandela/beelzebub` pinned at commit `39242822af79a59a6b8d0139adc4a8ccf2edec0c` (tagged `v3.9.0` at integration time) — the actual MCP protocol handling and event logging live in that upstream source, not in this repository. To answer "what does the sensor capture" honestly, I cloned the pinned commit and read it directly: [`internal/protocols/strategies/MCP/mcp.go`](https://github.com/mariocandela/beelzebub/blob/39242822af79a59a6b8d0139adc4a8ccf2edec0c/internal/protocols/strategies/MCP/mcp.go).

Every tool invocation runs through one closure (`mcp.go:70-86`) that emits exactly one `tracer.Event` (`internal/tracer/tracer.go:15-40` defines the struct) per call:

```go
tr.TraceEvent(tracer.Event{
    Msg:           "New MCP tool invocation",
    Protocol:      tracer.MCP.String(),
    Status:        tracer.Stateless.String(),   // mcp.go:76 -- a compile-time constant, not derived from the request
    RemoteAddr:    ctx.Value(remoteAddrCtxKey{}).(string),
    SourceIp:      host,
    SourcePort:    port,
    ID:            uuid.New().String(),          // a fresh random UUID per event, not a session/handle id
    Description:   servConf.Description,
    Command:       fmt.Sprintf("%s|%s", request.Params.Name, request.Params.Arguments),
    CommandOutput: toolConfig.Handler,
})
```

Established directly from this code, not inferred:

- **`Status` is a hardcoded constant on every event** (`tracer.Stateless.String()`, `mcp.go:76`). There is no branch anywhere in this file that inspects a session header, a handle argument, or any other state-carrying signal to set this field differently. Whatever session mechanism a real client actually used — legacy `Mcp-Session-Id` header or a `2026-07-28`-style handle argument — is invisible to this field; it always reads the same.
- **The `Mcp-Session-Id` header was never captured, before or after `2026-07-28`.** `Event` has `Headers`/`HeadersMap` fields (`tracer.go:35-36`), but the MCP strategy's own `WithHTTPContextFunc` (`mcp.go:92-94`) only threads the remote address into context — no header is read or stored anywhere in this file. This corrects any assumption that the spec change caused a regression from "used to track sessions, now can't": the sensor's MCP path has **zero** header-derived session visibility in either the pre- or post-`2026-07-28` world. Framing this as something the spec change took away would be wrong; it was never there.
- **`Command` does capture the raw argument payload verbatim**, via Go's default `%s` formatting of the `mcp.CallToolRequest.Params.Arguments` map (`mcp.go:82`). Concretely: if a real client passed a `2026-07-28`-style portable handle as a tool argument, its literal value **would** land in this log line as an opaque token embedded in the `Command` string — the raw data is not lost. What's genuinely missing is *interpretation*: nothing parses that string to identify "this looks like a handle," nothing labels which tool call *issued* a handle versus which tool call *presented* one, and nothing cross-references handle values across separate `ID`s (each event gets its own fresh random UUID, `mcp.go:80`, with no linkage field back to a prior event). Surface 1's proposed detection signature (§3.1, and the issue's own sketch) is genuinely unimplemented — not because the data is absent from the log, but because nothing structures or correlates it.
- **No filesystem-scope/`Roots` handling exists at all.** Both decoy tools (`user-account-manager`, `system-log`) are non-filesystem tools by design (per the `#1418` comment in `mcp-8000.yaml`, deliberately baiting prompt-injection-driven agent misuse, not filesystem access). There is no code path in `mcp.go` that requests, receives, or logs a `roots/list` response, and no filesystem-touching tool in the current config for a scope violation to even apply to. The honeypot cannot currently observe Surface 2 in any form — not "observes it poorly," genuinely cannot, because it never asks for or exposes anything roots-shaped.
- **No MCP Apps / UI-resource support exists at all.** `mcpServer.AddTool` handlers only ever return `mcp.NewToolResultText(...)` (`mcp.go:85`) — plain text. There is no `ui://` resource declaration, no `text/html;profile=mcp-app` content anywhere in this codebase or the vendored upstream's MCP strategy. The sensor cannot bait or observe Surface 3 in its current form for the same reason as Surface 2: the capability required to even attempt it isn't wired in.

**Summary, stated plainly:** the coverage gap is real for all three surfaces, but it is not the gap the issue's blog source implies (a regression from previously-adequate session tracking). It is closer to: the sensor was built before any of this was a consideration, captures raw data broadly (everything ends up in `Command`/`CommandOutput` as text) but interprets none of it, and has no filesystem- or UI-shaped decoy tooling to even present a target for surfaces 2 and 3.

## 3. Proposed detection signatures

Proposals only, per the issue's instruction — not implemented, not scheduled, explicitly marked with assumptions and false-positive shape.

### 3.1 Handle cross-attribution (Surface 1)

**Idea:** when a decoy tool's static `handler:` response is extended to itself mint a fake handle (a random token embedded in `CommandOutput`), record `{handle_value, issuing_event_id, issuing_tool}` in a short-lived lookup keyed by source IP (or MCP client identity, once/if that's captured). On a later tool call, scan `Command`'s argument string for any previously-issued handle value; if found, tag the event with the issuing tool/event id it traces back to, and flag if the presenting tool differs from what the handle was scoped for, or if the presenting session/IP differs from the one the handle was issued to.

**Assumptions:** (a) requires the decoy config to actually mint and embed a plausible-looking handle in at least one tool's response — none of the current two decoy tools do this today; (b) requires a short-lived, in-memory (or Redis-backed, matching this stack's existing patterns elsewhere) issuance table, which is new state this sensor doesn't currently keep; (c) assumes an attacking agent treats the decoy's fake handle as real and re-presents it, which is the same assumption the real-world AuthZed incident the issue cites demonstrates agents do make.

**False-positive shape:** legitimate MCP clients that retry a call after a transient error may re-send the same handle to the same tool from the same session — that's normal, not cross-attribution, and must be excluded by checking tool/session match before flagging. A cross-session presentation (the interesting signal) should have a very low false-positive rate *if* session/IP identity is itself reliable — which it currently is not (see §3.4).

### 3.2 Filesystem-scope tagging (Surface 2)

**Idea, adjusted for what §1.2 actually found:** don't build this around "flag calls outside a declared root" — the spec never enforced that, so a decoy modeling strict enforcement would test something real MCP servers never guaranteed either. Instead: add at least one filesystem-shaped decoy tool (there are currently none) that (a) issues a `roots/list` request per the spec's own message flow, logs whatever the client returns (or whether it returns nothing, which is itself informative — a client presenting itself as filesystem-capable while declining to enumerate roots is a signal), and (b) accepts a path-like argument on a subsequent call, logging whether the path falls inside any previously-declared root. The point isn't to enforce a boundary MCP itself doesn't enforce — it's to observe whether a real attacking client requests paths outside what it was told to consider relevant, which is exactly the AuthZed-shaped behavior (~340 files reached via portable handles) the issue's motivating incident describes.

**Assumptions:** requires adding new decoy tooling this sensor doesn't have (out of scope for this issue per its own "at most, instrumentation of an existing sensor's logging" boundary — flagging as a **follow-on**, not proposing to build it here).

**False-positive shape:** a legitimate agent operating without ever having received a `roots/list` response (because the client doesn't support `roots`, which is common and unrelated to malice) would trivially "violate" any path-based check — this signature is only meaningful when a root was actually declared and then exceeded, not on its absence.

### 3.3 MCP Apps rendering-layer canary (Surface 3)

**Idea, matching the issue's own comparison to #2689's agent-`llms.txt` supply-chain honeypot:** rather than trying to detect malicious HTML in general (a much harder, higher-false-positive problem, and one the spec's own iframe sandboxing/predeclaration/consent controls already partially address per §1.3), scope this narrowly to *deception*, the same way #2689 does: predeclare a `ui://` resource whose HTML visually imitates a **specific, known, static** consent/credential-prompt shape (not a generic phishing detector), and treat any interaction with that specific decoy surface as unambiguous, since a legitimate host-native consent dialog and this decoy resource are never the same DOM. Log the interaction (which button/field, timing, any submitted values) the same way #2689 logs supply-chain bait engagement.

**Assumptions:** requires MCP Apps/UI-resource support in the vendored `beelzebub` build at all, which does not currently exist (§2) — this is a larger lift than an instrumentation change, likely upstream feature work or a fork, and squarely a **follow-on**, not something to build under this issue's scope ("do not implement a new sensor end-to-end").

**False-positive shape:** near-zero for the interaction-with-decoy-surface signal itself (nothing legitimate should ever load *this specific* fake resource), but the signature is only as good as how convincingly the decoy imitates a real consent flow — a decoy that's too obviously fake teaches nothing about real attacker behavior against real MCP Apps UI.

### 3.4 A precondition worth stating plainly

All three signatures above lean on being able to correlate events to *the same client/session* over time. Per §2, this sensor currently has no such identity beyond raw source IP/port (`SourceIp`, `SourcePort`, `mcp.go:78-79`) — no session header was ever captured, and handles (once minted) aren't tracked. Any of 3.1–3.3 that involve "the same client did X then Y" are only as reliable as IP-based correlation, which is weak (NAT, proxies, agent-gateway fan-out — see the decoy tools' own `agent-gateway-01@nexusai.local` bait detail, which already anticipates a shared-gateway attacker shape). This is the honest limiting factor across all three proposals, not something any single signature design can route around.

## 4. What I could not verify

- Could not reach the raw MCP spec changelog/diff page directly (only the announcement blog and the individual `roots`/SEP-1865 pages, both of which are still primary — published by the protocol's own site, not a third party). If a reviewer wants the literal PR/diff, the spec announcement links `SEP-2577` (Roots deprecation) and PR `#1865` (MCP Apps) directly — I did not additionally pull those PR diffs.
- Did not attempt to independently verify the AuthZed incident details the issue and the Backslash post cite (the ~340-file/webhook-exfiltration story) — that's a third-party incident report, not something with a primary source available to check from here, and outside this issue's ask (verify the *spec* claims, not the *incident* claims).
- Did not check whether `mark3labs/mcp-go` (the underlying Go MCP library `beelzebub` builds on) exposes session/handle information at a lower level that `beelzebub`'s own code simply doesn't surface — establishing that would mean reading a second vendored dependency's source, which felt like it was drifting past this issue's "read what the sensors currently log" scope into "redesign the sensor," and I stopped at the layer `beelzebub` itself controls.
