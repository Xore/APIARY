# Research: MCPoison (CVE-2025-54136) vs the Beelzebub MCP sensor (#2649)

Verifies MCPoison's actual mechanism against primary sources, then checks it
against `honeypot-beelzebub`'s MCP strategy at the exact upstream commit this
repo pins (`39242822af79a59a6b8d0139adc4a8ccf2edec0c`, tag `v3.9.0`, per
`arcane/home/honeypot-beelzebub/beelzebub/Dockerfile:19`) by reading its
source directly, not by assuming the issue's "every MCP honeypot implements
the FastMCP middleware pattern" framing applies to ours. Gathered 2026-09-01.

**Scope, per the issue:** analysis only. No detection was implemented, no
Beelzebub config was touched.

## 1. What the source actually claims

Checked against the vendor's fix notes and independent technical write-ups
(Check Point's own post returned only a truncated fetch in this session —
noted as a gap below — so the mechanism is corroborated instead from
HackTheBox's and SentinelOne's independent technical summaries, both citing
the same PoC, plus the CVE record itself):

- **CVSS 3.1: 8.8 (HIGH)**, vector `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`.
  Confirmed via `cvedetails.com`/`tenable.com` CVE-2025-54136 records. The
  issue's severity claim is accurate.
- **The vulnerable component is Cursor 1.2.4 and below — the MCP *client*,
  not any MCP server.** Per the CVE description: *"attackers can achieve
  remote and persistent code execution by modifying an already trusted MCP
  configuration file inside a shared GitHub repository or editing the file
  locally on the target's machine. Once a collaborator accepts a harmless
  MCP, the attacker can silently swap it for a malicious command ... without
  triggering any warning or re-prompt."* The trust boundary bypassed is
  Cursor's own approval model for `.cursor/rules/mcp.json`: *"once an MCP is
  approved, future modifications to its command or arguments are trusted
  without any additional validation or prompt."* Persistence is client-side
  too — *"every time a project is opened in Cursor, the IDE scans for the
  `.cursor/` directory and automatically processes any MCP-related files
  inside it,"* re-executing the swapped command on every reopen.
- **Already fixed upstream**: Cursor 1.3 patches it. This is not an
  unpatched, actively-exploited-in-the-wild primitive at the time of this
  assessment — it's a disclosed-and-fixed client bug, corroborated by
  multiple independent write-ups agreeing on the same mechanism and fix
  version.
- **The exploit requires zero interaction with any MCP server at all.**
  Every step — committing the malicious config to a shared repo (or editing
  it locally), and Cursor silently re-trusting and re-executing it on next
  open — happens entirely on the victim's own machine, against the victim's
  own local MCP client configuration file. The "malicious command" example
  given (`calc.exe`) doesn't even need to speak the MCP protocol; it's an
  arbitrary local process launch. No MCP `tools/list`/`tools/call` JSON-RPC
  traffic to any server is a necessary part of the exploit chain.

## 2. What our sensors would see today

`honeypot-beelzebub`'s MCP strategy is
`internal/protocols/strategies/MCP/mcp.go` at the pinned commit, built on
`github.com/mark3labs/mcp-go v0.57.0` (`go.mod:10`) — a Go library, **not**
FastMCP (Python, `jlowin/fastmcp`). This is a direct correction to the
issue's claim that "every one of [the listed MCP honeypot projects, plus our
Beelzebub integration] implements the FastMCP middleware pattern that
MCPoison attacks" — ours demonstrably does not use FastMCP at all, and
MCPoison's PoC has nothing to do with any server-side middleware pattern in
the first place (see §1: it's a client-config bug).

Reading `mcp.go` in full:

- `Init()` runs once at service startup. It builds the tool set from
  `servConf.Tools` — YAML config baked into the image/compose stack at
  deploy time (`configurations/services/mcp-8000.yaml`) — and registers each
  tool via `mcpServer.AddTool(tool, func(ctx, request) {...})` (`mcp.go:70`).
  **There is no code path anywhere in this file, or in the upstream
  `mcp-go` server it wraps, that lets a connected MCP client modify a
  registered tool's command/args after `Init()` has run.** The tool set is
  fixed for the lifetime of the running process.
- Every tool invocation emits exactly one `tracer.Event` with a hardcoded
  `Status: tracer.Stateless.String()` (`mcp.go:76` — a compile-time
  constant, not derived from the request), `SourceIp`/`SourcePort` from the
  connecting peer, and `Command` set to
  `fmt.Sprintf("%s|%s", request.Params.Name, request.Params.Arguments)` —
  the raw tool name and arguments the *caller* sent on this one call.
- **Our sensor plays the MCP *server* role exclusively.** It has no MCP
  *client* component, no local `.cursor/`-style config file that a second
  actor with repo/workspace write access could poison, and no
  "project-level trust that persists across restarts without
  re-verification" concept at all — the only party that can change what
  tools this decoy serves is whoever redeploys the compose stack with a
  different YAML file, which is entirely our own operator-side action, not
  an attacker-controlled one via the protocol.

## 3. Which of the issue's premises survive

| premise | verdict |
|---|---|
| CVSS 8.8, HIGH severity | **confirmed** |
| Public PoC, corroborated by multiple sources | **confirmed** |
| "Not yet in CISA KEV at time of capture" | not independently re-checked here (KEV status is a moving target and not load-bearing for the finding below) |
| "Every [MCP honeypot project, incl. ours] implements the FastMCP middleware pattern that MCPoison attacks" | **false for our sensor** — ours is a Go implementation on `mark3labs/mcp-go`, not FastMCP, and MCPoison's mechanism doesn't touch server-side middleware of any framework (§1) |
| "What does an MCPoison-shaped attack look like in our telemetry" (implies our MCP sensor is a plausible target/vantage point) | **the premise is the wrong shape.** MCPoison is a vulnerability in a specific MCP *client* (Cursor ≤1.2.4, already patched) trusting a local/shared config file across restarts. Our sensor is an MCP *server*; it has no config file an external attacker can silently modify through the protocol, and the exploit itself generates no MCP server traffic at all (§1, §2). There is no server-observable signal corresponding to this CVE, because the entire exploit completes on the attacking developer's own machine before any MCP request would reach a server, decoy or real. |

The issue's proposed detection signature ("MCP tool entry modified
post-creation, args/command divergence from a known-good baseline") is not
buildable against this CVE from any server-side vantage point — not because
our sensor's telemetry is too weak to capture it (the usual honeypot-gap
framing), but because the exploited component and the observing component
are different, non-interacting systems. A Zeek-side monitor watching our
MCP traffic would see the same nothing our own sensor sees, for the same
reason: there is nothing MCP-protocol-shaped to see.

## 4. The gap, costed

There is no gap to close here in the sense the issue asks about (a
detection signature for MCPoison-shaped attacker behavior against our MCP
honeypot). Building either a per-tool integrity check inside the sensor or
an external Zeek-side monitor would instrument a mechanism (runtime tool
mutation over the wire) that:

1. does not exist in our sensor's architecture (tools are immutable for the
   life of the process, §2), and
2. would not detect the actual CVE even if it did, since the CVE's exploit
   never sends the honeypot a JSON-RPC request at all.

Cost of building either option: effectively wasted engineering effort
against a threat model that doesn't apply. **Zero container decision to
make** — the "one container or two" question in the issue's suggested next
step is moot because neither container has anything to observe.

The one adjacent, genuinely real question this CVE raises for APIARY is
**not** about the honeypot: if anyone on this project develops using Cursor
against this shared repository, an MCPoison-shaped attack against *that*
workflow (a malicious PR silently swapping a previously-approved
`.cursor/rules/mcp.json` entry) is a real supply-chain concern for the
engineering side, separate from anything the honeypot fleet observes. That
is a dev-security hygiene item (confirm no `.cursor/` MCP config is
committed to this repo, and if one ever is, treat every change to it as a
reviewable diff), not a sensor design question, and out of this issue's
scope ("assess against our MCP surface" — the decoy, not our own tooling). A
quick check: `git log --all --diff-filter=A -- '**/.cursor/**'` and a
present-tree `find . -path '*/.cursor/*'` both come back empty in this repo,
so there is currently nothing to harden here either.

## 5. Recommendation

**No sensor work, no follow-up issue.** MCPoison does not apply to
`honeypot-beelzebub`'s MCP mode: the vulnerable role (MCP client with a
locally-trusted, silently-mutable config) is a role our sensor does not
play, the specific vulnerable product (Cursor ≤1.2.4) is already patched
upstream, and the exploit chain never produces MCP server traffic for any
sensor — ours or a Zeek-side one — to observe. Filing a follow-up issue to
build detection here would be manufacturing work against a threat that
cannot reach this system, which is the failure mode this batch's own
instructions warn against ("reasoning from 'MCP honeypots implement the
FastMCP middleware pattern' to 'ours is vulnerable' without reading our
pinned commit").

The RedEvoAgent (arXiv 2608.27439) "attack-skill evolution" framing in the
issue is speculative on its own terms ("we should expect the pattern to
appear... within Q4 2026") and, per the above, would still need a
server-observable primitive to evolve *against* — there isn't one here for
this specific technique. Not pursued further; revisit only if a future CVE
describes a genuine MCP *server*-side trust bypass, which this one is not.

## What I could not verify

- `research.checkpoint.com`'s original write-up returned only a stripped
  page (title only) through this session's fetch tool; the mechanism above
  is instead corroborated across three independent secondary write-ups
  (HackTheBox, SentinelOne, the CVE aggregators) that all agree on the same
  technical description and fix version, plus the CVE record's own
  description text, which is itself close to primary. Did not additionally
  chase Zealynx's or Safeguard.sh's posts, since the CVE description alone
  already settled the one fact (client vs. server) that this assessment
  turns on.
- Did not independently verify current CISA KEV listing status — not
  load-bearing for the finding above either way.
