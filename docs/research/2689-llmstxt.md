# Research: the llms.txt supply-chain class and a proposed `honeypot-llmstxt` sensor (#2689)

Checks the PANDEX/Hertz 2026-08-28 disclosure against reachable primary and
secondary sources, then checks the two proposed detection ideas — a new
`honeypot-llmstxt` sensor, and agent-CLI parent-process tagging on existing
sensors — against how this fleet's sensors and Traefik/HTTP surface actually
work, by reading the code rather than the issue's summary. Gathered
2026-09-01.

**Scope: assessment only.** No package name was registered on PyPI or npm,
and no sensor was stood up.

To be clear about whose judgment that is: this is **this document's call,
and it overrides the issue.** The issue does not defer registration — it
presupposes it, describing the surface as pointing "at canary PyPI/npm
slots we have pre-registered." Nor does the issue contain a section
weighing how the proposal goes wrong. The argument for treating
registration as a separate, prior, irreversible decision is made in §5
below and is not attributable to the issue.

## 1. What the source actually claims

**The primary source is reachable and was fetched.** `whatwouldai.do` —
PANDEX Research's own site, which the issue names as the primary — returns
**HTTP 200**. An earlier draft of this document did not attempt it and
should not have described the primary as unavailable. What it publishes is
the *method* and the finding taxonomy, not the headline counts:

- Method, in its own words: pull every `llms.txt` the company directories
  list; run real agents against a company's own material in a sandbox and
  watch what they fetch and run; resolve every external asset the agent
  reaches against the registry that would serve it (npm and PyPI for
  packages, RDAP for hosts).
- Finding taxonomy, rated CRITICAL by PANDEX: packages nobody has published
  (first-come registry names); domains anyone can buy (expired/typo'd hosts,
  including free-tier Render/Vercel/Netlify/Fly subdomains); instructions
  aimed at the agent (directives addressed to the model, bidi overrides,
  Unicode tag smuggling, zero-width splitting); and commands it will run.
- It links the write-up as published on Medium and "also posted on Ars
  Technica."

This matters for our purposes: PANDEX's own "instructions aimed at the
agent" category is a *content* class, independent of package registration —
which supports the split this document recommends in §5.

The narrative article itself (Hertz's Medium post) and `cybernews.com` both
return HTTP 403 to a scripted fetch (bot protection, not absence);
`arstechnica.com` likewise 403s a bare `curl`. The numeric claims below are
therefore corroborated across `gbhackers.com`, a WebSearch aggregate
spanning `startupfortune.com`/`cyberpress.org`/`webpronews.com` summaries,
and — for the Clerk incident specifically — a second independent search
converging on the same MAL/CWE identifiers. Where a specific technical
detail could not be independently confirmed, it's flagged rather than
repeated as fact.

- **Scan scope and headline numbers — corroborated**: 8,565 `llms.txt`/
  `llms-full.txt` files resolved across 6,214 live domains, spanning
  Fortune 500/defense/Big Tech. 120 files contained 227 install commands
  pointing at unregistered package names or unclaimed domains. (An earlier
  draft added "~15,000 companies surveyed"; that figure appeared in no
  source this document can cite, is absent from the primary site, and has
  been dropped rather than carried forward unattributed.)
- **Live callbacks from real corporate networks — corroborated**: first
  Fortune 500 callback in under 4 minutes, second within the hour, "a few
  dozen more" total, spanning startups and enterprises.
- **Three named coding-agent brands (Claude/Codex/Hermes) confirmed as the
  process that ran the install — could not independently verify the
  identification mechanism.** Every reachable secondary source states the
  fact (three agents ran the installs) without describing *how* the
  researchers attributed a given callback to a specific agent brand.
  `gbhackers.com`'s summary explicitly notes the packages were benign,
  deployed no persistence, and collected no sensitive data — consistent with
  a narrow, deliberately limited telemetry payload — but does not say
  whether attribution came from a parent-process name, an environment
  variable, a working-directory/lockfile fingerprint, or something else
  entirely. **This matters directly for §3**: the issue's proposed Cowrie
  enrichment assumes the *same* mechanism (parent-process name inspection)
  works for an inbound network protocol, which is a different situation
  from a callback that executes locally on the machine that ran the install
  (§2 explains why).
- **The Clerk incident — corroborated with primary-source current-state
  check**: MAL-2026-11069 / CWE-506, flagged by Google OSV.dev and Amazon
  Inspector, is independently corroborated by a second search converging on
  the same identifiers. One aggregate summary states the technique "evaded
  endpoint detection because every observable signal appeared legitimate:
  HTTPS delivery from a trusted vendor domain, standard package manager
  traffic to allowlisted registries, and execution via an agent the
  organization intentionally installed" — a sharper articulation of *why*
  this class is hard than the issue itself gives. Fetching `clerk.com/llms.txt`
  directly today shows no npx/npm install command with a bare package name
  at all (the CLI section describes installation only in prose) — consistent
  with "disclosed to Clerk, resolved."

## 2. What our sensors would see today

**Serving a crafted `llms.txt` needs no new container.** Reading
`docs/SENSORS.md`'s sensor table: `http-honeypot` already serves "fake nginx
/ login pages" via Traefik and a raw port, and `api-honeypot` is *the same
binary* already purpose-built for "cloud metadata, Kubernetes, registry,
DevOps and LLM API probes." A static `llms.txt` route is an additive path on
an existing Go binary this fleet already runs and already logs through the
same ES pipeline — not a new nginx deployment as the issue's design sketch
assumes. This directly changes the "one container or two" costing in the
issue's own framing: for the *serving* half, it's zero new containers.

**The callback-capture half is genuinely new, and its mechanism is sound —
but for a different reason than the issue's parallel proposal for existing
sensors.** The canary package's install hook runs *on the machine that ran
the install* (the coding agent's own sandbox, or its host) and
self-reports over an outbound HTTP call — this is exactly how the primary disclosure's own beacon
worked (§1), and it's a legitimate, implementable pattern: our canary
package's postinstall/on-load code executes with the same privilege as the
`npm install`/`pip install` that triggered it, so `process.cwd()`,
`process.env`, and even a local `ps`-style parent-process walk are all real,
locally-available data *on the victim's own machine*, phoned home to us.
Nothing about this needs correction; it's the sound half of the proposal.

**The proposed "existing sensor enrichment" (agent-CLI parent-process
tagging on Cowrie/Dionaea/Conpot/Beelzebub) does not work as described, and
this is worth stating plainly rather than building around a silent gap.**
Read Cowrie's transport handling directly
(`src/cowrie/ssh/transport.py`, pinned commit `ced855a5cda953eb4ad439d8ee8060afe4234fe4`,
confirmed against `arcane/home/honeypot-cowrie/cowrie/Dockerfile:30`):
line 155 captures `self.otherVersionString` — the SSH client's own version
banner, sent over the wire during the protocol handshake — and emits it as
the `cowrie.client.version` event (line 158-160).

That is not the only client-identity signal available, and an earlier draft
of this document wrongly said it was. At the same pinned commit there are
two more, both client-sent and both already captured:

- **`cowrie.client.kex`** (`transport.py:253`) — the client's **hassh**
  fingerprint plus the raw algorithm lists it offered (`kexAlgs`, `keyAlgs`,
  `encCS`, `macCS`, `compCS`, `langCS`). This fingerprints the SSH
  *implementation and its build-time algorithm ordering*, which is
  materially sharper than the version banner.
- **`cowrie.client.var`** (`session.py:42`) — environment variables the
  client asks the server to set, captured as `name`/`value` pairs. This is
  precisely the "env-var fingerprints that identify the agent framework"
  the issue asks about, and it is already flowing today.

What remains structurally true — and it is the load-bearing finding — is
narrower: SSH (like every other protocol our raw-tunnel sensors speak) is a
network protocol, so the connecting party's local **process tree** lives on
*their* machine and is never transmitted to ours. The issue's
proposed mechanism — "a host-level process enumeration at the moment of
session open... detect any parent process on the host named `claude*` /
`codex*` / ..." — describes inspecting processes on **our own sensor host**,
which would only ever show our own container's processes (Cowrie's Python
interpreter, system daemons), never the remote attacker's client process.
There is no `/proc` entry, cgroup, or `ps` output on our side that
corresponds to a process running on a machine across the internet. This
isn't a capability gap to close with more instrumentation; it's not
observable by definition, for the same structural reason #2649 found
MCPoison unobservable from a server vantage point.

### Re-answering the issue's second question against the signals that exist

The question worth answering is not "can we read the remote process tree"
(no) but "do the three client-sent signals we already capture separate
agent-driven from human-driven SSH?" Taken one at a time:

- **Version banner** — no. An agent CLI orchestrating SSH does so through a
  standard library (the system `ssh` binary via subprocess, Paramiko,
  libssh2, Go's `x/crypto/ssh`), and the library owns the banner. An agent
  shelling out to the real `ssh` presents byte-for-byte what a human typing
  `ssh` presents.
- **hassh** (`cowrie.client.kex`) — better, same ceiling. hassh fingerprints
  the *library and its algorithm ordering*, so it separates Paramiko from
  OpenSSH from Go's `x/crypto/ssh` quite sharply. That is a real
  discriminator when an agent uses a library a human at a shell would not,
  but it still identifies the library, not the thing driving it. An agent
  invoking the system `ssh` binary is hassh-identical to a human.
- **Client-sent env vars** (`cowrie.client.var`) — the only one of the three
  that could carry an agent-framework fingerprint, and the one the issue
  actually asks for. Its ceiling is different in kind: it depends entirely on
  what the client volunteers. OpenSSH sends nothing by default —
  `SendEnv`/`SetEnv` is opt-in and typically limited to `LANG`/`LC_*`. So
  this is high-value-when-present and absent by default, not a reliable tag.

**Net:** the issue's proposed `agent_mediated: true` tag cannot be built the
way it describes, and cannot be built reliably from what SSH carries either.
But `cowrie.client.var` is worth *looking at* rather than dismissing — an
agent framework that does set a distinguishing variable would already be
landing that value in our events today. Checking whether any captured
`cowrie.client.var` value has ever looked agent-shaped is a cheap query
against data we already hold, and is a better next step than the host-level
`ps` snapshot the issue proposes. It is not attempted here.

## 3. Which of the issue's premises survive

| premise | verdict |
|---|---|
| Scan scope, headline callback numbers, Clerk MAL-2026-11069/CWE-506 identifiers | **corroborated** across independent sources |
| Beacon parent-process chain "confirmed three coding agents" | **partially unverifiable** — the fact is corroborated, the specific attribution mechanism is not documented in any source reachable from here; treat as established outcome, unconfirmed method |
| `honeypot-llmstxt` needs a new nginx container to serve the file | **false** — `http-honeypot`/`api-honeypot` is an existing binary already purpose-built for LLM/API-probe bait and already wired into this fleet's ES pipeline; serving is additive, not new infrastructure |
| Canary-package install-hook callback capturing local machine state (cwd, env, parent process) is a sound, implementable telemetry mechanism | **confirmed sound** — matches the primary disclosure's own technique and requires no new capability our fleet lacks (an HTTP callback endpoint), only the (out-of-scope, correctly deferred) package registration decision |
| "Existing sensor fingerprinting (Cowrie/Dionaea/Conpot/Beelzebub) can extend to flag agent-CLI parent processes via host-level `ps` at session open" | **false as designed**, but the issue's underlying question is better served than an earlier draft of this document allowed. The mechanism cannot work: these are inbound-connection sensors and the peer's process tree is never network-visible. However Cowrie already captures three client-sent signals, not one — version banner, **hassh** (`cowrie.client.kex`) and **client-set env vars** (`cowrie.client.var`), the last being exactly the "env-var fingerprints that identify the agent framework" the issue asks for. Banner and hassh identify the SSH *library*, not the orchestrating agent; `cowrie.client.var` could identify the framework but is absent unless the client volunteers it (OpenSSH sends nothing by default). So no reliable `agent_mediated` tag — but see §2 for the cheap query worth running against data we already hold |

## 4. The gap, costed

Two genuinely separable pieces, with very different cost and risk shape —
this is itself a finding the issue's single combined framing obscures:

**Serving the bait file — cheap, reversible, one existing container.** Add
one more static route (a hardcoded `llms.txt` response) to the
`http-honeypot`/`api-honeypot` binary, logged the same way every other probe
path already is. No new container, no new ES index needed beyond what that
binary already writes to. Low cost, fully reversible (delete the route).

**Registering canary package slots and standing up a callback listener —
expensive in a way that doesn't reverse.** This is this document's
judgment, and it goes against the issue, which treats the slots as already
pre-registered rather than as a decision to be weighed. The reasons:

- A registered PyPI/npm package name is a public, permanent artifact tied to
  whatever account registers it — it cannot be quietly deleted the way a
  compose file can be reverted, and per house rule 2 in the batch
  instructions, it must not carry any string identifying this project
  (`apiary`, `honeypot`, or an internal handle) in the package itself, its
  metadata, or its `llms.txt` reference — meaning the naming/legal/ownership
  decision has to be made *before* anything else here, not derived from the
  sensor design.
- A live install hook that calls home from an attacker's/agent's own
  machine is executing our code inside systems we don't control, on
  networks we don't control — a materially different risk posture than
  every other sensor in this fleet, all of which run entirely inside our own
  containers. The issue's own severity section already names this
  (sensor-container isolation for the canary code) but the actual
  registration step is the irreversible action, not the isolation
  engineering around it.
- The callback ingress needs a new internet-facing endpoint (the issue's
  option (a), Cowrie/Dionaea's own pattern) — a new piece of public attack
  surface distinct from the bait file itself, since it has to accept
  arbitrary inbound HTTP from anywhere a canary package might get installed,
  not from a fixed decoy IP range the way our other sensors implicitly
  assume.

**Existing-sensor "agent_mediated" tagging — not worth building as
proposed.** Per §2/§3, the mechanism described doesn't observe what it
claims to. A cheaper, honest alternative — tagging Cowrie sessions by SSH
client version string alone — already has the data captured
(`cowrie.client.version`) and needs no new work, but should not be labeled
"agent-mediated," only "client library observed," since that's what the
signal actually says.

## 5. Recommendation

**Split the issue's single proposal into two, and treat them very
differently:**

1. **The bait-file half (serving a crafted `llms.txt` off the existing
   `http-honeypot`/`api-honeypot` binary) is low-cost and worth a follow-up
   implementation issue** — it needs no package registration, no new
   internet-facing service, and produces real telemetry (which UAs/IPs fetch
   `llms.txt` at all, a signal this fleet currently has zero visibility
   into) even before any canary-package decision is made.
2. **The canary-package-registration half needs its own decision record
   first, not a sensor-design issue.** Per §4, the naming/ownership/legal
   question is irreversible and prior to any container-layout question. This
   should not be scoped as "design the sensor" — it should be scoped as
   "decide whether APIARY registers and operates public package-registry
   identities at all," a decision this research pass is not positioned to
   make on the project's behalf given the batch's explicit instruction not
   to touch PyPI/npm.
3. **Do not build the proposed Cowrie/Dionaea/Conpot/Beelzebub
   parent-process enrichment as described** — it instruments a signal that
   does not exist for an inbound-connection sensor. If agent-vs-human SSH
   traffic is worth distinguishing at all, that's a separate, much weaker
   research question (can SSH client version strings or timing/command-
   cadence patterns distinguish agent-driven sessions?) than what this issue
   proposes, and not costed here.

**Follow-up issues filed**: none yet. Recommend the project decide item 2
above (package-registry identity ownership) before either #2689's bait-file
half or a Cowrie-enrichment follow-up is filed as an implementation issue,
since the naming decision affects both.

## What I could not verify

- The primary site `whatwouldai.do` **was** reached (HTTP 200) and its
  method and finding taxonomy are quoted in §1. What it does not publish is
  the headline counts or the agent-attribution mechanism.
- Hertz's own Medium post and `cybernews.com` both 403'd to a scripted
  fetch, as does `arstechnica.com`; these are bot-protection responses, not
  evidence the articles are gone. Relied on gbhackers.com plus WebSearch
  aggregates for the numeric claims. The specific agent-attribution
  mechanism (§1, §3) could not be confirmed from any source reachable here.
- The "~15,000 companies surveyed" figure carried by an earlier draft was
  dropped: it is absent from the primary site and no citable source for it
  was found.
- The `cowrie.client.var` query proposed at the end of §2 — whether any
  captured client-set env var has ever looked agent-shaped — was **not**
  run. It is cheap and worth doing before anyone revisits the tagging idea.
- Did not attempt to reach `startupfortune.com`/`webpronews.com`/
  `cyberpress.org` articles individually beyond what WebSearch's own
  aggregate summary surfaced; treated as secondary corroboration, not primary.
- Did not check whether Dionaea/Conpot/Beelzebub's own vendored source
  captures anything equivalent to Cowrie's SSH version string for their
  respective protocols — the structural argument (network protocols don't
  transmit the peer's local process tree) holds regardless of protocol, so
  this wasn't needed to reach the conclusion in §2/§3, but a
  protocol-by-protocol audit of what *is* captured was out of scope here.
