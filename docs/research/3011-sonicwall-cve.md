# Research: CVE-2026-83548/83549 — SonicWall SMA1000 SSRF+RCE chain — fleet coverage (#3011)

Checks whether this fleet runs or emulates the affected SonicWall SMA1000
surface, what the existing generic decoys would make of an exploitation
attempt, what the fleet's own IDS already carries, and whether a new dedicated
decoy is warranted. Gathered 2026-09-05, re-derived against `origin/main` and
against the live VPS IDS.

**Scope, per this batch's house rules (established in #2861/#2919):**
analysis. No sensor was built, no persona classification was added, nothing
was deployed.

## 1. Does this fleet run or emulate SonicWall SMA1000 anywhere?

**No — confirmed by grep over every tracked file, not assumed from the
sensor list.**

```
$ git grep -i -l -E "sonicwall|sma1000|SMA 1000" origin/main -- .
(no output, exit 1)
```

`docs/SENSORS.md`'s full sensor table (checked directly) has two other
edge/VPN-appliance decoys — `citrix-honeypot` (line 19: Citrix ADC/NetScaler
Gateway, CVE-2019-19781) and `cisco-asa-honeypot` (line 20: Cisco ASA WebVPN +
IKE, CVE-2018-0101) — but no SonicWall entry of any kind. This fleet has no
SonicWall SMA1000 exposure, self-hosted or decoy, to patch or audit. The KEV
deadline of 2026-09-05 does not apply to anything here.

## 2. Would a SonicWall-shaped probe be recognized as one?

**Only as undifferentiated noise, checked by reading the generic HTTP
classifier directly (`arcane/home/honeypot-http/http-honeypot/main.go`,
`classify()` at 633-695, `classifyPayload()` at 330-490).**

The issue's proposed decoy-side signature targets `/cgi-bin/` Work Place-relay
paths reaching AMC (Appliance Management Console) endpoints. `classify()` has
a `cgi-bin` bucket:

```go
// main.go:676-678
case strings.Contains(p, "cgi-bin"), strings.Contains(p, "shell"),
    strings.Contains(p, "boaform"), strings.Contains(p, "hnap"):
    return "rce-probe"
```

Note the return value is **`rce-probe`** — `"shell"` is a sibling match
pattern in the same case list, not the classification. So today's coverage is
better than "generic scan": a `/cgi-bin/` probe is already tagged as an
RCE-class probe. It is still undifferentiated, though: every unrelated
`cgi-bin` scanner on the open internet lands in the same bucket, and nothing
in either `classify()` or `classifyPayload()` distinguishes a Work Place → AMC
SSRF chain attempt from that background. Two further caveats:

- The switch is ordered, and `login`/`admin` (:673-675 → `login-probe`) and
  `config`/`secret` (:638-641 → `secret-hunt`) are matched *before* `cgi-bin`.
  A Work Place path containing any of those substrings never reaches the
  `rce-probe` case at all.
- Stage two (OS command injection in AMC) has no bucket whatsoever — AMC's
  route family is Struts-style `.action`, which falls to the `default: "scan"`
  arm.

**The SSRF half's canonical target is emulated here, and it is worth naming.**
`docs/SENSORS.md:23` lists **`api-honeypot`** — raw 8888 → `10.8.0.2:18083`,
raw tunnel + PROXY, same binary as http-honeypot — described as *"cloud
metadata, Kubernetes, registry, DevOps and LLM API probes"*. It serves fake
EC2 IAM credentials at `/latest/meta-data/iam/security-credentials/worker-node`
(`main.go:810-812`, an `ASIAFAKEDECOY…` key), a GCP `/computeMetadata/v1` and
Azure `/metadata/instance` instance document (`main.go:822-824`), and
`classify()` has a dedicated `cloud-metadata` bucket at `main.go:679-681`.
A probe for `169.254.169.254`-style metadata paths landing on this fleet today
therefore produces a classified `cloud-metadata` event *and* a plausible
credential the attacker may go on to use — which is the observable half of an
SSRF chain we already have. What is missing is the *relay*: nothing in this
fleet accepts an attacker-supplied URL and fetches it, so the SSRF itself
cannot be observed, only its intended destination shape.

**On the issue's second proposed signal** — outbound requests to
`169.254.169.254` from an appliance-class sensor host as evidence of
successful SSRF — the previous draft of this note claimed no decoy makes
outbound requests while handling inbound traffic. That is wrong: `galah`
(`docs/SENSORS.md:29`) generates its response via the shared Ollama instance
through `galah-llm-broker`, an outbound call made while serving the inbound
request (galah's own response caching means only the first hit on a given
request shape pays it). The conclusion survives, but on the real basis:

- No decoy fetches an *attacker-controlled* URL. galah's egress goes to one
  fixed broker upstream, so it can never be steered at link-local metadata.
- More decisively, there is no monitored egress point to attach the signal to.
  Suricata runs `network_mode: host` on the VPS's public NIC (`-i eth0`,
  `HOME_NET` = the VPS public `/32`) with
  `bpf-filter: "not udp port 51820"` (`vps/suricata/suricata.yaml:239-241`)
  excluding the WireGuard tunnel. The decoys run on the homeserver behind that
  tunnel, so homeserver-side container egress never crosses the monitored
  interface regardless of which container makes it.

## 3. What the fleet's detection layer already carries

This repo does carry detection content — `vps/suricata/` holds
`rules/honeypot-web.rules` (SID range 92040000-92049999),
`rules/honeypot-scan.rules`, `rules/honeypot-ics.rules`, `suricata.yaml`,
`disable.conf`, `threshold.config`, `vps/suricata-rules-refresh.sh` and
`docs/vps/suricata/README.md`. `hp-suricata` was up 36h at time of writing
with 79,746 rules loaded (ET Open + oisf/trafficid + abuse.ch + etnetera +
tgreen, refreshed 2026-09-05 23:29), and the repo's own `HONEYPOT-WEB` /
`HONEYPOT-SCAN` rules are firing in today's `eve.json`.

Checked against that live ruleset:

| check | result |
|---|---|
| `grep -ci sonicwall` | 74 rules |
| `grep -ciE "sma1000\|sma 1000"` | 2 rules |
| `grep -cE "2026-83548\|2026-83549"` | **0** |

The issue body's claim that the "detection content gap is total" is therefore
independently confirmed on this fleet's own IDS, not merely asserted. The two
SMA1000 rules are for other CVEs, and only one of them could ever fire here:

- `sid:2056308` — *SonicWall SMA1000 Directory Traversal (CVE-2023-0126)*,
  `alert http any any -> $HOME_NET 8443`. Port-locked to 8443, which on this
  fleet is `cisco-asa-honeypot`'s TLS WebVPN listener. That traffic is
  encrypted end to end at the decoy, so this rule is structurally dead here.
- `sid:2071214` — *SonicWall SMA1000 AMC Authenticated Path Traversal
  (CVE-2026-15410)*, `alert http any any -> [$HOME_NET,$HTTP_SERVERS] any`,
  matching `http.uri content:"/rollbackConfirm.action"` plus a POST body
  `hotfix=`, `reference:url,rapid7.com/…sma1000-zero-days…`. Port-agnostic and
  cleartext-matchable, so this one **would** fire against the raw-tunnelled
  cleartext HTTP decoys (`tcp:8081:10.8.0.2:19081:pp`,
  `tcp:8888:10.8.0.2:18083:pp`) if anyone probed that route at them.

So the fleet has exactly one live SMA1000 detection path today, for a
different CVE, on the generic HTTP decoys.

## 4. Could a cheap detection change have shipped here?

The previous draft of this note asserted there was "no cheap one-line
classifier fix available". That was wrong as stated — the option exists and is
worth naming precisely so the judgment can be made on the facts:

- **The vehicle exists and demonstrably works.** `vps/suricata/rules/honeypot-web.rules`
  is the fleet's own honeypot-scoped rule file with a documented free SID range
  (92040000-92049999), and its header explicitly covers this traffic: *"the
  raw-tunnelled :8081 http honeypot and plain :80 decoy traffic are
  inspected"*. That is not theoretical — `HONEYPOT-WEB Local/Remote file
  inclusion attempt in URI`, an `http.uri` rule from that same file, fired 72
  times in the 23:00 hour of today's `eve.json`. A honeypot-scoped rule over
  the cleartext decoy streams is a real, in-house, precedent-backed option.
  (Contrast `citrix-honeypot`, which terminates its own TLS on 4443 and is
  genuinely opaque — see #2977's note.)

**Judgment: still premature, but for a content reason, not a vehicle one.**
The vendor released no IOCs for CVE-2026-83548/83549 and no public PoC gives
the literal Work Place relay path or the AMC command-injection parameter. The
only primary-sourced SMA1000 route shape available — `/rollbackConfirm.action`
from `sid:2071214` — belongs to CVE-2026-15410, and that rule is *already
loaded*, so writing our own copy of it adds nothing. Writing a rule for
`.action` generally would fire on every Struts-convention URL on the internet;
writing one for a guessed `/cgi-bin/` Work Place path would be exactly the
false-precision failure #2919's confirm-before-classify discipline exists to
prevent, with the extra cost that a decoy-scoped rule reports *every* hit as
malicious by construction.

The concrete trigger for revisiting: the moment a literal path or parameter
for either CVE is published (vendor IOC, PoC, or a real hit observed against
the generic decoys), a `honeypot-web.rules` entry in the 9204xxxx range over
the `:8081` / `:8888` cleartext streams is the cheapest available coverage and
should be written then. Noted on #3033.

## 5. Is a new dedicated decoy warranted?

**Yes, in principle, but it is new decoy capability, not a config or
detection-query change — out of scope for this research row (same disposition
as #2861's Artifactory finding, not #2919's Switchvox finding).**

The two existing edge-appliance decoys (`citrix-honeypot`,
`cisco-asa-honeypot`) establish a working pattern this CVE fits cleanly: a
small Go service presenting a login/portal page, TLS self-signed at startup,
PROXY-protocol fronted, unconditional per-request logging
(path/headers/UA/JA3/JA4) regardless of path match, plus specific classified
event types for the CVE(s) it is built to detect. A SonicWall SMA1000 decoy
following the same shape would need:

- a Work Place-style login/portal page (the pre-auth entry point)
- recognition of the SSRF-shaped relay request (`/cgi-bin/...` paths that, on
  a real appliance, reach the internal AMC) — classified as a distinct
  `cve_2026_83548_ssrf_probe` event, not lumped into the generic `rce-probe`
  bucket
- a synthetic internal-AMC "hop" response (the issue's own suggestion) so the
  decoy can also capture stage two (the `cve_2026_83549` command-injection
  payload) rather than only the entry probe — this is what makes it worth a
  dedicated decoy rather than a classifier tweak: the generic HTTP decoy has
  no AMC-shaped internal surface to relay to, so the full chain can never
  complete far enough to be observed end to end. `api-honeypot`'s metadata
  surface (§2) is the natural relay destination to point it at, which would
  make the SSRF itself observable for the first time in this fleet
- its own persona/asset identity, port, compose entry, docs update
  (`docs/SENSORS.md`), and retention-parity coverage
  (`scripts/check-json-sink-retention-parity.py`, per #2892's ledger)

That is a genuine new-service build (Dockerfile, Go binary, compose
integration, dashboard sensor registration, persona design review) — not
achievable within this research row's scope. Filed as **#3033**.

## 6. What was not verified

- Did not re-check the advisory's own numbers (CVSS 10.0, affected firmware
  ranges, the July MFA-seed compromise claim) against a primary source — the
  fleet-exposure question (§1) does not depend on those figures being exact.
- Did not search for a public PoC or vendor IOC for either CVE; §4's judgment
  is that none was available as of 2026-09-05, and that is the condition it
  asks to be revisited on.
- Nothing was deployed and no rule was written, so there is nothing here to
  verify live beyond the read-only checks above.

## 7. Bottom line

**No fleet exposure to defend** — no self-hosted SonicWall SMA1000 anywhere,
no decoy presenting that surface, nothing in scope for the KEV deadline. A
Work Place → AMC probe against the generic HTTP decoy today classifies as
`rce-probe` (or as `login-probe`/`secret-hunt`, depending on the path
substrings) — recorded, RCE-flagged, but indistinguishable from routine
`cgi-bin` scanning, with no bucket at all for the chain's second stage. The
fleet's IDS carries 74 SonicWall rules, 2 SMA1000-specific, **0** for this CVE
pair, and only one of the two SMA1000 rules can fire here at all. A
honeypot-scoped Suricata rule over the cleartext decoy streams is a real
option and the right vehicle when a literal path lands; it is not written now
because no primary source gives one. A dedicated SonicWall SMA1000 decoy —
with `api-honeypot`'s metadata surface as its relay target — is the
substantive follow-up, tracked in #3033.
