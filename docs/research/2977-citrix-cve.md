# Research: CVE-2026-19490 — Citrix NetScaler ADC/Gateway auth bypass — citrix-honeypot coverage (#2977)

Checks whether this fleet's existing Citrix decoy plausibly presents as the
affected surface (an AAA virtual server or Gateway configured with a SAML
Action), whether it would capture exploitation attempts, and what detection
the fleet already has. Gathered 2026-09-05, re-derived against `origin/main`
and against the live VPS IDS.

**Scope, per this batch's house rules (established in #2861/#2919/#2903):**
analysis, plus a classifier/detection change only where the exact request
shape can be confirmed against a primary source — not a new honeypot service,
not a new exposed port, not a change to what the decoy *serves*.

## 1. Does this fleet present a Citrix ADC/Gateway surface?

**Yes — `citrix-honeypot`** (`arcane/home/honeypot-citrix-honeypot/citrix-honeypot/`),
a Go port of `t3chn0m4g3/CitrixHoneypot`, exposed on raw port 4443 (→
container 443) with its own self-signed TLS certificate, PROXY-protocol
fronted (`docs/SENSORS.md:19`; portbridge rule `tcp:4443:10.8.0.2:443:pp` in
`vps/docker-compose.yml:567`). This is the right product family — the CVE's
affected surface (NetScaler ADC/Gateway) is exactly what this decoy
impersonates.

## 2. Is it plausible as *this specific* vulnerable configuration?

**No, not without changes, checked by reading the handler directly rather
than assumed from the persona name.**

`main.go`'s comment header states the decoy's actual scope precisely: *"a
Citrix ADC/NetScaler Gateway decoy for CVE-2019-19781 (path traversal ->
arbitrary file read / RCE via newbm.pl)"* — a different CVE, a different
vulnerability class (path traversal, not auth bypass), from 2019.

`serveGET` (`main.go:231-269`) and `servePOST` (`main.go:271-284`) only
recognize:

- `/` and `/vpn` → the login page (`pages.go`'s `citrixLoginPage`)
- `/vpns/...` paths containing a literal `/../` traversal → CVE-2019-19781's
  three scan/completion/payload event types
- everything else → an empty 200, logged generically as `get`/`post`

CVE-2026-19490's affected surface per the issue body is an **AAA virtual
server or Gateway configured with a SAML Action** — SAML-relying-party
endpoints and the AAA authentication flow. None of those paths exist in the
handler. The login page itself (`pages.go`, 68 lines) is the generic upstream
HTML with no version banner, no SAML configuration indicator, and no
AAA-specific endpoint, so a scanner fingerprinting for "is this box configured
as an AAA/SAML Gateway" (as opposed to a bare Gateway) finds nothing
distinguishing this decoy as the vulnerable configuration class.

That distinction matters more than the classifier question: a scanner that
fingerprints the decoy as a bare Gateway never sends the exploit traffic in
the first place, so no amount of later classification recovers it.

## 3. Would exploitation attempts still be captured, even unclassified?

**Partly. Not fully — this decoy discards the query string.**

The good half: `h.log2` (defined `main.go:187`, called unconditionally at
`main.go:232` and `main.go:273`) runs at the top of both `serveGET` and
`servePOST` before any path-specific branching, so every request's path,
method, full header set, User-Agent and (per #414) JA3/JA4 TLS fingerprint are
logged regardless of whether the path matches a known pattern. A request to an
unrecognised path does not silently disappear.

The bad half:

```go
// main.go:217 -- the only r.URL reference in the entire file
reqPath := r.URL.Path
```

`r.URL.Path` excludes `RawQuery`; `reqPath` is the only value ever handed to
`h.log2`; the `event` struct (`main.go:52-68`) has no query field; `Data` is
populated on POST only. So for a GET there is no field anywhere in the emitted
document that holds `?...`. Nothing downstream recovers it either — this
sensor is raw-tunnel + PROXY, not Traefik-routed, so there is no proxy access
log holding the request line, and it terminates its own TLS, so the VPS
Suricata sees ciphertext (§5). The sibling generic decoy does it correctly
(`http-honeypot/main.go:743` emits `Query: r.URL.RawQuery` and classifies on
it at :748), so this is an inconsistency, not a design choice.

This matters directly here: #2977's own stated traffic of interest is
"SAML-related parameter probing", and one of the confirmed NetScaler
auth-surface shapes below (`/wsfed/passive?wctx=...`, CVE-2026-3055 M1) is
identified *by its query string*. For that traffic the data is lost, not
merely unlabelled. Filed as **#3044**; it is a prerequisite for full-fidelity
capture on this surface and is not fixed here.

## 4. What the fleet's detection layer actually says

This repo does carry detection content — `vps/suricata/` holds
`rules/honeypot-web.rules` (SID range 92040000-92049999),
`rules/honeypot-scan.rules` (92050000-92059999),
`rules/honeypot-ics.rules` (92010000-92039999), plus `suricata.yaml`,
`disable.conf`, `threshold.config`, `vps/suricata-rules-refresh.sh` and
`docs/vps/suricata/README.md`. It is live, not aspirational: `hp-suricata` on
the VPS was up 36h at time of writing with 79,746 rules loaded (ET Open +
oisf/trafficid + abuse.ch + etnetera + tgreen, refreshed 2026-09-05 23:29),
and the repo's own `HONEYPOT-WEB` / `HONEYPOT-SCAN` rules are firing in
today's `eve.json`.

Checked against that live ruleset:

| check | result |
|---|---|
| `grep -ci citrix` | 51 rules |
| `grep -ci netscaler` | 30 rules |
| `grep -c 2026-19490` | **0** |

So the fleet has broad Citrix/NetScaler ET coverage and nothing for this CVE —
consistent with a CVE patched mid-August 2026 whose PoC only surfaced in early
September.

**But the more important finding is structural: none of those 51 rules can
ever fire on this fleet's own Citrix decoy.** Suricata runs `network_mode:
host` on the VPS's single public NIC (`-i eth0`, `HOME_NET` = the VPS public
`/32`), with `bpf-filter: "not udp port 51820"` excluding the WireGuard tunnel
to the homeserver (`vps/suricata/suricata.yaml:239-241`). citrix-honeypot is
tunnelled raw (`tcp:4443:10.8.0.2:443:pp`) and terminates its own TLS, so what
crosses the monitored interface is an opaque TLS stream. `honeypot-web.rules`'
own header states the same constraint for the Traefik `:443` path: *"traffic
that arrives TLS-encrypted through Traefik on :443 is opaque to Suricata"*.
Only `tls`/JA3 rules can match this sensor's traffic.

**The decoy's own classifier is therefore the only viable detection point for
this sensor** — which is why §5 does the work in the sensor rather than in a
Suricata rule.

## 5. What was changed, and what was deliberately not

### Changed: the auth-surface probe is now classified

Added `authSurfaceEvent` (`main.go`) plus two call sites in
`serveGET`/`servePOST`. A request to a known NetScaler AAA / SAML / OAuth
endpoint now emits a second, classified event alongside the unconditional
`get`/`post` one:

| event | paths |
|---|---|
| `netscaler_saml_surface_probe` | `/saml/login`, `/cgi/samlauth`, `/wsfed/passive`, `/cgi/logout` |
| `netscaler_oauth_surface_probe` | `/oauth/idp/.well-known/openid-configuration`, `/oauth/rp/.well-known/openid-configuration` |
| `netscaler_aaa_surface_probe` | `/p/u/doAuthentication.do` |

Every literal is taken from an ET signature **already loaded on this fleet's
own Suricata**, each carrying a vendor-research reference — not guessed from
the shape of a NetScaler URL:

```
sid 2048930  /oauth/idp/.well-known/openid-configuration  CVE-2023-4966   assetnote.io
sid 2048931  /oauth/rp/.well-known/openid-configuration   CVE-2023-4966   assetnote.io
sid 2063315  /p/u/doAuthentication.do                     CVE-2025-5777   labs.watchtowr.com
sid 2065742  /cgi/logout  (RelayState=)                   CVE-2025-12101
sid 2068631  /saml/login  (SAMLRequest=, samlp:AuthnRequest)  CVE-2026-3055  labs.watchtowr.com
sid 2068632  /wsfed/passive?wctx                          CVE-2026-3055   labs.watchtowr.com
sid 2071537  /cgi/samlauth                                CVE-2026-8452
```

CVE-2026-3055 is the same CVE #2977's own body cites as its KEV precedent.

The change is **additive to the log only**. Responses are byte-identical —
the classified paths still return the same empty 200 they did before, so the
decoy's fingerprint to a scanner is unchanged. That is covered by a test
(`TestAuthSurfaceProbeIsLoggedWithoutChangingTheResponse`).

This answers #2977's own "Proposed detection signature / log query" ask: there
is now a field to filter on in Kibana (`sensor=citrix-honeypot AND
event:netscaler_*_surface_probe`) instead of only a raw path string, and a
post-2026-09-03 spike on it is the signal the issue describes.

### Not changed: presenting *as* the vulnerable configuration

Making the decoy *look* like an AAA/SAML-configured vserver — serving
plausible SAML metadata, an IdP-shaped login flow, a version banner — is a
deception-design change with its own review, not a classification change. It
is the higher-value half (see §2) and it is **not** gated on the CVE's PoC
shape. Tracked as #3032 item (a).

### Not changed: a CVE-2026-19490-specific event type

The issue body's description of the exploitation traffic is a paraphrase
("requests matching the PoC request shape", "AAA/Gateway auth endpoint,
SAML-related parameter probing") — it gives no literal path or parameter. This
repo's precedent for a CVE-specific classifier is #2919's single
`case p == "/pa"`, added only because the *exact* path was independently
confirmed. Hard-coding a guessed CVE-2026-19490 path would produce false
precision (attackers using a slightly different path go unclassified anyway)
and, worse, a classifier that looks like real detection coverage in the
dashboard while never having been checked against a real request. Tracked as
#3032 item (b), still gated on a primary source.

The distinction is the point: *which surface was probed* is confirmable today
and now classified; *which CVE the probe was for* is not, and is not guessed.

## 6. What was not verified

- Did not pull the primary Citrix advisory or a public PoC for
  CVE-2026-19490's literal request path/parameters — the referenced sources
  (BleepingComputer, Previdian telemetry, NCC-BE) describe the exploitation
  class, not a byte-level request shape. That is exactly the gap #3032 (b)
  stays gated on.
- Did not deploy. The change is in the repo only; citrix-honeypot needs an
  Arcane build + redeploy before any of the new event kinds can appear in ES,
  and the first real hit should be verified on a document indexed *after* that
  deploy.
- Did not check the other raw-tunnelled Go decoys for the same query-string
  loss (#3044 carries that note).

## 7. Bottom line

**Fleet exposure is partial, not absent.** `citrix-honeypot` presents the
right product family but the wrong vulnerability's surface — it has no
AAA/SAML/logon endpoints for CVE-2026-19490 to hit, so it cannot look like the
specifically-vulnerable configuration to a fingerprinting scanner (#3032 a).
The fleet's IDS has 51 Citrix / 30 NetScaler ET rules and none for this CVE,
and none of them can fire on this decoy anyway because its traffic is TLS the
decoy terminates itself — the sensor's own classifier is the only detection
point that works here. That classifier now recognises the NetScaler AAA / SAML
/ OAuth surface using seven literal paths confirmed from ET signatures loaded
on this very fleet, with responses unchanged. Capture is good but not
complete: the query string is dropped at the sensor (#3044), which loses
precisely the parameter-probing traffic this issue is about. A
CVE-2026-19490-specific event type stays gated on a confirmed PoC shape
(#3032 b).
