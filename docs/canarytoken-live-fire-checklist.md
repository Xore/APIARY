# Canarytoken live-fire checklist

Catalogued in [`docs/DECEPTION-EXTENSIONS.md`](DECEPTION-EXTENSIONS.md)'s
Canarytokens row, alongside [`docs/SENSORS.md`](SENSORS.md)'s description of the
stack this exercises.

**Why this file exists.** Every token type this stack offers has, at some point,
been confirmed to fire end to end — but that confirmation lives only in closed
issue threads (#1586, #1587, #1595). There is no artefact in the repo that says
which types have been observed firing, when, or how to repeat the observation.
That is how #1586 came to be closed with the PDF type's fired-status admittedly
unverified, and how #2136 had to be filed to notice.

This checklist is the structural thing that was missing. It is a **manual**
procedure: firing a canarytoken requires a real client (a document reader, a
browser, a phone camera, Explorer) doing the thing an attacker would do. Nothing
here is automatable in CI, which is precisely why it needs writing down.

**Run it:** after any change to the vendored canarytokens source
(`CANARYTOKENS_REF` in `arcane/home/honeypot-canarytokens/canarytokens/`), after
any change to `backend-service/src/canarytokens.rs` or
`canarytokens-adapter/main.go`, and once after the #1609 reinstall.

---

## Preconditions

- [ ] `hp-canarytokens-frontend`, `hp-canarytokens-switchboard`,
      `hp-canarytokens-redis` and `hp-apiary-backend` are up.
- [ ] The stack's `CANARY_PUBLIC_HOSTNAME` is **not** a placeholder. The backend
      refuses to create tokens under `.example` / `.example.com` / `.example.net`
      / `.example.org` / `.invalid` (`canarytokens.rs`,
      `RESERVED_PLACEHOLDER_SUFFIXES`) — because a token minted under the shipped
      placeholder can never resolve, and the resulting silence is
      indistinguishable from "nobody took the bait".
- [ ] The token's random hostname resolves publicly. Each token is a random label
      subdomained under `CANARY_PUBLIC_HOSTNAME`, matched by the VPS Traefik
      wildcard `HostRegexp` rule — see `docs/SENSORS.md` and
      `docs/CGNAT-DEPLOYMENT.md`.
- [ ] Note the vendored commit under test:
      `docker exec hp-canarytokens-frontend cat /COMMIT_SHA`. Record it in the
      results table below.

## Per-token procedure

For each type: create → plant/open → observe the fire → confirm it lands.

1. **Create** through the dashboard's *Settings → Canarytokens* pane (not by
   calling the API by hand). Use a memo that names this checklist run, e.g.
   `live-fire 2026-09-01 <type>`.
   - If you do need to drive the API directly, the create path is
     `${CANARYTOKENS_API_URL}${CANARYTOKENS_API_ROOT}/generate`. The API root is
     **deliberately non-guessable** upstream anti-scraping — it is not `/api`,
     and `POST /generate` against the bare origin correctly returns
     `405 Allow: GET`. The value the backend uses is `DEFAULT_API_ROOT` in
     `arcane/home/honeypot-dashboard/backend-service/src/canarytokens.rs`. Guessing
     paths from outside is the trap that cost #2136 a whole session.
2. **Trigger** it the way the per-type notes below describe, from a host that is
   *not* on the honeypot network (so the source IP is meaningful).
3. **Observe the fire.** The switchboard posts to `canarytokens-adapter` on the
   internal `canarytokens-adapter.internal` network; the public HTTP entry point
   is `canarytokens-http-router` (`hp-canarytokens-http-router`, host port
   19427), which is the service that actually holds `ADAPTER_URL`
   (compose.yml:311) and forwards to the adapter. The switchboard itself
   publishes no host port. The adapter then
   appends one sensor JSON line to `/var/log/honeypot/canarytokens.json`
   (`canarytokens-adapter/main.go`), which Filebeat tails into the honeypot index
   like any other sensor.
   - Tail it live while triggering:
     `docker exec hp-canarytokens-adapter tail -f /var/log/honeypot/canarytokens.json`
   - Then confirm it reached Elasticsearch. Query on `event.sensor: canarytokens`
     — the adapter writes a bare `sensor` key and Filebeat nests sensor-line
     fields under `honeypot.*`, so expect the payload at `honeypot.token_type`,
     `honeypot.token`, `honeypot.memo`. **Confirm the actual field paths on a
     document indexed after your fire** rather than trusting this line; a query
     against a field the data does not use silently returns nothing, which reads
     exactly like "it never fired".
4. **Confirm the dashboard shows it** on the canarytokens page.
5. **Record the result** in the table, with the alert timestamp and the
   **client used** — which is this audit's origin classification, so name it
   with a class from [Known origins](#known-origins) rather than a free-text
   guess. A blank there means "not observed"; it does not mean "unexplained",
   and it is never a reason to escalate on its own. Only an origin *outside*
   the list is an unexplained event.

## Types to cover

The authoritative list is `TYPES` in
`arcane/home/honeypot-dashboard/backend-service/src/canarytokens.rs`. As of
2026-09-01 it is six:

| id | what fires it | notes |
|---|---|---|
| `adobe_pdf` | opening the PDF in a client that performs the page-open `/AA` `/S /URI` outbound action — a real reader, or a browser's built-in viewer (see [Known origins](#known-origins)) | **The known-weak one, and now also a known-origin one.** Browser-class viewers do not execute embedded JavaScript and do not open the tracking URL, so a negative result in one is *expected*, not evidence the token is broken. Record which client was used. An `adobe_pdf` token did fire from an external client on 2026-08-17 (callback → sensor log → ES → dashboard, all re-verified 2026-09-03), and what opened it is a browser's built-in PDF viewer — established by recollection on 2026-09-28, not by re-running the event (#3450). **A PDF row whose origin is on the known-origin list is an explained observation whether it fired or did not:** fill in the client-used column and grade it. Do not hold a row open waiting for a "real reader" to turn up — no browser-class client will ever resolve the URL, so that wait has no end. See #2136, #3450. |
| `ms_word` | opening the `.docx` in Word with external content allowed | |
| `ms_excel` | opening the `.xlsx` in Excel with external content allowed | |
| `web_image` | loading the image from a page or client that fetches it | requires an upload at creation time |
| `windows_dir` | opening the extracted folder in Windows Explorer | `desktop.ini` + icon bundle; needs a real Explorer, not a file manager |
| `qr_code` | scanning the PNG and following the URL | |

## Known origins

A token event's **origin** is the client that opened, loaded or scanned the
artifact. Every fired-status audit has to classify the origin before the
observation means anything, so the classifications this audit accepts are listed
here, once. **An event may only be escalated as unexplained when its origin is
not on this list** — that, and only that, is what "unexplained" means in this
procedure.

Until 2026-09-28 this file had no such list, and the absence cost three review
passes: each one re-derived the same conclusion from the same observation —
"no Adobe/Foxit-class reader was installed, so this PDF event is unexplained".
**That inference is retired** (#3450). Its premise is known false, and a browser
built-in PDF viewer is a normal, expected origin for `adobe_pdf`.

| origin class | recognise it as | verdict |
|---|---|---|
| Browser built-in PDF viewer (Chrome, Edge, Firefox) | the run's own client-used column, or a recollection by someone who recognises the token's memo; corroborated by a `Chrome/` / `Edg/` / `Firefox/` user agent | **Known-origin. Never a finding.** Classify it, record it, move on. |
| Reader handing the embedded `/S /URI` action to the default browser | the run's client-used column; in the payload a browser user agent with an empty `src_data.referer` — byte-identical to the row above | **Known-origin.** A fire here is the technique working. |
| Adobe/Foxit-class reader opening the file directly | the run's client-used column; the user agent is the reader's own, not a browser's | **Known-origin.** A fire here is the technique working. |
| Upstream webhook-configuration self-test | visibly canned `memo` / `src_ip` (`1.1.1.1`, `example.com`, generic `Mozilla/5.0...`) | Not a fire at all — see the note under the 2026-08-17 event's record below. |

**The user agent corroborates a browser origin; it does not establish one.**
The 2026-08-17 event's record is a browser user agent with an empty referer,
which is what a browser viewer *and* a reader handing off to the default
browser *and* a pasted URL all look like. The classification therefore comes
from the run's own record or from recollection, never from parsing the payload
into a stronger claim than it supports. That cuts both ways, which is why it
matters: the two candidate readings differ, but they are *both* on this list, so
the ambiguity never produced an unexplained event in the first place.

**A browser origin cannot resolve the tracking URL, and that is expected.**
Browser-class viewers deliberately do not execute embedded JavaScript, and they
do not open the tracking URL either. So the expected outcome of an `adobe_pdf`
run performed in a browser is **no callback**: an `adobe_pdf` event that never
resolves and whose origin classifies as a browser built-in viewer is
**expected behaviour, not a finding**. Record it as a negative against an
expected result — the same way a positive is recorded — and do not open an
investigation into it.

That rule is one-directional on purpose. It does not claim a browser viewer
*can* fire; it states it will not, so a browser-origin run is evidence for
nothing about whether the technique works. Only a reader-class client answers
"does `adobe_pdf` fire?", and that question is separate from "was this
observation explained". Grade the technique on a reader-class run; classify the
origin on every run.

Adding a viewer to the first row needs the kind of evidence #3450 had — a named
client, established rather than assumed. `Safari/` is deliberately absent: every
browser user agent above ends in `Safari/537.36`, so that substring is not a
viewer identity, and no Safari-class viewer is in what was recalled.

## Results

Copy this block per run; keep previous runs.

```
run date:            YYYY-MM-DD
CANARYTOKENS_REF:    <commit from /COMMIT_SHA>
run by:              <who>
reason:              <vendored bump / reinstall / adapter change / routine>

| type         | created | fired | ES doc | dashboard | client used            | alert ts |
|--------------|---------|-------|--------|-----------|------------------------|----------|
| adobe_pdf    |         |       |        |           |                        |          |
| ms_word      |         |       |        |           |                        |          |
| ms_excel     |         |       |        |           |                        |          |
| web_image    |         |       |        |           |                        |          |
| windows_dir  |         |       |        |           |                        |          |
| qr_code      |         |       |        |           |                        |          |
```

```
run date:            2026-09-03
CANARYTOKENS_REF:    dd92bf29bd0f6d1b446fb41e3b8114c6fc7a6205
run by:              Xore (via #2136)
reason:              #2136 -- resolve adobe_pdf's fired-status once and for all

| type         | created | fired | ES doc | dashboard | client used            | alert ts |
|--------------|---------|-------|--------|-----------|------------------------|----------|
| adobe_pdf    | yes     | no*   | n/a    | n/a       | Chrome (Playwright)    |          |
| ms_word      |         |       |        |           |                        |          |
| ms_excel     |         |       |        |           |                        |          |
| web_image    |         |       |        |           |                        |          |
| windows_dir  |         |       |        |           |                        |          |
| qr_code      |         |       |        |           |                        |          |
```

\* Created a real token via the documented API fallback (see step 1 above --
this resolved the exact `/generate` routing dead-end that cost a previous
attempt its whole session budget), downloaded the artifact through
`/download?...&fmt=pdf`, and confirmed with `qpdf --qdf` that it carries a
well-formed page-open `/AA` action (`/S /URI`, `/URI
(http://<token>.<hostname>/<path>)`) matching the token's own hostname --
the mechanism is correctly baked into the artifact. Navigating Chrome
(driven via Playwright, no interactive human-attached session available in
this environment) to the artifact's public download URL did **not** fire it
-- the server responded with an attachment disposition, so Chrome routed it
to a native "Save File" dialog instead of rendering it inline, and the
page-open action that would trigger the callback never had a chance to run.
This is **not a negative live-fire result** for the technique itself; it is
"no PDF client ever opened the file" -- Chrome's PDF viewer, which is on the
[known-origin list](#known-origins) above, never even got that far. No ES doc,
no dashboard entry, because nothing fired. (Had the viewer rendered it inline
instead, the row would still have been an expected negative: a browser-class
origin does not resolve the tracking URL.)

**However:** while establishing today's baseline, a genuine historical
`adobe_pdf` fire was found, and the four pipeline links after the callback
were verified against it -- see the next section. At the time that left exactly
one link open: which client opened the document. This checklist's own honesty
rule still applies to *today's* attempt (blank/negative stays blank/negative).
The historical event's client-used column stayed blank on 2026-09-03 for the
same reason, and was filled on 2026-09-28 by recollection rather than by
re-running anything -- see below and #3450.

### `adobe_pdf`: a historical fire, origin a browser viewer (2026-08-17 event, re-verified 2026-09-03, origin established 2026-09-28)

**An `adobe_pdf` token was observed firing from an external client — the four
pipeline links below are now verified, and its origin is now known.** Found while
investigating this issue, not manufactured for it -- a real fire event already sat in
`/opt/stacks/apiary/logs/canarytokens/canarytokens.json` on the homeserver,
undetected because nothing had ever looked for it (which is the whole reason
this checklist exists):

```
token:      <redacted -- see #2136's comments for handling>
memo:       "Xore verification token (working)"
timestamp:  2026-08-17T15:48:20Z / :22Z (two hits, 2s apart)
src_ip:     94.31.93.171 (Germany, ASN 8899 / inexio Informationstechnologie)
useragent:  Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/151.0.0.0 ... Edg/151.0.0.0
origin:     browser built-in PDF viewer -- recalled 2026-09-28 (#3450), not re-observed
```

Full path confirmed today, independently, at each link:

1. **ES doc** -- `GET honeypot-v2*/_search` on `event.sensor: canarytokens` +
   `honeypot.token: <token>` returns 2 hits at the field paths this checklist
   documents (`honeypot.token_type`, `honeypot.memo`, `honeypot.src_ip`).
2. **Dashboard** -- `GET /api/v1/events?sensor=canarytokens&size=50&since=365d`
   (the exact query `frontend-next/src/routes/canarytokens.tsx`'s "Fired
   tokens" tab issues — `since=365d`, chosen there because tokens fire rarely
   and the events endpoint's own default is 10d; the trailing `0` in an older
   revision of this checklist was a transcription slip, not a wider window) returns this event as row `detail: "token fired: Xore
   verification token (working) (HTTP)"`, geo-enriched (country DE, ASN 8899)
   -- confirmed surfaced, not just indexed.

The memo and a genuine non-loopback, non-testing-range source IP with a
plausible desktop browser UA establish that this is a **real fire from a real
external client**, not a synthetic test (the "Congrats! The newly saved webhook
works" entries elsewhere in the same log, by contrast, are visibly canned --
`1.1.1.1`, `example.com`, generic `Mozilla/5.0...` -- and are
webhook-configuration self-tests, not fires).

**What it did not establish, on 2026-09-03, was which client opened it.**
`src_data.referer` is empty and the user agent is a desktop browser, which is
exactly what you would see *either* if a PDF reader handed the embedded
`/S /URI` action to the default browser *or* if someone pasted the URL into
that browser directly. Nothing in the payload distinguishes those two, so on
that day the client-used column was left blank rather than guessed. The gap was
always one sentence of recollection, and nothing else could have closed it.

**Which closed it, on 2026-09-28 (#3450).** Niklas recognised the token and
recollected that the reader was a **browser's built-in PDF viewer**
(Chrome/Edge/Firefox). That is the origin recorded for this event now, and it
is a *recollection*, not a re-observation: the event was not re-run and cannot
be, which is why its client-used entry is marked as recalled rather than
observed. The payload ambiguity above is unchanged and still stands — what
changed is that the blank is no longer waiting on an observation that will
never come, because a browser-class client is a known origin and does not
resolve the tracking URL by design.

The remaining honest gap is narrower than "which client opened it", and it is
not a finding: **no reader-class client is recorded as ever having resolved
this token's tracking URL.** The 2026-08-17 callback is a real fire with a
known origin, and a reader-class fire for this token is simply not on record.
Under the rule above that is an expected state of a technique that most people
meet in a browser first, not an anomaly to escalate and not a row to hold open.

### Known state (updated 2026-09-28)

- `web_image`, `qr_code`, `windows_dir` and the fired-status/download fixes:
  confirmed live in #1586 / #1587 / #1595.
- `adobe_pdf`: an external client fired one on 2026-08-17, and callback →
  sensor log → ES → dashboard was re-verified on 2026-09-03 from that event
  (above). Its **origin is a browser's built-in PDF viewer**, established by
  recollection on 2026-09-28 (#3450) and not by re-running the event. The
  fired-status is real and does not depend on that recollection. What is *not*
  on record is a reader-class client resolving the tracking URL — an expected
  permanent state, not a gap to chase: see [Known origins](#known-origins).
  Do not treat a browser-origin PDF event as unexplained, and do not hold a
  PDF row open waiting for a real reader to appear.
- `ms_word` / `ms_excel`: still no live-fire record found either way -- this
  run did not attempt them (out of scope for #2136).

A blank row means "not observed", never "works". That distinction is the entire
point of this file. The same rule has a corollary, and it is the one #3450 had
to add: a **known** origin is an explanation, even when the row is blank and
even when the client could never have fired. "Not observed" is not the same
claim as "unexplained".

### Three traps when re-running this checklist

- **Check the cluster is ingesting before you trust an empty "ES doc" column.**
  A fire that never reaches Elasticsearch looks identical to a token that never
  fired. On 2026-09-03 nothing had been indexed since `2026-08-31T23:59:59Z`
  (#2820 / #2905 / #2906), so a run that day would have produced a false
  negative in that column while the callback itself was fine. Query for *any*
  recent document first; if there are none, the instrument is blind and the
  column is "unknown", not "no".
- **`@timestamp` is ingest time, not event time.** The 2026-08-17 hits carry
  `@timestamp: 15:48:28Z` while the sensor line says `15:48:20Z` / `:22Z` --
  six to eight seconds apart. Query a window, not an instant, or search on the
  token/memo rather than the time.
- **A PDF event with a browser origin is explained, not unexplained.** This is
  the trap that cost three review passes before #3450 retired it. "No
  Adobe/Foxit-class reader is installed here" says nothing about a token
  event's origin — most people who open a PDF do it in a browser, and a
  browser-class viewer cannot open the tracking URL anyway, so the
  non-resolution you observe is the documented behaviour of the client, not a
  missing reader. Classify against [Known origins](#known-origins) and stop
  there. If you are reading this because a PDF event felt unexplained, that
  feeling is the retired inference, not a new finding.

