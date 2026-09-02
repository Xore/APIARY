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
3. **Observe the fire.** The switchboard posts to `canarytokens-adapter`, which
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
5. **Record the result** in the table, with the alert timestamp.

## Types to cover

The authoritative list is `TYPES` in
`arcane/home/honeypot-dashboard/backend-service/src/canarytokens.rs`. As of
2026-09-01 it is six:

| id | what fires it | notes |
|---|---|---|
| `adobe_pdf` | opening the PDF in a reader that performs the embedded outbound request | **The known-weak one.** Many viewers — including Chrome's built-in PDF viewer — do not execute the active-content path this technique relies on, so a negative result in one reader is *not* evidence the token is broken. Record which reader was used. See #2136. |
| `ms_word` | opening the `.docx` in Word with external content allowed | |
| `ms_excel` | opening the `.xlsx` in Excel with external content allowed | |
| `web_image` | loading the image from a page or client that fetches it | requires an upload at creation time |
| `windows_dir` | opening the extracted folder in Windows Explorer | `desktop.ini` + icon bundle; needs a real Explorer, not a file manager |
| `qr_code` | scanning the PNG and following the URL | |

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

### Known state at the time this checklist was written (2026-09-01)

Carried over from the issue record, **not** re-observed:

- `web_image`, `qr_code`, `windows_dir` and the fired-status/download fixes:
  confirmed live in #1586 / #1587 / #1595.
- `adobe_pdf`: **never observed firing end to end.** #1586 was closed with that
  explicitly admitted; #2136 tracks it and is open. Do not treat a PDF row as
  passing until someone fills it in from a real reader.
- `ms_word` / `ms_excel`: no live-fire record found either way.

A blank row means "not observed", never "works". That distinction is the entire
point of this file.

