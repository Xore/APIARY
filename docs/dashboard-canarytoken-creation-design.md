# Dashboard-driven Canarytoken creation for external use — design decision

> **Status**: Decided and implemented, first cut. Tracking: [#1487](https://github.com/Xore/APIARY/issues/1487).

## Why this exists

[#1426](https://github.com/Xore/APIARY/issues/1426) stood up a self-hosted
`thinkst/canarytokens` platform and confirmed token creation is scriptable
(a real `POST {ROOT_API_ENDPOINT}/generate` exists, not web-UI-only as the
`#1415` research pass assumed). [#1427](https://github.com/Xore/APIARY/issues/1427)
used that to plant hand-authored breadcrumbs into persona files at
build/deploy time. Neither gave an operator a way to create a token live,
on demand, for use **outside** this honeypot entirely — a PDF to plant on a
real fileshare, a beaconed image to embed in a phishing-awareness email,
etc. `#1487` is that operator workflow, scoped down from its own full
five-item wishlist to just item 1 (manual creation) for external use — items
2 (auto-implant into a honeypot persona's fake filesystem), 3/5 (credential
provisioning/rotation, linking a token to a credential file) stay out of
scope; #1487 itself flagged those as needing their own separate design
passes.

## Decision 1: which token types

Six of `thinkst/canarytokens`' ~28 types are exposed
(`dashboard/canarytokens_client.go`'s `canarytokensSupportedTypes`): PDF, MS
Word, MS Excel, custom image (a "web bug"), Windows Folder token, QR code.
These are exactly the types that produce a plantable file/document artifact
or an embeddable image — matching #1487's own "deploy PDFs, images,
textfiles... for use outside the honeypot" framing. Credential/AWS-key/
listener-service token types (MySQL, Kubeconfig, AWS keys, cloned sites,
SQL Server, etc.) are out of scope: those either need their own delivery
mechanism entirely or overlap with #1427/#1485's already-decided credential
design.

Canarytokens has no literal "plain text file" type; Windows Folder (a
desktop.ini + icon bundle) is the closest artifact-shaped equivalent to a
generic dropped file, and was included on that basis.

## Decision 2: public reachability — expose only the HTTP trigger channel

Every one of the six selected types fires over HTTP only (confirmed against
the vendored source at `canarytokens/Dockerfile`'s pinned
`CANARYTOKENS_REF`: `canary_http_channel` in `frontend/app.py`, switchboard's
`ChannelHTTP`). Before #1487, the whole canarytokens stack was WireGuard-
internal-only (#1426's own explicit scope decision, since nothing was
planted yet). An externally-planted token is useless if its trigger URL only
resolves inside our own WireGuard net — the entire point of #1487 is that
these tokens get used *outside* this infrastructure.

So #1487 makes exactly one thing public: switchboard's HTTP channel, bridged
`vps/docker-compose.yml`'s new `socat-hp-canarytokens` → this stack's 19427
→ `vps/traefik/dynamic.yml`'s new `honeypot-canarytokens` router,
unauthenticated (same posture as `honeypot-http`/`honeypot-snare` — it must
be reachable by whoever opens the planted artifact, not just an operator).

**Deliberately not exposed**: the frontend token creation/management API
(port 19426) stays WireGuard-tunnel-only. The dashboard's own backend is the
only caller, reaching it directly over the tunnel — there is no operator-
facing reason to put a token-creation API on the public internet, and doing
so would be a real credential-exposure cost for zero benefit. DNS-channel/
NXDOMAIN-based token types and detection remain unexposed too — none of the
six selected types need them, and delegating a real DNS zone is a
separate, larger decision (`arcane/home/honeypot-canarytokens/compose.yml`'s own header,
inherited unchanged from #1426/#1427).

## Decision 3: the public hostname is deliberately generic

`cdn` (this repo's usual `honeypot.example` placeholder gets sed-replaced to
the real deployed domain at deploy time -- see `docs/CGNAT-DEPLOYMENT.md` --
so the literal domain doesn't appear here or anywhere else in this public
repo, enforced by `scripts/check-public-leaks.py`), not `canary` or anything
containing "token"/"honeypot". A planted PDF/doc's embedded trigger URL is
visible to
anyone who inspects the file (`strings a.pdf`, view the image's `<img src>`,
etc.) — a hostname that announces "this is a tripwire" defeats the token's
entire purpose before it's even opened. This follows the same instinct
already established for this repo's actual honeypot-facing lure subdomains
(`decoy`, `snare`, `www-portal` — plausible, not literal).

## Decision 4: web_image never gets re-fetched server-side

`thinkst/canarytokens` has no `/download` support for the `web_image` type
(no `DownloadFmtTypes` entry exists for it — confirmed against
`canarytokens/models/web_image.py` and `models/common.py`'s enum). That's
not an oversight: a web-bug token's "artifact" *is* its trigger URL, and
`channel_http.py`'s `render_GET` fires the alert on exactly the same GET
request that would "preview" or "download" the image. Fetching it from the
dashboard's own backend to show a preview would be indistinguishable from a
real "someone opened this" hit — a false positive on a token nobody has
planted yet.

`dashboard/canarytokens_api.go` handles this by construction: `web_image`
creation returns `embed_only: true` and the trigger URL, never a
`download_url`. The dashboard already has the exact bytes the operator
uploaded (from the multipart request itself) — there's nothing to "download
back" that the browser doesn't already have locally.

## Decision 5: creation is admin/operator-only, ES-backed history

Same `adminSettingsIdentity(w, r, write)` guard as every other Settings-pane
mutation (`dashboard/settings_admin_api.go`) — this creates a real,
internet-triggerable monitoring artifact and hands back a downloadable file,
not a read-only view. `dashboard/canarytokens_manager.go` is a direct
structural copy of `ipBlockManager` (#914): a dedicated Elasticsearch index
(`dashboard-canarytokens-v1`), so an operator can revisit and re-download an
artifact without needing WireGuard access to canarytokens' own (internal-
only) management UI.

The stored record includes canarytokens' own per-token `auth_token` — a
real management/download credential, equivalent to a password. It is
persisted (required to re-call `/download` later) but never serialized into
any HTTP response this package sends to a browser: every response goes
through `canarytokensRecordToPublic`, a redacted projection with no
`auth_token` field, rather than encoding the storage struct directly. Tests
(`dashboard/canarytokens_test.go`) assert this explicitly — the response
body and the list body must never contain the credential.

## What "first step" deliberately leaves out

- No automatic implant into a honeypot persona's fake filesystem (#1487
  item 2) — this is for external use; internal breadcrumb planting stays
  #1427's own, separate, deploy-time mechanism.
- No credential provisioning/rotation or "link a canarytoken to a
  credential file" (#1487 items 3/5) — #1485 owns the credential design
  this would build on, and hasn't been extended to cover it yet.
- No DNS-channel token types (plain DNS tokens, NXDOMAIN detection) — all
  six selected types fire over HTTP only; delegating a real DNS zone stays
  a follow-up decision, not made here.
- `CANARYTOKENS_API_URL` reaching `10.8.0.2:19426` from within the
  dashboard's own container (same host, default bridge network, not the
  cross-host VPS→homeserver case Kibana's own `10.8.0.2:19601` exposure
  is) is unverified — confirm this actually routes at deploy time before
  relying on it.
