# Dashboard Profile Actions

> **Status (2026-07-31):** built. This was a five-milestone roadmap; four of the
> five shipped, and the fifth shipped in a different shape than the plan
> allowed. The milestone list and its exit criteria have been removed — they
> described work that is done, and a plan nobody can fail is just noise.
>
> The settings pane is a bare iframe onto the auth origin, which this document
> originally ruled out except behind explicit preconditions:
> [#93](https://github.com/Xore/APIARY/issues/93). Three of the four
> are done: `frame-ancestors` is enforced on the auth origin (auth-backend's
> `APP_FRAME_ANCESTORS`, verified live), `AUTH_ACCOUNT_URL` is validated at
> dashboard startup against the configured auth origin
> (`validatedAuthAccountURL` in `authorization.go`), and the dashboard side of
> the close/expiry `postMessage` contract is in `hp-account.js`. The
> auth-backend side of that contract — actually posting `close`/`expired` to
> the parent — has not shipped yet; until it does, the frame's own expiry or a
> logout inside it will not close the modal. The remaining deployment
> verification for the settings stack is
> [#81](https://github.com/Xore/APIARY/issues/81).

---

## 1. What it does

The authenticated identity at the bottom-left of the sidebar is a button. It
opens a floating menu with **Settings** and **Log out**. Settings opens a
centered modal over the dashboard; logout is a top-level navigation to the auth
backend.

Both items stay hidden until `/api/whoami` returns a usable identity. There is
no fallback identity and there must never be one — `dashboard operator` was
removed, and two tests
([`settings_page_test.go:88`](../dashboard/settings_page_test.go:88),
[`shell_layout_test.go:38`](../dashboard/shell_layout_test.go:38)) assert the
string does not reappear in rendered HTML.

## 2. Where it lives

| Piece | File |
|---|---|
| Trigger, menu markup, modal shell | `dashboard/ui/partials/dashboard.html` |
| Menu, popup, logout, keyboard contract | `dashboard/static/hp-account.js` |
| `/api/whoami` and the identity struct | `dashboard/authorization.go` |
| The account URL | `AUTH_ACCOUNT_URL`, in `.env.example` and `docker-compose.yml` |

Only one URL is configured. The logout endpoint is derived from its origin in
`hp-account.js`, rather than being a second variable as the plan proposed.

## 3. Why the settings pane is an iframe

The plan preferred extracting auth-backend's settings UI for reuse, with an
iframe as a last resort behind explicit preconditions. The implementation went
straight to the iframe, and the reason is a good one: account credentials,
passkeys and session management never enter the dashboard origin at all. The
dashboard cannot leak what it never handles.

What it does not get for free is everything the preconditions covered:
`frame-ancestors` on the auth origin, validation of the configured URL, and a
close/expiry signal from the frame. Tracked in
[#93](https://github.com/Xore/APIARY/issues/93), **do not replace the
modal to close them** — the gaps are additive.

- **`frame-ancestors`** — done. auth-backend serves the settings app with
  `frame-ancestors` (and a matching `X-Frame-Options` relaxation) scoped to an
  explicit allowlist, `APP_FRAME_ANCESTORS` (`forward-auth/config.go`'s
  `parseFrameAncestors`: https-only, deduped, capped at 8 origins), enforced
  by `allowAppFraming` in `forward-auth/apppage.go`. Verified live on the
  VPS: `APP_FRAME_ANCESTORS` is set to the dashboard's own public origin.
- **URL validation** — done. `validatedAuthAccountURL` in
  `dashboard/authorization.go` runs once at startup: rejects anything that
  isn't a clean HTTPS URL (or HTTP to loopback), and rejects a host that
  doesn't match `AUTH_INTROSPECTION_URL`'s. A bad value is logged loudly to
  stderr and the settings item just stays hidden — never a silently blank
  iframe.
- **Close/expiry signal** — half done. `dashboard/static/hp-account.js`
  listens for `postMessage`, checking both `event.source` (must be the
  settings iframe's own `contentWindow`) and `event.origin` (must match the
  account URL's origin) before trusting `{source:"xore-auth-app",
  type:"close"|"expired"}`: `"close"` dismisses the modal, `"expired"`
  dismisses it and re-fetches `/api/whoami`. auth-backend does not yet post
  either message — that's the remaining half of #93, tracked separately since
  it lands in a different repository (`Xore/auth-backend`).

## 4. Rules that still bind

These are the parts of the original design that are not merely descriptions of
finished work — they constrain future changes:

- **Visibility is not authorization.** Hiding an admin pane is a courtesy to the
  user, not a control. Auth-backend re-checks session, CSRF token, role and
  payload on every read and write; the dashboard is authoritative for none of
  it.
- **Caller-supplied `X-Auth-*` headers are non-authoritative.** The
  `strip-auth-identity` middleware removes them at the edge and
  `authorization_test.go` forges them to prove they grant nothing.
- **A failed identity fails closed.** No guessed header, no username hash, no
  compatibility identity — the profile stays hidden.
- **Never build a security-sensitive URL from browser input.** The account URL
  comes from the server; the logout URL is derived from its origin, not from
  anything the page can influence.
- **If a dashboard-side proxy is ever added**, it must be a narrow allowlisted
  pass-through: preserves method and status, forwards only the session and CSRF
  data, bounded request/response/timeout, logs no credentials or tokens, no
  permissive CORS.

## 5. Pinned upstream references

Re-pin and re-read these before changing the modal or the dropdown:

- `Xore/theme` `efcc979faaa7d2dc9b533dfb0bfe8891ca3a9356` —
  `examples/components.html` (Floating layers), `docs/MODALS.md`,
  `docs/ADOPTION.md`
- `Xore/auth-backend` `184b5bccb29afc25dde35525c5b5c2e742f3a828` —
  `forward-auth/ui/app.html`, panes `account` and `admin-settings`;
  `forward-auth/apppage.go` (`allowAppFraming`); `forward-auth/config.go`
  (`parseFrameAncestors`)

## References

- [`settings-user-configuration-roadmap.md`](settings-user-configuration-roadmap.md)
  — the settings stores, audit log and admin configuration behind this UI
- [`settings-operations.md`](settings-operations.md) — the runbook for those stores
