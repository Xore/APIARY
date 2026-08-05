# AI implementation guide: render the dashboard with the Xore/auth-backend engine

> **Implementation status (2026-07-30):** the template migration is **done** —
> the shared head/shell blocks and all fourteen route templates load from the
> embedded `dashboard/ui/` tree, and a test fails the build if markup moves back
> into Go. Nonce and security-header primitives exist for the later CSP cutover,
> the current Xore/theme stylesheet is vendored, and the shared modal controller
> protects alert acknowledgement and sandbox submission.
>
> What is left is tracked in issues, not in the phase list below: the CSP
> cutover is [#58](https://github.com/Xore/apiary/issues/58), the
> remaining modal inventory is
> [#59](https://github.com/Xore/apiary/issues/59), and tests plus the
> visual acceptance matrix are
> [#60](https://github.com/Xore/apiary/issues/60). The phases below
> remain as the design record for how the migration was structured.

## Objective

Render every page of the APIARY dashboard (`dashboard/`) with the same
render engine that `Xore/auth-backend` uses for its embedded Go UI
(`forward-auth/`), styled by the shared `Xore/theme` design system, including
its modal architecture. Present the honeypot data in a logical, investigation-
first layout.

This is a frontend/rendering task. Do not touch ingestion, aggregation,
analysis, alerting, or storage logic. Every existing HTML route, JSON API,
export, and live behavior must keep working.

## How to read the source references

Every claim in this guide is cross-referenced to a **commit-pinned permalink
with line numbers**. The pins are:

| Repository | Pinned commit |
|---|---|
| `Xore/auth-backend` | [`a789089`](https://github.com/Xore/auth-backend/tree/a789089fd85397c2ded300c6ac2a91f386b25fc6) |
| `Xore/theme` | [`7612eb5`](https://github.com/Xore/theme/tree/7612eb5f16589621744a1e734a57b27060c2ed91) |
| `Xore/apiary` | [`e3b6bc9`](https://github.com/Xore/apiary/tree/e3b6bc92c5149492fcaddb7526c3934d51dd3513) |

When you implement, re-fetch the referenced files at `main` and treat the line
numbers as locators, not gospel — the surrounding identifiers (function names,
CSS classes, template names) are the stable anchors.

Read first, in this order:

1. [`Xore/theme` → `docs/TOKENS.md`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/TOKENS.md) — token contract.
2. [`Xore/theme` → `docs/MODALS.md`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md) — modal behavior contract.
3. [`Xore/theme` → `docs/MIGRATE-HONEYPOT-STACK.md`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MIGRATE-HONEYPOT-STACK.md) — migration invariants.
4. `docs/DASHBOARD-UI-REDESIGN-GUIDE.md` (this repo) — current dashboard state.

Before editing:

```bash
git fetch origin --prune
git checkout main
git merge --ff-only origin/main
git status --short   # stop if dirty
```

---

## 1. The auth-backend render engine (reference spec)

Everything below is extracted from `Xore/auth-backend/forward-auth/`. Treat it
as the canonical pattern to replicate — each subsection cites the exact code.

### 1.1 Embedded assets, served at `/static/`

[`forward-auth/static.go#L13-L23`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/static.go#L13-L23):

```go
//go:embed ui
var uiFS embed.FS

func staticHandler() http.Handler {
	sub, _ := fs.Sub(uiFS, "ui")
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
```

- `static/` holds the vendored `theme.css` (byte-identical to the pinned
  `Xore/theme` commit — verified by `scripts/check-vendored-theme.sh` against
  [`Xore/theme/theme.css`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css))
  and the compiled CSS/JS; `ui/partials/` holds the shared page templates.
  No CDN, no external fonts, no runtime Node.js.
- Pages link `/static/theme.css`; the palette is never inlined into Go code.
  All colors in page-level CSS reference theme custom properties
  (`var(--surface-1)`, `var(--accent)`, … — token list in
  [`docs/TOKENS.md` §Surface hierarchy](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/TOKENS.md#L7-L18)).

### 1.2 Three rendering patterns

Pick per page size; never mix them inside one page.

**A. File-based `html/template` (default for real pages).**
`ui/login.html`, `ui/verify.html`, `ui/app.html` are parsed once at init —
[`page.go#L17-L30`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L17-L30)
and [`apppage.go#L14-L22`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/apppage.go#L14-L22):

```go
var loginTmpl = template.Must(template.New("login").Funcs(tmplFuncs).
	Parse(string(mustReadUI("login.html"))))
```

Each page gets a typed data struct and a `renderX(w, …)` method that sets
`Content-Type`, injects a per-request CSP nonce, and executes the template —
see [`LoginPageData` + `renderLogin`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L34-L75)
and [`AppPageData` + `renderApp`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/apppage.go#L25-L50).
Template values are auto-escaped by `html/template`; JS-side interpolation
goes through an `esc()` helper (§1.6).

**B. Const-string pages with placeholder substitution (only for tiny,
static pages).** Small transactional pages (forbidden, password change,
recovery) are Go `const` strings built from a shared `pageHead` plus body,
with `strings.ReplaceAll` for the few `{{TOKEN}}`-style slots — consts at
[`page.go#L253-L396`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L253-L396),
substitution example in [`renderEnroll`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L88-L105).
Every dynamic value passes through `htmlEscape`. Do not use this pattern for
data-rich dashboard pages — it exists for pages with <10 substitutions.

**C. Application shell (one rich page).** `ui/app.html` is a single template
that renders the whole authenticated surface: a permanent native `<dialog>`
with a sidebar, pane skeletons rendered client-side from a `PANE_TEMPLATES`
registry ([`app.html#L411`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L411)),
data filled by `PANE_LOADERS` fetch calls
([`app.html#L1043-L1052`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1043-L1052)),
and all nested overlays living **inside** the dialog element (§1.5).

### 1.3 Shared page head and nonce'd page CSS

`page.go` builds every head from one const —
[`pageHead` at `page.go#L230-L240`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L230-L240):

```go
const pageHead = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>xore//auth</title>
<link rel="stylesheet" href="/static/theme.css">
<style nonce="{{NONCE}}">` + pageCSS + `</style>
</head>`
```

Rules:

- `pageCSS` ([`page.go#L184-L228`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L184-L228))
  contains **layout only**. Every color is a theme custom property;
  redefining the palette is a defect.
- Inline `<style>` and `<script>` blocks always carry the per-request nonce.
- `meta robots noindex` on all authenticated surfaces.

### 1.4 Security headers and CSP

`renderApp` calls `secHeaders(w, nonce)` before writing
([`apppage.go#L39-L41`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/apppage.go#L39-L41)).
The helpers live in [`server.go`: `nonce()` at L140-L146, `secHeaders` at
L165-L173](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/server.go#L140-L173).
The CSP is nonce-based plus `'self'`:

```text
default-src 'none'; style-src 'self' 'nonce-<n>'; script-src 'nonce-<n>';
img-src data:; connect-src 'self'; form-action 'self'; base-uri 'none';
frame-ancestors 'none'
```

This is only possible because there are **no inline event handlers** — all JS
wiring is `addEventListener` or event delegation from a nonce'd script block
(see the wiring block at [`app.html#L1117-L1205`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1117-L1205)).
CSRF lives in a `<meta name="csrf-token">` tag
([`app.html#L7`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L7))
and is sent as an `X-Csrf` header on every mutating fetch
([`app.html#L206-L214`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L206-L214)).

### 1.5 Modal architecture (the part to copy faithfully)

From `ui/app.html`, implementing
[`Xore/theme/docs/MODALS.md`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md):

- **Permanent surface**: one native `<dialog class="modal modal--permanent">`
  ([`app.html#L91-L92`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L91-L92)),
  opened with `showModal()` on load
  ([`openSettings`, `app.html#L1082-L1090`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1082-L1090)),
  sized `100vw × 100dvh` by a page-CSS override
  ([`app.html#L13-L16`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L13-L16)),
  no close button, and its native `cancel` event is `preventDefault()`'ed so
  Escape can never close it
  ([`app.html#L1117`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1117)).
  This implements [MODALS.md §Permanent settings behavior](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md#L64-L82).
- **Nested overlays are descendants of the dialog.** The edit, rotate-key,
  and danger confirmations are `<div class="edit-dialog-backdrop">` elements
  placed *inside* the `<dialog>`
  ([`app.html#L112-L148`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L112-L148)),
  because a native top-layer dialog hides any sibling overlay regardless of
  `z-index` — the [top-layer invariant, MODALS.md#L18-L62](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md#L18-L62).
  Never render an overlay next to a permanent native dialog.
- **State machine per overlay**: closed = `aria-hidden="true"` + `inert` +
  no `.open` class; opening removes `inert`, sets `aria-hidden="false"`,
  adds `.open`, then moves focus into the panel — see
  [`openDangerDialog`/`closeDangerDialog`, `app.html#L224-L243`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L224-L243)
  and [`openEditDialog`, `app.html#L306-L333`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L306-L333).
  Opacity alone never "closes" anything
  ([MODALS.md §State and accessibility](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md#L115-L128)).
- **Confirmation contract**: initiating click/Enter opens the warning →
  warning names the action and its consequences (the copy table in
  [`confirmAct`, `app.html#L252-L303`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L252-L303)) →
  focus lands on the confirm control → Cancel closes only the nested layer
  and returns focus → Confirm clears the pending callback *before* running it
  ([`runDangerAction`, `app.html#L244-L250`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L244-L250))
  so double-Enter cannot fire twice, executes once, and reports via a flash
  toast. Required by [MODALS.md §Confirmation behavior](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md#L84-L101).
- **Keyboard layering**: Escape closes the deepest open layer first (danger →
  rotate → edit → action menu), never the permanent surface
  ([`app.html#L1092-L1108`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1092-L1108)).
  Enter in a config field opens the same confirmation as its Save button
  ([`app.html#L1199-L1205`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1199-L1205)).
  Rules from [MODALS.md §Keyboard rules](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md#L103-L113).
- **Roles**: `role="dialog"` for edits, `role="alertdialog"` for
  consequential confirmations, always `aria-modal="true"` +
  `aria-labelledby` ([`app.html#L113`, `L126`, `L138`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L112-L148)).
- **Flash toast**: a single `#flash` fixed-position element
  ([`app.html#L90`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L90),
  [`flash()` at `app.html#L197-L204`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L197-L204))
  reports success/failure of async actions; errors get a longer timeout.

### 1.6 Client-side conventions

- `esc(s)` escapes every value interpolated into `innerHTML` — no exceptions
  ([`app.html#L160-L165`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L160-L165)).
- One `api(path, body)` helper: JSON POST, `X-Csrf` header, parses
  `{error: …}` and flashes it
  ([`app.html#L206-L214`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L206-L214)).
- Event delegation on stable containers (`document` or `#settings-content`),
  because pane DOM is re-rendered; delegated handlers survive re-renders
  (the master click router at [`app.html#L1140-L1195`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1140-L1195),
  input/change delegation at [`app.html#L1197-L1198`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1197-L1198)).
- Background state polling must not clobber interaction: re-render is skipped
  while an action menu is open (guard at
  [`app.html#L792`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L792)),
  and config inputs are never refreshed while the admin is typing
  (comment in [`fetchState`, `app.html#L1066-L1080`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1066-L1080)).
- Panes/routes are data-driven registries
  ([`SETTINGS_NAV`/`ADMIN_NAV`, `app.html#L363-L375`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L363-L375)),
  not ad-hoc `if` chains. The initial pane comes from the URL with a safe
  fallback ([`app.html#L1209-L1212`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1209-L1212)).

---

## 2. Dashboard baseline (what exists today)

All references pinned to `Xore/apiary@e3b6bc9`.

- Pages are Go templates assembled as one `pageTemplate` const
  ([`dashboard/page.go#L12`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/page.go#L12)
  = `pageStyle + pageOverview + pageEvents + pageIPs + pageSession +
  pageIntel + pagePayloads + pageSandbox + pageOps`), parsed once in
  [`main.go#L118-L133`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L118-L133)
  with a `FuncMap` (`worldMap`, `json`, `dict`) and executed per route with
  typed data structs (`s.get()`, `s.eventsData(r)`, `s.attackerData(ip)`, …).
- The semantic shell is already server-rendered in `ui/partials/dashboard.html`:
  `{{define "style"}}` ([L1-L13](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html#L1-L13)),
  `{{define "sidebar"}}` ([L15-L74](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html#L15-L74)),
  `{{define "topbar"}}` incl. the `.command-bar` investigation dock
  ([L76-L126](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html#L76-L126)),
  and the shared `tbl`/`techniques` blocks
  ([L128-L141](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html#L128-L141)).
  No client-side DOM reconstruction.
- `dashboard/static/theme.css` is vendored byte-identical to
  `Xore/theme@7612eb5`. The pin lives in
  [`dashboard/frontend/theme.lock`](https://github.com/Xore/apiary/blob/main/dashboard/frontend/theme.lock)
  and is enforced on every push by `scripts/check-vendored-theme.sh`
  (the `Vendored Xore/theme is in sync` job); re-vendor with
  `scripts/sync-theme.sh`. There is no separate dashboard CSS file —
  `#191` removed the Tailwind build entirely and the dashboard's
  app-specific styling has since been folded upstream into `theme.css`
  itself; `hp-app.js` is the hand-written
  enhancement layer (SSE, lazy rows, live refresh, theme toggle, recents).
  Static assets are embedded via [`dashboard/assets.go`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/assets.go)
  (`//go:embed static`) and served with long-cache headers at
  [`main.go#L360-L365`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L360-L365).
- Row-fragment endpoints return server-rendered HTML for lazy loading:
  `/api/event-rows` and `/api/ip-rows`
  ([`main.go#L165-L198`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L165-L198)),
  `/api/payload-rows`
  ([`main.go#L306-L320`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L306-L320)).
- HTML routes are registered at
  [`main.go#L231-L372`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L231-L372)
  (`/`, `/events`, `/ips`, `/investigate/ip/`, `/sessions/`, `/clusters`,
  `/campaigns`, `/history`, `/dead-letters`, `/source-health`, `/alerts`,
  `/payloads`, `/sandbox`, `/commands`, `/payload-analysis/`, exports).
- **Gaps this guide closes**: templates live as Go string consts instead of
  embedded files; there is no nonce-based CSP (the pre-paint theme script in
  `{{define "style"}}` runs without one); and there are **no modals at all** —
  no detail dialogs, no destructive confirmations.

---

## 3. Target architecture

### 3.1 Directory layout (auth-backend pattern, adapted)

```text
dashboard/
  ui/                      # NEW — embedded templates (//go:embed ui)
    partials/head.html         # doctype, head, asset links, nonce'd pre-paint script
    partials/shell.html        # app-shell: topbar, sidebar, command-bar, flash, modal-root
    partials/tbl.html          # reusable "tbl" and "techniques" blocks
    overview.html
    events.html                # includes the "eventrows" fragment template
    ips.html                   # includes "iprows"
    attacker.html              # attack-chain profile (currently in page_ips.go)
    session.html
    campaigns.html
    clusters.html
    commands.html
    payloads.html              # includes "payloadrows"
    payload_analysis.html
    sandbox.html
    alerts.html
    source_health.html
    history.html
    dead_letters.html
  static/                  # unchanged: theme.css, hp-dashboard.css, hp-app.js,
                           # hp-api.js, hp-modals.js (NEW), leaflet.*
  ui.go                    # NEW — embed, mustReadUI, template parsing, FuncMap
  render.go                # NEW — PageData structs + renderX methods, secHeaders+nonce
```

Keep `page_*.go` during the transition: move each `{{define}}` block into its
`ui/*.html` file one route at a time, and shrink
[`page.go#L12`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/page.go#L12)
until it concatenates nothing. Delete each Go const only after its file
template renders the route byte-comparably (allowing for whitespace).

### 3.2 Template parsing and render functions

Mirror auth-backend exactly
([`page.go#L17-L30`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L17-L30),
[`apppage.go#L14-L22`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/apppage.go#L14-L22)):

```go
// ui.go
//go:embed ui
var uiFS embed.FS

func mustReadUI(name string) []byte { /* panic on error, same as auth-backend apppage.go#L14-L20 */ }

var tmplFuncs = template.FuncMap{
	"worldMap": func() template.HTML { return template.HTML(worldMapSVG) },
	"json":     func(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) },
	"dict":     func(pairs ...any) map[string]any { /* as in main.go#L118-L131 today */ },
	"seq":      func(n int) []int { /* as in auth-backend page.go#L18-L24 */ },
	"add":      func(a, b int) int { return a + b },
}
```

Parse per page: every page template is parsed together with the shared
partials (`template.ParseFS(uiFS, "ui/partials/*.html", "ui/overview.html")`
or via `mustReadUI` + `Parse`). Keep the existing `{{define "style"}}`,
`{{define "sidebar"}}`, `{{define "topbar"}}`, `{{define "tbl"}}` names so
`main_test.go`'s shell/route assertions keep passing.

Each route keeps its current data struct and gains a render method modeled on
[`renderApp`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/apppage.go#L33-L50):

```go
func (s *server) renderEvents(w http.ResponseWriter, r *http.Request) {
	n := nonce()
	secHeaders(w, n)                      // NEW: nonce-based CSP, auth-backend server.go#L165-L173
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := s.eventsData(r)
	data.Nonce = n                        // every PageData gains a Nonce field
	if err := eventsTmpl.ExecuteTemplate(w, "events", data); err != nil {
		s.log.Error("render events", "error", err)
	}
}
```

### 3.3 Shared head and shell partial

`partials/head.html` reproduces the current `{{define "style"}}`
([`ui/partials/dashboard.html#L1-L13`](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html#L1-L13))
but with the pre-paint theme script nonce'd, like auth-backend's `pageHead`
([`page.go#L230-L240`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L230-L240)):

```html
<link rel="stylesheet" href="/static/theme.css?v={{.AssetVersion}}">
<link rel="stylesheet" href="/static/leaflet.css?v={{.AssetVersion}}">
<link rel="stylesheet" href="/static/hp-dashboard.css?v={{.AssetVersion}}">
<script nonce="{{.Nonce}}">(function(){try{var t=localStorage.getItem("hp-theme");
if(t==="light"||t==="dark"){document.documentElement.dataset.theme=t;}}catch(e){}})();</script>
<script defer src="/static/leaflet.js?v={{.AssetVersion}}"></script>
<script defer src="/static/hp-api.js?v={{.AssetVersion}}"></script>
<script defer src="/static/hp-modals.js?v={{.AssetVersion}}"></script>
<script defer src="/static/hp-app.js?v={{.AssetVersion}}"></script>
```

Load order is invariant: theme → leaflet → dashboard layer; deferred scripts
after. Bump the `?v=` buster whenever a static asset changes.

### 3.4 Row fragments

`/api/event-rows`, `/api/ip-rows`, `/api/payload-rows`
([`main.go#L165-L198`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L165-L198),
[`L306-L320`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L306-L320))
stay HTML-fragment endpoints. Their `eventrows` / `iprows` / `payloadrows`
templates move into the corresponding `ui/*.html` files unchanged, so the
lazy-list contract (25 rows per fetch, sentinel-driven) is untouched.

### 3.5 CSP

Add `nonce()` and `secHeaders(w, nonce)` copied from auth-backend
[`server.go#L140-L173`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/server.go#L140-L173).
The dashboard needs a slightly wider policy than auth-backend's
(`default-src 'none'`) because of Leaflet map tiles and inline SVG:

```text
default-src 'self'; script-src 'self' 'nonce-<n>'; style-src 'self' 'nonce-<n>';
img-src 'self' data: <tile-origin>; connect-src 'self' <tile-origin>;
font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'
```

This requires `hp-app.js`/`hp-modals.js` to contain zero inline-handler
reliance (they already use `addEventListener`) and every inline `<script>`
in templates to carry `nonce="{{.Nonce}}"`.

---

## 4. Presenting the data: information architecture

Organize by the operator's workflow: **detect → triage → investigate →
preserve evidence**. The existing three sidebar groups
([`ui/partials/dashboard.html#L15-L74`](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html#L15-L74))
already encode this — keep them, and make every page answer exactly one
question. All primitives cited below exist in `theme.css` (`.metric-grid`/
`.metric` at [L444-L458](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L444-L458),
`.badge` at [L460-L481](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L460-L481),
`.data-table`/`.table-scroll` at [L519-L541](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L519-L541),
`.card` at [L414-L442](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L414-L442)).

### 4.1 Monitor (answer: "is something happening right now?")

| Route | Question answered | Layout |
|---|---|---|
| `/` overview | What is the current threat picture? | Full width. `.metric-grid` KPI row (events 24h, unique sources, payloads, open alerts — neutral tiles, severity only in badges). Attack-origin map (Leaflet, state preserved across refresh). Activity feed + top-N `tbl` cards (top IPs, usernames, passwords, commands, paths — the shared block at [`ui/partials/dashboard.html#L128-L137`](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html#L128-L137)). Source-health strip. |
| `/source-health` | Are all sensors and the pipeline alive? | `.app-content` (1120px). Status grid: one card per expected sensor with last-seen, event rate, and a `.badge` state (green/red). Elasticsearch/filebeat status rows. |
| `/alerts` | What needs acknowledgement? | `.app-content`. Alert table (rule, severity badge, first/last fired, count) with per-row **Acknowledge** action → confirmation modal (§5). |

### 4.2 Investigate (answer: "who/what/where exactly?")

| Route | Question answered | Layout |
|---|---|---|
| `/events` | Which raw events match my filter? | Full width. Sticky filter bar (time range, sensor, IP, free text) → lazy 25-row `.data-table` in `.table-scroll`, expandable normalized JSON per row, "load more" sentinel, CSV export. Row click opens the **event detail modal** (§5) instead of navigating away when only reading. |
| `/ips` | Which sources attack us? | Full width lazy table: IP, country/ASN (GeoIP), first/last seen, sensor spread, event count. Row → `/investigate/ip/{ip}`. |
| `/investigate/ip/{ip}` | What did this one source do, in order? | `.app-content--wide` (1360px). Header card: IP, geo/ASN, totals, MITRE `techniques` block (shared template at [`ui/partials/dashboard.html#L139-L141`](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html#L139-L141)). Below: chronological **attack-chain timeline** (vertical, timestamped events, session boundaries), linked sessions and payload references. |
| `/sessions/{id}` | What happened inside this session? | `.app-content--wide`. Session header (src, duration, credentials tried) + replay timeline of commands with mono font, linked payload hashes. |
| `/campaigns` | Which activity is coordinated? | `.app-content`. Campaign cards: shared fingerprint, member IPs, time span, event volume. |
| `/clusters` | Which infrastructure is shared? | `.app-content`. Cluster table (ASN/prefix, members, first/last seen). |
| `/commands` | What did attackers try to run? | Full width table: command (mono), count, first/last seen, linked sessions. |

### 4.3 Evidence (answer: "what can I keep, detonate, or export?")

| Route | Question answered | Layout |
|---|---|---|
| `/payloads` | What files were captured? | Full width lazy table: SHA (short, mono), kind, source, size, YARA verdict badge, first seen. Row actions: **preview modal** (§5), analyze, submit to sandbox. |
| `/payload-analysis/{hash}` | What is this file? | `.app-content--wide`. Metadata card, strings/hex sections in mono, YARA matches, sandbox verdicts, download (authorized). |
| `/sandbox` `/sandbox/{job}` | What did detonation show? | `.app-content`. Queue table (job, status badge, submitted, duration); detail: artifact list, exports, screenshots if present. |
| `/history` `/dead-letters` | What is in Elasticsearch / what failed to ingest? | `.app-content` tables with the same lazy-row pattern; dead letters get a retry/inspect affordance. |

### 4.4 Cross-cutting presentation rules

- KPI tiles stay neutral; severity appears only in `.badge` text, never as
  whole-panel color ([token contract, TOKENS.md §Semantic color](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/TOKENS.md#L27-L42);
  the `--*-soft` badge surfaces at [`theme.css#L473-L480`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L473-L480)).
- Identifiers (IPs, hashes, sessions, commands) always render in the mono
  stack and are copy-on-click where useful — reuse the auth-backend
  clipboard pattern ([`copyToClipboard`, `app.html#L173-L188`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L173-L188)
  and the `copy-box` CSS at [`page.go#L210-L216`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L210-L216))
  with the flash toast as feedback.
- Every list page has an explicit empty state (`(none)`/`empty-row`) and an
  error state; every table is horizontally scrollable on narrow screens
  (`.table-scroll`, [`theme.css#L541`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L541)).
- Widths: full width for map/large tables, 1120px `.app-content` for
  list/status pages, 1360px `.app-content--wide` for investigations
  (geometry tokens in [TOKENS.md §Geometry](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/TOKENS.md#L44-L52)).
- The `.command-bar` investigation dock
  ([`ui/partials/dashboard.html#L93-L101`](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html#L93-L101),
  themed at [`theme.css#L953-L967`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L953-L967))
  stays the global entry point (`/` shortcut) — it is a command bar, not a
  modal; do not convert it.
- Live behavior is non-negotiable: SSE toasts
  ([`/api/stream`, `main.go#L159`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L159)),
  15s in-place overview refresh preserving map pan/zoom/selection,
  alert-bell polling (all in `hp-app.js`).

---

## 5. Modal plan for the dashboard

The dashboard currently has no modals; add them per
[`Xore/theme/docs/MODALS.md`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md).
The dashboard shell is an ordinary server-rendered page (not a permanent
dialog), so dashboard modals are **temporary application-managed overlays**
rendered in a single `#modal-root` at the end of `partials/shell.html`. If
any native `<dialog>` is ever used as a permanent surface, every overlay
becomes its descendant — the
[top-layer invariant](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md#L18-L62)
is absolute. The theme provides the visual base (`.modal-backdrop`/`.modal`
at [`theme.css#L969-L1002`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L969-L1002));
the behavior contract comes from auth-backend (§1.5).

### 5.1 Modal inventory

| Modal | Trigger | Role | Notes |
|---|---|---|---|
| Event detail | Row click in `/events` | `dialog` | Full normalized JSON (pretty-printed with the existing `json` template func, [`main.go#L120-L123`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L120-L123)), sensor, geo, links to attacker profile/session. Read-only. |
| Payload preview | "Preview" in `/payloads` | `dialog` | Safe text/hex rendering only — server must sanitize/escape; never inject raw payload bytes as HTML. Size-capped. |
| Alert acknowledgement | "Acknowledge" in `/alerts` | `alertdialog` | Confirmation contract: names rule + consequence (silences for the cooldown window), confirm runs once. Copy pattern: [`confirmAct`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L252-L303). |
| Sandbox submit / resubmit | "Submit to sandbox" | `alertdialog` | Confirms detonation of a specific hash; result links to job (`/sandbox/submit` exists at [`main.go#L322`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L322)). |
| Report / export options | Export buttons (PDF report, CSV) | `dialog` | Time-range and section selection, then navigates to the export URL ([`/export/report.pdf`, `main.go#L230`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L230); CSV at [`L357-L358`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L357-L358)). |
| Destructive ops (dead-letter purge, payload delete if added) | Row action menus | `alertdialog` | Same copy pattern as auth-backend `confirmAct`: title = question, desc = consequences, warning box lists immediate effects. |

### 5.2 DOM skeleton (in `partials/shell.html`)

Modeled on [`app.html#L90` and `L112-L148`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L90-L148):

```html
<div id="flash" role="status" aria-live="polite"></div>
<div id="modal-root">
  <div class="edit-dialog-backdrop" id="detail-backdrop" aria-hidden="true" inert>
    <section class="edit-dialog" role="dialog" aria-modal="true"
             aria-labelledby="detail-title">…</section>
  </div>
  <div class="edit-dialog-backdrop" id="confirm-backdrop" aria-hidden="true" inert>
    <section class="edit-dialog" role="alertdialog" aria-modal="true"
             aria-labelledby="confirm-title">…
      <div class="danger-dialog__warning" id="confirm-warning"></div>
      <button class="btn btn-secondary" data-modal-cancel type="button">Cancel</button>
      <button class="btn btn-danger" id="confirm-action" type="button">Confirm</button>
    </section>
  </div>
</div>
```

### 5.3 Behavior (new `static/hp-modals.js`, hand-written like `hp-app.js`)

Implement the auth-backend state machine verbatim: open = remove `inert`,
`aria-hidden="false"`, add `.open`, focus first control
([`app.html#L224-L236`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L224-L236));
close = reverse + restore focus to the initiating element
([`app.html#L237-L243`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L237-L243)).
One pending-callback variable, cleared before execution
([`app.html#L244-L250`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L244-L250)).
Escape closes only the deepest layer
([`app.html#L1092-L1108`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1092-L1108)).
Backdrop click (target === backdrop) cancels temporary dialogs
([`app.html#L1125-L1127`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1125-L1127)).
Tab cycles within the open layer. All wiring via delegation — no inline
handlers (CSP, §3.5).

Regression checks to automate (from
[MODALS.md §Required regression checks](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md#L140-L154),
jsdom or browser test):

- closed overlays have `inert` + `aria-hidden="true"` and zero dimensions;
- opening an alert ack shows a visible, focused confirmation;
- double-Enter on confirm fires exactly one request;
- Cancel sends no request and restores focus;
- Escape closes the modal but never navigates or reloads the page;
- modals work at 390×844 and with `prefers-reduced-motion`.

---

## 6. Implementation phases (small, reviewable commits, in order)

1. **Embed scaffolding**: add `ui.go` (`//go:embed ui`, `mustReadUI`,
   `tmplFuncs`) and `render.go` (`nonce()`, `secHeaders()`, render methods).
   No route changes yet.
2. **Partials**: extract `{{define "style"/"sidebar"/"topbar"/"tbl"/
   "techniques"}}` from
   [`ui/partials/dashboard.html`](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html)
   into `ui/partials/*.html` with the nonce'd head. Wire parsing; verify
   every route still renders.
3. **Page migration**: move one route's template per commit, easiest first:
   ops pages (`alerts`, `source-health`, `history`, `dead-letters`) →
   `events`, `ips`, `payloads` (+ row fragments) → investigations
   (`attacker`, `session`, `payload-analysis`) → `campaigns`, `clusters`,
   `commands`, `sandbox` → `overview` last (most JS surface). After each
   move, delete the corresponding Go const.
4. **CSP hardening**: enable `secHeaders` on all HTML routes once no inline
   handler or un-nonced script remains.
5. **Modal layer**: add `#modal-root`, `hp-modals.js`, then the inventory in
   §5.1 in this order: event detail → alert ack → payload preview → sandbox
   submit → export options.
6. **Cleanup**: remove dead Go consts, bump `?v=` busters, record the
   theme commit if re-vendored.

Keep each phase independently revertible. Never reset the branch or touch
honeypot data volumes.

## 7. Validation

On every change:

```bash
git diff --check
docker compose config --quiet
cd dashboard && go build ./... && go test ./...
npm --prefix dashboard/frontend ci
npm --prefix dashboard/frontend run typecheck
npm --prefix dashboard/frontend run build   # after any template/hp-app.js edit
```

Add/extend Go tests (pattern: existing `main_test.go`) for: initial shell
HTML per route, nonce presence on inline blocks, CSP header shape, row-
fragment endpoints, and the modal DOM contract. Visual acceptance matrix per
[MIGRATE-HONEYPOT-STACK.md §Visual acceptance](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MIGRATE-HONEYPOT-STACK.md)
— all routes at 1440×900, 1024×768, 390×844, dark and light, including each
open modal state.

## 8. Non-negotiable invariants

- Every current HTML route and JSON API stays available with the same
  shapes; filters, pagination, lazy loading, exports, external-tool links,
  PDF report, alert acknowledgement, and download authorization keep working.
- SSE, live toasts, and the map-preserving overview refresh keep working.
- `data-hp-*` hooks, `class="wrap"` + `data-hp-page-content`, and the
  `sidebar`/`topbar` template names stay load-bearing.
- `theme.css` stays byte-identical to the recorded `Xore/theme` commit;
  there is no separate dashboard CSS file — page CSS uses only theme custom
  properties for color.
- No CDN assets, no external fonts, no inline event handlers, no palette
  redefinition in Go strings.
- Modal behavior follows `MODALS.md` exactly — visual styling alone is not a
  modal implementation.

## 9. Completion criteria

- All templates render from embedded `ui/` files; `page_*.go` consts are gone
  or reduced to data assembly.
- Every HTML route sends the nonce-based CSP; no un-nonced inline script or
  style remains.
- The six modals of §5.1 are implemented with the full behavior contract and
  pass the §5.3 regression checks.
- All Go, TypeScript, Compose, and CI checks pass; the visual acceptance
  matrix is reviewed.
- Production deployment happens only when explicitly authorized.

---

## Appendix: source reference index

### Xore/auth-backend @ `a789089` — the render engine

| Construct | Location |
|---|---|
| `//go:embed ui` + `staticHandler` | [`forward-auth/static.go#L13-L23`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/static.go#L13-L23) |
| `tmplFuncs` + file-template parsing | [`forward-auth/page.go#L17-L30`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L17-L30) |
| `LoginPageData` + `renderLogin`/`renderVerify` | [`forward-auth/page.go#L34-L86`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L34-L86) |
| Const-page substitution (`renderEnroll`) | [`forward-auth/page.go#L88-L105`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L88-L105) |
| `pageCSS` (layout-only) | [`forward-auth/page.go#L184-L228`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L184-L228) |
| `pageHead` + page consts | [`forward-auth/page.go#L230-L396`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/page.go#L230-L396) |
| `mustReadUI` + `appTmpl` | [`forward-auth/apppage.go#L14-L22`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/apppage.go#L14-L22) |
| `AppPageData` + `renderApp` | [`forward-auth/apppage.go#L25-L50`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/apppage.go#L25-L50) |
| `nonce()` + `secHeaders()` (CSP) | [`forward-auth/server.go#L140-L173`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/server.go#L140-L173) |
| CSRF meta tag | [`forward-auth/ui/app.html#L7`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L7) |
| Permanent-modal CSS override | [`forward-auth/ui/app.html#L13-L16`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L13-L16) |
| `#flash` + permanent `<dialog>` + sidebar | [`forward-auth/ui/app.html#L90-L110`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L90-L110) |
| Three nested overlay backdrops (inside dialog) | [`forward-auth/ui/app.html#L112-L148`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L112-L148) |
| `esc()` / `copyToClipboard()` | [`forward-auth/ui/app.html#L160-L188`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L160-L188) |
| `flash()` / `api()` | [`forward-auth/ui/app.html#L197-L214`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L197-L214) |
| Danger-dialog state machine | [`forward-auth/ui/app.html#L224-L250`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L224-L250) |
| `confirmAct` confirmation copy table | [`forward-auth/ui/app.html#L252-L303`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L252-L303) |
| Edit dialog open/close/save | [`forward-auth/ui/app.html#L306-L360`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L306-L360) |
| `SETTINGS_NAV` / `ADMIN_NAV` / `renderNav` | [`forward-auth/ui/app.html#L363-L409`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L363-L409) |
| `PANE_TEMPLATES` registry | [`forward-auth/ui/app.html#L411`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L411) |
| Poll guard (open action menu) | [`forward-auth/ui/app.html#L792`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L792) |
| `PANE_LOADERS` / `showPane` / `fetchState` | [`forward-auth/ui/app.html#L1043-L1080`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1043-L1080) |
| `openSettings` (`showModal()`) | [`forward-auth/ui/app.html#L1082-L1090`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1082-L1090) |
| Keyboard layering (Escape/Enter) | [`forward-auth/ui/app.html#L1092-L1108`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1092-L1108) |
| `cancel` prevention + event wiring | [`forward-auth/ui/app.html#L1117-L1138`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1117-L1138) |
| Master delegated click router | [`forward-auth/ui/app.html#L1140-L1195`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1140-L1195) |
| Content delegation + Enter-in-field confirm | [`forward-auth/ui/app.html#L1197-L1205`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1197-L1205) |
| State poll interval + initial pane from URL | [`forward-auth/ui/app.html#L1207-L1212`](https://github.com/Xore/auth-backend/blob/a789089fd85397c2ded300c6ac2a91f386b25fc6/forward-auth/ui/app.html#L1207-L1212) |

### Xore/theme @ `7612eb5` — the design system

| Construct | Location |
|---|---|
| Top-layer invariant + containment examples | [`docs/MODALS.md#L18-L62`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md#L18-L62) |
| Permanent settings behavior | [`docs/MODALS.md#L64-L82`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md#L64-L82) |
| Confirmation behavior | [`docs/MODALS.md#L84-L101`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md#L84-L101) |
| Keyboard rules | [`docs/MODALS.md#L103-L113`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md#L103-L113) |
| State and accessibility | [`docs/MODALS.md#L115-L128`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md#L115-L128) |
| Required regression checks | [`docs/MODALS.md#L140-L154`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/MODALS.md#L140-L154) |
| Surface/text tokens | [`docs/TOKENS.md#L7-L42`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/TOKENS.md#L7-L42) |
| Geometry tokens | [`docs/TOKENS.md#L44-L52`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/docs/TOKENS.md#L44-L52) |
| `.btn` variants | [`theme.css#L272-L307`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L272-L307) |
| `.form-input` | [`theme.css#L326-L349`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L326-L349) |
| `.card` | [`theme.css#L414-L442`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L414-L442) |
| `.metric-grid` / `.metric` | [`theme.css#L444-L458`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L444-L458) |
| `.badge` semantic modifiers | [`theme.css#L460-L481`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L460-L481) |
| `.tabs` | [`theme.css#L498-L517`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L498-L517) |
| `.data-table` / `.table-scroll` | [`theme.css#L519-L541`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L519-L541) |
| `.toast` | [`theme.css#L679-L691`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L679-L691) |
| App-shell primitives (`.app-shell` → `.command-bar`) | [`theme.css#L892-L967`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L892-L967) |
| `.modal-backdrop` / `.modal` | [`theme.css#L969-L1002`](https://github.com/Xore/theme/blob/7612eb5f16589621744a1e734a57b27060c2ed91/theme.css#L969-L1002) |

### Xore/apiary @ `e3b6bc9` — the baseline being migrated

| Construct | Location |
|---|---|
| `pageTemplate` const concatenation | [`dashboard/page.go#L12`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/page.go#L12) |
| `{{define "style"}}` (asset links, pre-paint theme script) | [`dashboard/ui/partials/dashboard.html#L1-L13`](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html#L1-L13) |
| `{{define "sidebar"}}` (nav groups, recents, profile) | [`dashboard/ui/partials/dashboard.html#L15-L74`](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html#L15-L74) |
| `{{define "topbar"}}` + investigation command dock | [`dashboard/ui/partials/dashboard.html#L76-L126`](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html#L76-L126) |
| Shared `tbl` / `techniques` blocks | [`dashboard/ui/partials/dashboard.html#L128-L141`](https://github.com/Xore/apiary/blob/main/dashboard/ui/partials/dashboard.html#L128-L141) |
| Template `FuncMap` + one-time parse | [`dashboard/main.go#L118-L133`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L118-L133) |
| `/api/whoami` (forward-auth identity) | [`dashboard/main.go#L150-L157`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L150-L157) |
| SSE stream | [`dashboard/main.go#L159`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L159) |
| Lazy row-fragment endpoints | [`dashboard/main.go#L165-L198`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L165-L198), [`L306-L320`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L306-L320) |
| Exports (PDF report, CSV, history) | [`dashboard/main.go#L223-L230`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L223-L230), [`L357-L358`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L357-L358) |
| HTML route registrations | [`dashboard/main.go#L231-L372`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L231-L372) |
| Embedded static assets + cache headers | [`dashboard/assets.go`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/assets.go), [`dashboard/main.go#L360-L365`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/main.go#L360-L365) |
| Frontend architecture + theme sync | [`dashboard/frontend/README.md`](https://github.com/Xore/apiary/blob/e3b6bc92c5149492fcaddb7526c3934d51dd3513/dashboard/frontend/README.md) |
