# AI implementation guide: render the dashboard with the Xore/auth-backend engine

## Objective

Render every page of the honeypot-stack dashboard (`dashboard/`) with the same
render engine that `Xore/auth-backend` uses for its embedded Go UI
(`forward-auth/`), styled by the shared `Xore/theme` design system, including
its modal architecture. Present the honeypot data in a logical, investigation-
first layout.

This is a frontend/rendering task. Do not touch ingestion, aggregation,
analysis, alerting, or storage logic. Every existing HTML route, JSON API,
export, and live behavior must keep working.

Read first, in this order:

1. [`Xore/theme` → `docs/TOKENS.md`](https://github.com/Xore/theme/blob/main/docs/TOKENS.md) — token contract.
2. [`Xore/theme` → `docs/MODALS.md`](https://github.com/Xore/theme/blob/main/docs/MODALS.md) — modal behavior contract.
3. [`Xore/theme` → `docs/MIGRATE-HONEYPOT-STACK.md`](https://github.com/Xore/theme/blob/main/docs/MIGRATE-HONEYPOT-STACK.md) — migration invariants.
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
as the canonical pattern to replicate.

### 1.1 Embedded assets, served at `/static/`

`forward-auth/static.go`:

```go
//go:embed ui
var uiFS embed.FS

func staticHandler() http.Handler {
	sub, _ := fs.Sub(uiFS, "ui")
	return http.StripPrefix("/static/", http.FileServer(http.FS(sub)))
}
```

- `ui/` holds the vendored `theme.css` (byte-identical to a recorded
  `Xore/theme` commit), page templates, and compiled CSS. No CDN, no external
  fonts, no runtime Node.js.
- Pages link `/static/theme.css`; the palette is never inlined into Go code.
  All colors in page-level CSS reference theme custom properties
  (`var(--surface-1)`, `var(--accent)`, …).

### 1.2 Three rendering patterns

Pick per page size; never mix them inside one page.

**A. File-based `html/template` (default for real pages).**
`ui/login.html`, `ui/verify.html`, `ui/app.html` are parsed once at init:

```go
var loginTmpl = template.Must(template.New("login").Funcs(tmplFuncs).
	Parse(string(mustReadUI("login.html"))))
```

Each page gets a typed data struct (`LoginPageData`, `AppPageData`) and a
`renderX(w, …)` method that sets `Content-Type`, injects a per-request CSP
nonce, and executes the template. Template values are auto-escaped by
`html/template`; JS-side interpolation goes through an `esc()` helper.

**B. Const-string pages with placeholder substitution (only for tiny,
static pages).** Small transactional pages (forbidden, password change,
recovery) are Go `const` strings built from a shared `pageHead` plus body,
with `strings.ReplaceAll` for the few `{{TOKEN}}`-style slots. Every dynamic
value passes through `htmlEscape`. Do not use this pattern for data-rich
dashboard pages — it exists for pages with <10 substitutions.

**C. Application shell (one rich page).** `ui/app.html` is a single template
that renders the whole authenticated surface: a permanent native `<dialog>`
with a sidebar, pane skeletons rendered client-side from a `PANE_TEMPLATES`
registry, data filled by `PANE_LOADERS` fetch calls, and all nested overlays
living **inside** the dialog element.

### 1.3 Shared page head and nonce'd page CSS

`page.go` builds every head from one const:

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

- `pageCSS` contains **layout only**. Every color is a theme custom property;
  redefining the palette is a defect.
- Inline `<style>` and `<script>` blocks always carry the per-request nonce.
- `meta robots noindex` on all authenticated surfaces.

### 1.4 Security headers and CSP

`renderApp` calls `secHeaders(w, nonce)` before writing. The CSP is
nonce-based plus `'self'`, which is only possible because there are **no
inline event handlers** — all JS wiring is `addEventListener` or event
delegation from a nonce'd script block. CSRF lives in a
`<meta name="csrf-token">` tag and is sent as an `X-Csrf` header on every
mutating fetch.

### 1.5 Modal architecture (the part to copy faithfully)

From `ui/app.html`, implementing `Xore/theme/docs/MODALS.md`:

- **Permanent surface**: one native `<dialog class="modal modal--permanent">`
  opened with `showModal()` on load, `100vw × 100dvh`, no close button, and
  its native `cancel` event is `preventDefault()`'ed so Escape can never
  close it.
- **Nested overlays are descendants of the dialog.** The edit, rotate-key,
  and danger confirmations are `<div class="edit-dialog-backdrop">` elements
  placed *inside* the `<dialog>`, because a native top-layer dialog hides any
  sibling overlay regardless of `z-index`. Never render an overlay next to a
  permanent native dialog.
- **State machine per overlay**: closed = `aria-hidden="true"` + `inert` +
  no `.open` class; opening removes `inert`, sets `aria-hidden="false"`,
  adds `.open`, then moves focus into the panel. Closing reverses it and
  restores focus. Opacity alone never "closes" anything.
- **Confirmation contract**: initiating click/Enter opens the warning →
  warning names the action and its consequences → focus lands on the confirm
  control → Cancel closes only the nested layer and returns focus → Confirm
  clears the pending callback *before* running it (so double-Enter cannot
  fire twice), executes once, and reports via a flash toast.
- **Keyboard layering**: Escape closes the deepest open layer first (danger →
  rotate → edit → action menu), never the permanent surface. Enter in a
  config field opens the same confirmation as its Save button.
- **Roles**: `role="dialog"` for edits, `role="alertdialog"` for
  consequential confirmations, always `aria-modal="true"` +
  `aria-labelledby`.
- **Flash toast**: a single `#flash` fixed-position element reports
  success/failure of async actions; errors get a longer timeout.

### 1.6 Client-side conventions

- `esc(s)` escapes every value interpolated into `innerHTML` — no exceptions.
- One `api(path, body)` helper: JSON POST, `X-Csrf` header, parses
  `{error: …}` and flashes it.
- Event delegation on stable containers (`document` or `#settings-content`),
  because pane DOM is re-rendered; delegated handlers survive re-renders.
- Background state polling must not clobber interaction: re-render is skipped
  while an action menu is open, and config inputs are never refreshed while
  the admin is typing.
- Panes/routes are data-driven registries (`SETTINGS_NAV`, `PANE_TEMPLATES`,
  `PANE_LOADERS`), not ad-hoc `if` chains.

---

## 2. Dashboard baseline (what exists today)

- Pages are Go templates assembled as one `pageTemplate` const
  (`dashboard/page.go` = `pageStyle + pageOverview + pageEvents + pageIPs +
  pageSession + pageIntel + pagePayloads + pageSandbox + pageOps`), parsed
  once in `main.go` with a `FuncMap` (`worldMap`, `json`, `dict`) and executed
  per route with typed data structs (`s.get()`, `s.eventsData(r)`,
  `s.attackerData(ip)`, …).
- The semantic shell is already server-rendered in `page_style.go`:
  `.app-shell` → `{{define "topbar"}}` (`.app-toolbar`), `{{define "sidebar"}}`
  (`.app-sidebar`), `[data-hp-page-content]` inside `.app-main`, and the
  `.command-bar` investigation dock. No client-side DOM reconstruction.
- `dashboard/static/theme.css` is vendored byte-identical to
  `Xore/theme@9e11b23`; `hp-tailwind.css` is the dashboard layer compiled
  from `dashboard/frontend/src/shell.css`; `hp-app.js` is the hand-written
  enhancement layer (SSE, lazy rows, live refresh, theme toggle, recents).
- Row-fragment endpoints (`/api/event-rows`, `/api/ip-rows`,
  `/api/payload-rows`) return server-rendered HTML for lazy loading.
- **Gaps this guide closes**: templates live as Go string consts instead of
  embedded files; there is no nonce-based CSP (an inline pre-paint script
  runs without one); and there are **no modals at all** — no detail dialogs,
  no destructive confirmations.

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
  static/                  # unchanged: theme.css, hp-tailwind.css, hp-app.js,
                           # hp-api.js, hp-modals.js (NEW), leaflet.*
  ui.go                    # NEW — embed, mustReadUI, template parsing, FuncMap
  render.go                # NEW — PageData structs + renderX methods, secHeaders+nonce
```

Keep `page_*.go` during the transition: move each `{{define}}` block into its
`ui/*.html` file one route at a time, and shrink `page.go` until it only
concatenates nothing. Delete each Go const only after its file template
renders the route byte-comparably (allowing for whitespace).

### 3.2 Template parsing and render functions

Mirror auth-backend exactly:

```go
// ui.go
//go:embed ui
var uiFS embed.FS

func mustReadUI(name string) []byte { /* panic on error, same as auth-backend */ }

var tmplFuncs = template.FuncMap{
	"worldMap": func() template.HTML { return template.HTML(worldMapSVG) },
	"json":     func(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) },
	"dict":     func(pairs ...any) map[string]any { /* as in main.go today */ },
	"seq":      func(n int) []int { /* as in auth-backend */ },
	"add":      func(a, b int) int { return a + b },
}
```

Parse per page: every page template is parsed together with the shared
partials (`template.ParseFS(uiFS, "ui/partials/*.html", "ui/overview.html")`
or via `mustReadUI` + `Parse`). Keep the existing `{{define "style"}}`,
`{{define "sidebar"}}`, `{{define "topbar"}}`, `{{define "tbl"}}` names so
`main_test.go`'s shell/route assertions keep passing.

Each route keeps its current data struct and gains a render method:

```go
func (s *server) renderEvents(w http.ResponseWriter, r *http.Request) {
	n := nonce()
	secHeaders(w, n)                      // NEW: nonce-based CSP, same helper as auth-backend
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := s.eventsData(r)
	data.Nonce = n                        // every PageData gains a Nonce field
	if err := eventsTmpl.ExecuteTemplate(w, "events", data); err != nil {
		s.log.Error("render events", "error", err)
	}
}
```

### 3.3 Shared head and shell partial

`partials/head.html` reproduces the current `{{define "style"}}` but with the
pre-paint theme script nonce'd:

```html
<link rel="stylesheet" href="/static/theme.css?v={{.AssetVersion}}">
<link rel="stylesheet" href="/static/leaflet.css?v={{.AssetVersion}}">
<link rel="stylesheet" href="/static/hp-tailwind.css?v={{.AssetVersion}}">
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

`/api/event-rows`, `/api/ip-rows`, `/api/payload-rows` stay HTML-fragment
endpoints. Their `eventrows` / `iprows` / `payloadrows` templates move into
the corresponding `ui/*.html` files unchanged, so the lazy-list contract
(25 rows per fetch, sentinel-driven) is untouched.

### 3.5 CSP

Add a `secHeaders(w, nonce)` equivalent. Target policy:

```text
default-src 'self'; script-src 'self' 'nonce-<n>'; style-src 'self' 'nonce-<n>';
img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'
```

This requires `hp-app.js`/`hp-modals.js` to contain zero inline-handler
reliance (they already use `addEventListener`) and every inline `<script>`
in templates to carry `nonce="{{.Nonce}}"`.

---

## 4. Presenting the data: information architecture

Organize by the operator's workflow: **detect → triage → investigate →
preserve evidence**. The existing three sidebar groups already encode this —
keep them, and make every page answer exactly one question.

### 4.1 Monitor (answer: "is something happening right now?")

| Route | Question answered | Layout |
|---|---|---|
| `/` overview | What is the current threat picture? | Full width. `.metric-grid` KPI row (events 24h, unique sources, payloads, open alerts — neutral tiles, severity only in badges). Attack-origin map (Leaflet, state preserved across refresh). Activity feed + top-N `tbl` cards (top IPs, usernames, passwords, commands, paths). Source-health strip. |
| `/source-health` | Are all sensors and the pipeline alive? | `.app-content` (1120px). Status grid: one card per expected sensor with last-seen, event rate, and a `.badge` state (green/red). Elasticsearch/filebeat status rows. |
| `/alerts` | What needs acknowledgement? | `.app-content`. Alert table (rule, severity badge, first/last fired, count) with per-row **Acknowledge** action → confirmation modal (§5). |

### 4.2 Investigate (answer: "who/what/where exactly?")

| Route | Question answered | Layout |
|---|---|---|
| `/events` | Which raw events match my filter? | Full width. Sticky filter bar (time range, sensor, IP, free text) → lazy 25-row `.data-table` in `.table-scroll`, expandable normalized JSON per row, "load more" sentinel, CSV export. Row click opens the **event detail modal** (§5) instead of navigating away when only reading. |
| `/ips` | Which sources attack us? | Full width lazy table: IP, country/ASN (GeoIP), first/last seen, sensor spread, event count. Row → `/investigate/ip/{ip}`. |
| `/investigate/ip/{ip}` | What did this one source do, in order? | `.app-content--wide` (1360px). Header card: IP, geo/ASN, totals, MITRE `techniques` block. Below: chronological **attack-chain timeline** (vertical, timestamped events, session boundaries), linked sessions and payload references. |
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
  whole-panel color (token contract, `--*-soft` surfaces).
- Identifiers (IPs, hashes, sessions, commands) always render in the mono
  stack and are copy-on-click where useful (reuse the auth-backend
  `copy-box`/clipboard pattern with the flash toast as feedback).
- Every list page has an explicit empty state (`(none)`/`empty-row`) and an
  error state; every table is horizontally scrollable on narrow screens.
- Widths: full width for map/large tables, 1120px `.app-content` for
  list/status pages, 1360px `.app-content--wide` for investigations.
- The `.command-bar` investigation dock stays the global entry point (`/`
  shortcut) — it is a command bar, not a modal; do not convert it.
- Live behavior is non-negotiable: SSE toasts, 15s in-place overview refresh
  preserving map pan/zoom/selection, alert-bell polling.

---

## 5. Modal plan for the dashboard

The dashboard currently has no modals; add them per
`Xore/theme/docs/MODALS.md`. The dashboard shell is an ordinary
server-rendered page (not a permanent dialog), so dashboard modals are
**temporary application-managed overlays** rendered in a single
`#modal-root` at the end of `partials/shell.html`. If any native
`<dialog>` is ever used as a permanent surface, every overlay becomes its
descendant — the top-layer invariant is absolute.

### 5.1 Modal inventory

| Modal | Trigger | Role | Notes |
|---|---|---|---|
| Event detail | Row click in `/events` | `dialog` | Full normalized JSON (pretty `json` func), sensor, geo, links to attacker profile/session. Read-only. |
| Payload preview | "Preview" in `/payloads` | `dialog` | Safe text/hex rendering only — server must sanitize/escape; never inject raw payload bytes as HTML. Size-capped. |
| Alert acknowledgement | "Acknowledge" in `/alerts` | `alertdialog` | Confirmation contract: names rule + consequence (silences for the cooldown window), confirm runs once. |
| Sandbox submit / resubmit | "Submit to sandbox" | `alertdialog` | Confirms detonation of a specific hash; result links to job. |
| Report / export options | Export buttons (PDF report, CSV) | `dialog` | Time-range and section selection, then navigates to the export URL. |
| Destructive ops (dead-letter purge, payload delete if added) | Row action menus | `alertdialog` | Same copy pattern as auth-backend `confirmAct`: title = question, desc = consequences, warning box lists immediate effects. |

### 5.2 DOM skeleton (in `partials/shell.html`)

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
`aria-hidden="false"`, add `.open`, focus first control; close = reverse +
restore focus to the initiating element. One pending-callback variable,
cleared before execution. Escape closes only the deepest layer. Backdrop
click (target === backdrop) cancels temporary dialogs. Tab cycles within the
open layer. All wiring via delegation — no inline handlers (CSP).

Regression checks to automate (jsdom or browser test):

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
   "techniques"}}` from `page_style.go` into `ui/partials/*.html` with the
   nonce'd head. Wire parsing; verify every route still renders.
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
`MIGRATE-HONEYPOT-STACK.md` §Visual acceptance — all routes at 1440×900,
1024×768, 390×844, dark and light, including each open modal state.

## 8. Non-negotiable invariants

- Every current HTML route and JSON API stays available with the same
  shapes; filters, pagination, lazy loading, exports, external-tool links,
  PDF report, alert acknowledgement, and download authorization keep working.
- SSE, live toasts, and the map-preserving overview refresh keep working.
- `data-hp-*` hooks, `class="wrap"` + `data-hp-page-content`, and the
  `sidebar`/`topbar` template names stay load-bearing.
- `theme.css` stays byte-identical to the recorded `Xore/theme` commit;
  dashboard-specific CSS lives only in `shell.css`/`hp-tailwind.css`;
  page CSS uses only theme custom properties for color.
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
