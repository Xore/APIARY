# Honeystack Dashboard — UI Redesign Guide

> **Governing document:** the dashboard UI now follows the shared **Xore/theme**
> design system. The authoritative migration plan, invariants, visual
> requirements, and acceptance criteria live in the theme repository:
> [`Xore/theme` → `docs/MIGRATE-HONEYPOT-STACK.md`](https://github.com/Xore/theme/blob/main/docs/MIGRATE-HONEYPOT-STACK.md).
> Read that document first; this file only records the honeypot-stack-specific
> state and decisions. Theme tokens and primitives are documented in
> `Xore/theme` → `docs/TOKENS.md`; modal behavior (settings, command palette,
> destructive confirmations) in `Xore/theme` → `docs/MODALS.md`.
>
> **Do not** reintroduce the older Claude-theme/AdminLTE instructions that
> previous revisions of this file contained — they are superseded.

---

## 1. Vendored theme (Phase 1 — done)

- `dashboard/static/theme.css` is a **byte-identical** copy of
  `Xore/theme@31ea47f` (`31ea47ff9e272b032d85b2019feb1e6e59e72954`).
- Sync command (run from the repo root, with a local clone of Xore/theme at
  `../theme`):

  ```bash
  cp ../theme/theme.css dashboard/static/theme.css
  ```

  After syncing, bump the `?v=` cache-buster on the `theme.css` link in
  `dashboard/page_style.go` and rebuild nothing else — the file is embedded
  as-is.
- `theme.js` is intentionally **not** vendored: `dashboard/static/hp-app.js`
  owns theme preference, navigation, tabs, and keyboard shortcuts.
- Load order in every page head (`{{define "style"}}` in
  `ui/partials/dashboard.html`): `theme.css` → `leaflet.css`, then the
  deferred scripts (`leaflet.js`, `hp-api.js`, `hp-app.js`, …). All
  dashboard-specific styling that used to live in `hp-dashboard.css` has
  been folded upstream into `Xore/theme`'s `theme.css` and that file
  deleted — there is no separate dashboard CSS layer any more. A pre-paint
  inline
  script applies the saved theme preference (`localStorage hp-theme`:
  `light` / `dark` / absent = system) so there is no flash.

## 2. Implemented architecture (Phases 2–4 — done)

- **Server-rendered semantic shell** in `page_style.go`:
  `.app-shell` (CSS grid) → `.app-toolbar` (32 px) + `.app-sidebar` (224 px) +
  `.app-main`, with the investigation command dock rendered as `.command-bar`.
  No post-load DOM reconstruction; the toolbar exists in the initial HTML.
- **Sidebar**: brand, "New investigation" (`/` shortcut), nav groups
  Monitor / Investigate / Evidence covering all 12 routes, recent
  investigations (route/label/timestamp only — never event bodies), and a
  bottom `.sidebar__profile` row. Username/role come from live auth-backend
  session introspection via `GET /api/whoami`; unsigned `X-Auth-*` request
  headers are ignored. The row is filled by `hp-app.js`.
- **Templates**: the old ~106 KB `page.go` was split into nine files —
  `page_style.go` (head/shell/shared partials), `page_overview.go`,
  `page_events.go`, `page_ips.go` (+ attacker), `page_session.go`,
  `page_intel.go` (clusters/campaigns/commands), `page_payloads.go`
  (+ payload-analysis), `page_sandbox.go`, `page_ops.go` (history,
  dead-letters, source-health, alerts). `page.go` concatenates them into the
  `pageTemplate` const that `main.go` parses.
- **Content widths**: overview/events/ips/payloads run full-width (map + large
  tables); list/status pages use `.app-content` (1120 px); investigation pages
  (attacker, session, payload-analysis) use `.app-content--wide` (1360 px).
- **No dashboard-specific CSS layer.** `#191` removed the Tailwind build
  entirely, and the formerly-separate `static/hp-dashboard.css`
  (dashboard-specific components: KPI tiles, sensor badges, map/Leaflet
  overrides, tabs, lazy-list hooks, toast stacking, one-off spacing/layout
  rules) has since been folded upstream into `Xore/theme`'s `theme.css` and
  deleted from this repo. Every primitive (`.card`, `.btn`, `.badge`,
  `.form-input`, `.data-table`, `.tabs`, `.metric`, `.app-shell`, `.toast`,
  KPI/sensor-badge/Leaflet/command-palette classes, …) now comes from the
  single vendored `theme.css`.
- **Behavior** (`dashboard/static/hp-app.js`): SSE live updates, overview
  refresh that preserves the Leaflet map (pan/zoom/selection), lazy 25-row
  table loading, command-bar investigation router, alert-bell polling,
  recents, active-nav marking, sidebar collapse, and the
  system → dark → light toolbar theme toggle.
- **Assets**: fully self-contained — no CDN, no external fonts. AdminLTE and
  Bootstrap Icons were removed (Phase 4 step 7); Leaflet 1.9.4 remains
  vendored.
- Rebuild the frontend layer after editing `dashboard/frontend/src/`:

  ```bash
  ./scripts/build-dashboard-frontend.sh
  ```

  The script runs `npm ci`, `typecheck`, and `build` (with a local npm, or a
  `node:22-alpine` docker fallback) and then verifies that the compiled asset
  (`static/hp-api.js`) is current — the same check the "Dashboard frontend"
  CI job enforces with `git diff --exit-code`. Pass `--check` to fail instead
  of only reporting when the committed output is stale. Commit the
  regenerated asset together with the source change, and never hand-edit it:
  the minifier's property ordering cannot be reproduced by hand. There is no
  separate dashboard CSS file any more — styling changes go through
  `Xore/theme`'s `theme.css`, then `scripts/sync-theme.sh` to re-vendor.

## 3. Invariants that must not regress

From the migration guide — keep these green in every future change:

- Every HTML route and JSON API stays available; filters, pagination, lazy
  loading, exports, external-tool links, report generation, alert
  acknowledgement, and download authorization keep working.
- Live refresh preserves map center, zoom, selected marker, and popup; SSE
  and live-event toasts keep working.
- `class="wrap"` and `data-hp-page-content` on the content container, the
  `data-hp-*` JS hooks, and the `{{template "sidebar" .}}` /
  `{{template "topbar" .}}` calls are load-bearing — do not remove them.
- `theme.css` stays byte-identical to a recorded Xore/theme commit; there is
  no separate dashboard CSS file to drift from it.

## 4. Remaining work

Tracked as issues, not as a checklist here:

| What is left | Issue |
|---|---|
| Event detail, payload preview, export options, destructive dead-letter modals | [#59](https://github.com/Xore/honeypot-stack/issues/59) |
| Behavioural tests and the visual acceptance matrix | Built ([#60](https://github.com/Xore/honeypot-stack/issues/60)) |
| CSP cutover with a per-request nonce | [#58](https://github.com/Xore/honeypot-stack/issues/58) |
| Profile action menu, route/administrator settings, logout | Built ([#77](https://github.com/Xore/honeypot-stack/issues/77) closed). Remaining gap: [#93](https://github.com/Xore/honeypot-stack/issues/93) |

The shared modal root/controller and the first consequential flows — alert
acknowledgement and sandbox submission — already follow `Xore/theme` →
`docs/MODALS.md`, and are the reference for the rest.

Two standing rules that are not work items and so stay here:

- **Validate every change**: `git diff --check`, `docker compose config
  --quiet`, `go test ./...` in `dashboard/`, and frontend `ci` / `typecheck` /
  `build` / `test:browser`.
- **Production deployment only when explicitly authorized.**

## 5. Cross-references

- Migration plan & invariants:
  [`docs/MIGRATE-HONEYPOT-STACK.md`](https://github.com/Xore/theme/blob/main/docs/MIGRATE-HONEYPOT-STACK.md) (Xore/theme)
- Tokens & primitives:
  [`docs/TOKENS.md`](https://github.com/Xore/theme/blob/main/docs/TOKENS.md) (Xore/theme)
- Modal contract:
  [`docs/MODALS.md`](https://github.com/Xore/theme/blob/main/docs/MODALS.md) (Xore/theme)
- Frontend build details: `docs/dashboard/frontend/README.md`
- Root README dashboard section: `README.md` → “Analyse the data”
