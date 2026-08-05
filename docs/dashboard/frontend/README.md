# Typed frontend boundary

This directory owns the browser-facing assets of the dashboard. The
production image serves the committed bundles in `../static/`, so Node.js is
not required at runtime. Run `npm ci`, `npm run typecheck`, and
`npm run build` after changing anything here.

## Vendored theme

`../static/theme.css` is a byte-identical copy of the shared Xore theme
(https://github.com/Xore/theme). The pinned commit and its SHA-256 live in
[`theme.lock`](../../../dashboard/frontend/theme.lock) — that file is the single source of truth, and
`scripts/check-vendored-theme.sh` enforces it in CI. It owns the
design tokens (dark, light, and system modes, plus the `--space-*` and
`--font-size-*` scales), the app-shell primitives
(`.app-shell`, `.app-toolbar`, `.app-sidebar`, `.app-main`, `.command-bar`),
and the shared components (`.card`, `.btn`, `.badge`, `.form-input`,
`.data-table`, `.tabs`, `.metric`). `theme.js` is intentionally not vendored —
`hp-app.js` owns theme preference, navigation, and command-dock behavior, and
`hp-modals.js`/`hp-settings.js` own the modal contract.

To re-sync after a theme release, from the repository root:

```bash
scripts/sync-theme.sh ../theme
```

The script copies the stylesheet, rewrites `theme.lock` with the new commit
and hash, and reminds you to rebuild the frontend bundle. Verify at any time
with:

```bash
scripts/check-vendored-theme.sh
```

When the vendored copy changes, re-read the shared docs before adapting the
dashboard: `docs/TOKENS.md` (token contract), `docs/MODALS.md` (modal
behavior contract), and `docs/MIGRATE-HONEYPOT-STACK.md` (migration
invariants) in `Xore/theme`.

## Architecture

- **Server-rendered shell, markup in `../ui/`.** Every page is a Go
  `html/template`, but no template text lives in Go any more. The app shell —
  `{{define "topbar"}}` (`.app-toolbar`), `{{define "sidebar"}}`
  (`.app-sidebar`), and the `[data-hp-page-content]` main container inside
  `.app-main` — is `../ui/partials/dashboard.html`, and each route's markup is
  its own file under `../ui/` (`overview.html`, `events.html`, `ips.html`, …).
  The `../page_*.go` files hold page *data*, not markup.
  There is no client-side DOM transform.

  This is enforced, not conventional: `TestRouteTemplatesRenderFromEmbeddedUI`
  in `../main_test.go` checks each expected `{{define}}` is present in its `ui/`
  file and reaches `pageTemplate`, then greps every non-test `.go` file in
  `dashboard/` and fails the build on any `{{define "` it finds. Putting markup
  back into a `page_*.go` breaks CI.
- **No app-specific CSS, vendored theme only, no build step.** `#191`
  removed the Tailwind build entirely, and the dashboard's own
  `hp-dashboard.css`/`hp-settings-modal.css` have since been folded upstream
  into `Xore/theme`'s `theme.css` and deleted — KPI tiles, tabs, data tables,
  sensor `badge b-*` hues, per-column table semantics
  (`td.n`/`td.v`/`td.ago`/`td.state`), Leaflet overrides, command-palette
  internals, and the rest all live in `../static/theme.css` now, vendored
  byte-identical from `Xore/theme` (see `../frontend/theme.lock` and
  `scripts/sync-theme.sh`/`scripts/check-vendored-theme.sh` at the repo
  root). To change dashboard styling, edit `theme.css` in the `Xore/theme`
  repo and re-vendor; there is no local CSS to hand-edit.
- **hp-api.js** — the typed API client (`src/api.ts`, esbuild bundle).
- **hp-app.js** — hand-written, framework-free enhancement layer in
  `../static/` (not built here): SSE live updates, in-place overview refresh
  that preserves the connected Leaflet map, dashboard tabs, lazy table-row
  loading, the investigation command dock (`/` shortcut), alert-bell polling,
  recent investigations, active-nav marking, sidebar collapse, the toolbar
  theme toggle (system/dark/light via `localStorage["hp-theme"]`), and the
  sidebar profile row (`/api/whoami`).
- **Leaflet** stays vendored for the attack-origin map.

After editing `../ui/*.html` or `hp-app.js`, re-run `npm run build` so the
Tailwind scan picks up new `tw:` utilities, then `go build ./... &&
go test ./...` from `dashboard/`.

## Browser regression suite

`npm run test:browser` starts the real Go dashboard against synthetic Cowrie
telemetry and checks all fourteen HTML routes across the dark/light and
desktop/tablet/mobile matrix. It also covers command routing, remote lazy-row
paging, map-preserving live replacement, role-aware report actions, and shared
confirmation-modal focus state. Playwright retains a trace and screenshot for
failures.

Install the browser once on a development machine, then run the suite:

```bash
npx playwright install chromium
npm run test:browser
```

To run the same read-only checks against an already running deployment, skip
the synthetic server by setting its base URL:

```bash
DASHBOARD_E2E_BASE_URL=https://dashboard.example npm run test:browser
```
