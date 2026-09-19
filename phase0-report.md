# Phase 0 — Recon report (dashboard design lane)

Date: 2026-09-16. Branch: `design/dashboard-restyle` @ 00593d1d (clean).

## Serving method (no decision needed)

The frontend ships its own hermetic browser-test stack: `frontend-next/e2e/start-dashboard.mjs`
spins up fake redis (fixture OIDC sessions) + shape-correct fake backend (`e2e/fake-backend.mjs`,
`/api/v1/*` fixture JSON) and runs the **built production server** (`npm run build` →
`.output/server/index.mjs`) on `http://127.0.0.1:18080`. Auth = seeded session cookie
`__Host-apiary_bff=e2e-fixture-admin-session`. This is what the Playwright e2e matrix itself
uses — no homeserver, no real credentials, CPU-only.

## Stack

| Layer | What |
|---|---|
| Framework | React 19 + TanStack Start/Router (file routes, SSR shell + client hydrate), Vite 8, Nitro BFF |
| Charts | echarts 6 (wrapped `EChart.tsx`), cytoscape (graphs), leaflet (maps) |
| Other | xterm (TTY replay), noVNC (sandbox), ioredis (sessions) |
| Styling | **One vendored stylesheet**: `public/static/theme.css` (5071 lines, 612 custom properties), pinned to xore/theme@4a02619 (`theme.lock`, `sync-theme.sh`/`check-vendored-theme.sh` enforce byte-identity). No CSS-in-JS, no CSS modules, no Tailwind. |
| Theming | Dual-scheme: `:root` + `[data-theme="light"]`/`[data-theme="dark"]` + `prefers-color-scheme` fallback; persisted via `hp-theme` localStorage + appearance cookie; boot script applies before paint. Theme art toggle vars (`--theme-art-*-display`). |
| Branding | `branding/` = canonical visual spec: `tokens.json`, `source/` marks, `templates/web`, `design-lab/`, `pdf/`. |

## App surface

- Shell: `AppShell.tsx` (sidebar + topbar + modal layer), `Sidebar.tsx` (5 sections), `Topbar.tsx`
  (breadcrumb, LIVE badge, theme cycler, live toggle, command palette, avatar→settings modal).
- 23 nav routes across Monitor / Investigate / Operations / Reports / Tools / Evidence + 5
  off-nav pages (`/settings`, `/search`, `/dead-letters`, `/problem-reports`, `/credentials` is
  nav'd) + drill-downs (`/sessions/:id`, `/investigate/ip/:ip`, `/investigate/cidr/:cidr`,
  `/payload-analysis/:hash`, `/sandbox/:job`, `/tty-replay/:shasum`, `/revdeck/:sha`,
  `/ghidra/:sha`, `/cape/:sha`, `/github-analysis/:sha`).
- Components (25): AppShell, OverviewPanels, EChart, AttackerGraph, FiltersModal,
  CommandPalette, SettingsModal, ConfirmDialog, Tabs, SensorEvents, StoreList, CuratedSensorViews,
  Investigate, ArtifactList, CapturedMail, EsHistoryConsole, GhidraCallGraph, LiveToasts,
  ProblemReportButton, RowActions, ThemeGallery, ErrorState, CardIcons, Topbar, Sidebar.

## Screenshots — `dash-shots/before/` (114 files, ~9 MB)

28 top-level routes × {1280×800, 390×844} × {light, dark} = 112, plus settings modal (2).
Dark set captured by injecting `localStorage.hp-theme='dark'` via addInitScript. DOM health
sweep (error-boundary markers + empty-body check) passed on every route except one:

**Known fixture gap:** `/settings` (both viewports, both themes) renders the error boundary
under the fake backend — it fetches `/api/v1/settings/storage`, which `fake-backend.mjs` does
not implement. Not a dashboard defect. The settings *surface* is captured instead via the
avatar→SettingsModal shots (`settings-modal-1280.png`, `settings-modal-390.png`). The full
`/settings` page (2.5k-line route) would need a fixture addition if the redesign touches it —
flagging for Phase 1 rather than editing the repo now.

## Notes for later phases

- All CSS for the restyle lands in xore/theme (repo rule); `theme.css` is consumed verbatim.
- `branding/tokens.json` + `branding/templates/web` exist — Phase 3 token work should start
  from these, not invent a parallel source.
- Detail/drill-down routes were not shot (need fixture ids); baseline covers all sidebar-level
  surfaces, which is where the lane's visual decisions live.

phase0-DONE rc=0
