# Review #3226 — Leaflet shadcn theme

- Scope: `leafletTheme.ts` resolves shadcn CSS tokens through the shared `cssVar()` helper, writes Leaflet-specific custom properties, and activates the overrides through the `leaflet-shadcn` class swap.
- Integration: `OverviewPanels.tsx` applies the theme after map creation and reapplies it from the existing appearance subscription on palette or mode changes.
- Preservation: tile provider URL, attribution, layer options, map data, interactions, and route logic are unchanged. The browser gate confirms the tile URL is stable across palette changes and zoom, tooltip, and attribution controls remain visible and interactive.
- `npm run build`: PASS (rc0).
- `npm run typecheck`: PASS (rc0).
- `npx vitest run src/routes/-*-routes.test.tsx`: PASS (7 files, 24 tests).
- `EVIDENCE_DIR=/tmp/round10-logs/evidence-leaflet-s4-review npx playwright test e2e/leaflet-theme.spec.ts`: PASS (4 tests; 2 palettes × light/dark, exact token colors, palette refresh, zoom and tooltip interaction smoke).
- `git diff --check`: PASS (rc0).
- Evidence: gate logs and four screenshots are in `/tmp/round10-logs/evidence-leaflet-s4-review`.

SHIP
