# Review #3225 — Cytoscape shadcn theme

- Scope: `cytoscapeTheme.ts` reads runtime shadcn tokens through the shared `cssVar()` helper used by ECharts/Xterm; no AI attribution.
- Integration: `AttackerGraph.tsx` applies the stylesheet at Cytoscape initialization and reapplies it from the existing appearance subscription without rebuilding or refetching the graph.
- Preservation: graph elements, concentric layout, zoom bounds, resize handling, spoke navigation, endpoint, and route logic are unchanged. Added hover/selection rules are presentation-only.
- `npm run build`: PASS (rc0).
- `npm run typecheck`: PASS (rc0).
- `npx vitest run src/routes/-*-routes.test.tsx`: PASS (7 files, 24 tests).
- `EVIDENCE_DIR=/tmp/round10-logs/evidence-cytoscape-s3-review npx playwright test e2e/cytoscape-theme.spec.ts`: PASS (4 tests; 2 palettes × light/dark, desktop/mobile, exact token colors, palette refresh, hover and spoke-navigation smoke).
- `git diff --check`: PASS (rc0).
- Evidence: four screenshots in `/tmp/round10-logs/evidence-cytoscape-s3-review`.

SHIP
