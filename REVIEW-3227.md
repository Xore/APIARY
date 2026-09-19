# Review #3227 — noVNC shadcn theme

- Scope: `novncTheme.ts` resolves toolbar, border, button, hover, and focus colors from shadcn CSS custom properties via `getComputedStyle`; `sandbox.vnc.tsx` reapplies them through the existing appearance subscription.
- Preservation: RFB construction, WebSocket target, `viewOnly`, canvas setup, event handling, teardown, loader, authorization, and route behavior are unchanged.
- `npm run build`: PASS (rc0).
- `npm run typecheck`: PASS (rc0).
- `npx vitest run src/routes/-*-routes.test.tsx`: PASS (7 files, 24 tests).
- `EVIDENCE_DIR=/tmp/round10-logs/evidence-novnc-s5-review npx playwright test e2e/novnc-theme.spec.ts`: PASS (4 tests; 2 palettes × light/dark, exact chrome token colors, palette refresh, canvas and RFB startup smoke).
- `git diff --check`: PASS (rc0).
- Evidence: gate logs and four screenshots are in `/tmp/round10-logs/evidence-novnc-s5-review`.

SHIP
