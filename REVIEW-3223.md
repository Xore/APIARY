# #3223 review

1. `arcane/home/honeypot-dashboard/frontend-next/src/lib/echartsTheme.ts:10`: 🔴 bug: `buildShadcnTheme` resolves axis grid lines from `--shadcn-muted` and never reads the required `--chart-grid` custom property. Resolve `--chart-grid` with its fallback and use it for `splitLine`.

## Verification

- Behavior: data fetching, resize observation, zoom, pan, drag, click handling, and builder data/options are unchanged outside theme-token selection and theme registration.
- Theme: `shadcn` registration and repaint-driven re-registration are present; `--chart-1` through `--chart-5`, `--foreground`, `--muted-foreground`, `--card`, and `--border` resolve through `cssVar`/`getComputedStyle(document.documentElement)` with fallbacks. `--chart-grid` is missing as noted above.
- Tests: `e2e/echarts-theme.spec.ts` defines 12 palette/mode/viewport matrix cases plus one palette-switch/resize/zoom case. Existing browser evidence reports 13 theme tests and four interaction tests passing, with 12 screenshots in `/tmp/round10-logs/evidence-subissue-creation`; browsers were not re-run.
- Scope: the S1 implementation touches only `EChart.tsx`, `echartsTheme.ts`, and `echarts-theme.spec.ts`; no route, primitive, or `theme.css` change is part of S1, and no AI attribution is present. Color literals are fallback values rather than direct theme sources.
- Gates: `npm run build` rc0; `npm run typecheck` rc0; seven requested route Vitest files, 24 tests, rc0; `git diff --check` rc0. Logs and rc files are in `/tmp/round10-logs/evidence-echarts-s1-review`.

VERDICT: FIX
