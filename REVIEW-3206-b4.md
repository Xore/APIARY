# REVIEW 3206-B4

Branch: `design/shadcn-migration` at `b8e8486ff6f6d17ecfee383d74d03c165fcc7a9a`

## Findings

1. `arcane/home/honeypot-dashboard/frontend-next/e2e/fake-backend.mjs:646` / `src/routes/-b4-routes.test.tsx:46`: 🔴 bug: `action_trail` is fixture-only `string[]`, but `ProblemReportButton` and `backend-service/src/problem_reports.rs:211-214` persist `{ at, kind, detail }[]`. Use real action-entry objects in both fixtures and assert one rendered detail so the problem-report route is exercised against the backend response shape.
2. `arcane/home/honeypot-dashboard/frontend-next/src/routes/reports.tsx:860,877,933`: 🔴 bug: visible `FieldLabel`s for Theme, Window, and Analysis job are not programmatically associated with their button group/select triggers; the new tests only query label text. Add `id` + `htmlFor` for the select triggers and `aria-labelledby` (or `FieldSet`/`FieldLegend`) for the theme group, then assert with label-based queries.

## Verified preservation and scope

1. Route fetch endpoints, pagination, semantic search, auth-event pivot link, problem-report status PATCH/refresh, report CRUD/generate/view/download/delete actions, report wizard state, and sidebar view-tab state are unchanged by the diff.
2. `StoreList.tsx`, `ErrorState.tsx`, and `ProblemReportButton.tsx` are unchanged. Existing shared `ProblemReportButton` integration remains intact.
3. The four routes use existing shadcn primitives with semantic `h2` headings. No inline styles, added raw hex values, `theme.css`/token edits, vendored primitives, or AI attribution were added.
4. LLM-analysis, auth-event, report-definition, generated-report, and problem-report field names otherwise match their worker/backend producers.

## Deferred theme.css deletion candidates

Do not delete in this leg. No runtime TS/TSX/JS consumer remains for:

- `public/static/theme.css:3185-3195` — `.hp-num` comment and rule.
- `public/static/theme.css:3593,3602,4817` — `.hp-rp-row-actions` rules.
- `public/static/theme.css:4433-4461` — `.template-card`, states, children, and `.template-card .chip`.
- `public/static/theme.css:4677-4694` — `.hp-rp-template`, states, and child rules.
- `public/static/theme.css:4772-4779,4816` — `.hp-rp-tag` and `.hp-rp-tag--light`.
- `public/static/theme.css:4788-4804` — `.hp-rp-payload-row`, states, code, and child rules.

## Gates

1. `npm run build`: PASS (`01-build.rc=0`).
2. `npm run typecheck`: PASS (`02-typecheck.rc=0`).
3. Requested seven-file Vitest command: PASS, 7 files / 24 tests (`03-vitest.rc=0`).
4. `git diff --check`: PASS (`04-diff-check.rc=0`).
5. Existing browser evidence verified without rerun: PASS, Playwright 8/8 and 16 screenshots in `/tmp/round10-logs/evidence-3206-b4` (`05-browser-evidence.rc=0`).

Review evidence: `/tmp/round10-logs/evidence-3206-b4-review`.

VERDICT: FIX
