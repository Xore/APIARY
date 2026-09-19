# REVIEW 3206-B3

1. `arcane/home/honeypot-dashboard/frontend-next/src/routes/canarytokens.tsx:408`: 🔴 bug: each template card uses a raw `<button>` containing `<h2>` and `<p>` flow content; that is invalid button markup, weakens the requested semantic per-card headings, and bypasses stock shadcn `Button` chrome. Render the `CardTitle`/description outside the control and use a labeled shadcn `Button` (or a valid labeled overlay control) for template selection.

Verified: event URL state, live refresh, paging, row actions, lazy controls, non-reflowing 390 table, payload paging/actions, canary tabs/filters/gallery data flow, and the existing `ConfirmDialog`/`FiltersModal`/`StoreList`/`ErrorState` call contracts are otherwise preserved. The B3 event fixture matches `backend-service/src/events.rs` (`EventRow`, `EventPivots`, `EventsPage`) without invented fields. No inline styles, raw hex colors, theme/token edits, vendored primitives, or AI attribution were added.

Gates: `npm run build` rc0; `npm run typecheck` rc0; requested six-file Vitest run 20/20; `git diff --check` rc0. Existing `/tmp/round10-logs/evidence-3206-b3` contains 12 screenshots and Playwright rc0 for 3 routes × 1280/390 × light/dark; browsers were not rerun.

VERDICT: FIX
