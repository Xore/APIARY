# Phase 1 — Web Interface Guidelines baseline audit

Audited: branch `design/dashboard-restyle` @ 00593d1d, against the hermetic fixture stack
(127.0.0.1:18080) + `dash-shots/before/` captures (default "claude" palette, light + dark,
1280/390) + static review of `src/` and vendored `public/static/theme.css`.
Guidelines: vercel-labs/web-interface-guidelines @ 2026-09-16.

**Overall verdict: strong baseline.** The recent a11y work (#3182, #3183, #3193) closed the
worst gaps: skip link, toast live region, keyboard-operable everything, no div-onClick nav,
no `transition: all`, no `outline: none`, no zoom-blocking viewport. The findings below are
ranked; none are blockers, P1 items are the ones the restyle should fix while it's in there.

## P1 — Accessibility (should fix)

1. **Tap targets below WCAG 2.2 2.5.8 (24×24 min) in the 390px topbar.**
   Measured on `/` @390: brand link 22×22 (`theme.css:2763` `.app-toolbar__brand`), LIVE
   toggle 56×21 (`theme.css:2822` `.hp-live-state`, 10px font + 2px padding), avatar 30×30
   (`theme.css:1682`), icon buttons 32×32 (`theme.css:1058` `.btn-icon` — passes 24 min but
   under the 44px touch guideline). Fix = padding/hit-area expansion, not visual growth.

2. **Status colors used as 10–12px text at AA-large-only ratios (light mode).**
   `--success` 3.99, `--warning` 4.29, `--info` 4.01, `--danger` 4.4–4.5 on light surfaces —
   fine for 18px+ text, failing AA at the sizes actually used:
   `theme.css:3118-3120` `td.s-active/s-quiet/s-stale` (11px uppercase),
   `theme.css:2822` `.hp-live-state` (10px), `theme.css:2385` `.restart-note` (12px),
   `theme.css:1302-1303` `.metric__trend--up/down`, `theme.css:3216` `[data-copy]::after`
   "copied" (11px). Dark mode passes. Fix: dedicated `-text-on-soft`-style darkened text
   variants per status for small text (the pattern already exists for soft badges).

3. **`--accent` as small text = 4.49:1 in light mode (0.01 under AA).**
   Used as text at `theme.css:2037`, `:2091`, `:2734`, `:2750` (`.hp-brand-accent`).
   Also dark-mode accent/link on raised/200 surfaces: 3.77–4.48. Nudge one step.

4. **`--text-300` is decorative-only contrast (2.28 light / 2.74 dark).**
   Single use today: `theme.css:1097` `.form-input:disabled` (also opacity 0.62 → ~1.4:1
   effective). Disabled controls are WCAG-exempt, but this is effectively invisible; if
   text-300 gains new uses in the restyle it will fail everywhere.

5. **No `<meta name="theme-color">`.** `__root.tsx:146` sets viewport only. Mobile browser
   chrome won't match the (nice) warm surfaces in either mode.

## P2 — Guidelines polish (worth folding into the restyle)

6. **No `font-variant-numeric: tabular-nums`** anywhere in theme.css — every table/KPI/
   sparkline column compares numerals in proportional figures. One utility class + apply on
   `.metric__value`, `td.n`, mono table cells (some already get it via Fira Code).

7. **Only 7 of 44 route files sync state to the URL** (`useSearch`: index, events,
   recordings, search, settings, agent-campaigns, investigate.cluster). Filter/tab state on
   alerts, ips, payloads, credentials, canarytokens, history, source-health, ml-anomalies,
   llm-analysis, dead-letters is component-state only → not deep-linkable, breaks
   back-button expectations after a filter round-trip.

8. **`touch-action: manipulation` absent** (`theme.css` sets `-webkit-tap-highlight-color`
   at :812 but not touch-action) — legacy double-tap-zoom delay on iOS Safari tap targets.
   One line on the interactive-element rule.

9. **`.modal` (theme.css:2269) lacks `overscroll-behavior: contain`** — modal body scroll
   chains to the page behind on touch. Only one rule (:2910) has it today.

10. **No `env(safe-area-inset-*)` anywhere** — 390px captures show no current clipping
    (topbar is flush), but a restyle that moves chrome to the viewport edge needs them.

11. **No `scroll-margin-top` on heading anchors / `text-wrap: balance` on headings.** Minor:
    headings aren't anchor-linked today; balance matters if the restyle lengthens titles.

## P3 — Notes / non-issues (verified passes)

- ✓ Icon-only buttons all carry `aria-label`/`title` (0 unnamed in DOM sweep, both viewports).
- ✓ All `<img>` have `alt` + `width`/`height` (dimension-less imgs are Leaflet tiles, CSS-sized).
- ✓ All form inputs have labels/id/aria-label (DOM sweep: 0 unlabelled).
- ✓ Skip link + global `:focus-visible` ring (`theme.css:866`) work via real Tab keypress.
- ✓ `prefers-reduced-motion` honored (7 rules); transitions list properties explicitly.
- ✓ No horizontal overflow at 390px on any of 13 sampled routes (incl. tables, kill-chain,
  topology).
- ✓ `aria-live` on toasts, lazy-loaded panels, modal status; empty states styled + live.
- ✓ Unsaved-changes guard on settings (useBlocker + beforeunload, settings.tsx:8).
- ✓ ECharts canvas text reads theme tokens (`EChart.tsx` `themeColor()`), not hardcoded.
- ✓ No `user-scalable=no`, no paste-blocking, no autoFocus abuse (one justified use,
  investigate.lookup.tsx:134).
- Loading states use `…` correctly.
- Terminal pair is AAA (7.9/14.3); text-on-accent/status AA in both modes.
- `/settings` page error under fixture backend = fixture gap (see phase0-report), not a defect.

## Contrast reference (claude palette, key pairs)

| Pair | Light | Dark |
|---|---|---|
| text-000 on bg-000 | 12.98 AAA | 13.08 AAA |
| text-100 on bg-000 | 5.64 AA | 6.57 AA |
| accent on bg-000 | **4.49 ✗(by .01)** | 5.22 AA |
| text-on-accent on accent | 4.68 AA | 5.49 AA |
| success as text (small) | **3.99 ✗** | 6.4+ AA |
| warning as text (small) | **4.29 ✗** | 8.4+ AA |
| text-300 on bg-000 | **2.28 ✗** | **2.74 ✗** |

## Restyle-relevant observations (input for Phase 2)

- The system is already a 9-palette × light/dark token architecture (`src/lib/themes.ts`,
  `[data-hp-palette]` blocks in theme.css) with a copper/ivory default ("claude"). Any style
  lane picked in Phase 2 has to answer: does it replace the 9 palettes, become the 10th, or
  re-skin the default? (Not a Phase 2 decision — flag for DECISION-02 context.)
- Type system: 5-step scale 11–18px, Fira Sans body / Space Grotesk display / Fira Code mono /
  Georgia serif accents. Radius scale recently refreshed (6/12/16/24/999). Spacing scale
  4–40px. Shadows are token-based per-mode.
- Baseline captures exist for all 28 top-level routes × 2 viewports × 2 modes — the audit
  above sampled `claude` only; other 8 palettes inherit the same token structure.

phase1-DONE rc=0
