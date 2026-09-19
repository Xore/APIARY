# Phase 2 — Style direction (three lanes)

Branch `design/dashboard-restyle`. Inputs: phase0-report.md (serving method, stack),
phase1-findings.md (audit + restyle-relevant observations). CPU-only, no homeserver touches.

## Deliverables — `design-lanes/`

Each lane = ONE self-contained HTML example of the dashboard overview screen only
(hero + KPI strip + 5 view tabs + activity heatmap + origins table + recent events +
sensor feeds + protocols; content mirrored from `src/routes/index.tsx` and
`components/OverviewPanels.tsx`), with a spec block in an HTML comment at the top.
Both light and dark schemes included per file (`data-theme="light"` + dark override block).

| Lane | File | 1280 shot | 390 shot |
|---|---|---|---|
| A — minimalist | `design-lanes/minimalist-overview.html` | `minimalist-overview-1280.png` | `minimalist-overview-390.png` |
| B — soft | `design-lanes/soft-overview.html` | `soft-overview-1280.png` | `soft-overview-390.png` |
| C — brutalist | `design-lanes/brutalist-overview.html` | `brutalist-overview-1280.png` | `brutalist-overview-390.png` |

All six PNGs verified: valid PNG, 1280w desktop, exactly 390w mobile (no horizontal
overflow; tables/tabs contained via overflow-x + flex-wrap at small viewports).

These are throwaway examples. All final CSS lands in `xore/theme` (repo rule) in later
phases — nothing here is applied to the dashboard.

## Lane summaries

**A — minimalist.** Near-white canvas, pure-white cards, hairline separation (no
shadows), single steel-blue accent, 4–6px radii, system sans, 34px tabular display
numerals. Status = colored dot + word, never a big color field. Flat hierarchy, most
"quiet" of the three.

**B — soft.** Warm ivory canvas closest to the existing "claude" palette (muted
terracotta accent — least disruptive to current branding), 14px radii, layered soft
shadows, pill tabs/badges, Nunito Sans, rounded heat cells. Most approachable.

**C — brutalist.** Paper/ink, 0 radius, 2px rules everywhere, mono-forward type
(IBM Plex Mono data + Archivo display), inverted-block active nav, stepped-opacity
outlined heat cells, solid status chips (word inside every chip — never color-alone).
Highest information density, most distinctive, largest departure from current UI.

## Phase 1 findings folded into all three lanes

- P1-2: small status text uses darkened per-status text variants (AA at 11–12px).
- P2-6: `font-variant-numeric: tabular-nums` on the page root (KPI numerals + tables).
- P2-8: `touch-action: manipulation` on body.
- P1-1: 44px tap targets in the topbar (icon buttons + avatar).
- Visible `:focus-visible` rings in every lane.

## Decision

`DECISION-02-style-lane.md` written to `/home/xore/desktop/` — WAITING on lane pick.
Per protocol, this leg stops here; nothing applied.

phase2-DONE rc=0
