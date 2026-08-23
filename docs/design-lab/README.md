# Design lab

The tooling that produced the dashboard's current design and its colour
palettes. Recovered from a local scratch directory where it was the only
copy — see #1763.

Nothing here runs in production. It is kept because the stylesheet's own
comments refer to decisions ("pick 6E, supersedes 6D") whose evidence lived
nowhere durable, and because the palette generator is the only executable
record of *why* the themes are the colours they are.

Real hostnames, the internal server address and a captured attacker IP were
replaced with documentation-range placeholders when these files were moved
into the public repository. Nothing else was edited.

## Contents

| file | what it is |
|---|---|
| `gen_palettes.py` | Generates the accent palettes and auto-tunes each until it clears WCAG AA. Holds the seed hues and the pair table. |
| `contrast_scan.js` | The scanning half of the same. |
| `palettes.css` | Generated output — the block that was pasted into `theme.css`. |
| `playground/` | `elements.html` is the option gallery Xore picked from: per-component variants, choices captured in `localStorage`, with a "copy picks" export. `compare.html` is a drag-split variant comparison. |
| `v5-picks-override.css` | A named variant as a token-override block layered on the vendored `theme.css` — the authoring pattern the variants were built with. |
| `design-notes.md` | The raw review log the picks came out of: per-page findings, the reference-app pattern catalog, and the directives collected during review. |

## The two rounds

The pick letters in `theme.css` comments refer to the **second** round. Both
are recorded in merged PRs:

| round | picks | shipped as |
|---|---|---|
| Design refresh | elements `1D/2D/3B/4C/5D/6D/7D/8B/9C/10C`, layouts `OV-B/EV-B/AS-C/RP-C`, shell `11C/12B/13B/14B` | #1573 + `Xore/theme#79` |
| **Design refresh 2 — "claude-pure"** *(current)* | all-**E** element set, with `scroll:D events:D sources:D reports:D` | #1588 + `Xore/theme#84`–`#89`, pin `68e3f09` |

The live design is the second: floating pill topbar with breadcrumb and
avatar, focus-column overview, minute-grouped event feed with the normalized
record pane opening only on row click, profile-card source grid,
document-style reports studio, circular scroll button, serif empty states
with line icons.

## Standing rules set during that session

- No lazy-loading. A "view more" button instead.
- Anything populated from Elasticsearch renders skeletons first, then
  hydrates.
- One page width across all pages; the overview is full-width but keeps its
  focus elements.
- SPA feel: only the centre content refreshes, never a full browser reload.

## Colour research

The palettes came from a 2026 UI colour-trend pass, not a brand benchmark.
Its findings were mostly about **grounds and neutrals** — elevated neutrals
(soft greys, warm sand, stone, muted clay, oatmeal, taupe), zinc/slate as the
dominant direction for technology products, lime with cool whites for
dashboards, "avoid grey-on-grey fatigue" in dark mode, and earth tones for a
sense of long-term value.

Only the accent half was implementable at the time, because a preset could
reach eight accent tokens. Finishing the other half is #1753.

## Rebuilding the harness

The original lab served variant builds against real Elasticsearch data on
ports 19201–19205, driven by an env-guarded Go test that booted the dashboard
with a stubbed OIDC session, a `STATIC_DIR` override and nil write-services
so the real index stayed read-only. That harness depended on the Go dashboard
and went away with it. A `frontend-next` equivalent needs the same read-only
guarantees; scoped separately.
