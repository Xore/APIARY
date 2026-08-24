// The theme catalogue: one list, in one place.
//
// #1758: the same nine names used to live in four hardcoded lists across two
// repositories -- the picker, the settings search index, the token overrides
// in theme.css and the swatch colours in theme.css. Two of those are in the
// vendored stylesheet and cannot be edited from this repo at all, so adding a
// theme meant an upstream PR and a re-vendor before the other two could even
// be tested, and missing the search-index one made a theme invisible to
// search with no error anywhere.
//
// The stylesheet still owns the tokens -- it must, it is the vendored file --
// but the catalogue lives here, and `scripts/check-theme-catalogue.sh`
// cross-checks the two so they cannot drift apart silently.
//
// Preview colours are deliberately NOT listed here. The gallery renders each
// tile by scoping the theme's own attributes onto the tile
// (`<div data-hp-theme="slate" data-theme="dark">`), which works because
// every theme block in theme.css is an attribute selector rather than a
// `:root` rule, and `color-scheme` is set the same way. Verified in a
// browser: a nested slate tile paints rgb(29,31,34) in dark and
// rgb(242,244,247) in light, straight from the real tokens.
//
// That is worth more than tidiness. The old swatches were hardcoded
// dark-mode accents, so in light mode the operator picked from a row of
// colours that appeared nowhere in the interface they were looking at. A
// tile that renders the actual tokens cannot be wrong in one mode, because
// there is no second copy to get out of step.

export type Theme = {
  /** Written to `data-hp-theme` and stored as the `palette` preference. */
  id: string
  label: string
  /** One line, shown under the tile. Describes the surface, not the accent. */
  description: string
}

export const THEMES: Theme[] = [
  { id: 'claude', label: 'Claude', description: 'Warm charcoal and ivory, copper accent. The default.' },
  { id: 'slate', label: 'Slate', description: 'Cool blue-grey, the neutral technology palette.' },
  { id: 'ocean', label: 'Ocean', description: 'Deep blue ground with a bright cyan accent.' },
  { id: 'sage', label: 'Sage', description: 'Muted green, low saturation throughout.' },
  { id: 'lavender', label: 'Lavender', description: 'Soft violet ground, gentle contrast.' },
  { id: 'lime', label: 'Lime', description: 'Cool grey ground with a sharp green accent.' },
  { id: 'amber', label: 'Amber', description: 'Warm sand and a golden accent.' },
  { id: 'rose', label: 'Rose', description: 'Warm pink-grey, softer than Claude.' },
  { id: 'neon', label: 'Neon', description: 'Near-black ground, high-chroma accent.' },
]

export const DEFAULT_THEME = 'claude'

/** Ids only, for allowlists and tests. */
export const THEME_IDS: string[] = THEMES.map((theme) => theme.id)

/**
 * The words settings search matches a theme on.
 *
 * Derived rather than written out, which is the point: the hand-maintained
 * copy of this string was one of the four lists, and forgetting it hid a
 * theme from search with nothing to indicate why.
 */
export function themeSearchTerms(): string {
  return THEMES.map((theme) => `${theme.id} ${theme.label}`)
    .join(' ')
    .toLowerCase()
}
