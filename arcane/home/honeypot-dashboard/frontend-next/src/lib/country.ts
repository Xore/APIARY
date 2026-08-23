// ISO-3166 alpha-2 -> full country name, for the hover title on every
// country badge.
//
// The pre-port Go dashboard did this in static/hp-app.js: it resolved the
// name with Intl.DisplayNames and set `title` on every `[data-hp-country]`
// element, re-running through a MutationObserver so lazily loaded rows
// picked it up too. The port kept the badges and dropped the resolution,
// so a badge reading "CN" no longer told anyone it meant China.
//
// React needs no MutationObserver — deriving the title at render covers
// rows added later for free. Intl.DisplayNames exists in Node too, so the
// server render and the client render agree and hydration stays quiet.

const displayNames = (() => {
  try {
    return typeof Intl !== 'undefined' && 'DisplayNames' in Intl ? new Intl.DisplayNames(['en'], { type: 'region' }) : null
  } catch {
    return null
  }
})()

/**
 * The full English name for a country code, or undefined when it cannot be
 * resolved — an unknown code, a non-region string, or a runtime without
 * Intl.DisplayNames. Returning undefined (rather than echoing the code)
 * keeps `title={countryName(code)}` from rendering a tooltip that just
 * repeats the two letters already on screen, which is what the legacy
 * `name !== code.toUpperCase()` guard was for.
 */
export function countryName(code: string | null | undefined): string | undefined {
  if (!code) return undefined
  const upper = code.toUpperCase()
  try {
    const name = displayNames?.of(upper)
    return name && name !== upper ? name : undefined
  } catch {
    return undefined
  }
}
