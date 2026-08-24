// Resolves a CSS custom property to a value a canvas can actually paint.
//
// #1853: reading the property directly is not enough any more. Since
// Xore/theme#104 the colour tokens are declared as `light-dark()`:
//
//     --text-000: light-dark(#2f2b27, #e9e6df);
//
// `getPropertyValue('--text-000')` returns that string verbatim, because a
// custom property's value is whatever text it was given -- the function is
// only evaluated when the value is *used* in a real property. So every
// canvas surface (ECharts, the cytoscape graphs, xterm) was handed the
// literal string `light-dark(#2f2b27, #e9e6df)`, could not parse it, and
// fell back to its own default: black text and black strokes on a dark
// ground, with legends unreadable.
//
// Painting it resolves it. A detached probe with `color: var(--x)` gives the
// computed colour for the mode currently in effect -- rgb(233, 230, 223) for
// the token above in dark, the light value in light -- which is what a
// canvas needs.
//
// The probe is deliberately cheap and short-lived: one element, appended,
// read, removed. Results are cached per (name, appearance) because charts
// resolve a dozen tokens each and a page can hold several charts; the cache
// is dropped whenever the appearance changes, since that is exactly when the
// answers change.

let cache = new Map<string, string>()
let cacheKey = ''

/** Drop the memoised values. Called when the theme or mode changes. */
export function resetCssVarCache(): void {
  cache = new Map()
  cacheKey = ''
}

function currentAppearance(): string {
  if (typeof document === 'undefined') return ''
  const root = document.documentElement
  return `${root.dataset.theme ?? ''}:${root.dataset.hpTheme ?? ''}`
}

export function cssVar(name: string, fallback = ''): string {
  if (typeof document === 'undefined') return fallback

  const appearance = currentAppearance()
  if (appearance !== cacheKey) {
    cache = new Map()
    cacheKey = appearance
  }
  const hit = cache.get(name)
  if (hit !== undefined) return hit

  const raw = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  if (!raw) return fallback

  // Already a plain colour (hex, rgb(), a keyword) -- nothing to resolve, and
  // no reason to touch the DOM for it.
  if (!raw.includes('(') || /^(rgb|rgba|hsl|hsla)\(/i.test(raw)) {
    cache.set(name, raw)
    return raw
  }

  // light-dark(), color-mix(), var() indirection: let the engine compute it.
  try {
    const probe = document.createElement('span')
    probe.style.cssText = 'position:absolute;visibility:hidden;pointer-events:none'
    probe.style.color = `var(${name})`
    document.documentElement.appendChild(probe)
    const resolved = getComputedStyle(probe).color
    probe.remove()
    const value = resolved || fallback
    cache.set(name, value)
    return value
  } catch {
    return fallback
  }
}
