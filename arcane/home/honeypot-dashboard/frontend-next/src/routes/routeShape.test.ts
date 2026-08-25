// A route file that has children is a layout, and a layout that redirects
// is an infinite loop.
//
// This is the shape that broke every sensor page on a cold load. `sensors.tsx`
// looked like a page — it had no component, only a `beforeLoad` that sent
// /sensors to the busiest sensor. But TanStack's file convention nests
// `sensors.$sensor` under any `sensors` route that exists, so it was the
// detail page's *parent*: loading /sensors/cowrie entered the parent,
// which redirected to /sensors/cowrie, which entered the parent again.
//
// Nothing caught it. It typechecks, it builds, and a client-side
// transition inside an already-loaded app does not re-enter the parent the
// same way — so it survives desktop clicking and fails on a deep link, a
// refresh, or a phone opening a fresh document.
//
// The rule is mechanical, so it is checked mechanically rather than
// remembered: if `X.tsx` and any `X.<child>.tsx` both exist, `X.tsx` is a
// layout and must not redirect. Put the redirect in `X.index.tsx`, which
// is a leaf and has no children to drag with it.
import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROUTES = dirname(fileURLToPath(import.meta.url))

/** Route modules, by their file-convention name: "sensors.$sensor", "index". */
function routeNames(): string[] {
  return readdirSync(ROUTES)
    .filter((f) => f.endsWith('.tsx') || f.endsWith('.ts'))
    .filter((f) => !f.endsWith('.test.ts') && !f.endsWith('.test.tsx'))
    .map((f) => f.replace(/\.tsx?$/, ''))
}

/** The routes that own children, and are therefore layouts. */
function layoutRoutes(names: string[]): string[] {
  return names.filter((name) => {
    // ".index" is a leaf by definition; it cannot parent anything.
    if (name.endsWith('.index')) return false
    return names.some((other) => other !== name && other.startsWith(`${name}.`))
  })
}

describe('route shape', () => {
  it('no layout route redirects', () => {
    const names = routeNames()
    const offenders: string[] = []

    for (const layout of layoutRoutes(names)) {
      const source = readFileSync(join(ROUTES, `${layout}.tsx`), 'utf8')
      // `redirect` imported from the router and thrown, as opposed to the
      // word appearing in a comment or a URL parameter named redirect.
      if (/\bthrow\s+redirect\s*\(/.test(source)) {
        offenders.push(layout)
      }
    }

    expect(
      offenders,
      `${offenders.join(', ')} has child routes and throws a redirect, so loading any child ` +
        `re-enters it forever. Move the redirect into ${offenders[0] ?? 'X'}.index.tsx.`,
    ).toEqual([])
  })

  it('recognises the shape that caused the outage', () => {
    // Guards the guard: if layoutRoutes stopped identifying parents, the
    // test above would pass by finding nothing to check.
    expect(layoutRoutes(['sensors', 'sensors.$sensor', 'events'])).toEqual(['sensors'])
    expect(layoutRoutes(['sensors.index', 'sensors.$sensor'])).toEqual([])
  })

  it('sensors is a leaf pair, not a layout with a child', () => {
    // The specific regression. /sensors must be an index route.
    const names = routeNames()
    expect(names).toContain('sensors.index')
    expect(names).not.toContain('sensors')
  })
})
