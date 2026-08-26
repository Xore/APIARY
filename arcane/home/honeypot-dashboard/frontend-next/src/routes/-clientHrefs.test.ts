// Named with a leading "-" so TanStack's route generator skips it (same
// trick as -routeShape.test.ts); vitest still collects it.
//
// #2122: three "raw report" anchors pointed at /api/v1/... — Rust-tier
// paths the frontend host does not route (Traefik sends every path to
// frontend-next), so the chips 404ed exactly where the page's own prose
// told operators to click. Client anchors must only ever hit BFF seams;
// forwarding /api/v1 in Traefik instead would bypass this tier's session
// gates, because the Rust tier has no admin check of its own.
//
// Server-side serviceJSON/serviceFetch calls legitimately build /api/v1
// URLs, so the guard matches anchor hrefs specifically — `href=` followed
// by a literal or template that embeds the prefix.
import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROUTES = dirname(fileURLToPath(import.meta.url))
const COMPONENTS = join(ROUTES, '..', 'components')

/** Anchor hrefs embedding /api/v1 — the shape that 404s on this host. */
function apiV1AnchorFiles(dir: string): string[] {
  return readdirSync(dir, { recursive: true, encoding: 'utf8' })
    .filter((f) => f.endsWith('.tsx') && !f.endsWith('.test.tsx'))
    .filter((f) => {
      const source = readFileSync(join(dir, f), 'utf8')
      return /href=\{?[`"'][^`"']*\/api\/v1/.test(source)
    })
    .map((f) => `${dir}/${f}`)
}

describe('client anchors never link into /api/v1', () => {
  it('no route or component href points at the Rust tier', () => {
    const offenders = [...apiV1AnchorFiles(ROUTES), ...apiV1AnchorFiles(COMPONENTS)]
    expect(
      offenders,
      `${offenders.join(', ')} links a client anchor at /api/v1 — a path this host does not serve. ` +
        'Add or extend a session-guarded seam under src/routes/api/ and point the anchor there.',
    ).toEqual([])
  })

  it('recognises the shape that caused the dead chips', () => {
    const probe = (snippet: string) => /href=\{?[`"'][^`"']*\/api\/v1/.test(snippet)
    expect(probe('href={`/api/v1/cape/${sha}/raw`}')).toBe(true)
    expect(probe('href="/api/v1/github-analysis/x"')).toBe(true)
    // The legitimate server-side shapes must stay out of the match.
    expect(probe("serviceJSON<StorePage>(`/api/v1/store/rows`)")).toBe(false)
    expect(probe('href={`/api/raw-report/cape/${sha}`}')).toBe(false)
  })
})
