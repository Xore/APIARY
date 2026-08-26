// #2028: tests for the per-request CSP nonce seam.
//
// Split of responsibilities mirrors how the guarantee itself is structured:
//
//   * the policy string and its variance are real behaviour -> exercised by
//     calling the module;
//   * everything else about this seam is WIRING across four files (start.ts
//     opens one scope per request, router.tsx reads the nonce out of it,
//     the policy is stamped inside cspNonce.server.ts and nowhere else,
//     inline scripts stay centralised where the framework can nonce them)
//     -> pinned by reading the sources directly, the same idea as
//     bootScript.test.ts: follow the string that actually ships rather than
//     reimplementing it here.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { beforeEach, describe, expect, it } from 'vitest'
import { buildCsp, createCspNonce } from './cspNonce.server'

const ROOT = join(__dirname, '..', '..')

function source(rel: string): string {
  return readFileSync(join(ROOT, rel), 'utf8')
}

beforeEach(() => {
  // The server-only module publishes its scope reader onto globalThis on
  // first import; tests must not see a stale value between files.
  delete (globalThis as { __APIARY_CSP__?: unknown }).__APIARY_CSP__
})

describe('the CSP policy', () => {
  it('constrains scripts to self and exactly the request nonce', () => {
    const policy = buildCsp(createCspNonce())
    expect(policy).toMatch(/^script-src 'self' 'nonce-[A-Za-z0-9+/=]+';/)
  })

  it('embeds its nonce exactly once', () => {
    const policy = buildCsp('Q7w8e9R0tY')
    expect(policy.match(/nonce-Q7w8e9R0tY/g)).toHaveLength(1)
  })

  it('never reintroduces an unsafe escape hatch', () => {
    const policy = buildCsp(createCspNonce())
    expect(policy).not.toContain("'unsafe-inline'")
    expect(policy).not.toContain("'unsafe-eval'")
  })

  it('keeps the free directives without inventing new breakage', () => {
    const policy = buildCsp(createCspNonce())
    expect(policy).toContain("object-src 'none'")
    expect(policy).toContain("base-uri 'self'")
    expect(policy).toContain("frame-ancestors 'self'")
    // Deliberately absent (see the module comment): default-src would gate
    // off-origin loads this tier relies on (OSM tiles).
    expect(policy).not.toContain('default-src')
  })

  it('issues a different nonce every time — variance is the whole point', () => {
    const a = createCspNonce()
    const b = createCspNonce()
    expect(a).not.toBe(b)
    expect(buildCsp(a)).toContain(`'nonce-${a}'`)
    expect(buildCsp(b)).toContain(`'nonce-${b}'`)
    expect(buildCsp(a)).not.toContain(b)
  })
})

describe('the CSP wiring', () => {
  it('opens exactly one scope per request, wrapping next()', () => {
    const start = source('src/start.ts')
    expect(start).toMatch(/type:\s*'request'/)
    const mw = start.match(/requestMiddleware:\s*\[[\s\S]*?\]/)?.[0]
    expect(mw).toBeTruthy()
    expect(mw).toContain("import('./lib/cspNonce.server')")
    // The scope must CONTAIN next(), not merely precede it — an enter-and-
    // return scheme leaves the store invisible to everything the pipeline
    // spawns (that failure mode shipped a nonce'd header over bare script
    // tags during development; see withCspScope's comment).
    expect(mw).toContain("csp.withCspScope(() => next())")
    expect(mw).toContain("return csp.withCspScope")
    // The session gate this file also owns must survive the addition.
    expect(start).toMatch(/functionMiddleware:\s*\[requireSession\]/)
  })

  it('stamps the header inside cspNonce.server.ts, and nowhere else', () => {
    const own = source('src/lib/cspNonce.server.ts')
    expect(own).toContain("setResponseHeader('content-security-policy'")
    for (const rel of ['src/start.ts', 'src/router.tsx', 'src/routes/__root.tsx']) {
      expect(source(rel)).not.toMatch(/content-security-policy/i)
    }
  })

  it('reads the nonce out of the published scope when building routers', () => {
    const routerSrc = source('src/router.tsx')
    expect(routerSrc).toContain('__APIARY_CSP__')
    expect(routerSrc).toMatch(/ssr:\s*\{\s*nonce:/)
  })

  it('roots the scope at next() with storage.run, never enterWith', () => {
    const own = source('src/lib/cspNonce.server.ts')
    // Comments discuss the enterWith trap; the ban applies to code, so read
    // the source with line and block comments stripped.
    const code = own.replace(/\/\*[\s\S]*?\*\//g, '').split('\n').filter((l) => !l.trim().startsWith('//')).join('\n')
    expect(code).toContain('return storage.run(nonce, restOfPipeline)')
    expect(code).not.toContain('enterWith')
  })

  it('publishes the scope reader before any router can be built', () => {
    const own = source('src/lib/cspNonce.server.ts')
    const publish = own.indexOf('__APIARY_CSP__ = {')
    const reader = own.indexOf('current: () => storage.getStore()')
    expect(publish).toBeGreaterThan(-1)
    expect(reader).toBeGreaterThan(-1)
    expect(reader).toBeGreaterThan(publish)
  })
})

describe('the inline-script surface', () => {
  // #58 carried a source-grep audit so new routes could not quietly skip its
  // single renderPage(); this suite's equivalent boundary is different but
  // just as load-bearing: EVERY script tag rendered to the operator goes
  // through HeadContent/Scripts — both of which apply the router's nonce.
  // A literal <script> element written in JSX would bypass them un-nonced,
  // and the moment it exists these assertions fail instead of the browser.
  const FILES_WITH_SET_INNER_HTML_ALLOWLIST =
    // Not a script sink: renders an attacker-influenced SVG *path* argument
    // React cannot express as JSX attribute syntax.
    ['src/components/Sidebar.tsx']

  it('renders no JSX script tags outside the framework seams', () => {
    const offenders: string[] = []
    for (const f of ['src/routes/__root.tsx', 'src/components/AppShell.tsx', 'src/router.tsx']) {
      if (/<script[\s>]/.test(source(f))) offenders.push(f)
    }
    expect(offenders).toEqual([])
  })

  it('keeps dangerouslySetInnerHTML limited to the audited allowlist', () => {
    const hits = new Set<string>()
    for (const rel of [
      'src/components/Sidebar.tsx',
      'src/routes/__root.tsx',
      'src/components/AppShell.tsx',
    ]) {
      const text = source(rel)
      if (text.includes('dangerouslySetInnerHTML')) hits.add(rel)
    }
    expect([...hits]).toEqual([...FILES_WITH_SET_INNER_HTML_ALLOWLIST])
  })

  it('keeps the pre-hydration boot script going through head(), which gets the nonce', () => {
    const root = source('src/routes/__root.tsx')
    // The boot script must remain a head() scripts entry (nonced like every
    // other HeadContent tag) — not moved into a raw <script>, not inlined
    // outside the framework's control.
    expect(root).toMatch(/scripts:\s*\[/)
    expect(root).toContain('hp-theme')
  })
})
