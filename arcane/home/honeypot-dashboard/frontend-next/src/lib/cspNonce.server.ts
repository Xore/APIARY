// #2028: re-establishes the second line of defence #58 built for the Go
// dashboard, whose guarantee died with the framework cutover: nothing in the
// TanStack Start stack set any Content-Security-Policy, so every page renders
// attacker-controlled bytes (event details, payload previews, workbench
// reports) with template escaping as its only line of defence.
//
// This module is the single owner of the policy and its per-request nonce.
// start.ts's request-type middleware hands its `next` to withCspScope() once
// per HTTP request — before anything renders or a server function executes —
// and that one call does three things:
//
//   1. builds the policy string around a freshly generated nonce;
//   2. stamps it onto the live response via the h3-backed setResponseHeader
//      seam (@tanstack/react-start/server), valid because we are inside the
//      request's execution context;
//   3. runs the remaining pipeline inside an AsyncLocalStorage scope keyed
//      by that nonce (see the withCspScope comment for why this is run(),
//      not enterWith()).
//
// The scope matters because the nonce has to reach a place the middleware
// cannot pass values to directly: `router.options.ssr?.nonce`. That one
// option is what makes EVERY script tag the framework itself emits carry the
// same token — react-dom's stream renderer takes it wholesale
// (renderToReadableStream({ nonce })), and HeadContent/Scripts/ScriptOnce
// read it there directly. The router factory is app code (src/router.tsx),
// but it cannot statically import node:async_hooks from this file: start.ts
// and src/router.tsx compile into BOTH bundles (the constraint documented in
// start.ts), while this file is server-only by suffix. It therefore publishes
// a reader onto globalThis instead — a global absent client-side by
// construction, which is exactly what makes the optional read in router.tsx
// safe.
//
// Why only these directives: script-src is the guarantee #58 delivered and
// what an escaping-first posture needs behind it ('self' because Vite's lazy
// route chunks load as element-less module requests the nonce alone cannot
// cover; every inline script — ours and the framework's — carries the
// nonce). object-src, base-uri and frame-ancestors are the free wins that do
// not alter behaviour this tier relies on (framing already locks to
// SAMEORIGIN at the edge per #1897; base tags are unused; no plugin content
// exists). Deliberately no default-src: this tier loads OSM tiles off-origin
// (OverviewPanels), so anything sourced through default-src would either grow
// a per-host exception list or break maps — a widening decision to make
// consciously, not inheritably here.
import { randomBytes } from 'node:crypto'
import { AsyncLocalStorage } from 'node:async_hooks'

const storage = new AsyncLocalStorage<string>()

/** What src/router.tsx reads through globalThis (see the comment above). */
export type CspRuntime = {
  /** The nonce of the request currently executing, if any. */
  readonly current?: () => string | undefined
}

const globalScope = globalThis as typeof globalThis & { __APIARY_CSP__?: CspRuntime }

if (!globalScope.__APIARY_CSP__) {
  globalScope.__APIARY_CSP__ = {
    current: () => storage.getStore(),
  }
}

export function createCspNonce(): string {
  // 16 bytes -> 22 base64 chars. Entropy is not the boundary (the browser
  // enforces exact-token equality); size just costs header bytes.
  return randomBytes(16).toString('base64')
}

export function buildCsp(nonce: string): string {
  return [
    `script-src 'self' 'nonce-${nonce}'`,
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'self'",
  ].join('; ')
}

/**
 * Called exactly once per HTTP request from start.ts's request middleware,
 * before anything renders or a server function executes: header stamped,
 * and the whole remaining pipeline (`next`, and thus rendering and every
 * server-function invocation beneath it) executed inside the nonce scope.
 *
 * Why a wrapper rather than open-then-enter: AsyncLocalStorage.enterWith()
 * called inside THIS function would only affect continuations begun below
 * that call — the awaiting middleware resumes in its own earlier context,
 * and the store would be invisible to everything it spawns (verified live:
 * header arrived with a nonce while every script tag shipped bare until
 * enterWith was replaced by run()). storage.run() roots the store at the
 * `next` invocation instead, which is where consumers actually sit.
 *
 * The dynamic import is what lets this module sit behind a `.server.ts`
 * boundary the bundler honours even though every caller is start.ts, which
 * compiles into both bundles — the import edge only exists inside server
 * callbacks, so nothing h3-shaped can leak into the client graph.
 */
export async function withCspScope<T>(restOfPipeline: () => T): Promise<Awaited<T>> {
  const { setResponseHeader } = await import('@tanstack/react-start/server')
  const nonce = createCspNonce()
  setResponseHeader('content-security-policy', buildCsp(nonce))
  // This async function is the Awaited<T> boundary: what comes back from
  // run() may be the framework's thenable-but-not-a-Promise next() result,
  // which TypeScript's passthrough typing cannot prove.
  return storage.run(nonce, restOfPipeline) as Awaited<T>
}
