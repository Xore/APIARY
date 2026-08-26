import { createRouter as createTanStackRouter } from '@tanstack/react-router'
import { routeTree } from './routeTree.gen'

// #2028: the per-request CSP nonce, published onto globalThis by
// lib/cspNonce.server.ts when start.ts's request middleware opens each
// request's scope (that file explains why a direct import is impossible:
// this module compiles into both bundles). On the server a fresh router is
// created per request — inside that scope, so every invocation gets its own
// nonce, which is then what HeadContent/Scripts/ScriptOnce and react-dom's
// stream renderer stamp onto every script tag they emit. In the browser
// bundle the global does not exist by construction and the read degrades to
// undefined — exactly what this file said before the change.
export function getRouter() {
  // The registry read happens HERE, per invocation, not at module scope:
  // this bundle's top level executes once at server boot, before any request
  // has dynamic-imported lib/cspNonce.server.ts, so a module-scope capture
  // would be permanently undefined (that exact bug was caught by the curl
  // smoke test: nonced CSP header over bare script tags).
  type CspRuntime = { readonly current?: () => string | undefined }
  const cspRuntime = (globalThis as typeof globalThis & { __APIARY_CSP__?: CspRuntime })
    .__APIARY_CSP__
  const router = createTanStackRouter({
    routeTree,
    scrollRestoration: true,
    defaultPreload: 'intent',
    defaultPreloadStaleTime: 0,
    ssr: { nonce: cspRuntime?.current?.() },
  })

  return router
}

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof getRouter>
  }
}
