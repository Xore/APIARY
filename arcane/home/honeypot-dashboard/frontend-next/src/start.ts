// Global middleware wiring for server functions (#2123).
//
// Every createServerFn in this app is a plain HTTP endpoint on the BFF
// origin; nothing else in the stack authenticates them (the root route's
// beforeLoad guard runs on navigation only, and the /api/* route seams do
// their own checks separately). This middleware is the load-bearing
// authentication layer: no session, no invocation. The per-function
// getSessionUser/role checks scattered through the routes remain as
// defense in depth and for admin-vs-user authorization, which this layer
// deliberately does not decide.
//
// Throwing the Response rather than returning it is deliberate: the
// runtime short-circuits either way, but the middleware's return type
// only admits next() results. The server-functions handler re-emits a
// thrown Response verbatim, so callers see a real 401.
//
// The session store is imported dynamically inside the server callback:
// start.ts is part of both bundles, and a static import would drag
// ioredis into the client graph.
import { createStart, createMiddleware } from '@tanstack/react-start'
import { getRequest } from '@tanstack/react-start/server'

const requireSession = createMiddleware({ type: 'function' }).server(
  async ({ serverFnMeta, next }) => {
    const { isPublicFn, resolveFunctionUser, unauthenticatedResponse } = await import(
      './lib/sessionGate.server'
    )
    // One next() call with one context shape keeps the middleware's
    // inferred types uniform; exempted functions simply carry no user.
    const exempt = isPublicFn(serverFnMeta)
    const user: import('./lib/auth').User | undefined = exempt
      ? undefined
      : ((await resolveFunctionUser(getRequest())) ?? undefined)
    if (!exempt && !user) throw unauthenticatedResponse()
    return next({ context: { user } })
  },
)

export const startInstance = createStart(() => ({
  functionMiddleware: [requireSession],
  // #2028: one CSP per request, emitted by one place. Type 'request' runs
  // once per HTTP request around the whole Start handler — HTML documents
  // and server-fn RPCs alike — before anything renders, which is exactly
  // the "every route sends CSP is a property of one function" property #58
  // gave the Go dashboard via its single renderPage() call site. No route
  // can forget it because no route has a say in it.
  //
  // The nonce itself must ALSO reach the markup (router options carry it
  // into every script tag react-dom emits); that half of the plumbing lives
  // in lib/cspNonce.server.ts — withCspScope runs next() INSIDE its scope,
  // because an enter-then-return scheme would leave the store invisible to
  // everything this pipeline spawns (see that file's rationale).
  requestMiddleware: [
    createMiddleware({ type: 'request' }).server(async ({ next }) => {
      // #1972 observability wraps the whole pipeline: one request id scoped
      // over everything (echoed as x-request-id and forwarded to the Rust
      // tier), then the CSP scope, then the app. Duration covers all of it;
      // a throw still lands the duration before propagating (#1942 showed
      // failed requests are precisely the ones worth counting).
      const started = performance.now()
      const reqCtx = await import('./lib/requestContext.server')
      const obs = await import('./lib/obs.server')
      let inboundId: string | undefined
      try {
        const { getRequest } = await import('@tanstack/react-start/server')
        inboundId = getRequest()?.headers.get('x-request-id') ?? undefined
      } catch {
        /* no ambient request here — mint fresh, correlation unaffected */
      }
      return reqCtx.withRequestScope(inboundId, async () => {
        const csp = await import('./lib/cspNonce.server')
        try {
          const result = await csp.withCspScope(() => next())
          obs.recordBffRequest(performance.now() - started)
          return result
        } catch (error) {
          obs.recordBffRequest(performance.now() - started)
          throw error
        }
      })
    }),
  ],
}))
