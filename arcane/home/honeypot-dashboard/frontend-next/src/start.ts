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
}))
