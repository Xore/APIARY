// The central 401-recovery path (#1975, the last item of the loading-experience
// epic; the dashboard-next half of what #1582 did for the Go tier).
//
// #1966 gave the query layer an honest error state, so an expired session
// stopped rendering as an endless skeleton. But "honest" only got as far as
// "something failed, here is a Retry button" -- and for an expired session
// that button can never succeed, because nothing in the client had a path
// back to sign-in. The operator's only recovery was to notice the failure
// was really a logout and reload the page by hand.
//
// Why it needs its own layer at all: __root.tsx's beforeLoad redirects to
// /auth/login, but it runs on NAVIGATION only. Every hydrate-in-place fetch
// on an already-open page -- which, per the shell-and-hydrate rule, is how
// every page gets its data -- goes around it entirely and lands on
// start.ts's requireSession middleware instead, which answers 401.
//
// Two things are wrong with that 401 by the time it reaches a component,
// and this module fixes both:
//
//  1. The 401 did not arrive as a failure at all -- it arrived as DATA.
//     start.ts's comment ("callers see a real 401") is right about the
//     wire and wrong about the client. A Response thrown from middleware
//     is caught by createServerFn's runner and returned as `res.error`,
//     and server-functions-handler.js re-emits it with `x-tss-raw: true`
//     stamped on. That header is the very first thing the client fetcher
//     tests -- serverFnFetcher.js's getResponse opens with
//     `if (response.headers.get("x-tss-raw") === "true") return response`
//     -- so the RESPONSE OBJECT ITSELF came back as a resolved value.
//     Nothing in src/ inspects x-tss-raw or does `instanceof Response` on
//     a server-fn result, and useServerQuery calls any non-null resolve
//     'ready': the query layer reported `{status: 'ready', data:
//     <Response>}` and components rendered against a Response, which is
//     not an endless skeleton but a wrong one -- typically a TypeError at
//     render, escaping into a tree with no errorComponent to catch it.
//     Rejecting here, before the fetcher ever sees the response, is what
//     makes the 401 reach the query layer as the failure it is.
//
//  2. Even reported honestly, a failure is the wrong end state for an
//     expired session. beginReauth() sends the browser through /auth/login,
//     which self-heals silently against Keycloak's own SSO cookie -- the
//     same mechanism a manual reload always relied on, now triggered
//     without the operator having to work out that "failed to load" meant
//     "signed out".
import { setConnectionHealthy } from './live'

/** Rejection raised in place of a 401 so the failure reaches the query
 * layer as a failure. Distinguishable by callers that want to say
 * "signing you back in" rather than "this failed"; nothing has to. */
export class SessionExpiredError extends Error {
  constructor() {
    super('Session expired — returning to sign-in.')
    this.name = 'SessionExpiredError'
  }
}

// One navigation per expiry, not one per in-flight request. A page mid-load
// has several fetches outstanding and they all 401 together; without this
// latch each would call location.assign and the last one to land would
// decide the return_to.
let reauthStarted = false

/** Test seam: the latch is module state, and a suite that exercises the
 * expiry path more than once needs it back at its initial value. */
export function resetReauthForTests() {
  reauthStarted = false
}

/** Send the browser back through the sign-in flow, preserving where the
 * operator was so Keycloak's SSO cookie can put them straight back.
 *
 * No-ops off the client, on the /auth/* pages themselves (redirecting the
 * login page to the login page is a loop), and after the first call. */
export function beginReauth(): void {
  if (typeof window === 'undefined') return
  if (reauthStarted) return
  if (window.location.pathname.startsWith('/auth/')) return
  reauthStarted = true
  // LIVE goes unhealthy the moment this fires, matching the Go tier's
  // behaviour under #1582: the badge is the shell's one connection
  // indicator, and a session that has expired is not a live one.
  setConnectionHealthy(false)
  const returnTo = window.location.pathname + window.location.search
  window.location.assign(`/auth/login?return_to=${encodeURIComponent(returnTo)}`)
}

/** The fetch every client-side server-function call goes through, wired in
 * start.ts via createStart's `serverFns.fetch`. That option is client-only
 * by contract ("During SSR, server functions are called directly"), which
 * is exactly the scope wanted here -- SSR has beforeLoad's redirect.
 *
 * Only 401 is special-cased. Every other status, and every transport
 * failure, is handed back untouched so #1966's error state keeps owning
 * "the backend is down", which is a different problem with a different
 * remedy (Retry actually works for it). */
export const sessionAwareFetch: typeof fetch = async (input, init) => {
  const response = await fetch(input, init)
  if (response.status === 401) {
    beginReauth()
    throw new SessionExpiredError()
  }
  return response
}

/** Ask the server whether this session is still alive.
 *
 * getSessionUser is the one server function exempt from requireSession
 * (sessionGate.server.ts's PUBLIC_FN_FILES), so it reports a dead session
 * as `null` instead of the 401 that would make this check recursive. That
 * exemption is what makes it usable as the probe, the same role
 * /api/whoami plays in the Go tier's checkSessionAlive().
 *
 * A transport failure is deliberately NOT treated as an expiry: the backend
 * being unreachable must not sign the operator out. */
export async function checkSessionAlive(): Promise<void> {
  if (typeof window === 'undefined') return
  if (window.location.pathname.startsWith('/auth/')) return
  try {
    const { getSessionUser } = await import('./auth')
    const user = await getSessionUser()
    if (!user) beginReauth()
  } catch {
    /* unreachable != signed out */
  }
}
