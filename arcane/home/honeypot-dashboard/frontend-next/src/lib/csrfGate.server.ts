// Fail-closed CSRF guard for server functions (#3109).
//
// Every createServerFn is a plain HTTP endpoint on the BFF origin (see
// sessionGate.server.ts's header comment). SameSite=Lax on the session
// cookie already blocks the classic cross-site form/fetch POST in current
// browsers, but that is a browser behaviour, not a server-enforced control —
// this is the auth boundary of the analyst UI, so it should not rely on it
// alone. Validate the request's Origin (falling back to Referer, since some
// same-site navigations omit Origin) against externalURL()'s origin for
// every state-changing call; missing or mismatched fails closed, same
// posture as sessionGate.server.ts's fail-closed session check.
import { externalURL } from './oidc.server'

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS'])

export function crossOriginResponse(): Response {
  return Response.json({ ok: false, error: 'Cross-origin request rejected.' }, { status: 403 })
}

export function isSameOriginRequest(request: Request): boolean {
  if (SAFE_METHODS.has(request.method)) return true
  const header = request.headers.get('origin') ?? request.headers.get('referer')
  if (!header) return false
  try {
    return new URL(header).origin === new URL(externalURL()).origin
  } catch {
    return false
  }
}
