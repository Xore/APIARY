// Fail-closed session gate shared by every server function (#2123).
//
// The per-function guards this complements used to read
// `if (user && user.role !== 'admin')` — written so a missing session
// passed as admin for local/dev convenience (the comment on the dead-letters
// page said so outright). But getSessionUser() returns null for every
// request without a valid session cookie, not just in dev: TanStack Start
// exposes server functions as plain HTTP endpoints on the BFF origin, so
// that shape let anyone who could reach the host invoke any mutation —
// provision bait credentials, purge dead letters, mint canarytokens, flip
// alert acks — and read anything, including plaintext bait passwords.
//
// Dev keeps working without any null-pass-through: getSessionUser() itself
// returns the fixture operator when OIDC_DISABLED=1, and so does
// resolveFunctionUser below. There is no mode where "no session" means
// "admin" anymore.
import { oidcDisabled } from './oidc.server'
import { getSession, sidFrom } from './session.server'
import type { User } from './auth'

export function unauthenticatedResponse(): Response {
  return Response.json({ ok: false, error: 'Authentication required.' }, { status: 401 })
}

export async function resolveFunctionUser(request: Request): Promise<User | null> {
  const session = await getSession(sidFrom(request))
  if (session) {
    return {
      sub: session.sub,
      username: session.username,
      displayName: session.displayName,
      role: session.role,
    }
  }
  if (oidcDisabled()) {
    return { sub: 'dev', username: 'dev', displayName: 'Dev Operator', role: 'admin' }
  }
  return null
}

// Functions exempt from the gate: they have to work pre-authentication,
// because the root route's beforeLoad resolves the session through
// getSessionUser to decide whether to redirect to /auth/login — a gate on
// that lookup itself would turn every anonymous page load into an error.
// Keyed by the module path TanStack reports in serverFnMeta, so a whole
// file's functions share one decision.
const PUBLIC_FN_FILES = new Set(['src/lib/auth.ts'])

export function isPublicFn(meta: { filename?: string }): boolean {
  return PUBLIC_FN_FILES.has(meta.filename ?? '')
}
