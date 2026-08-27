// GET /auth/login — begins the Keycloak PKCE flow (same path the Go tier
// registered, so the realm's redirect config is untouched at cutover).
//
// #1942: a beginLogin throw used to escape the handler and surface as the
// framework's bare 53-byte 500 with nothing of ours in the log. The
// offline-queue and non-poisoning-discovery fixes in oidc.server.ts
// address the two known live causes; this catch is what keeps any future
// cause visible (logged with its reason) and actionable (rendered page
// with status 503) instead of an anonymous 500.
import { createFileRoute } from '@tanstack/react-router'
import { beginLogin, oidcDisabled, safeReturnTo } from '../../lib/oidc.server'
import { authErrorPage } from '../../lib/oidcErrors.server'
import { createSession, sessionCookie } from '../../lib/session.server'
import { recordNamedEvent } from '../../lib/obs.server'

export const Route = createFileRoute('/auth/login')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const url = new URL(request.url)
        const returnTo = url.searchParams.get('return_to') ?? '/'
        if (oidcDisabled()) {
          // Dev mode works without redis: the root guard already accepts
          // the fixture identity cookie-lessly; a session is created only
          // when the store is reachable. Same redirect guard as the OIDC
          // path — this branch's old startsWith('/')-only check was weaker
          // than beginLogin's and shared its backslash bypass (#2121).
          const headers: Record<string, string> = { location: safeReturnTo(returnTo) }
          try {
            const sid = await createSession({ sub: 'dev', username: 'dev', displayName: 'Dev Operator', role: 'admin' })
            headers['set-cookie'] = sessionCookie(sid)
          } catch {
            /* no redis in dev — cookie-less fixture auth */
          }
          return new Response(null, { status: 303, headers })
        }
        try {
          const { redirect } = await beginLogin(returnTo)
          // #1972: named outcomes — "how often is sign-in failing, and
          // since when" becomes a counter over durable lines instead of
          // grepping stdout that a redeploy already deleted.
          recordNamedEvent('auth_login_started')
          return new Response(null, { status: 303, headers: { location: redirect } })
        } catch (error) {
          console.error('[auth] /auth/login could not start sign-in:', error)
          recordNamedEvent('auth_login_failed', {
            reason: error instanceof Error ? error.message.slice(0, 200) : 'unknown',
          })
          return authErrorPage({
            status: 503,
            heading: 'Sign-in is temporarily unavailable',
            detail:
              'The identity provider or session store did not answer, so this ' +
              'sign-in could not start. Reload to retry; if it persists the ' +
              'Keycloak tier may be degraded.',
          })
        }
      },
    },
  },
})
