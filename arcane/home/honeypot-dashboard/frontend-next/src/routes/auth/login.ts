// GET /auth/login — begins the Keycloak PKCE flow (same path the Go tier
// registered, so the realm's redirect config is untouched at cutover).
import { createFileRoute } from '@tanstack/react-router'
import { beginLogin, oidcDisabled } from '../../lib/oidc.server'
import { createSession, sessionCookie } from '../../lib/session.server'

export const Route = createFileRoute('/auth/login')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const url = new URL(request.url)
        const returnTo = url.searchParams.get('return_to') ?? '/'
        if (oidcDisabled()) {
          // Dev mode works without redis: the root guard already accepts
          // the fixture identity cookie-lessly; a session is created only
          // when the store is reachable.
          const headers: Record<string, string> = { location: returnTo.startsWith('/') ? returnTo : '/' }
          try {
            const sid = await createSession({ sub: 'dev', username: 'dev', displayName: 'Dev Operator', role: 'admin' })
            headers['set-cookie'] = sessionCookie(sid)
          } catch {
            /* no redis in dev — cookie-less fixture auth */
          }
          return new Response(null, { status: 303, headers })
        }
        const { redirect } = await beginLogin(returnTo)
        return new Response(null, { status: 303, headers: { location: redirect } })
      },
    },
  },
})
