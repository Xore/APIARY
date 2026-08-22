// GET /auth/logout — destroys the BFF session, clears the cookie, and ends
// Keycloak's own SSO session (RP-Initiated Logout). Destroying only the
// local session is not enough on its own: Keycloak keeps its own SSO
// cookie scoped to the Keycloak issuer's own host independently of this app's session,
// so the very next /auth/login (including the one dashboard-next's own
// unauthenticated-page redirect fires automatically) gets silently
// re-approved with no login form shown -- confirmed live (#1628): clicking
// "Sign out" landed back on an already-authenticated Overview page every
// time. The old Go dashboard's own serveLogout already redirected to
// Keycloak's end_session_endpoint with id_token_hint for exactly this
// reason; this port had dropped that step. buildEndSessionUrl requires
// live discovery metadata, so it's wrapped in a fallback to the previous
// local-only behavior -- a Keycloak hiccup must never leave a user unable
// to sign out of the BFF session at all.
import { createFileRoute } from '@tanstack/react-router'
import * as oidc from 'openid-client'
import { clearSessionCookie, destroySession, getSession, sidFrom } from '../../lib/session.server'
import { externalURL, oidcConfig } from '../../lib/oidc.server'

export const Route = createFileRoute('/auth/logout')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const sid = sidFrom(request)
        const session = await getSession(sid)
        await destroySession(sid)

        let location = '/auth/login'
        try {
          const config = await oidcConfig()
          const endSessionUrl = oidc.buildEndSessionUrl(config, {
            post_logout_redirect_uri: `${externalURL()}/`,
            ...(session?.idToken ? { id_token_hint: session.idToken } : {}),
          })
          location = endSessionUrl.href
        } catch {
          /* Keycloak unreachable -- still tear down the local session below */
        }

        return new Response(null, {
          status: 303,
          headers: { location, 'set-cookie': clearSessionCookie() },
        })
      },
    },
  },
})
