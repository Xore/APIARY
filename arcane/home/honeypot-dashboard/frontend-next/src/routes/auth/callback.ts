// GET /auth/callback — completes the PKCE code exchange and establishes
// the redis-backed BFF session.
//
// #1942: every failure used to collapse into a bare-text 502 — including
// protocol-level provider errors, which OIDC delivers as callback query
// parameters (an expired/replayed authorization request arrives here as
// error=invalid_request, by design). Those now render as pages a person
// can act on; genuine exchange failures are logged with their real cause
// (the container log previously carried nothing for these) and also
// render rather than escaping as a framework body. createSession joined
// the try: its redis write is just as capable of throwing as the token
// exchange it follows, and an unhandled throw here produced exactly the
// 53-byte 500 class this issue documents.
import { createFileRoute } from '@tanstack/react-router'
import { completeLogin } from '../../lib/oidc.server'
import { authErrorPage, providerErrorFrom } from '../../lib/oidcErrors.server'
import { createSession, sessionCookie } from '../../lib/session.server'
import { recordNamedEvent } from '../../lib/obs.server'

export const Route = createFileRoute('/auth/callback')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const url = new URL(request.url)
        const providerError = providerErrorFrom(url)
        if (providerError) {
          // Provider-decided failure (expired request, denied consent,
          // replayed state). A warn, not an error: this is protocol.
          recordNamedEvent('auth_callback_provider_refused', { reason: providerError.error })
          console.warn(
            `[auth] idp refused login at /auth/callback: ${providerError.error}`,
            providerError.description,
          )
          return authErrorPage({
            status: 400,
            heading: 'Sign-in was not completed',
            detail:
              `The identity provider refused this sign-in attempt (${providerError.error}). ` +
              'This usually means the attempt expired or was already used.',
            retryHref: '/auth/login',
          })
        }
        try {
          const result = await completeLogin(url)
          if (!result) {
            recordNamedEvent('auth_callback_expired')
            return authErrorPage({
              status: 400,
              heading: 'Login attempt expired',
              detail:
                'This sign-in took too long or was already completed. Start again to continue.',
              retryHref: '/auth/login',
            })
          }
          const sid = await createSession({
            sub: result.sub,
            username: result.username,
            displayName: result.displayName,
            role: result.role,
            idToken: result.idToken,
          })
          // The event carries the outcome only — usernames never become
          // label values or searchable log fields here.
          recordNamedEvent('auth_callback_completed', { role: result.role })
          return new Response(null, {
            status: 303,
            headers: { location: result.returnTo, 'set-cookie': sessionCookie(sid) },
          })
        } catch (error) {
          console.error('[auth] /auth/callback exchange failed:', error)
          recordNamedEvent('auth_callback_failed', {
            reason: error instanceof Error ? error.message.slice(0, 200) : 'unknown',
          })
          return authErrorPage({
            status: 502,
            heading: 'Sign-in could not be completed',
            detail:
              'The identity provider did not accept the token exchange. ' +
              'If this keeps happening, the Keycloak tier may be degraded.',
            retryHref: '/auth/login',
          })
        }
      },
    },
  },
})
