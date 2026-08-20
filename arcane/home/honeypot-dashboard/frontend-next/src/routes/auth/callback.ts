// GET /auth/callback — completes the PKCE code exchange and establishes
// the redis-backed BFF session.
import { createFileRoute } from '@tanstack/react-router'
import { completeLogin } from '../../lib/oidc.server'
import { createSession, sessionCookie } from '../../lib/session.server'

export const Route = createFileRoute('/auth/callback')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        try {
          const result = await completeLogin(new URL(request.url))
          if (!result) return new Response('login expired — retry', { status: 400 })
          const sid = await createSession({
            sub: result.sub,
            username: result.username,
            displayName: result.displayName,
            role: result.role,
            idToken: result.idToken,
          })
          return new Response(null, {
            status: 303,
            headers: { location: result.returnTo, 'set-cookie': sessionCookie(sid) },
          })
        } catch (error) {
          return new Response(`authentication failed: ${(error as Error).message}`, { status: 502 })
        }
      },
    },
  },
})
