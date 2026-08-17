// GET /auth/logout — destroys the BFF session and clears the cookie.
import { createFileRoute } from '@tanstack/react-router'
import { clearSessionCookie, destroySession, sidFrom } from '../../lib/session.server'

export const Route = createFileRoute('/auth/logout')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        await destroySession(sidFrom(request))
        return new Response(null, {
          status: 303,
          headers: { location: '/auth/login', 'set-cookie': clearSessionCookie() },
        })
      },
    },
  },
})
