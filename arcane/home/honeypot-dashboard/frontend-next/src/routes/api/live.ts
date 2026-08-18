// GET /api/live — BFF proxy for the Rust tier's SSE event stream.
// Session-guarded (server handlers don't run the root beforeLoad), then
// pipes the upstream body straight through: no buffering, connection
// closes when the client disconnects. No AbortSignal.timeout here — the
// stream is long-lived by design.
import { createFileRoute } from '@tanstack/react-router'
import { backendURL } from '../../lib/backend.server'
import { getSession, sidFrom } from '../../lib/session.server'

export const Route = createFileRoute('/api/live')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        if (process.env.OIDC_DISABLED !== '1') {
          const session = await getSession(sidFrom(request)).catch(() => null)
          if (!session) return new Response('unauthorized', { status: 401 })
        }
        const upstream = await fetch(`${backendURL()}/api/v1/live`, {
          headers: { 'x-service-token': process.env.SERVICE_TOKEN ?? '' },
          signal: request.signal,
        })
        if (!upstream.ok || !upstream.body) {
          return new Response('stream unavailable', { status: 502 })
        }
        return new Response(upstream.body, {
          status: 200,
          headers: {
            'content-type': 'text/event-stream',
            'cache-control': 'no-cache',
            connection: 'keep-alive',
            'x-accel-buffering': 'no',
          },
        })
      },
    },
  },
})
