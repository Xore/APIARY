// GET /api/live — BFF proxy for the Rust tier's SSE event stream.
// Session-guarded (server handlers don't run the root beforeLoad), then
// pipes the upstream body straight through: no buffering, connection
// closes when the client disconnects. No AbortSignal.timeout here — the
// stream is long-lived by design.
//
// #1616: an SSE connection holds a slot for as long as the client stays
// on the page, unlike a normal request/response — so it gets its own
// admission gate (LIVE_MAX_STREAMS concurrent, no wait queue: a stream
// either opens now or the client gets a 503 to retry, queuing an SSE open
// makes no sense) instead of sharing backendLimiter's short-lived-request
// budget.
import { createFileRoute } from '@tanstack/react-router'
import { backendURL } from '../../lib/backend.server'
import { ConcurrencyLimiter, envInt, Overloaded, overloadedResponse, releaseOnFinish } from '../../lib/backpressure.server'
import { getSession, sidFrom } from '../../lib/session.server'

const streamLimiter = new ConcurrencyLimiter(envInt('LIVE_MAX_STREAMS', 500), 0)

export const Route = createFileRoute('/api/live')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        if (process.env.OIDC_DISABLED !== '1') {
          const session = await getSession(sidFrom(request)).catch(() => null)
          if (!session) return new Response('unauthorized', { status: 401 })
        }
        let release: () => void
        try {
          release = await streamLimiter.acquire()
        } catch (err) {
          if (err instanceof Overloaded) return overloadedResponse(err)
          throw err
        }
        const upstream = await fetch(`${backendURL()}/api/v1/live`, {
          headers: { 'x-service-token': process.env.SERVICE_TOKEN ?? '' },
          signal: request.signal,
        }).catch((err) => {
          release()
          throw err
        })
        if (!upstream.ok || !upstream.body) {
          release()
          return new Response('stream unavailable', { status: 502 })
        }
        return new Response(releaseOnFinish(upstream.body, release), {
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
