// GET /api/canarytoken/{id}/download — session-guarded proxy for a
// canarytoken's generated artifact.
//
// #1616: own (small — this is a rare, low-volume download) admission gate,
// same rationale as the artifact/report proxies above.
import { createFileRoute } from '@tanstack/react-router'
import { backendURL } from '../../lib/backend.server'
import { ConcurrencyLimiter, envInt, Overloaded, overloadedResponse, releaseOnFinish } from '../../lib/backpressure.server'
import { getSession, sidFrom } from '../../lib/session.server'

const canarytokenLimiter = new ConcurrencyLimiter(envInt('CANARYTOKEN_MAX_CONCURRENT', 16), 8)

export const Route = createFileRoute('/api/canarytoken/$id/download')({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        if (process.env.OIDC_DISABLED !== '1') {
          const session = await getSession(sidFrom(request)).catch(() => null)
          if (!session) return new Response('unauthorized', { status: 401 })
        }
        let release: () => void
        try {
          release = await canarytokenLimiter.acquire()
        } catch (err) {
          if (err instanceof Overloaded) return overloadedResponse(err)
          throw err
        }
        const upstream = await fetch(
          `${backendURL()}/api/v1/canarytokens/${encodeURIComponent(params.id)}/download`,
          { headers: { 'x-service-token': process.env.SERVICE_TOKEN ?? '' }, signal: request.signal },
        ).catch((err) => {
          release()
          throw err
        })
        if (!upstream.ok || !upstream.body) {
          release()
          return new Response('artifact unavailable', { status: upstream.status })
        }
        return new Response(releaseOnFinish(upstream.body, release), {
          status: 200,
          headers: {
            'content-type': upstream.headers.get('content-type') ?? 'application/octet-stream',
            'content-disposition': upstream.headers.get('content-disposition') ?? 'attachment',
          },
        })
      },
    },
  },
})
