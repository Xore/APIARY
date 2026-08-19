// GET /api/canarytoken/{id}/download — session-guarded proxy for a
// canarytoken's generated artifact.
//
// #1616: own (small — this is a rare, low-volume download) admission gate,
// same rationale as the artifact/report proxies above.
import { createFileRoute } from '@tanstack/react-router'
import { backendURL } from '../../lib/backend.server'
import { ConcurrencyLimiter, envInt, limitedStreamProxy } from '../../lib/backpressure.server'
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
        return limitedStreamProxy(
          request,
          canarytokenLimiter,
          `${backendURL()}/api/v1/canarytokens/${encodeURIComponent(params.id)}/download`,
          (upstream) => ({
            'content-type': upstream.headers.get('content-type') ?? 'application/octet-stream',
            'content-disposition': upstream.headers.get('content-disposition') ?? 'attachment',
          }),
          { message: 'artifact unavailable' },
        )
      },
    },
  },
})
