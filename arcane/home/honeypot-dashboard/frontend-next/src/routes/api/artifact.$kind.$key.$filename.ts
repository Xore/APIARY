// GET /api/artifact/{kind}/{key}/{filename} — session-guarded proxy for
// analysis artifacts (ghidra reports, sandbox exports).
import { createFileRoute } from '@tanstack/react-router'
import { backendURL } from '../../lib/backend.server'
import { getSession, sidFrom } from '../../lib/session.server'

export const Route = createFileRoute('/api/artifact/$kind/$key/$filename')({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        if (process.env.OIDC_DISABLED !== '1') {
          const session = await getSession(sidFrom(request)).catch(() => null)
          if (!session) return new Response('unauthorized', { status: 401 })
        }
        const upstream = await fetch(
          `${backendURL()}/api/v1/artifacts/${encodeURIComponent(params.kind)}/${encodeURIComponent(params.key)}/${encodeURIComponent(params.filename)}`,
          { headers: { 'x-service-token': process.env.SERVICE_TOKEN ?? '' } },
        )
        if (!upstream.ok) return new Response('artifact unavailable', { status: upstream.status })
        return new Response(upstream.body, {
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
