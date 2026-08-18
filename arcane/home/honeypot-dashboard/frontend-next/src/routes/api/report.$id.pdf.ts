// GET /api/report/{id}/pdf — session-guarded proxy for a generated
// report's PDF bytes from the Rust tier.
import { createFileRoute } from '@tanstack/react-router'
import { backendURL } from '../../lib/backend.server'
import { getSession, sidFrom } from '../../lib/session.server'

export const Route = createFileRoute('/api/report/$id/pdf')({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        if (process.env.OIDC_DISABLED !== '1') {
          const session = await getSession(sidFrom(request)).catch(() => null)
          if (!session) return new Response('unauthorized', { status: 401 })
        }
        const upstream = await fetch(`${backendURL()}/api/v1/reports/${encodeURIComponent(params.id)}/pdf`, {
          headers: { 'x-service-token': process.env.SERVICE_TOKEN ?? '' },
        })
        if (!upstream.ok) return new Response('report unavailable', { status: upstream.status })
        return new Response(upstream.body, {
          status: 200,
          headers: {
            'content-type': 'application/pdf',
            'content-disposition': upstream.headers.get('content-disposition') ?? 'inline',
          },
        })
      },
    },
  },
})
