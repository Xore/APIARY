// GET /api/topology/flow — session-guarded proxy for the fleet-topology
// DAG payload. Same posture as api/chart.$name: the browser only ever sees
// this one slice of /api/v1/topology, and only with a dashboard session.
import { createFileRoute } from '@tanstack/react-router'
import { getSession, sidFrom } from '../../lib/session.server'

export const Route = createFileRoute('/api/topology/flow')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        if (process.env.OIDC_DISABLED !== '1') {
          const session = await getSession(sidFrom(request)).catch(() => null)
          if (!session) return new Response('unauthorized', { status: 401 })
        }
        const { serviceJSON } = await import('../../lib/backend.server')
        const data = await serviceJSON<{ flow: unknown }>('/api/v1/topology')
        if (data === null || !data.flow) return new Response('topology unavailable', { status: 502 })
        return Response.json(data.flow, { headers: { 'cache-control': 'no-store' } })
      },
    },
  },
})
