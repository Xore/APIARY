// GET /api/chart/{name} — session-guarded BFF proxy for the Rust tier's
// chart-data endpoints. Allowlisted so the browser can only reach chart
// payloads, mirroring the store passthrough's posture.
import { createFileRoute } from '@tanstack/react-router'
import { getSession, sidFrom } from '../../lib/session.server'

const CHARTS = new Set([
  'kill-chain-sankey',
  'attck-coverage',
  'campaign-timeline',
  'ml-backlog',
  'netflow-bytes',
  'netflow-packets',
  'anomaly-trend',
  'dionaea-cves',
  'os-distribution',
  'tcp-stack-clusters',
  'tls-fingerprints',
  'ssh-fingerprints',
  'endlessh-held-histogram',
  'ml-anomaly-scores',
  'attacker-fusion',
])

export const Route = createFileRoute('/api/chart/$name')({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        if (process.env.OIDC_DISABLED !== '1') {
          const session = await getSession(sidFrom(request)).catch(() => null)
          if (!session) return new Response('unauthorized', { status: 401 })
        }
        if (!CHARTS.has(params.name)) return new Response('unknown chart', { status: 404 })
        const { serviceJSON } = await import('../../lib/backend.server')
        // Forward the query string (attacker-fusion takes ?id=).
        const search = new URL(request.url).search
        const data = await serviceJSON<unknown>(`/api/v1/charts/${params.name}${search}`)
        if (data === null) return new Response('chart unavailable', { status: 502 })
        return Response.json(data, { headers: { 'cache-control': 'no-store' } })
      },
    },
  },
})
