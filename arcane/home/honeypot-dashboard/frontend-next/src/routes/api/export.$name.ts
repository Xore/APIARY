// GET /api/export/{name} — session-guarded proxy for the bulk CSV/JSON
// exports (backend-service's exports.rs). One allowlisted dynamic route
// instead of six near-identical ones, mirroring the same "generic
// allowlisted passthrough" idiom stores.rs's own /api/v1/store/{name}
// already uses on the Rust side.
//
// #1616: own small admission gate, same rationale as the artifact/report/
// payload proxies above — a full-scope export can run for several seconds
// against Elasticsearch (unbounded aggregations, 10k-row scans), so it
// shouldn't share backendLimiter's request budget with every cheap JSON
// call.
import { createFileRoute } from '@tanstack/react-router'
import { backendURL } from '../../lib/backend.server'
import { ConcurrencyLimiter, envInt, Overloaded, overloadedResponse, releaseOnFinish } from '../../lib/backpressure.server'
import { getSession, sidFrom } from '../../lib/session.server'

const ALLOWED_EXPORTS = new Set(['events.csv', 'commands.csv', 'ips.csv', 'campaigns.csv', 'clusters.csv', 'history.json'])
const exportLimiter = new ConcurrencyLimiter(envInt('EXPORT_MAX_CONCURRENT', 4), 4)

export const Route = createFileRoute('/api/export/$name')({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        if (process.env.OIDC_DISABLED !== '1') {
          const session = await getSession(sidFrom(request)).catch(() => null)
          if (!session) return new Response('unauthorized', { status: 401 })
        }
        if (!ALLOWED_EXPORTS.has(params.name)) return new Response('unknown export', { status: 404 })
        let release: () => void
        try {
          release = await exportLimiter.acquire()
        } catch (err) {
          if (err instanceof Overloaded) return overloadedResponse(err)
          throw err
        }
        const search = new URL(request.url).search
        const upstream = await fetch(`${backendURL()}/api/v1/export/${params.name}${search}`, {
          headers: { 'x-service-token': process.env.SERVICE_TOKEN ?? '' },
          signal: request.signal,
        }).catch((err) => {
          release()
          throw err
        })
        if (!upstream.ok || !upstream.body) {
          release()
          return new Response('export unavailable', { status: upstream.status })
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
