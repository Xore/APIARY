// GET /metrics — the BFF's Prometheus baseline (#1972).
//
// Unlike backend-service's /metrics (internal-listener-only, /healthz
// posture), this tier IS internet-facing through Traefik, so unauthenticated
// exposition would leak request volumes and cache behavior publicly. Same
// inbound check as proxyToRust (#2183's seam discipline): with SERVICE_TOKEN
// configured the header is required; without one this refuses loudly rather
// than silently opening metrics to the world — boot-time policy assertion
// already makes unset-token production configs impossible, so this branch
// exists for the split-tier HMR/dev edge.
import { createFileRoute } from '@tanstack/react-router'
import { serviceTokenPolicy } from '../lib/serviceToken.server'

export const Route = createFileRoute('/metrics')({
  server: {
    handlers: {
      GET: async ({ request }) => {
        // 'token' → require the shared secret; 'dev-override' → open in the
        // explicitly opted-in dev instance; 'refuse' is unreachable (the
        // boot assertion kills the process before it listens) but fails
        // closed here all the same.
        const expected = process.env.SERVICE_TOKEN ?? ''
        if (serviceTokenPolicy().kind !== 'dev-override' && request.headers.get('x-service-token') !== expected) {
          return new Response('unauthorized', { status: 401 })
        }
        const { renderMetrics } = await import('../lib/obs.server')
        return new Response(renderMetrics(), {
          status: 200,
          headers: { 'content-type': 'text/plain; version=0.0.4' },
        })
      },
    },
  },
})
