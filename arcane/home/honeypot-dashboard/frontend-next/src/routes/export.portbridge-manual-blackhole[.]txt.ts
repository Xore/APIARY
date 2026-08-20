// GET /export/portbridge-manual-blackhole.txt — the VPS firewall puller's
// URL (portbridge-manual-blackhole-refresh.sh, every 5 minutes; must stay
// byte-identical across the cutover). Deliberately NO session check, same
// as the legacy exemption: this port is WireGuard-tunnel-bound and the
// tunnel is the trust boundary. ES outages surface as 5xx so the puller
// keeps its existing rules instead of clearing them (#1342).
import { createFileRoute } from '@tanstack/react-router'
import { backendURL } from '../lib/backend.server'

export const Route = createFileRoute('/export/portbridge-manual-blackhole.txt')({
  server: {
    handlers: {
      GET: async () => {
        const upstream = await fetch(`${backendURL()}/api/v1/ip-block-export`, {
          headers: { 'x-service-token': process.env.SERVICE_TOKEN ?? '' },
        })
        if (!upstream.ok) {
          return new Response('manual blackhole export unavailable', { status: 502 })
        }
        return new Response(upstream.body, {
          status: 200,
          headers: { 'content-type': 'text/plain; charset=utf-8' },
        })
      },
    },
  },
})
