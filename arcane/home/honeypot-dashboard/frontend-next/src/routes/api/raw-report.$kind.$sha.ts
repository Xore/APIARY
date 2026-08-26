// GET /api/raw-report/{kind}/{sha} — session-guarded proxy for the full
// machine reports behind the "raw report" chips on cape.$sha and
// github-analysis.$sha (#2122).
//
// Those chips used to point at /api/v1/... directly: paths the old Go
// dashboard served same-origin, but this host does not route (every path
// goes to frontend-next per vps/traefik's dashboard router), so all three
// anchors 404ed. Moving them here keeps the split-host rule — client
// anchors only ever hit BFF seams; the Rust tier stays unreached except
// through session-gated proxies, which is also why "just forward /api/v1
// in Traefik" is not a fix (the Rust tier has no admin check of its own).
//
// One allowlisted seam instead of two near-identical routes, mirroring
// export.$name's idiom. These are single-document fetches but can be
// sizeable (a full CAPE call trace), so they get their own small
// admission gate per #1616 rather than sharing backendLimiter's budget.
import { createFileRoute } from '@tanstack/react-router'
import { backendURL } from '../../lib/backend.server'
import { ConcurrencyLimiter, envInt, limitedStreamProxy } from '../../lib/backpressure.server'
import { getSession, sidFrom } from '../../lib/session.server'

const RAW_REPORT_UPSTREAMS: Record<string, (sha: string) => string> = {
  cape: (sha) => `${backendURL()}/api/v1/cape/${encodeURIComponent(sha)}/raw`,
  'github-analysis': (sha) => `${backendURL()}/api/v1/github-analysis/${encodeURIComponent(sha)}`,
}
const rawReportLimiter = new ConcurrencyLimiter(envInt('RAW_REPORT_MAX_CONCURRENT', 8), 4)

export const Route = createFileRoute('/api/raw-report/$kind/$sha')({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        if (process.env.OIDC_DISABLED !== '1') {
          const session = await getSession(sidFrom(request)).catch(() => null)
          if (!session) return new Response('unauthorized', { status: 401 })
        }
        const upstream = RAW_REPORT_UPSTREAMS[params.kind]
        if (!upstream) return new Response('unknown report kind', { status: 404 })
        return limitedStreamProxy(
          request,
          rawReportLimiter,
          upstream(params.sha),
          (upstreamResponse) => ({
            'content-type': upstreamResponse.headers.get('content-type') ?? 'application/json',
            'content-disposition': upstreamResponse.headers.get('content-disposition') ?? 'attachment',
          }),
          { message: 'raw report unavailable' },
        )
      },
    },
  },
})
