// GET /api/report/{id}/pdf — session-guarded proxy for a generated
// report's PDF bytes from the Rust tier.
//
// #1616: PDF generation is the heaviest byte-streaming proxy this tier
// runs (largest bodies, held longest), so it gets its own small admission
// gate rather than sharing backendLimiter's request budget with every
// cheap JSON call. request.signal is forwarded so an abandoned download
// frees its slot and the upstream Rust-tier work immediately, instead of
// both running to completion for nothing.
import { createFileRoute } from '@tanstack/react-router'
import { backendURL } from '../../lib/backend.server'
import { ConcurrencyLimiter, envInt, limitedStreamProxy } from '../../lib/backpressure.server'
import { getSession, sidFrom } from '../../lib/session.server'

const pdfLimiter = new ConcurrencyLimiter(envInt('REPORT_PDF_MAX_CONCURRENT', 8), 4)

export const Route = createFileRoute('/api/report/$id/pdf')({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        if (process.env.OIDC_DISABLED !== '1') {
          const session = await getSession(sidFrom(request)).catch(() => null)
          if (!session) return new Response('unauthorized', { status: 401 })
        }
        return limitedStreamProxy(
          request,
          pdfLimiter,
          `${backendURL()}/api/v1/reports/${encodeURIComponent(params.id)}/pdf`,
          (upstream) => ({
            'content-type': 'application/pdf',
            'content-disposition': upstream.headers.get('content-disposition') ?? 'inline',
          }),
          { message: 'report unavailable' },
        )
      },
    },
  },
})
