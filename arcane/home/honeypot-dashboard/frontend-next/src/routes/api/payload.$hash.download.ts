// GET /api/payload/{hash}/download — admin-gated proxy for a captured
// payload's raw bytes, ported from payloads_data.go's servePayload.
//
// Admin-gated at the BFF, same posture as every other admin action in this
// port (settings.tsx, payload-analysis.$hash.tsx's submit actions) — the
// Rust tier itself has no admin check. Go's requireAdmin only enforced
// this behind DASHBOARD_REQUIRE_ADMIN=true; this port always enforces it,
// same simplification already made everywhere else admin-gating exists
// here.
//
// #1616: own small admission gate, same rationale as the artifact/report/
// canarytoken proxies above — a raw-binary download shouldn't share
// backendLimiter's request budget with every cheap JSON call.
import { createFileRoute } from '@tanstack/react-router'
import { backendURL } from '../../lib/backend.server'
import { ConcurrencyLimiter, envInt, Overloaded, overloadedResponse, releaseOnFinish } from '../../lib/backpressure.server'
import { getSession, sidFrom } from '../../lib/session.server'

const HASH_RE = /^[0-9a-fA-F]{32,64}$/
const payloadLimiter = new ConcurrencyLimiter(envInt('PAYLOAD_DOWNLOAD_MAX_CONCURRENT', 8), 4)

export const Route = createFileRoute('/api/payload/$hash/download')({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        if (process.env.OIDC_DISABLED !== '1') {
          const session = await getSession(sidFrom(request)).catch(() => null)
          if (!session) return new Response('unauthorized', { status: 401 })
          if (session.role !== 'admin') return new Response('administrator role required', { status: 403 })
        }
        if (!HASH_RE.test(params.hash)) return new Response('invalid payload id', { status: 400 })
        let release: () => void
        try {
          release = await payloadLimiter.acquire()
        } catch (err) {
          if (err instanceof Overloaded) return overloadedResponse(err)
          throw err
        }
        const upstream = await fetch(`${backendURL()}/api/v1/payloads/${encodeURIComponent(params.hash)}/raw`, {
          headers: { 'x-service-token': process.env.SERVICE_TOKEN ?? '' },
          signal: request.signal,
        }).catch((err) => {
          release()
          throw err
        })
        if (!upstream.ok || !upstream.body) {
          release()
          return new Response('payload unavailable', { status: upstream.status })
        }
        return new Response(releaseOnFinish(upstream.body, release), {
          status: 200,
          headers: {
            'content-type': 'application/octet-stream',
            'x-content-type-options': 'nosniff',
            'content-disposition': upstream.headers.get('content-disposition') ?? 'attachment',
          },
        })
      },
    },
  },
})
