// GET /api/artifact/{kind}/{key}/{filename} — session-guarded proxy for
// analysis artifacts (ghidra reports, sandbox exports).
//
// #1616: own admission gate (same rationale as report.$id.pdf.ts) sized
// for parallel artifact downloads rather than the PDF route's heavier
// per-item cost, plus request.signal forwarding so an abandoned download
// frees its slot immediately.
import { createFileRoute } from '@tanstack/react-router'
import { backendURL } from '../../lib/backend.server'
import { ConcurrencyLimiter, envInt, Overloaded, overloadedResponse, releaseOnFinish } from '../../lib/backpressure.server'
import { getSession, sidFrom } from '../../lib/session.server'

const artifactLimiter = new ConcurrencyLimiter(envInt('ARTIFACT_MAX_CONCURRENT', 32), 16)

export const Route = createFileRoute('/api/artifact/$kind/$key/$filename')({
  server: {
    handlers: {
      GET: async ({ request, params }) => {
        if (process.env.OIDC_DISABLED !== '1') {
          const session = await getSession(sidFrom(request)).catch(() => null)
          if (!session) return new Response('unauthorized', { status: 401 })
        }
        let release: () => void
        try {
          release = await artifactLimiter.acquire()
        } catch (err) {
          if (err instanceof Overloaded) return overloadedResponse(err)
          throw err
        }
        const upstream = await fetch(
          `${backendURL()}/api/v1/artifacts/${encodeURIComponent(params.kind)}/${encodeURIComponent(params.key)}/${encodeURIComponent(params.filename)}`,
          { headers: { 'x-service-token': process.env.SERVICE_TOKEN ?? '' }, signal: request.signal },
        ).catch((err) => {
          release()
          throw err
        })
        if (!upstream.ok || !upstream.body) {
          release()
          return new Response('artifact unavailable', { status: upstream.status })
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
