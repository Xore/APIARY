// ANY /bff/{...splat} — the tier boundary a split-off frontend-only host
// calls to reach the Rust service tier through the BFF (Xore's
// host-separation requirement, #1608 architecture addendum: "the frontend
// ... must be deployable on a completely different docker host from the
// BFF"). Deliberately mounted at the process root, not under /api/, so
// Traefik can route this one path prefix to the BFF host and send
// everything else to the frontend host when split — see the
// honeypot-dashboard-bff router in vps/traefik/dynamic.yml.
//
// Only serves while this process is playing the BFF role (SERVE_MODE=all
// or bff, the same modes serviceFetch itself calls BACKEND_URL directly
// in) — a frontend-only instance has no BACKEND_URL to reach and must
// never proxy to the Rust tier itself. Gated by the same x-service-token
// serviceFetch already attaches to every BFF -> Rust call (lib/
// backend.server.ts): this is a machine-to-machine hop between tiers, not
// a browser-facing endpoint, so it reuses that existing shared secret
// (DASHBOARD_SERVICE_TOKEN, deployed identically to both tiers) as its
// trust boundary rather than inventing a second one.
//
// Streams the upstream response straight through, same posture as
// api/live.ts's SSE passthrough — no buffering, no assumption about the
// response shape (the splat can be any Rust /api/v1/... path serviceFetch
// callers pass today or add later).
import { createFileRoute } from '@tanstack/react-router'
import { backendURL, serveMode } from '../lib/backend.server'

const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

async function proxy(request: Request, splat: string | undefined): Promise<Response> {
  if (serveMode() === 'frontend') {
    // This instance IS the frontend-only tier — it has no Rust backend to
    // proxy to. Reaching this branch means /bff/* was routed here by
    // mistake (Traefik split misconfigured, or a direct hit that bypassed
    // it) rather than to the actual BFF host.
    return new Response('not the bff tier', { status: 404 })
  }
  const token = process.env.SERVICE_TOKEN ?? ''
  if (token && request.headers.get('x-service-token') !== token) {
    return new Response('unauthorized', { status: 401 })
  }
  const search = new URL(request.url).search
  const upstreamPath = `/${splat ?? ''}${search}`
  const contentType = request.headers.get('content-type')
  const upstream = await fetch(`${backendURL()}${upstreamPath}`, {
    method: request.method,
    headers: {
      ...(contentType ? { 'content-type': contentType } : {}),
      'x-service-token': token,
    },
    body: BODY_METHODS.has(request.method) ? await request.arrayBuffer() : undefined,
    signal: AbortSignal.timeout(15_000),
  })
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { 'content-type': upstream.headers.get('content-type') ?? 'application/octet-stream' },
  })
}

export const Route = createFileRoute('/bff/$')({
  server: {
    handlers: {
      GET: ({ request, params }) => proxy(request, params._splat),
      POST: ({ request, params }) => proxy(request, params._splat),
      PUT: ({ request, params }) => proxy(request, params._splat),
      PATCH: ({ request, params }) => proxy(request, params._splat),
      DELETE: ({ request, params }) => proxy(request, params._splat),
    },
  },
})
