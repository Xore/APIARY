// ANY /bff/{...splat} — the tier boundary a split-off frontend-only host
// calls to reach the regular (non-mounted) Rust service tier through the
// BFF (Xore's host-separation requirement, #1608 architecture addendum:
// "the frontend ... must be deployable on a completely different docker
// host from the BFF"). Deliberately mounted at the process root, not under
// /api/, so Traefik can route this one path prefix to the BFF host and
// send everything else to the frontend host when split — see the
// honeypot-dashboard-bff router in vps/traefik/dynamic.yml. See
// bff-mounted.$.ts for the write-capable backend-service-mounted's own
// copy of this same seam.
//
// proxyToRust (lib/backend.server.ts) carries the actual proxy behavior —
// SERVE_MODE gate, x-service-token check, backendLimiter admission,
// unbuffered streaming — shared with bff-mounted.$.ts so the two only
// differ in which Rust-tier base they forward to.
import { createFileRoute } from '@tanstack/react-router'
import { backendURL, proxyToRust } from '../lib/backend.server'

const proxy = (request: Request, splat: string | undefined) => proxyToRust(request, splat, backendURL())

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
