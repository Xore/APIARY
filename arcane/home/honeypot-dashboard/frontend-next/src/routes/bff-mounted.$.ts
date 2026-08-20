// ANY /bff-mounted/{...splat} — bff.$.ts's own seam, but forwarding to
// backend-service-mounted instead: the only Rust-tier container with the
// host-side sandbox/Ghidra/GitHub-analysis request-spool mounts (#1612
// phase 3a/3b — see backendMountedURL()'s doc comment in
// lib/backend.server.ts for the full route list this covers). A split-off
// frontend-only host has no direct route to either Rust-tier container, so
// serviceFetch's `{ mounted: true }` calls come through here the same way
// its regular calls come through bff.$.ts.
import { createFileRoute } from '@tanstack/react-router'
import { backendMountedURL, proxyToRust } from '../lib/backend.server'

const proxy = (request: Request, splat: string | undefined) => proxyToRust(request, splat, backendMountedURL())

export const Route = createFileRoute('/bff-mounted/$')({
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
