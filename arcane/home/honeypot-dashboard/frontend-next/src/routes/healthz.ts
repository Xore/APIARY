// GET /healthz — Traefik's active health probe for this service (hardcoded
// to this path in vps/traefik/dynamic.yml's honeypot-dashboard healthCheck
// block) and Docker's own container healthcheck once this replaces the Go
// dashboard's listener. Deliberately unauthenticated, same exemption as the
// Go dashboard's own /healthz (main.go's healthzHandler, excluded from the
// OIDC gate in oidc_auth.go) — a probe hit on a fixed interval by
// infrastructure, not an operator, must never depend on a session existing.
//
// Always answers 200 once this handler is reachable at all. The Go
// dashboard's /healthz gates on a separate "starting" 503 until its
// in-memory rebuild() loop has loaded real ES-derived data — there's no
// equivalent warm-up phase here to report on: this tier queries ES live
// through backend-service per request rather than caching it in-process,
// so there's nothing between "the process is up" and "ready".
import { createFileRoute } from '@tanstack/react-router'

export const Route = createFileRoute('/healthz')({
  server: {
    handlers: {
      GET: () => new Response('ok', { status: 200, headers: { 'content-type': 'text/plain' } }),
    },
  },
})
