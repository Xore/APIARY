// Per-request identity for the serving tier (#1972).
//
// The request-id property #1942 proved missing: when a page fetch 500s, one
// id must string together Traefik's access line → this BFF's outbound call →
// backend-service's handler logs → the durable JSONL lines both tiers ship.
// This module owns that id per HTTP request:
//
//   - start.ts's 'request' middleware calls withRequestScope() once per
//     request around the whole pipeline; it stamps x-request-id onto the
//     live response via the same h3-backed seam cspNonce.server.ts uses,
//     and runs everything inside an AsyncLocalStorage scope (same
//     run()-not-enterWith() rationale as there — enterWith leaves the store
//     invisible to the awaiting middleware's own continuations).
//   - lib/backend.server.ts reads currentRequestId() and forwards it as
//     x-request-id on every Rust-tier call; backend-service echoes its own
//     copy back either way, so a split-tier hop chain stays joinable.
//
// Why not fold into cspNonce.server.ts: one store type per concern keeps
// the CSP module's carefully-worded globalThis contract unchanged, and the
// two middlewares compose visibly in start.ts instead of inside a shared
// closure.
import { randomBytes } from 'node:crypto'
import { AsyncLocalStorage } from 'node:async_hooks'

const storage = new AsyncLocalStorage<string>()

/** What server-fn/route code (backend.server.ts) reads through the scope.
 * Published on globalThis like cspNonce.server.ts does, so callers compiled
 * into BOTH bundles can reference it while only the server ever has it. */
export type RequestContextRuntime = {
  /** This request's id, when executing under withRequestScope. */
  readonly current?: () => string | undefined
}

const globalScope = globalThis as typeof globalThis & { __APIARY_REQ_ID__?: RequestContextRuntime }

if (!globalScope.__APIARY_REQ_ID__) {
  globalScope.__APIARY_REQ_ID__ = {
    current: () => storage.getStore(),
  }
}

export function createRequestId(): string {
  // Same entropy stance as CSP nonces: correlation key, not capability.
  // Hex keeps it modulo-free: base-36 over raw CSPRNG bytes is biased
  // (256 isn't divisible by 36 — CodeQL flagged exactly that), and the
  // rejection-sampling dance buys nothing for an id nobody guesses on.
  // 72 bits across 18 hex chars keep collision odds irrelevant.
  return `r-${randomBytes(9).toString('hex')}`
}

/**
 * Called exactly once per HTTP request from start.ts (before rendering or
 * any server fn): echo header stamped, pipeline run inside the scope.
 * `inboundId` accepts an upstream/edge-provided id verbatim — the point is
 * joining hops, so the OUTERMOST tier's id wins over regenerating; validity
 * filtering happens here AND on the far side (obs.rs re-checks before
 * trusting anything it receives).
 */
export async function withRequestScope<T>(inboundId: string | undefined, restOfPipeline: () => T): Promise<Awaited<T>> {
  const { setResponseHeader } = await import('@tanstack/react-start/server')
  const existing = inboundId?.trim()
  const id = existing && /^[\x21-\x7e]{1,128}$/.test(existing) ? existing : createRequestId()
  // Always stamp — Traefik access-log ↔ app-log joins want the value on
  // THIS tier's response regardless of who originally minted it.
  setResponseHeader('x-request-id', id)
  return storage.run(id, restOfPipeline) as Awaited<T>
}
