// The one network seam between tiers (per Xore's host-separation
// requirement): every SSR/server-function data access goes through these
// helpers, never through direct fetch calls — so the frontend tier can run
// on a different docker host from the BFF (SERVE_MODE=frontend +
// BFF_INTERNAL_URL) and the BFF from the Rust service (BACKEND_URL),
// without touching call sites. All state behind these calls is
// redis/ES-backed; no tier holds host-local state.
//
// In frontend mode, serviceFetch below doesn't reach BACKEND_URL at all —
// it calls the /bff/* proxy (routes/bff.$.ts) on bffInternalURL() instead,
// which forwards into the Rust tier from wherever the BFF role actually
// runs. In all-mode (the only mode deployed today), bffInternalURL() is
// unused and this is byte-for-byte the same direct backendURL() call as
// before #1608's cross-host split existed.
//
// #1616 scalability: a shared keep-alive undici Agent replaces Node's
// default global dispatcher so every fetch in this process — serviceFetch,
// the byte-streaming proxy routes, and bff.$.ts's forward — reuses a
// pooled set of sockets to the Rust tier instead of dialing fresh per
// request. backendLimiter is the bounded queue in front of that fan-out:
// BACKEND_MAX_INFLIGHT run at once, BACKEND_MAX_QUEUE more wait briefly,
// anything past that sheds with 503 rather than growing without bound.
import { Agent, setGlobalDispatcher } from 'undici'
import { ConcurrencyLimiter, envInt, Overloaded, overloadedResponse, releaseOnFinish } from './backpressure.server'
import { assertServiceTokenPolicy, SERVICE_TOKEN_GATE_CODE, serviceTokenPolicy } from './serviceToken.server'

// #2183: the boot half of the shared token contract. An unset/empty
// SERVICE_TOKEN used to silently switch off this file's inbound
// x-service-token check in proxyToRust exactly as it silently switched off
// backend-service's require_service_token. The route tree statically
// imports every route module into the server bundle, so this throws while
// Nitro boots — the process never listens misconfigured; see
// serviceToken.server.ts for the one decision both tiers render.
assertServiceTokenPolicy()

setGlobalDispatcher(
  new Agent({
    keepAliveTimeout: 30_000,
    keepAliveMaxTimeout: 60_000,
    connections: envInt('BACKEND_HTTP_MAX_SOCKETS', 128),
  }),
)

export const backendLimiter = new ConcurrencyLimiter(envInt('BACKEND_MAX_INFLIGHT', 64), envInt('BACKEND_MAX_QUEUE', 128))

export type ServeMode = 'all' | 'frontend' | 'bff'

export function serveMode(): ServeMode {
  const mode = process.env.SERVE_MODE
  return mode === 'frontend' || mode === 'bff' ? mode : 'all'
}

/** Base URL of the Rust service tier. */
export function backendURL(): string {
  return (process.env.BACKEND_URL ?? 'http://127.0.0.1:8081').replace(/\/$/, '')
}

/** Base URL of the write-capable "mounted" Rust service instance — the only
 * container with the host-side sandbox/Ghidra/GitHub-analysis request-spool
 * mounts (compose's backend-service-mounted, #1612 phase 3a/3b). Same image,
 * same route table as backendURL()'s target (routes aren't container-
 * specific — see main.rs); the only difference is which container has those
 * mounts. Every route that writes into (or reads a live listing straight off
 * disk from) a host spool — sandbox/ghidra/github-analysis submit, sandbox
 * golden-image-status and vnc status, and the whole workbench orchestrator
 * surface — must go through this base, or it silently comes back "not
 * configured"/empty against the regular instance instead of erroring loudly. */
export function backendMountedURL(): string {
  return (process.env.BACKEND_MOUNTED_URL ?? 'http://127.0.0.1:8082').replace(/\/$/, '')
}

/** Base URL of the BFF tier as seen from the frontend tier when split;
 * loopback (same process) in all-mode. */
export function bffInternalURL(): string {
  return (process.env.BFF_INTERNAL_URL ?? '').replace(/\/$/, '')
}

/** Fetch from the Rust service with the service token. The BFF tier (or
 * all-mode) calls the Rust service directly; a split frontend tier has no
 * route to BACKEND_URL at all, so it goes through the /bff/* proxy on
 * bffInternalURL() instead — same call site, same signature, the seam is
 * entirely inside this function. Pass `{ mounted: true }` for any route
 * that only exists on backend-service-mounted (see backendMountedURL()) —
 * routed to /bff-mounted/* in split mode, the same seam.
 *
 * Gated by backendLimiter (#1616): a 503 here on shed is indistinguishable
 * to callers from any other backend failure — serviceJSON already treats
 * !response.ok as "return null, let the route render its empty state",
 * and direct serviceFetch callers already branch on response.ok — so
 * shedding needed no new error-handling contract at any call site. */
export async function serviceFetch(path: string, init?: RequestInit, opts?: { mounted?: boolean }): Promise<Response> {
  const base =
    serveMode() === 'frontend'
      ? `${bffInternalURL()}/${opts?.mounted ? 'bff-mounted' : 'bff'}`
      : opts?.mounted
        ? backendMountedURL()
        : backendURL()
  return backendLimiter
    .run(() =>
      fetch(`${base}${path}`, {
        ...init,
        headers: {
          ...(init?.headers ?? {}),
          'x-service-token': process.env.SERVICE_TOKEN ?? '',
        },
        signal: init?.signal ?? AbortSignal.timeout(15_000),
      }),
    )
    .catch((err) => overloadedOrThrow(err))
}

function overloadedOrThrow(err: unknown): Response {
  if (err instanceof Overloaded) return overloadedResponse(err)
  throw err
}

/** Short-TTL payload cache behind the predictive prefetcher: a predicted
 * route's preload warms this, so the real click (or the SSR that follows)
 * reuses the payload instead of re-querying the Rust tier.
 *
 * Two layers (#1610 horizontal round): an in-process map for the
 * fastest repeat hit on the same replica, backed by the shared redis
 * (the same OIDC_SESSION_REDIS_URL valkey) so split/multiple BFF
 * replicas share warmth — one replica's prefetch warms every replica.
 * Redis being down degrades to in-process only, never to an error. */
const payloadCache = new Map<string, { at: number; body: unknown }>()
const PAYLOAD_TTL_MS = 15_000
const REDIS_PREFIX = 'bff:cache:'

let redisClient: import('ioredis').Redis | null | 'disabled' = null
async function cacheRedis(): Promise<import('ioredis').Redis | null> {
  if (redisClient === 'disabled') return null
  if (redisClient) return redisClient
  try {
    const { Redis } = await import('ioredis')
    const client = new Redis(process.env.OIDC_SESSION_REDIS_URL ?? 'redis://127.0.0.1:6379/0', {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
    })
    client.on('error', () => {
      /* degrade silently; the in-process layer still works */
    })
    await client.connect()
    redisClient = client
    return client
  } catch {
    redisClient = 'disabled'
    return null
  }
}

/** Why a call failed, as far as this wrapper can know. `status` is present
 * when there was an HTTP response at all (a shed request is a 503); the
 * remaining cases — timeout, socket failure, limiter throw — carry nothing
 * but the fact of the failure. `retryAfterSeconds` mirrors the shedder's
 * retry-after when one came back (#1966). */
export type ServiceFailure = { ok: false; status?: number; retryAfterSeconds?: number }

/** Either the parsed body or a ServiceFailure — never null-as-both (#1966). */
export type ServiceResult<T> = { ok: true; body: T } | ServiceFailure

/** retry-after is seconds by contract in this stack (backpressure.server's
 * overloadedResponse writes an integer); anything unparsable degrades to
 * "no hint" rather than to zero, which would read as "retry instantly". */
export function parseRetryAfter(value: string | null): number | undefined {
  if (!value) return undefined
  const seconds = Number(value)
  return Number.isFinite(seconds) ? seconds : undefined
}

/** serviceJSON without the collapse: same caching, same target rules, but
 * the caller learns whether a null-ish answer was a real body or a
 * failure. Pass `{ mounted: true }` for a backend-service-mounted-only
 * route, same as serviceFetch — the cache key is prefixed by target, not
 * just `path`, since backendURL() and backendMountedURL() can disagree on
 * the same path (confirmed live: without the prefix, whichever target
 * answered first poisons the cache for the other for PAYLOAD_TTL_MS).
 *
 * Only successes are cached, exactly as before — a failure must never turn
 * into fifteen seconds of cached certainty. */
export async function serviceJSONResult<T>(path: string, opts?: { mounted?: boolean }): Promise<ServiceResult<T>> {
  const cacheKey = opts?.mounted ? `mounted:${path}` : path
  const cached = payloadCache.get(cacheKey)
  if (cached && Date.now() - cached.at < PAYLOAD_TTL_MS) return { ok: true, body: cached.body as T }
  const redis = await cacheRedis()
  if (redis) {
    try {
      const shared = await redis.get(REDIS_PREFIX + cacheKey)
      if (shared) {
        const body = JSON.parse(shared) as T
        payloadCache.set(cacheKey, { at: Date.now(), body })
        return { ok: true, body }
      }
    } catch {
      /* fall through to the live fetch */
    }
  }
  try {
    const response = await serviceFetch(path, undefined, opts)
    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        retryAfterSeconds: parseRetryAfter(response.headers.get('retry-after')),
      }
    }
    const body = (await response.json()) as T
    payloadCache.set(cacheKey, { at: Date.now(), body })
    if (payloadCache.size > 500) {
      const cutoff = Date.now() - PAYLOAD_TTL_MS
      for (const [key, value] of payloadCache) if (value.at < cutoff) payloadCache.delete(key)
    }
    if (redis) {
      redis.set(REDIS_PREFIX + cacheKey, JSON.stringify(body), 'PX', PAYLOAD_TTL_MS).catch(() => {})
    }
    return { ok: true, body }
  } catch {
    return { ok: false }
  }
}

/** JSON convenience over serviceFetch; null on any failure so routes can
 * fall back to skeleton/error states without try/catch noise. The collapse
 * is now a thin wrapper over serviceJSONResult (#1966): callers that need
 * to distinguish "empty" from "down" use that directly instead of trying
 * to un-collapse this one. */
export async function serviceJSON<T>(path: string, opts?: { mounted?: boolean }): Promise<T | null> {
  const result = await serviceJSONResult<T>(path, opts)
  return result.ok ? result.body : null
}

const PROXY_BODY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

/** Shared implementation behind routes/bff.$.ts and routes/bff-mounted.$.ts
 * (the same seam, one per backendURL()/backendMountedURL() target): streams
 * a split-off frontend-only host's request into the given Rust-tier `base`
 * and the response straight back, no buffering — same posture as
 * api/live.ts's SSE passthrough. Gated by backendLimiter (#1616), shared
 * with serviceFetch's direct path since this is a split deployment's only
 * route to the Rust tier and must not duplicate that fan-out's bounded
 * queue. */
export async function proxyToRust(request: Request, splat: string | undefined, base: string): Promise<Response> {
  if (serveMode() === 'frontend') {
    // This instance IS the frontend-only tier — it has no Rust backend to
    // proxy to. Reaching this branch means /bff*/* was routed here by
    // mistake (Traefik split misconfigured, or a direct hit that bypassed
    // it) rather than to the actual BFF host.
    return new Response('not the bff tier', { status: 404 })
  }
  const token = process.env.SERVICE_TOKEN ?? ''
  const policy = serviceTokenPolicy()
  if (policy.kind === 'refuse') {
    // The boot assertion above makes this unreachable in a correctly
    // started process; kept as the mechanical backstop for #2183's seam-2
    // hazard — this proxy must never be the one open path when the token
    // went missing (HMR edge, env stripped after boot, a test importing
    // this module cold). Fails closed loudly instead of passing through.
    return new Response(`${SERVICE_TOKEN_GATE_CODE}: refusing to proxy without SERVICE_TOKEN`, {
      status: 503,
      headers: { 'content-type': 'text/plain' },
    })
  }
  if (token && request.headers.get('x-service-token') !== token) {
    return new Response('unauthorized', { status: 401 })
  }
  let release: () => void
  try {
    release = await backendLimiter.acquire()
  } catch (err) {
    if (err instanceof Overloaded) return overloadedResponse(err)
    throw err
  }
  const search = new URL(request.url).search
  const upstreamPath = `/${splat ?? ''}${search}`
  const contentType = request.headers.get('content-type')
  const upstream = await fetch(`${base}${upstreamPath}`, {
    method: request.method,
    headers: {
      ...(contentType ? { 'content-type': contentType } : {}),
      'x-service-token': token,
    },
    body: PROXY_BODY_METHODS.has(request.method) ? await request.arrayBuffer() : undefined,
    signal: request.signal,
  }).catch((err) => {
    release()
    throw err
  })
  if (!upstream.body) {
    release()
    return new Response(null, { status: upstream.status })
  }
  return new Response(releaseOnFinish(upstream.body, release), {
    status: upstream.status,
    headers: { 'content-type': upstream.headers.get('content-type') ?? 'application/octet-stream' },
  })
}
