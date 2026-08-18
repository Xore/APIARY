// The one network seam between tiers (per Xore's host-separation
// requirement): every SSR/server-function data access goes through these
// helpers, never through direct fetch calls — so the frontend tier can run
// on a different docker host from the BFF (SERVE_MODE=frontend +
// BFF_INTERNAL_URL) and the BFF from the Rust service (BACKEND_URL),
// without touching call sites. All state behind these calls is
// redis/ES-backed; no tier holds host-local state.
export type ServeMode = 'all' | 'frontend' | 'bff'

export function serveMode(): ServeMode {
  const mode = process.env.SERVE_MODE
  return mode === 'frontend' || mode === 'bff' ? mode : 'all'
}

/** Base URL of the Rust service tier. */
export function backendURL(): string {
  return (process.env.BACKEND_URL ?? 'http://127.0.0.1:8081').replace(/\/$/, '')
}

/** Base URL of the BFF tier as seen from the frontend tier when split;
 * loopback (same process) in all-mode. */
export function bffInternalURL(): string {
  return (process.env.BFF_INTERNAL_URL ?? '').replace(/\/$/, '')
}

/** Fetch from the Rust service with the service token. Only the BFF tier
 * (or all-mode) may call this; the split frontend tier goes through
 * bffFetch instead. */
export async function serviceFetch(path: string, init?: RequestInit): Promise<Response> {
  return fetch(`${backendURL()}${path}`, {
    ...init,
    headers: {
      ...(init?.headers ?? {}),
      'x-service-token': process.env.SERVICE_TOKEN ?? '',
    },
    signal: init?.signal ?? AbortSignal.timeout(15_000),
  })
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

/** JSON convenience over serviceFetch; null on any failure so routes can
 * fall back to skeleton/error states without try/catch noise. */
export async function serviceJSON<T>(path: string): Promise<T | null> {
  const cached = payloadCache.get(path)
  if (cached && Date.now() - cached.at < PAYLOAD_TTL_MS) return cached.body as T
  const redis = await cacheRedis()
  if (redis) {
    try {
      const shared = await redis.get(REDIS_PREFIX + path)
      if (shared) {
        const body = JSON.parse(shared) as T
        payloadCache.set(path, { at: Date.now(), body })
        return body
      }
    } catch {
      /* fall through to the live fetch */
    }
  }
  try {
    const response = await serviceFetch(path)
    if (!response.ok) return null
    const body = (await response.json()) as T
    payloadCache.set(path, { at: Date.now(), body })
    if (payloadCache.size > 500) {
      const cutoff = Date.now() - PAYLOAD_TTL_MS
      for (const [key, value] of payloadCache) if (value.at < cutoff) payloadCache.delete(key)
    }
    if (redis) {
      redis.set(REDIS_PREFIX + path, JSON.stringify(body), 'PX', PAYLOAD_TTL_MS).catch(() => {})
    }
    return body
  } catch {
    return null
  }
}
