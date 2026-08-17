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

/** JSON convenience over serviceFetch; null on any failure so routes can
 * fall back to skeleton/error states without try/catch noise. */
export async function serviceJSON<T>(path: string): Promise<T | null> {
  try {
    const response = await serviceFetch(path)
    if (!response.ok) return null
    return (await response.json()) as T
  } catch {
    return null
  }
}
