// #3110: the Rust tier's per-owner authorization is only as real as the
// identity headers reaching it. serviceFetch is the all-mode/BFF-direct
// path; proxyToRust is the split-deployment /bff and /bff-mounted hop
// (routes/bff.$.ts, routes/bff-mounted.$.ts). Both must carry
// x-actor-username/x-actor-role from a verified caller through unedited,
// and proxyToRust in particular uses an explicit header allowlist (see
// its own #2302 comment) — a silent regression there would drop identity
// and fail closed (401 at the Rust tier) rather than fail open, but it
// would still break every legitimate workbench call in split mode.
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { DEV_UNAUTH_OVERRIDE_ENV } from './serviceToken.server'

let serviceFetch: typeof import('./backend.server').serviceFetch
let proxyToRust: typeof import('./backend.server').proxyToRust

beforeAll(async () => {
  process.env[DEV_UNAUTH_OVERRIDE_ENV] = '1'
  process.env.SERVICE_TOKEN = 'test-token'
  ;({ serviceFetch, proxyToRust } = await import('./backend.server'))
})

afterAll(() => {
  delete process.env[DEV_UNAUTH_OVERRIDE_ENV]
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function interceptUpstream(): { forwarded: ReturnType<typeof vi.fn>; headers: () => Headers } {
  const forwarded = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', forwarded)
  return {
    forwarded,
    headers: () => new Headers(forwarded.mock.calls[0][1]?.headers as HeadersInit),
  }
}

describe('serviceFetch attaches the verified actor as headers (#3110)', () => {
  it('sends x-actor-username/x-actor-role when opts.actor is given', async () => {
    const { headers } = interceptUpstream()
    await serviceFetch('/api/v1/workbench/runs', undefined, { actor: { username: 'alice', role: 'user' } })
    expect(headers().get('x-actor-username')).toBe('alice')
    expect(headers().get('x-actor-role')).toBe('user')
  })

  it('omits both headers when no actor is given', async () => {
    const { headers } = interceptUpstream()
    await serviceFetch('/api/v1/overview/kpis')
    expect(headers().has('x-actor-username')).toBe(false)
    expect(headers().has('x-actor-role')).toBe(false)
  })
})

describe('proxyToRust forwards inbound actor headers unedited (#3110)', () => {
  it('carries x-actor-username/x-actor-role through to the upstream request', async () => {
    const { forwarded, headers } = interceptUpstream()
    const response = await proxyToRust(
      new Request('http://bff.local/bff/api/v1/workbench/runs', {
        headers: {
          'x-service-token': 'test-token',
          'x-actor-username': 'alice',
          'x-actor-role': 'user',
        },
      }),
      'api/v1/workbench/runs',
      'http://backend.local',
      '/bff',
    )
    expect(response.status).toBe(200)
    expect(forwarded).toHaveBeenCalledTimes(1)
    expect(headers().get('x-actor-username')).toBe('alice')
    expect(headers().get('x-actor-role')).toBe('user')
  })

  it('forwards neither header when the inbound request carries no actor identity', async () => {
    // A request that never went through serviceFetch (or an older client)
    // must not have identity synthesized for it — the Rust tier's
    // require_actor() is the one place absence turns into a 401.
    const { headers } = interceptUpstream()
    await proxyToRust(
      new Request('http://bff.local/bff/api/v1/workbench/runs', {
        headers: { 'x-service-token': 'test-token' },
      }),
      'api/v1/workbench/runs',
      'http://backend.local',
      '/bff',
    )
    expect(headers().has('x-actor-username')).toBe(false)
    expect(headers().has('x-actor-role')).toBe(false)
  })
})
