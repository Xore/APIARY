import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { DEV_UNAUTH_OVERRIDE_ENV } from './serviceToken.server'

// #2302: the /bff and /bff-mounted seam must forward the ORIGINAL request
// target verbatim instead of reassembling it from the splat params. Route
// params arrive percent-decoded, so the old reassembly collapsed a
// single-encoded %2F into a literal slash — splitting one path segment into
// two and 404ing axum's router on every real CIDR link while %252F "worked"
// only by decaying into the one encoding axum wanted.
//
// The import is dynamic since #2183: backend.server.ts refuses to evaluate
// without a SERVICE_TOKEN or the explicit dev override, and this test is
// about target forwarding, not tokens. The token itself is set so the
// proxy's inbound x-service-token check passes like any split-deployment
// BFF hop would.
let proxyToRust: typeof import('./backend.server').proxyToRust

beforeAll(async () => {
  process.env[DEV_UNAUTH_OVERRIDE_ENV] = '1'
  process.env.SERVICE_TOKEN = 'test-token'
  ;({ proxyToRust } = await import('./backend.server'))
})

afterAll(() => {
  delete process.env[DEV_UNAUTH_OVERRIDE_ENV]
})

afterEach(() => {
  vi.unstubAllGlobals()
})

/** Capture the first hop instead of dialing a nonexistent Rust tier; returns
 * the mock so assertions can read exactly what would hit axum. */
function interceptUpstream(): { forwarded: ReturnType<typeof vi.fn>; firstURL: () => string } {
  const forwarded = vi.fn(async (_input: RequestInfo | URL) => new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', forwarded)
  return {
    forwarded,
    firstURL: () => String(forwarded.mock.calls[0][0]),
  }
}

async function proxy(request: Request, splat: string | undefined, base: string, mount?: string) {
  return proxyToRust(request, splat, base, mount)
}

describe('proxyToRust forwards the original encoded request target (#2302)', () => {
  it('keeps single-encoded slashes in a path segment intact across /bff', async () => {
    // Exactly what TanStack hands the handler for a real CIDR link:
    // _splat already decoded (slash split out) while request.url still
    // carries the escaping. The reconstruction MUST lose.
    const { forwarded, firstURL } = interceptUpstream()
    const response = await proxy(
      new Request('http://bff.local/bff/api/v1/investigate/cidr/175.107.1.0%2F24?type=event', {
        headers: { 'x-service-token': 'test-token' },
      }),
      'api/v1/investigate/cidr/175.107.1.0/24',
      'http://backend.local',
      '/bff',
    )
    expect(response.status).toBe(200)
    expect(firstURL()).toBe('http://backend.local/api/v1/investigate/cidr/175.107.1.0%2F24?type=event')
    expect(String(forwarded.mock.calls[0][0])).not.toContain('175.107.1.0/24?type')
  })

  it('cuts the /bff-mounted prefix but keeps its encodings', async () => {
    const { firstURL } = interceptUpstream()
    await proxy(
      new Request('http://bff.local/bff-mounted/api/v1/sandbox/status/spool%2Fx', {
        headers: { 'x-service-token': 'test-token' },
      }),
      'api/v1/sandbox/status/spool/x',
      'http://backend.local',
      '/bff-mounted',
    )
    expect(firstURL()).toBe('http://backend.local/api/v1/sandbox/status/spool%2Fx')
  })

  it('passes query-string encoding through byte-for-byte', async () => {
    // Encoded slashes in query VALUES must survive independently of what
    // happened to the path (#2302's query regression case).
    const { firstURL } = interceptUpstream()
    await proxy(
      new Request(
        'http://bff.local/bff/api/v1/investigate/events?q=175.107.1.0%2F24&note=a%20b',
        { headers: { 'x-service-token': 'test-token' } },
      ),
      'api/v1/investigate/events',
      'http://backend.local',
      '/bff',
    )
    expect(firstURL()).toBe('http://backend.local/api/v1/investigate/events?q=175.107.1.0%2F24&note=a%20b')
  })

  it('maps a bare mount hit to the backend root', async () => {
    const { firstURL } = interceptUpstream()
    await proxy(
      new Request('http://bff.local/bff?probe=1', { headers: { 'x-service-token': 'test-token' } }),
      undefined,
      'http://backend.local',
      '/bff',
    )
    expect(firstURL()).toBe('http://backend.local/?probe=1')
  })

  it('falls back to splat reassembly when no mount prefix is known', async () => {
    // Direct callers without the #2302 argument keep working off the
    // decoded params — the guard exists so nothing outside the two route
    // files can silently stop forwarding at all.
    const { firstURL } = interceptUpstream()
    await proxy(
      new Request('http://bff.local/bff/api/v1/overview/kpis', {
        headers: { 'x-service-token': 'test-token' },
      }),
      'api/v1/overview/kpis',
      'http://backend.local',
    )
    expect(firstURL()).toBe('http://backend.local/api/v1/overview/kpis')
  })
})
