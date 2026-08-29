// #1975: an expired session must route to re-auth, not settle as a dead
// panel. The behaviours pinned here are the ones that were wrong before:
// a 401 resolving as data, and a 401 leaving the operator with no way back.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { SessionExpiredError, beginReauth, resetReauthForTests, sessionAwareFetch } from './reauth'

const assign = vi.fn()

function locate(pathname: string, search = '') {
  Object.defineProperty(window, 'location', {
    configurable: true,
    value: { pathname, search, assign },
  })
}

beforeEach(() => {
  resetReauthForTests()
  assign.mockClear()
  locate('/events')
})

afterEach(() => {
  vi.restoreAllMocks()
})

/** The exact bytes a sessionless server-fn call gets back: the JSON 401
 * from sessionGate.server.ts's unauthenticatedResponse(), plus the
 * `x-tss-raw` marker server-functions-handler.js stamps on any Response
 * thrown from middleware. The header is not incidental -- it is the first
 * thing serverFnFetcher's getResponse tests, and the reason this 401 used
 * to resolve as data instead of rejecting. Drop it from this fixture and
 * the test stops standing for the bug it was written against. */
const unauthenticated = () =>
  new Response(JSON.stringify({ ok: false, error: 'Authentication required.' }), {
    status: 401,
    headers: { 'content-type': 'application/json', 'x-tss-raw': 'true' },
  })

describe('sessionAwareFetch', () => {
  it('rejects a 401 instead of handing back its parsed body', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => unauthenticated()))
    // Rejecting is what keeps the query layer honest: resolve with the
    // error envelope and useServerQuery calls a non-null value 'ready'.
    await expect(sessionAwareFetch('/_serverFn/anything')).rejects.toBeInstanceOf(SessionExpiredError)
  })

  it('sends the browser to sign-in, carrying where it was', async () => {
    locate('/events', '?sensor=cowrie')
    vi.stubGlobal('fetch', vi.fn(async () => unauthenticated()))
    await expect(sessionAwareFetch('/_serverFn/anything')).rejects.toThrow()
    expect(assign).toHaveBeenCalledWith('/auth/login?return_to=%2Fevents%3Fsensor%3Dcowrie')
  })

  it('navigates once however many requests 401 together', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => unauthenticated()))
    await Promise.allSettled([
      sessionAwareFetch('/_serverFn/a'),
      sessionAwareFetch('/_serverFn/b'),
      sessionAwareFetch('/_serverFn/c'),
    ])
    expect(assign).toHaveBeenCalledTimes(1)
  })

  it('leaves every other failure to the error state that owns it', async () => {
    // A backend that is down is a different problem with a different
    // remedy: #1966's Retry actually works for it. Signing the operator
    // out over a 503 would be a regression, not a recovery.
    const body = new Response('{}', { status: 503, headers: { 'content-type': 'application/json' } })
    vi.stubGlobal('fetch', vi.fn(async () => body))
    await expect(sessionAwareFetch('/_serverFn/anything')).resolves.toBe(body)
    expect(assign).not.toHaveBeenCalled()
  })

  it('passes a success through untouched', async () => {
    const body = new Response('{"rows":[]}', { status: 200, headers: { 'content-type': 'application/json' } })
    vi.stubGlobal('fetch', vi.fn(async () => body))
    await expect(sessionAwareFetch('/_serverFn/anything')).resolves.toBe(body)
    expect(assign).not.toHaveBeenCalled()
  })
})

describe('beginReauth', () => {
  it('does not redirect the sign-in page to itself', () => {
    locate('/auth/login')
    beginReauth()
    expect(assign).not.toHaveBeenCalled()
  })
})
