// #3153: GET /auth/logout clears the session unconditionally, with no
// Origin/Referer/method check — any cross-site page (a plain <img> or
// top-level navigation) could force a signed-in operator's session closed.
// Pins that a cross-origin call is rejected the same way #3109's server-fn
// gate rejects one, and that a real same-origin logout still clears the
// cookie and redirects to the pinned Keycloak end-session URL.
import { afterEach, describe, expect, it, vi } from 'vitest'

const getSession = vi.fn()
const destroySession = vi.fn()
vi.mock('../../lib/session.server', () => ({
  sidFrom: () => 'sid-from-request',
  getSession: (...args: unknown[]) => getSession(...args),
  destroySession: (...args: unknown[]) => destroySession(...args),
  clearSessionCookie: () => 'cleared-cookie',
}))

vi.mock('../../lib/oidc.server', () => ({
  oidcConfig: async () => ({}),
  externalURL: () => process.env.OIDC_EXTERNAL_URL ?? 'https://dashboard.example',
}))

vi.mock('openid-client', () => ({
  buildEndSessionUrl: () =>
    new URL('https://keycloak.example/realms/apiary/protocol/openid-connect/logout?id_token_hint=t'),
}))

import { Route } from './logout'

const handlers = Route.options.server!.handlers as { GET: (ctx: { request: Request }) => Promise<Response> }
const handler = handlers.GET

function req(headers: Record<string, string> = {}) {
  return new Request('https://dashboard.example/auth/logout', { headers })
}

afterEach(() => {
  vi.clearAllMocks()
  delete process.env.OIDC_EXTERNAL_URL
})

describe('GET /auth/logout', () => {
  it('rejects a cross-origin Origin without touching the session', async () => {
    process.env.OIDC_EXTERNAL_URL = 'https://dashboard.example'
    const response = await handler({ request: req({ origin: 'https://evil.example' }) })
    expect(response.status).toBe(403)
    expect(destroySession).not.toHaveBeenCalled()
  })

  it('rejects a cross-site navigation with neither Origin nor Referer', async () => {
    process.env.OIDC_EXTERNAL_URL = 'https://dashboard.example'
    const response = await handler({
      request: req({ 'sec-fetch-site': 'cross-site', 'sec-fetch-dest': 'image' }),
    })
    expect(response.status).toBe(403)
    expect(destroySession).not.toHaveBeenCalled()
  })

  it('clears the cookie and redirects to the pinned Keycloak logout URL for a same-origin call', async () => {
    process.env.OIDC_EXTERNAL_URL = 'https://dashboard.example'
    getSession.mockResolvedValueOnce({ idToken: 'id-token' })
    const response = await handler({ request: req({ origin: 'https://dashboard.example' }) })
    expect(response.status).toBe(303)
    expect(response.headers.get('location')).toBe(
      'https://keycloak.example/realms/apiary/protocol/openid-connect/logout?id_token_hint=t',
    )
    expect(response.headers.get('set-cookie')).toBe('cleared-cookie')
    expect(destroySession).toHaveBeenCalledWith('sid-from-request')
  })
})
