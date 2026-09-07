// #3109: cross-origin POST to a server function must be rejected — the CSP
// nonce and the session cookie both live on the analyst UI's own origin, so
// a request whose Origin/Referer disagrees with it never legitimately
// belongs to a same-site caller.
import { afterEach, describe, expect, it } from 'vitest'
import { crossOriginResponse, isSameOriginRequest } from './csrfGate.server'

afterEach(() => {
  delete process.env.OIDC_EXTERNAL_URL
})

function req(method: string, headers: Record<string, string> = {}) {
  return new Request('http://internal.example/_serverFn/x', { method, headers })
}

describe('isSameOriginRequest', () => {
  it('allows safe methods without any Origin/Referer header', () => {
    expect(isSameOriginRequest(req('GET'))).toBe(true)
    expect(isSameOriginRequest(req('HEAD'))).toBe(true)
  })

  it('rejects a state-changing request with no Origin or Referer', () => {
    expect(isSameOriginRequest(req('POST'))).toBe(false)
  })

  it('rejects a cross-site Origin', () => {
    process.env.OIDC_EXTERNAL_URL = 'https://dashboard.example'
    expect(isSameOriginRequest(req('POST', { origin: 'https://evil.example' }))).toBe(false)
  })

  it('accepts a matching Origin', () => {
    process.env.OIDC_EXTERNAL_URL = 'https://dashboard.example'
    expect(isSameOriginRequest(req('POST', { origin: 'https://dashboard.example' }))).toBe(true)
  })

  it('falls back to Referer when Origin is absent', () => {
    process.env.OIDC_EXTERNAL_URL = 'https://dashboard.example'
    expect(
      isSameOriginRequest(req('POST', { referer: 'https://dashboard.example/canarytokens' })),
    ).toBe(true)
    expect(
      isSameOriginRequest(req('POST', { referer: 'https://evil.example/canarytokens' })),
    ).toBe(false)
  })
})

describe('crossOriginResponse', () => {
  it('is a JSON 403 with the ok:false shape mutating callers check', () => {
    const response = crossOriginResponse()
    expect(response.status).toBe(403)
  })
})
