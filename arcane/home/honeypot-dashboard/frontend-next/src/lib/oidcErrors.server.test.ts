// #1942: the OIDC front door must render failures as pages a person can
// act on, never as the 53-byte plaintext bodies that made every protocol-
// level hiccup look like the whole dashboard was down. These pin the
// contract: provider errors parse per RFC 6749 §4.1.2.1, pages escape
// everything interpolatable, and each failure class carries its distinct
// status (400 provider/expired vs 503 unstartable vs 502 exchange).
import { describe, expect, it } from 'vitest'
import { authErrorPage, escapeHtml, providerErrorFrom } from './oidcErrors.server'

describe('providerErrorFrom', () => {
  it('parses Keycloak error + description params', () => {
    const parsed = providerErrorFrom(
      new URL('https://dash/auth/callback?error=invalid_request&error_description=Expired%20request'),
    )
    expect(parsed).toEqual({ error: 'invalid_request', description: 'Expired request' })
  })

  it('falls back to the raw code when description is absent', () => {
    const parsed = providerErrorFrom(new URL('https://dash/auth/callback?error=access_denied'))
    expect(parsed).toEqual({ error: 'access_denied', description: 'access_denied' })
  })

  it('returns null for a normal code-bearing callback', () => {
    expect(providerErrorFrom(new URL('https://dash/auth/callback?state=abc&code=xyz'))).toBeNull()
  })

  it('returns null for an empty callback', () => {
    expect(providerErrorFrom(new URL('https://dash/auth/callback'))).toBeNull()
  })
})

describe('escapeHtml', () => {
  it.each([
    ['<script>alert(1)</script>', '&lt;script&gt;alert(1)&lt;/script&gt;'],
    ['&"\'', '&amp;&quot;&#39;'],
  ])('escapes %j', (input, expected) => {
    expect(escapeHtml(input)).toBe(expected)
  })
})

describe('authErrorPage', () => {
  it('renders html with the given status and content type', async () => {
    const res = authErrorPage({
      status: 503,
      heading: 'Sign-in is temporarily unavailable',
      detail: 'Reload to retry.',
    })
    expect(res.status).toBe(503)
    expect(res.headers.get('content-type')).toBe('text/html; charset=utf-8')
    const body = await res.text()
    expect(body).toContain('Sign-in is temporarily unavailable')
    expect(body).toContain('<!doctype html>')
  })

  it('omits the retry link when none is offered', async () => {
    const body = await authErrorPage({ status: 503, heading: 'h', detail: 'd' }).text()
    expect(body).not.toContain('/auth/login')
    expect(body).not.toContain('<a href')
  })

  it('interpolates no hostile content through heading, detail or href', async () => {
    const body = await authErrorPage({
      status: 400,
      heading: '<img src=x onerror=alert(1)>',
      detail: '<script>alert(2)</script>',
      retryHref: '/auth/login?next=<script>',
    }).text()
    expect(body).not.toContain('<img ')
    expect(body).not.toContain('<script>')
    expect(body).toContain('&lt;script&gt;')
  })
})
