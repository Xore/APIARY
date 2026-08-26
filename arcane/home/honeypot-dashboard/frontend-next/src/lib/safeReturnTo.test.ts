// #2121: safeReturnTo is the whole post-login redirect contract (#472
// "same-domain only"), so pin the hostile set — every one of these rode
// past or around the old startsWith('/') && !startsWith('//') check.
import { describe, expect, it } from 'vitest'
import { safeReturnTo } from './oidc.server'

const DASH = 'http://127.0.0.1:4173' // externalURL()'s default base

describe('safeReturnTo', () => {
  it.each([
    ['//evil.example'],
    ['/\\evil.example'],
    ['/\\/evil.example'],
    ['\\evil.example'],
    ['https://evil.example'],
    ['http://127.0.0.1:4173.evil.example'],
  ])('rejects the hostile %j', (hostile) => {
    expect(safeReturnTo(hostile)).toBe('/')
  })

  it('rejects script and data URLs on origin mismatch', () => {
    expect(safeReturnTo('javascript:alert(1)')).toBe('/')
    expect(safeReturnTo('data:text/html,hi')).toBe('/')
  })

  it.each([
    ['/alerts'],
    ['/investigate/ip/192.0.2.7'],
    ['/reports?status=open#trail'],
  ])('round-trips the benign path %j unchanged', (benign) => {
    expect(safeReturnTo(benign)).toBe(benign)
  })

  it('falls back to / for empty and missing input', () => {
    expect(safeReturnTo('')).toBe('/')
  })

  it('re-emits accepted absolute same-origin URLs as paths', () => {
    expect(safeReturnTo(`${DASH}/alerts`)).toBe('/alerts')
  })
})
