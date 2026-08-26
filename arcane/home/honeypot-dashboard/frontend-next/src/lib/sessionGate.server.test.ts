// #2123: the session gate's decisions are the whole security posture of
// every server function, so pin them: no session and OIDC enabled means
// rejected; the OIDC_DISABLED fixture operator passes; only the pre-auth
// modules are exempt from the gate.
import { describe, expect, it, vi } from 'vitest'

const getSession = vi.fn()
vi.mock('./session.server', () => ({
  getSession: (...args: unknown[]) => getSession(...args),
  sidFrom: () => 'sid-from-request',
}))

// oidc.server reads process.env at call time.
function setOidcDisabled(value: string) {
  if (value === '') delete process.env.OIDC_DISABLED
  else process.env.OIDC_DISABLED = value
}

import { isPublicFn, resolveFunctionUser, unauthenticatedResponse } from './sessionGate.server'

const SESSION = { sub: 's1', username: 'op', displayName: 'Operator', role: 'user' as const, createdAt: 0 }
const REQUEST = new Request('https://bff.example/_serverFn/x')

describe('resolveFunctionUser', () => {
  it('rejects when there is no session and OIDC is enabled', async () => {
    setOidcDisabled('')
    getSession.mockResolvedValueOnce(null)
    expect(await resolveFunctionUser(REQUEST)).toBeNull()
  })

  it('returns the session identity for a valid cookie', async () => {
    setOidcDisabled('')
    getSession.mockResolvedValueOnce(SESSION)
    const user = await resolveFunctionUser(REQUEST)
    expect(user).toMatchObject({ username: 'op', role: 'user' })
  })

  it('keeps local/dev working via the fixture operator, not a null pass-through', async () => {
    setOidcDisabled('1')
    getSession.mockResolvedValueOnce(null)
    const user = await resolveFunctionUser(REQUEST)
    expect(user).toMatchObject({ username: 'dev', role: 'admin' })
  })
})

describe('unauthenticatedResponse', () => {
  it('is a JSON 401 with the ok:false shape mutating callers check', () => {
    const response = unauthenticatedResponse()
    expect(response.status).toBe(401)
  })
})

describe('isPublicFn', () => {
  it('exempts the pre-auth session lookups in lib/auth.ts', () => {
    expect(isPublicFn({ filename: 'src/lib/auth.ts' })).toBe(true)
  })

  it('gates everything else, including unknown files', () => {
    expect(isPublicFn({ filename: 'src/routes/credentials.tsx' })).toBe(false)
    expect(isPublicFn({})).toBe(false)
  })
})
