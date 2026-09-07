// #3112: OIDC_DISABLED=1 hands out a fixture admin session
// (sessionGate.server.ts's resolveFunctionUser) -- this must never be
// sanctioned outside an explicit NODE_ENV=development, mirroring
// serviceToken.server.test.ts's coverage of the sibling boot gate.
import { describe, expect, it } from 'vitest'
import { assertOidcDisabledPolicy, OIDC_DISABLED_GATE_CODE, oidcDisabledPolicy } from './oidc.server'

describe('oidcDisabledPolicy', () => {
  it('is enforced (OIDC required) when OIDC_DISABLED is unset', () => {
    expect(oidcDisabledPolicy({}).kind).toBe('enforced')
  })

  it('is enforced when OIDC_DISABLED is anything other than exactly "1"', () => {
    for (const notOne of ['', '0', 'true', 'yes']) {
      expect(oidcDisabledPolicy({ OIDC_DISABLED: notOne }).kind).toBe('enforced')
    }
  })

  it('refuses OIDC_DISABLED=1 with no NODE_ENV', () => {
    const policy = oidcDisabledPolicy({ OIDC_DISABLED: '1' })
    expect(policy.kind).toBe('refuse')
    if (policy.kind !== 'refuse') return
    expect(policy.message).toContain(OIDC_DISABLED_GATE_CODE)
    expect(policy.message).toContain('OIDC_DISABLED')
    expect(policy.message).toContain('NODE_ENV=development')
  })

  it('refuses OIDC_DISABLED=1 under a production NODE_ENV', () => {
    expect(oidcDisabledPolicy({ OIDC_DISABLED: '1', NODE_ENV: 'production' }).kind).toBe('refuse')
  })

  it('sanctions OIDC_DISABLED=1 under NODE_ENV=development', () => {
    expect(oidcDisabledPolicy({ OIDC_DISABLED: '1', NODE_ENV: 'development' }).kind).toBe('dev-override')
  })

  it('also sanctions OIDC_DISABLED=1 via APIARY_ALLOW_UNAUTH_DEV=1, the escape hatch every harness that boots with OIDC_DISABLED=1 already sets', () => {
    expect(
      oidcDisabledPolicy({ OIDC_DISABLED: '1', APIARY_ALLOW_UNAUTH_DEV: '1' }).kind,
    ).toBe('dev-override')
  })

  it('still refuses OIDC_DISABLED=1 when neither escape hatch is set', () => {
    expect(
      oidcDisabledPolicy({ OIDC_DISABLED: '1', APIARY_ALLOW_UNAUTH_DEV: '0' }).kind,
    ).toBe('refuse')
  })

  it('names both escape hatches in the refusal message', () => {
    const policy = oidcDisabledPolicy({ OIDC_DISABLED: '1' })
    if (policy.kind !== 'refuse') throw new Error('expected refuse')
    expect(policy.message).toContain('NODE_ENV=development')
    expect(policy.message).toContain('APIARY_ALLOW_UNAUTH_DEV=1')
  })
})

describe('assertOidcDisabledPolicy', () => {
  it('throws the E-OIDC-DISABLED refusal when misconfigured', () => {
    expect(() => assertOidcDisabledPolicy({ OIDC_DISABLED: '1' })).toThrowError(OIDC_DISABLED_GATE_CODE)
  })

  it('passes silently when OIDC is enforced or the dev override is sanctioned', () => {
    expect(() => assertOidcDisabledPolicy({})).not.toThrow()
    expect(() => assertOidcDisabledPolicy({ OIDC_DISABLED: '1', NODE_ENV: 'development' })).not.toThrow()
    expect(() => assertOidcDisabledPolicy({ OIDC_DISABLED: '1', APIARY_ALLOW_UNAUTH_DEV: '1' })).not.toThrow()
  })
})
