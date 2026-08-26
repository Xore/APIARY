// #2183's BFF half pinned. The policy function is pure over an explicit env
// (no process.env mutation, no cross-test leakage) and its truth table must
// mirror backend-service/src/main.rs's resolve_service_token — the two are
// one contract rendered twice.
import { beforeAll, describe, expect, it } from 'vitest'
import {
  assertServiceTokenPolicy,
  DEV_UNAUTH_OVERRIDE_ENV,
  SERVICE_TOKEN_GATE_CODE,
  serviceTokenPolicy,
} from './serviceToken.server'

describe('serviceTokenPolicy', () => {
  it('refuses when SERVICE_TOKEN is unset and no override exists', () => {
    const policy = serviceTokenPolicy({})
    expect(policy.kind).toBe('refuse')
    if (policy.kind !== 'refuse') return
    expect(policy.message).toContain(SERVICE_TOKEN_GATE_CODE)
    expect(policy.message).toContain('SERVICE_TOKEN')
    expect(policy.message).toContain(`${DEV_UNAUTH_OVERRIDE_ENV}=1`)
  })

  it('treats an empty SERVICE_TOKEN as unset', () => {
    // compose ships `${DASHBOARD_SERVICE_TOKEN:-}`; a copied partial env
    // produces exactly this empty string, not undefined.
    expect(serviceTokenPolicy({ SERVICE_TOKEN: '' }).kind).toBe('refuse')
  })

  it('sanctions the unset token only under the explicit dev override', () => {
    expect(serviceTokenPolicy({ [DEV_UNAUTH_OVERRIDE_ENV]: '1' }).kind).toBe('dev-override')
    expect(
      serviceTokenPolicy({ SERVICE_TOKEN: '', [DEV_UNAUTH_OVERRIDE_ENV]: '1' }).kind,
    ).toBe('dev-override')
  })

  it('accepts exactly "1" for the override — no truthiness zoo', () => {
    // A future `=0` or `=false` must read as refusal, not as consent.
    for (const notOne of ['', '0', 'true', 'yes']) {
      expect(serviceTokenPolicy({ [DEV_UNAUTH_OVERRIDE_ENV]: notOne }).kind).toBe('refuse')
    }
  })

  it('lets a real token boot without any override', () => {
    expect(serviceTokenPolicy({ SERVICE_TOKEN: 's3cret' }).kind).toBe('token')
  })

  it('keeps enforcement on when both token and override are set', () => {
    // The override sanctions the token's absence, never weakens its presence.
    expect(serviceTokenPolicy({ SERVICE_TOKEN: 's3cret', [DEV_UNAUTH_OVERRIDE_ENV]: '1' }).kind).toBe('token')
  })
})

describe('assertServiceTokenPolicy', () => {
  it('throws the E-SERVICE-TOKEN refusal when misconfigured', () => {
    expect(() => assertServiceTokenPolicy({})).toThrowError(SERVICE_TOKEN_GATE_CODE)
  })

  it('passes silently with a token or the override', () => {
    expect(() => assertServiceTokenPolicy({ SERVICE_TOKEN: 's3cret' })).not.toThrow()
    expect(() => assertServiceTokenPolicy({ [DEV_UNAUTH_OVERRIDE_ENV]: '1' })).not.toThrow()
  })
})

// #2183 seam-2 backstop: even once backend.server.ts is loaded (under the
// sanctioned-dev import above), proxyToRust itself must refuse — not pass
// through open — when the running process's env would not sanction an
// unauthenticated tier.
describe('proxyToRust refuses closed without a sanctioned token contract', () => {
  let proxyToRust: typeof import('./backend.server').proxyToRust

  beforeAll(async () => {
    // Import under the dev override: the module-scope boot gate refuses to
    // evaluate its bundle cold, which is exactly what this describe is NOT
    // testing — it pins the per-request backstop below the gate.
    process.env[DEV_UNAUTH_OVERRIDE_ENV] = '1'
    ;({ proxyToRust } = await import('./backend.server'))
  })

  it('answers 503 E-SERVICE-TOKEN when neither token nor override is present', async () => {
    const priorToken = process.env.SERVICE_TOKEN
    const priorOverride = process.env[DEV_UNAUTH_OVERRIDE_ENV]
    const hadToken = 'SERVICE_TOKEN' in process.env
    const hadOverride = DEV_UNAUTH_OVERRIDE_ENV in process.env
    delete process.env.SERVICE_TOKEN
    delete process.env[DEV_UNAUTH_OVERRIDE_ENV]
    try {
      const response = await proxyToRust(new Request('http://bff.local/bff/api/v1/overview/kpis'), 'api/v1/overview/kpis', 'http://backend.local')
      expect(response.status).toBe(503)
      expect(await response.text()).toContain(SERVICE_TOKEN_GATE_CODE)
    } finally {
      if (hadToken) process.env.SERVICE_TOKEN = priorToken
      if (hadOverride) process.env[DEV_UNAUTH_OVERRIDE_ENV] = priorOverride
    }
  })
})

