import { describe, expect, it } from 'vitest'
import { describeCredentialState, type CredentialFacts } from './credentialState'

// #3213. Each of these is one of the ways the three axes can be rendered
// wrongly, and every one of them produces a screen that looks fine.

const SECRET = 'correct-horse-battery-staple-9f2c'

function row(over: CredentialFacts): CredentialFacts {
  return { username: '', auth_type: '', credential_status: '', credential_present: null, credential_indicator_match: false, auth_outcome: '', ...over }
}

describe('describeCredentialState', () => {
  it('renders only the account and a fixed vocabulary, and nothing else on the row', () => {
    // The label is assembled from a closed set of parts, so a field the API
    // grows later cannot start appearing in this cell by accident. Note the
    // account IS rendered verbatim -- a username may legitimately contain a
    // slash or a space, and mangling it would be worse than rendering it.
    // Keeping a secret out of that field is the backend boundary's job
    // (secrets_boundary.rs), proven there; asserting it again here would
    // only be a second, weaker copy of the same check.
    const state = describeCredentialState({
      ...row({ username: 'admin', auth_type: 'form', credential_status: 'extracted', credential_present: true, auth_outcome: 'simulated' }),
      // Fields this module has never heard of, two of them carrying a value.
      body: `password=${SECRET}`,
      headers: { authorization: SECRET },
      password: SECRET,
    } as CredentialFacts)
    expect(state.label).toBe('admin · credential extracted · auth simulated · via form')
    expect(state.label).not.toContain(SECRET)
  })

  it('keeps unknown apart from absent', () => {
    // The issue's central distinction. "no credential" and "we could not
    // tell" are different claims about the attacker.
    const absent = describeCredentialState(row({ credential_status: 'absent', credential_present: false, auth_outcome: 'unknown' }))
    const unknown = describeCredentialState(row({ credential_status: 'unknown', credential_present: null, auth_outcome: 'unknown' }))
    expect(absent.label).toContain('no credential')
    expect(unknown.label).toContain('credential unknown')
    expect(absent.label).not.toBe(unknown.label)
    expect(absent.present).toBe(false)
    expect(unknown.present).toBeNull()
  })

  it('reports present-but-unparsed as neither mapped nor absent', () => {
    const state = describeCredentialState(row({ credential_status: 'present_unparsed', credential_present: true }))
    expect(state.label).toContain('credential present, not parsed')
    expect(state.label).not.toContain('no credential')
    expect(state.present).toBe(true)
    expect(state.tone).toBe('warning')
  })

  it('words the bait indicator as an attempt, not as access', () => {
    const state = describeCredentialState(row({ username: 'admin', credential_status: 'extracted', credential_present: true, credential_indicator_match: true, auth_outcome: 'simulated' }))
    expect(state.label).toContain('bait credential attempted')
    expect(state.label).not.toMatch(/access|bypass|default credential|owned|compromised/i)
    expect(state.tone).toBe('danger')
  })

  it('never infers a real authentication from a status or an outcome default', () => {
    // `real` has to be spelled out by the sensor. Nothing here may produce it.
    for (const auth_outcome of ['', 'simulated', 'unknown']) {
      const state = describeCredentialState(row({ credential_status: 'extracted', credential_present: true, auth_outcome }))
      expect(state.label).not.toContain('auth real')
    }
  })

  it('says a pre-schema document had its credential removed, not that it had none', () => {
    const state = describeCredentialState(row({ username: 'admin', credential_status: '' }))
    expect(state.label).toContain('credentials removed')
    expect(state.label).not.toContain('no credential')
    // The account is the analytic value and survives.
    expect(state.account).toBe('admin')
  })

  it('renders an unrecognised status as its own word rather than a blank', () => {
    // A sensor that grows a fifth state should be visible on screen, not
    // silently swallowed into "nothing to report".
    const state = describeCredentialState(row({ credential_status: 'partially_read' }))
    expect(state.label).toContain('partially_read')
  })

  it('carries the account and the channel through to the cell', () => {
    const state = describeCredentialState(row({ username: 'admin', auth_type: 'basic', credential_status: 'extracted', credential_present: true, auth_outcome: 'simulated' }))
    expect(state.label).toBe('admin · credential extracted · auth simulated · via basic')
  })

  it('is empty rather than padded when the sensor reported nothing at all', () => {
    // tanner and the other out-of-scope sensors have none of these fields.
    // They must render as they did before, which is nothing.
    const state = describeCredentialState({})
    expect(state.label).toBe('credentials removed')
    expect(state.tone).toBe('muted')
  })
})
