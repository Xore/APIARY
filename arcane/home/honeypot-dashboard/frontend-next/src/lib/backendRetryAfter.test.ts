import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { DEV_UNAUTH_OVERRIDE_ENV } from './serviceToken.server'

// #1966: retry-after capture on ServiceFailure. The shedder writes integer
// seconds; anything else must degrade to "no hint", never to 0 (which would
// read as "retry instantly").
//
// The import is dynamic since #2183: backend.server.ts refuses to evaluate
// without a SERVICE_TOKEN or the explicit dev override (its module-scope
// boot gate), and this test is about retry-after parsing, not tokens — so
// it takes the sanctioned-dev door rather than fabricating one.
let parseRetryAfter: typeof import('./backend.server').parseRetryAfter

beforeAll(async () => {
  process.env[DEV_UNAUTH_OVERRIDE_ENV] = '1'
  ;({ parseRetryAfter } = await import('./backend.server'))
})

afterAll(() => {
  delete process.env[DEV_UNAUTH_OVERRIDE_ENV]
})

describe('parseRetryAfter', () => {
  it('parses integer seconds', () => {
    expect(parseRetryAfter('30')).toBe(30)
    expect(parseRetryAfter('0')).toBe(0)
  })

  it('absent header means no hint', () => {
    expect(parseRetryAfter(null)).toBeUndefined()
    expect(parseRetryAfter('')).toBeUndefined()
  })

  it('unparsable values mean no hint, not zero', () => {
    expect(parseRetryAfter('soon')).toBeUndefined()
    expect(parseRetryAfter('30, 45')).toBeUndefined()
  })
})
