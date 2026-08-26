import { describe, expect, it } from 'vitest'
import { parseRetryAfter } from './backend.server'

// #1966: retry-after capture on ServiceFailure. The shedder writes integer
// seconds; anything else must degrade to "no hint", never to 0 (which would
// read as "retry instantly").
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
