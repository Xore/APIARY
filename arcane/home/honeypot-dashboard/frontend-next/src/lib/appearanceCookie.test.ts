// #1833: the cookie decides what ground the very first frame paints, so a
// value it accepts wrongly is a wrong ground painted confidently.
import { describe, expect, it } from 'vitest'
import {
  APPEARANCE_COOKIE,
  parseAppearance,
  readAppearanceCookie,
  resolveMode,
  serialiseAppearance,
} from './appearanceCookie'

describe('parseAppearance', () => {
  it('reads a mode and a theme', () => {
    expect(parseAppearance('dark:slate')).toEqual({ mode: 'dark', theme: 'slate' })
  })

  it('accepts either half on its own', () => {
    expect(parseAppearance('light:')).toEqual({ mode: 'light', theme: null })
    expect(parseAppearance(':claude')).toEqual({ mode: null, theme: 'claude' })
  })

  it('never yields the literal system — the server cannot evaluate it', () => {
    expect(parseAppearance('system:slate').mode).toBeNull()
  })

  it('rejects a theme name that fails the shape', () => {
    // The value goes straight into an attribute selector on <html>, and a
    // cookie is attacker-writable on a shared machine.
    expect(parseAppearance('dark:"><script>x</script>').theme).toBeNull()
    expect(parseAppearance('dark:UPPER').theme).toBeNull()
    expect(parseAppearance('dark:ab').theme).toBeNull()
    expect(parseAppearance(`dark:${'a'.repeat(33)}`).theme).toBeNull()
  })

  it('treats absent and malformed alike, without guessing', () => {
    expect(parseAppearance(undefined)).toEqual({ mode: null, theme: null })
    expect(parseAppearance('')).toEqual({ mode: null, theme: null })
    expect(parseAppearance('nonsense')).toEqual({ mode: null, theme: null })
  })
})

describe('serialiseAppearance', () => {
  it('round-trips through parse', () => {
    const value = serialiseAppearance({ mode: 'dark', theme: 'slate' })
    expect(parseAppearance(value)).toEqual({ mode: 'dark', theme: 'slate' })
  })

  it('drops a value it would refuse to read back', () => {
    expect(serialiseAppearance({ mode: 'dark', theme: 'NOPE' })).toBe('dark:')
  })
})

describe('readAppearanceCookie', () => {
  it('finds the cookie among others', () => {
    const header = `other=1; ${APPEARANCE_COOKIE}=dark%3Aslate; another=2`
    expect(readAppearanceCookie(header)).toEqual({ mode: 'dark', theme: 'slate' })
  })

  it('is not fooled by a cookie whose name merely ends with ours', () => {
    const header = `not_hp_appearance=light%3Aclaude`
    expect(readAppearanceCookie(header)).toEqual({ mode: null, theme: null })
  })

  it('returns nothing for an absent header', () => {
    expect(readAppearanceCookie(undefined)).toEqual({ mode: null, theme: null })
    expect(readAppearanceCookie('')).toEqual({ mode: null, theme: null })
  })
})

describe('resolveMode', () => {
  it('passes a concrete mode through', () => {
    expect(resolveMode('dark')).toBe('dark')
    expect(resolveMode('light')).toBe('light')
  })

  it('resolves system against the device', () => {
    const original = globalThis.matchMedia
    // @ts-expect-error -- test double
    globalThis.matchMedia = (query: string) => ({ matches: query.includes('dark') })
    try {
      expect(resolveMode('system')).toBe('dark')
    } finally {
      globalThis.matchMedia = original
    }
  })

  it('yields null rather than a guess where matchMedia is unavailable', () => {
    const original = globalThis.matchMedia
    // @ts-expect-error -- test double
    globalThis.matchMedia = undefined
    try {
      expect(resolveMode('system')).toBeNull()
    } finally {
      globalThis.matchMedia = original
    }
  })
})
