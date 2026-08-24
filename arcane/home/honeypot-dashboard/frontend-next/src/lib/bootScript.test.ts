// #1831: the pre-hydration boot script, checked by running the string that
// actually ships.
//
// This is the only code in the tier that runs before hydration, it is
// stored as a string literal inside __root.tsx, and nothing typechecks a
// string. Its job is to stamp the stored theme onto <html> before first
// paint so a cold load does not flash the default ground.
//
// The string is extracted from the route file rather than copied here. A
// copy would keep passing while the shipped one rotted, which is the
// failure mode a test like this exists to prevent — the same reasoning as
// the projection test in zeek_proxy_attribution.rs.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { beforeEach, describe, expect, it } from 'vitest'

function shippedBootScript(): string {
  const source = readFileSync(join(__dirname, '..', 'routes', '__root.tsx'), 'utf8')
  // The script is a single-quoted literal beginning with an IIFE.
  const match = source.match(/'(\(function\(\)\{try\{var d=document\.documentElement;[\s\S]*?)',/)
  if (!match) {
    throw new Error(
      'could not find the pre-hydration boot script in __root.tsx — if it moved or changed shape, this test must follow it rather than be deleted',
    )
  }
  return match[1]
}

function runBoot() {
  // eslint-disable-next-line no-new-func
  new Function(shippedBootScript())()
}

describe('the pre-hydration boot script', () => {
  beforeEach(() => {
    document.documentElement.removeAttribute('data-theme')
    document.documentElement.removeAttribute('data-hp-theme')
    document.documentElement.removeAttribute('data-hp-palette')
    localStorage.clear()
  })

  it('is present in the shipped route file', () => {
    expect(shippedBootScript()).toContain('localStorage.getItem("hp-theme")')
  })

  it('stamps a stored mode before hydration', () => {
    localStorage.setItem('hp-theme', 'dark')
    runBoot()
    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('stamps a stored palette onto both attributes upstream reads', () => {
    localStorage.setItem('hp-palette', 'slate')
    runBoot()
    expect(document.documentElement.dataset.hpTheme).toBe('slate')
    expect(document.documentElement.dataset.hpPalette).toBe('slate')
  })

  it('ignores a mode it does not recognise instead of stamping it', () => {
    localStorage.setItem('hp-theme', 'chartreuse')
    runBoot()
    expect('theme' in document.documentElement.dataset).toBe(false)
  })

  it('ignores a palette that fails the name shape', () => {
    // Attacker-shaped values reach this through localStorage on a shared
    // machine, and the value goes straight into an attribute selector.
    localStorage.setItem('hp-palette', '"><script>x</script>')
    runBoot()
    expect('hpTheme' in document.documentElement.dataset).toBe(false)
  })

  it('never destroys a stored value it declined to apply', () => {
    // Degrading must not be destructive: a rejected value stays, so a
    // later version that understands it can still use it.
    localStorage.setItem('hp-theme', 'chartreuse')
    localStorage.setItem('hp-palette', 'UPPERCASE')
    runBoot()
    expect(localStorage.getItem('hp-theme')).toBe('chartreuse')
    expect(localStorage.getItem('hp-palette')).toBe('UPPERCASE')
  })

  it('does nothing at all when storage throws', () => {
    const original = Object.getOwnPropertyDescriptor(window, 'localStorage')
    Object.defineProperty(window, 'localStorage', {
      configurable: true,
      get() {
        throw new Error('storage disabled')
      },
    })
    try {
      expect(() => runBoot()).not.toThrow()
      expect('theme' in document.documentElement.dataset).toBe(false)
    } finally {
      if (original) Object.defineProperty(window, 'localStorage', original)
    }
  })
})
