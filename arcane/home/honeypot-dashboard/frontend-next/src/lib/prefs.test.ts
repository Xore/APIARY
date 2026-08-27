// #1831: the theme switch is entirely a matter of ordering, and every one
// of its steps typechecks identically whether it is right or wrong.
//
// The contract: suppress transitions, change the attributes, force the new
// values to be resolved while suppression is still active, and release on
// the *second* animation frame. Releasing on the first re-enables
// transitions before the new values are painted, which is the original bug
// with extra steps — and looks correct in review.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const SUPPRESS_CLASS = 'hp-theme-switching'

/** Run the queued animation-frame callbacks, one frame at a time. */
function makeFrameQueue() {
  let queue: FrameRequestCallback[] = []
  const raf = ((callback: FrameRequestCallback) => {
    queue.push(callback)
    return queue.length
  }) as typeof requestAnimationFrame
  const flushOneFrame = () => {
    const due = queue
    queue = []
    due.forEach((callback) => callback(0))
  }
  return { raf, flushOneFrame, pending: () => queue.length }
}

describe('applyTheme suppression ordering', () => {
  beforeEach(() => {
    document.documentElement.className = ''
    delete document.documentElement.dataset.theme
    localStorage.clear()
    vi.resetModules()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('still suppresses transitions when applyTheme returns', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    const { applyTheme } = await import('./prefs')

    applyTheme('dark')

    // The attribute is already changed, and suppression is still on: this
    // is the window in which the new values get resolved unanimated.
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(document.documentElement.classList.contains(SUPPRESS_CLASS)).toBe(true)
  })

  it('does not release on the first frame — that is the bug it exists to prevent', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    const { applyTheme } = await import('./prefs')

    applyTheme('dark')
    frames.flushOneFrame()

    expect(document.documentElement.classList.contains(SUPPRESS_CLASS)).toBe(true)
  })

  it('releases on the second frame', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    const { applyTheme } = await import('./prefs')

    applyTheme('dark')
    frames.flushOneFrame()
    frames.flushOneFrame()

    expect(document.documentElement.classList.contains(SUPPRESS_CLASS)).toBe(false)
  })

  it('releases synchronously where requestAnimationFrame does not exist', async () => {
    // Without this fallback the class is added and never removed, leaving
    // every transition in the application suppressed for the rest of the
    // session — a worse failure than the one being fixed, and one no type
    // can see.
    vi.stubGlobal('requestAnimationFrame', undefined)
    const { applyTheme } = await import('./prefs')

    applyTheme('dark')

    expect(document.documentElement.classList.contains(SUPPRESS_CLASS)).toBe(false)
    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('clearing back to system removes the attribute rather than blanking it', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    const { applyTheme } = await import('./prefs')

    applyTheme('dark')
    applyTheme('system')

    // An empty data-theme is not the same as an absent one: the stylesheet
    // distinguishes "explicitly light" from "follow the OS" by presence.
    expect('theme' in document.documentElement.dataset).toBe(false)
    expect(localStorage.getItem('hp-theme')).toBeNull()
  })
})

// #2138: appearance crosses tabs through localStorage alone — the appliers
// have always written hp-theme / hp-palette through to disk — so live sync
// is exactly the question of whether the receiving tab reacts to the storage
// event. These simulate another tab writing the keys by hand, which is all
// a real second tab does that a reloading tab would replay anyway.
//
// The listener is armed lazily like every other appearance plumbing here:
// void pullAppearance() runs its registration line synchronously (its
// server round-trip is irrelevant and best-effort), so these tests arm it
// the same way the root route's mount effect arms it in the app.
describe('cross-tab appearance propagation (#2138)', () => {
  beforeEach(() => {
    document.documentElement.className = ''
    delete document.documentElement.dataset.theme
    document.documentElement.removeAttribute('data-hp-theme')
    document.documentElement.removeAttribute('data-hp-palette')
    localStorage.clear()
    vi.resetModules()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  const arm = async () => {
    const prefs = await import('./prefs')
    void prefs.pullAppearance()
    return prefs
  }

  const fromAnotherTab = (key: string | null, newValue: string | null) => {
    window.dispatchEvent(new StorageEvent('storage', { key, newValue }))
  }

  it('applies an hp-theme flip from another tab live', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    await arm()

    fromAnotherTab('hp-theme', 'light')

    expect(document.documentElement.dataset.theme).toBe('light')
    expect(localStorage.getItem('hp-theme')).toBe('light')
  })

  it('treats a removed hp-theme key as back-to-system, not as a stale explicit value', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    const { applyTheme } = await import('./prefs')
    applyTheme('dark')
    await arm()

    // The reset case: the originating tab deleted the key entirely.
    fromAnotherTab('hp-theme', null)

    expect('theme' in document.documentElement.dataset).toBe(false)
    expect(localStorage.getItem('hp-theme')).toBeNull()
  })

  it('reads an unrecognized hp-theme value as system, mirroring the saved-value readers', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    await arm()

    fromAnotherTab('hp-theme', 'neon-flux')

    // The boot script ignores values that are not light/dark; reacting to
    // one by applying it would desync from every reload.
    expect('theme' in document.documentElement.dataset).toBe(false)
  })

  it('applies an hp-palette pick from another tab live', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    await arm()

    fromAnotherTab('hp-palette', 'slate')

    expect(document.documentElement.dataset.hpTheme).toBe('slate')
    expect(document.documentElement.dataset.hpPalette).toBe('slate')
    expect(localStorage.getItem('hp-palette')).toBe('slate')
  })

  it('treats a removed hp-palette key as back-to-default', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    const { applyPalette } = await import('./prefs')
    applyPalette('slate')
    await arm()

    fromAnotherTab('hp-palette', null)

    expect(document.documentElement.dataset.hpTheme).toBe('claude')
    expect(document.documentElement.dataset.hpPalette).toBe('claude')
  })

  it('reads a whole-area clear as a reset of both axes together', async () => {
    // localStorage.clear() arrives as one event with key:null — the appliers
    // never write that way, so it can only mean an outside hand wiped the
    // keys; both axes fall back together rather than leaving the last theme
    // riding on default mode.
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    const { applyTheme, applyPalette } = await import('./prefs')
    applyTheme('dark')
    applyPalette('slate')
    await arm()

    fromAnotherTab(null, null)

    expect('theme' in document.documentElement.dataset).toBe(false)
    expect(document.documentElement.dataset.hpTheme).toBe('claude')
    expect(document.documentElement.dataset.hpPalette).toBe('claude')
  })

  it('ignores a malformed hp-palette value exactly like the gallery toggle path does', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    const { applyPalette } = await import('./prefs')
    applyPalette('slate')
    await arm()

    fromAnotherTab('hp-palette', 'Not A Theme Name!')

    expect(document.documentElement.dataset.hpTheme).toBe('slate')
  })

  it('leaves the appearance alone when an unrelated key changes', async () => {
    const frames = makeFrameQueue()
    vi.stubGlobal('requestAnimationFrame', frames.raf)
    await arm()

    fromAnotherTab('hp-map-center', '42,42')

    expect('theme' in document.documentElement.dataset).toBe(false)
    expect(document.documentElement.dataset.hpTheme).toBeUndefined()
  })
})
