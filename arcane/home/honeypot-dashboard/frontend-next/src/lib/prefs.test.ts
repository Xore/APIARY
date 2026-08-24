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
