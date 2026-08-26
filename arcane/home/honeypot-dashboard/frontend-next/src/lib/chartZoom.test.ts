import { describe, expect, it } from 'vitest'
import { MAX_ZOOM, MIN_ZOOM, stepZoom, zoomFromWheel } from './chartZoom'

describe('stepZoom', () => {
  it('steps up and down multiplicatively', () => {
    expect(stepZoom(1, 1)).toBeCloseTo(1.2)
    expect(stepZoom(1.2, -1)).toBeCloseTo(1)
  })

  it('never leaves the useful range', () => {
    // Zooming out below "fits the card" has nothing to offer — the diagram
    // already fits at 1, and the pan affordance (scrollbars) only exists
    // once content overflows. Zooming in is bounded where pixels stop
    // buying legibility.
    let z = 1
    for (let i = 0; i < 20; i++) z = stepZoom(z, 1)
    expect(z).toBe(MAX_ZOOM)
    expect(MAX_ZOOM).toBeGreaterThan(MIN_ZOOM)

    z = MAX_ZOOM
    for (let i = 0; i < 20; i++) z = stepZoom(z, -1)
    expect(z).toBe(MIN_ZOOM)
  })

  it('does not accumulate float drift over repeated steps', () => {
    // 1.2 * 1.2 * ... / 1.2 / ... must land back on exactly 1, or the
    // reset button becomes a lie after enough round trips.
    let z = 1
    for (let i = 0; i < 4; i++) z = stepZoom(z, 1)
    for (let i = 0; i < 4; i++) z = stepZoom(z, -1)
    expect(z).toBe(1)
  })
})

describe('zoomFromWheel', () => {
  it('reads direction from the delta sign, not magnitude', () => {
    // Trackpads emit small deltas, mouse wheels large ones; line-mode
    // deltas differ again. Only the sign carries intent.
    expect(zoomFromWheel(1.5, -3)).toBeGreaterThan(1.5)
    expect(zoomFromWheel(1.5, -120)).toBeGreaterThan(1.5)
    expect(zoomFromWheel(1.5, 120)).toBeLessThan(1.5)
  })

  it('ignores non-finite deltas instead of poisoning the zoom state', () => {
    expect(zoomFromWheel(1.5, Number.NaN)).toBe(1.5)
  })
})
