// Zoom arithmetic for EChart's zoomable wrapper (#2130): the topology
// page's sankey drew the whole ingestion DAG at a fixed size with no way
// to magnify or move anything, so the middle stages collapsed into an
// unreadable knot. Pure module so the clamp/step rules are unit-tested
// separately from the component that applies them.

export const MIN_ZOOM = 1
export const MAX_ZOOM = 3

const STEP = 1.2

/**
 * One multiplicative zoom step. 1 is "fits the card" — there is nothing to
 * gain from shrinking an already-fitting diagram below its natural size,
 * and pan UI (native scrollbars) only exists once content overflows, so
 * sub-1 zoom would strand the reader. Rounding keeps repeated steps away
 * from float drift like 1.7279999999999998.
 */
export function stepZoom(current: number, direction: 1 | -1): number {
  const raw = current * (direction === 1 ? STEP : 1 / STEP)
  const rounded = Math.round(raw * 100) / 100
  return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, rounded))
}

/** Wheel deltas vary by device/platform; only the sign is meaningful. */
export function zoomFromWheel(current: number, deltaY: number, deltaMode = 0): number {
  if (!Number.isFinite(deltaY)) return current
  return stepZoom(current, deltaY < 0 ? 1 : -1)
}
