import { describe, expect, it } from 'vitest'
import { collapseRuns, foldedCount, idsFor } from './mlGrouping'
import type { StoreRow } from '../components/StoreList'

function row(id: string, ip: string, ts: string, score: number): StoreRow {
  return { _doc_id: id, src_ip: ip, '@timestamp': ts, composite_score: score }
}

describe('collapseRuns', () => {
  it('folds a burst from one address in one second into a single row', () => {
    // The measured shape of the bug: 48 rows for one IP inside one second,
    // every one scoring exactly 0.8000.
    const burst = Array.from({ length: 48 }, (_, i) =>
      row(`d${i}`, '153.75.87.176', `2026-08-24T20:59:23.${String(i).padStart(3, '0')}Z`, 0.8),
    )
    const out = collapseRuns(burst)
    expect(out).toHaveLength(1)
    expect(foldedCount(out[0])).toBe(48)
    expect(idsFor(out[0])).toHaveLength(48)
  })

  it('keeps different addresses apart even in the same second', () => {
    const out = collapseRuns([
      row('a', '1.1.1.1', '2026-08-24T20:59:23.100Z', 0.8),
      row('b', '2.2.2.2', '2026-08-24T20:59:23.200Z', 0.8),
    ])
    expect(out).toHaveLength(2)
  })

  it('keeps different seconds apart even from the same address', () => {
    const out = collapseRuns([
      row('a', '1.1.1.1', '2026-08-24T20:59:23.900Z', 0.8),
      row('b', '1.1.1.1', '2026-08-24T20:59:24.000Z', 0.8),
    ])
    expect(out).toHaveLength(2)
  })

  it('keeps materially different scores apart', () => {
    const out = collapseRuns([
      row('a', '1.1.1.1', '2026-08-24T20:59:23.100Z', 0.8),
      row('b', '1.1.1.1', '2026-08-24T20:59:23.200Z', 0.95),
    ])
    expect(out).toHaveLength(2)
  })

  it('does not chain a drift into one arbitrarily wide group', () => {
    // Each row is within the epsilon of the one before it, but the run spans
    // 0.05 end to end. Comparing against the representative rather than the
    // predecessor is what stops that becoming a single "group".
    const drift = Array.from({ length: 6 }, (_, i) =>
      row(`d${i}`, '1.1.1.1', '2026-08-24T20:59:23.100Z', 0.8 + i * 0.009),
    )
    const out = collapseRuns(drift)
    expect(out.length).toBeGreaterThan(1)
  })

  it('only folds rows that are actually adjacent', () => {
    // A lookalike separated by an unrelated row is a different moment, and
    // is left alone rather than reached across for.
    const out = collapseRuns([
      row('a', '1.1.1.1', '2026-08-24T20:59:23.100Z', 0.8),
      row('x', '9.9.9.9', '2026-08-24T20:59:23.150Z', 0.4),
      row('b', '1.1.1.1', '2026-08-24T20:59:23.200Z', 0.8),
    ])
    expect(out).toHaveLength(3)
  })

  it('never folds a row that has no score', () => {
    const out = collapseRuns([
      { _doc_id: 'a', src_ip: '1.1.1.1', '@timestamp': '2026-08-24T20:59:23.100Z' },
      { _doc_id: 'b', src_ip: '1.1.1.1', '@timestamp': '2026-08-24T20:59:23.200Z' },
    ])
    expect(out).toHaveLength(2)
  })

  it('leaves an ungrouped row reporting itself, so callers need no special case', () => {
    const out = collapseRuns([row('a', '1.1.1.1', '2026-08-24T20:59:23.100Z', 0.8)])
    expect(foldedCount(out[0])).toBe(1)
    expect(idsFor(out[0])).toEqual(['a'])
  })

  it('does not mutate the rows it was given', () => {
    const input = [
      row('a', '1.1.1.1', '2026-08-24T20:59:23.100Z', 0.8),
      row('b', '1.1.1.1', '2026-08-24T20:59:23.200Z', 0.8),
    ]
    const snapshot = JSON.parse(JSON.stringify(input))
    collapseRuns(input)
    expect(input).toEqual(snapshot)
  })

  it('handles an empty page', () => {
    expect(collapseRuns([])).toEqual([])
  })
})
