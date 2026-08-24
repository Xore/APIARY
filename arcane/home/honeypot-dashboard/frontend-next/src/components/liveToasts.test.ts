// #1900: the toast stopped announcing arriving events and started
// reporting conditions. The two pure functions that decide *what* is wrong
// and *what changed* are the whole behaviour worth pinning -- the rest of
// the component is a poll loop and a list.
import { describe, expect, it } from 'vitest'
import { conditionsFrom, transitions } from './LiveToasts'

const healthy = {
  cluster_status: 'green',
  sensors: [
    { sensor: 'cowrie', state: 'ACTIVE', last_seen: '2026-08-25T00:00:00Z' },
    { sensor: 'dionaea', state: 'QUIET', last_seen: '2026-08-24T23:30:00Z' },
  ],
  ingest: { state: 'healthy', age_seconds: 4 },
  pipeline: { state: 'healthy' },
  dead_letters: 0,
}

describe('conditionsFrom', () => {
  it('says nothing about a healthy fleet', () => {
    // The point of the change. A quiet sensor is not a problem, and a
    // fleet with nothing wrong must produce no toasts at all -- the old
    // behaviour was a notification that never stopped.
    expect(conditionsFrom(healthy)).toEqual([])
  })

  it('names the sensor that stopped reporting', () => {
    const conditions = conditionsFrom({
      ...healthy,
      sensors: [
        { sensor: 'cowrie', state: 'ACTIVE', last_seen: '' },
        { sensor: 'galah', state: 'STALE', last_seen: '' },
      ],
    })
    expect(conditions).toHaveLength(1)
    expect(conditions[0].key).toBe('sensor:galah')
    expect(conditions[0].message).toContain('galah')
  })

  it('treats a stalled ingest as more serious than a delayed one', () => {
    const delayed = conditionsFrom({ ...healthy, ingest: { state: 'delayed' } })
    const stalled = conditionsFrom({ ...healthy, ingest: { state: 'stale' } })
    expect(delayed[0].severity).toBe('warning')
    expect(stalled[0].severity).toBe('danger')
    // Same key either way, so the escalation reads as one condition
    // changing rather than two unrelated alerts.
    expect(delayed[0].key).toBe(stalled[0].key)
  })

  it('reports cluster colour, an unreachable pipeline, and dead letters', () => {
    const conditions = conditionsFrom({
      ...healthy,
      cluster_status: 'RED',
      pipeline: { state: 'unreachable' },
      dead_letters: 3,
    })
    const keys = conditions.map((c) => c.key)
    expect(keys).toContain('cluster')
    expect(keys).toContain('pipeline')
    expect(keys).toContain('dead-letters')
    // Case-insensitive: the endpoint has reported both spellings.
    expect(conditions.find((c) => c.key === 'cluster')?.severity).toBe('danger')
  })

  it('survives a health document with fields missing', () => {
    // A backend mid-deploy can answer with a partial document, and a toast
    // component that throws takes the whole shell down with it.
    expect(conditionsFrom({})).toEqual([])
  })
})

describe('transitions', () => {
  const stale = { key: 'sensor:galah', message: 'galah stopped reporting', severity: 'warning' as const, to: '/source-health' }

  it('raises a condition once, not on every poll', () => {
    const first = transitions(new Map(), [stale])
    expect(first.raised).toHaveLength(1)

    const known = new Map([[stale.key, stale]])
    const second = transitions(known, [stale])
    expect(second.raised).toEqual([])
    expect(second.cleared).toEqual([])
  })

  it('raises again when a condition gets worse', () => {
    const known = new Map([['ingest', { key: 'ingest', message: 'behind', severity: 'warning' as const, to: '/x' }]])
    const worse = { key: 'ingest', message: 'stalled', severity: 'danger' as const, to: '/x' }
    expect(transitions(known, [worse]).raised).toHaveLength(1)
  })

  it('reports a condition clearing', () => {
    const known = new Map([[stale.key, stale]])
    const { raised, cleared } = transitions(known, [])
    expect(raised).toEqual([])
    expect(cleared).toHaveLength(1)
    expect(cleared[0].key).toBe(stale.key)
  })

  it('handles several conditions independently', () => {
    const ingest = { key: 'ingest', message: 'stalled', severity: 'danger' as const, to: '/x' }
    const known = new Map([[stale.key, stale]])
    const { raised, cleared } = transitions(known, [stale, ingest])
    expect(raised.map((c) => c.key)).toEqual(['ingest'])
    expect(cleared).toEqual([])
  })
})
