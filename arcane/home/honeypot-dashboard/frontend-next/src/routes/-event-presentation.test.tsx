import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { expect, it, vi } from 'vitest'

const event = {
  id: 'sample-event', index: 'events', time: '2026-09-18T10:00:00Z', sensor: 'cowrie',
  src_ip: '192.0.2.1', session: 'session-1', community_id: 'flow-1', hashes: ['abc'],
  record: { honeypot: { message: 'captured session' } },
  session_events: {
    key: 'session-1', total: 2,
    rows: [
      { time: '2026-09-18T10:00:00Z', sensor: 'cowrie', src_ip: '192.0.2.1', detail: 'login' },
      { time: '2026-09-18T10:01:00Z', sensor: 'dionaea', src_ip: '192.0.2.1', detail: 'payload' },
    ],
  },
  flow_events: { key: '', total: 0, rows: [] },
  source_events: { key: '', total: 0, rows: [] },
  flow_link: {
    community_id: 'flow-1', families: ['ssh', 'malware'], sensors: ['cowrie', 'dionaea'],
    src_ip: '192.0.2.1', dst_ip: '192.0.2.2', dst_port: 22,
    first: '2026-09-18T10:00:00Z', last: '2026-09-18T10:01:00Z', events: 2, event_ids: [],
  },
}
const first = Promise.resolve({ state: 'event', event })

vi.mock('@tanstack/react-router', () => ({
  Link: 'a',
  createFileRoute: () => (config: any) => ({
    ...config, useParams: () => ({ id: 'sample-event' }),
    useLoaderData: () => ({ first }),
  }),
}))
vi.mock('@tanstack/react-start', () => ({ createServerFn: () => ({ validator() { return this }, handler: (fn: any) => fn }) }))

import { Route } from './event.$id'

it('renders cross-family badges outside paragraphs, sensor tones, and serif card headings', async () => {
  const prior = (globalThis as any).IS_REACT_ACT_ENVIRONMENT
  ;(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true
  const host = document.createElement('div')
  document.body.append(host)
  const root = createRoot(host)
  const Component = (Route as any).component
  try {
    await act(async () => root.render(<Component />))
    const familyBadges = ['ssh', 'malware'].map((family) =>
      [...host.querySelectorAll('div')].find((node) => node.textContent === family && node.classList.contains('inline-flex')),
    )
    expect(familyBadges.every(Boolean)).toBe(true)
    for (const badge of familyBadges) expect(badge?.closest('p')).toBeNull()

    for (const sensor of ['cowrie', 'dionaea']) {
      const badge = host.querySelector(`td .b-${sensor}`)
      expect(badge?.textContent).toBe(sensor)
      expect(badge?.classList.contains('badge')).toBe(true)
    }
    const headings = [...host.querySelectorAll('h2')]
    expect(headings.map((heading) => heading.textContent)).toEqual([
      'What this event is', 'What the sensor captured', 'Hashes in this event',
      'The rest of this session', 'Same connection, seen by 2 pipelines', 'The complete record',
    ])
    for (const heading of headings) {
      expect(heading.classList.contains('font-serif')).toBe(true)
      expect(heading.classList.contains('font-medium')).toBe(true)
    }
  } finally {
    await act(async () => root.unmount())
    host.remove()
    ;(globalThis as any).IS_REACT_ACT_ENVIRONMENT = prior
  }
})
