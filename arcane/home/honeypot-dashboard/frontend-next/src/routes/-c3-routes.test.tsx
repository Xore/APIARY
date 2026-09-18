import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { expect, it, vi } from 'vitest'

const fixture = vi.hoisted(() => ({ cidr: '203.0.113.0/24', first: Promise.resolve(null) as Promise<unknown> }))
vi.mock('@tanstack/react-router', () => ({
  Link: ({ to, search, children, ...props }: { to: string; search?: Record<string, string>; children: React.ReactNode }) =>
    <a href={`${to}${search ? `?${new URLSearchParams(search)}` : ''}`} {...props}>{children}</a>,
  createFileRoute: () => (config: Record<string, unknown>) => ({
    ...config, useParams: () => ({ cidr: fixture.cidr }), useLoaderData: () => ({ first: fixture.first }),
  }),
}))
vi.mock('@tanstack/react-start', () => ({ createServerFn: () => ({ validator() { return this }, handler: (fn: unknown) => fn }) }))
vi.mock('../components/Investigate', () => ({
  InvestigateHeader: ({ title, chips }: { title: string; chips: React.ReactNode }) => <header><h1>{title}</h1>{chips}</header>,
  MasterDetailTable: ({ rows, columns }: { rows: { sensor: string }[] | null; columns: { header: string; render: (row: { sensor: string }) => React.ReactNode }[] }) =>
    <div aria-label="Correlation records">{rows?.map((row, index) => <div key={index}>{columns.find(column => column.header === 'sensor')?.render(row)}</div>)}</div>,
}))

import { Route } from './investigate.cidr.$cidr'

async function mount() {
  const previous = (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  const host = document.createElement('div')
  document.body.append(host)
  const root = createRoot(host)
  const Component = (Route as unknown as { component: React.ComponentType }).component
  await act(async () => root.render(<Component />))
  return { host, cleanup: async () => {
    await act(async () => root.unmount())
    host.remove()
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = previous
  } }
}

it('shows the loading state then backend-shaped CIDR correlation with shadcn cards, table and pivots', async () => {
  let resolve!: (value: unknown) => void
  fixture.first = new Promise(done => { resolve = done })
  const view = await mount()
  try {
    expect(view.host.querySelector('[aria-label="Loading CIDR correlation"]')).toBeTruthy()
    await act(async () => resolve({ cidr: fixture.cidr, correlation: {
      total: 12, truncated: true, tunnel_connections: 3, tunnel_os_guesses: ['Linux (fixture)'],
      sensors: [{ key: 'cowrie', count: 9 }, { key: 'portbridge', count: 3 }],
      records: [{ time: '2026-09-18T10:00:00Z', sensor: 'cowrie', src_ip: '203.0.113.7', country: 'US', port: '22', proto: 'ssh', detail: 'login', session: 'sess-0', record: { 'event.sensor': 'cowrie' } }],
    } }))
    expect(view.host.querySelector('[aria-label="Loading CIDR correlation"]')).toBeNull()
    expect(view.host.querySelector('h1')?.textContent).toBe(fixture.cidr)
    expect(Array.from(view.host.querySelectorAll('h2')).map(node => node.textContent)).toEqual(['Total matches', 'Tunnel connections', 'Distinct sensors', 'Sensors'])
    expect(view.host.textContent).toContain('Showing the 1 most recent of 12 total matches.')
    expect(view.host.textContent).toContain('Linux (fixture)')
    expect(view.host.querySelectorAll('table tbody tr')).toHaveLength(2)
    expect(view.host.querySelector('[aria-label="Correlation records"]')?.textContent).toContain('cowrie')
    expect(view.host.querySelector('a[href="/campaigns"]')).toBeTruthy()
    expect(view.host.querySelector('a[href="/events?ip=203.0.113.0%2F24&since=168h"]')).toBeTruthy()
  } finally { await view.cleanup() }
})

it('retains the unavailable-range header without showing stale correlation data', async () => {
  fixture.first = Promise.resolve(null)
  const view = await mount()
  try {
    expect(view.host.querySelector('h1')?.textContent).toBe(fixture.cidr)
    expect(view.host.querySelector('[aria-label="Correlation records"]')).toBeNull()
    expect(view.host.querySelector('a[href="/campaigns"]')).toBeTruthy()
  } finally { await view.cleanup() }
})
