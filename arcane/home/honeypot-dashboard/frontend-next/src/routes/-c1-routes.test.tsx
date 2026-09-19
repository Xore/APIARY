import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { expect, it, vi } from 'vitest'

const fixture = vi.hoisted(() => ({ navigate: vi.fn(async () => {}), query: 'initial', first: Promise.resolve(null) as Promise<unknown> }))
vi.mock('@tanstack/react-router', () => ({
  Link: 'a',
  useNavigate: () => fixture.navigate,
  createFileRoute: () => (config: Record<string, unknown>) => ({
    ...config,
    useSearch: () => ({ q: fixture.query, kind: 'asn', value: 'AS64500' }),
    useLoaderData: () => ({ first: fixture.first }),
    useNavigate: () => fixture.navigate,
  }),
}))
vi.mock('@tanstack/react-start', () => ({ createServerFn: () => ({ validator() { return this }, handler: (fn: unknown) => fn }) }))
vi.mock('../components/Investigate', () => ({
  InvestigateHeader: ({ title }: { title: string }) => <h1>{title}</h1>,
  MasterDetailTable: () => <div aria-label="Correlation records" />,
}))

import { Route as LookupRoute } from './investigate.lookup'
import { Route as ClusterRoute } from './investigate.cluster'
import { Route as SearchRoute } from './search'

async function mount(Route: { component: React.ComponentType }) {
  const prior = (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  const host = document.createElement('div')
  document.body.append(host)
  const root = createRoot(host)
  await act(async () => root.render(<Route.component />))
  return { host, cleanup: async () => {
    await act(async () => root.unmount())
    host.remove()
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = prior
  } }
}

async function typeInto(input: HTMLInputElement, value: string) {
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, value)
    input.dispatchEvent(new Event('input', { bubbles: true }))
  })
}

it('lookup renders a labelled input and routes typed IPs on submit', async () => {
  fixture.navigate.mockClear()
  const view = await mount(LookupRoute as any)
  try {
    const input = view.host.querySelector<HTMLInputElement>('#ioc-value')!
    expect(input).toBeTruthy()
    expect(view.host.querySelector('label[for="ioc-value"]')?.textContent).toBe('Value to look up')
    expect(view.host.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled).toBe(true)
    await typeInto(input, '203.0.113.7')
    await act(async () => view.host.querySelector<HTMLFormElement>('form')!.requestSubmit())
    expect(fixture.navigate).toHaveBeenCalledWith({ to: '/investigate/ip/$ip', params: { ip: '203.0.113.7' } })
  } finally { await view.cleanup() }
})

it('search renders a skeleton then submits a trimmed query into URL state', async () => {
  fixture.navigate.mockClear()
  fixture.first = new Promise(() => {})
  const view = await mount(SearchRoute as any)
  try {
    expect(view.host.querySelector('[aria-label="Loading search results"]')).toBeTruthy()
    await typeInto(view.host.querySelector<HTMLInputElement>('#search-query')!, '  sensor  ')
    await act(async () => view.host.querySelector<HTMLFormElement>('form')!.requestSubmit())
    expect(fixture.navigate).toHaveBeenCalledWith({ search: { q: 'sensor' } })
  } finally { await view.cleanup() }
})

it('cluster renders loading chrome and replaces it with correlated data', async () => {
  let resolve!: (value: unknown) => void
  fixture.first = new Promise((done) => { resolve = done })
  const view = await mount(ClusterRoute as any)
  try {
    expect(view.host.querySelector('[aria-label="Loading cluster correlation"]')).toBeTruthy()
    await act(async () => resolve({ ip_count: 3, correlation: { total: 5, tunnel_connections: 1, tunnel_os_guesses: [], sensors: [], records: [], truncated: false } }))
    expect(view.host.textContent).toContain('Member IPs')
    expect(view.host.querySelector('[aria-label="Loading cluster correlation"]')).toBeNull()
  } finally { await view.cleanup() }
})
