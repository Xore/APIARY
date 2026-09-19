import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { expect, it, vi } from 'vitest'
import { Button } from '../components/ui/button'

// A route callback can dynamically import the real backend module despite the module mock.
// Keep its boot policy in the sanctioned dev mode for this isolated fixture suite.
vi.hoisted(() => { process.env.APIARY_ALLOW_UNAUTH_DEV = '1' })

const fixture = vi.hoisted(() => ({ params: {} as Record<string, string>, data: {} as Record<string, unknown>, navigate: vi.fn() }))
vi.mock('@tanstack/react-router', () => ({
  Link: 'a', useNavigate: () => fixture.navigate,
  createFileRoute: () => (config: Record<string, unknown>) => ({ ...config, useParams: () => fixture.params, useLoaderData: () => fixture.data }),
}))
vi.mock('@tanstack/react-start', () => ({ createServerFn: () => ({ validator() { return this }, handler: (fn: Function) => {
  // Workbench mounts also load owner-scoped recipes/runs. Stub those GETs at
  // the server-function seam: dynamic auth imports cannot use a Vitest request.
  const source = fn.toString()
  if (source.includes('/api/v1/workbench/recipes')) return async () => ({ recipes: [] })
  if (source.includes('/api/v1/workbench/runs')) return async () => ({ runs: [] })
  return fn
} }) }))
vi.mock('../lib/auth', () => ({ getSessionUser: async () => ({ username: 'operator', role: 'admin' }) }))
vi.mock('../lib/backend.server', () => ({
  serviceJSON: async (path: string) => path.includes('/ml-health') || path.includes('/gpu-queue') ? [] : ({ rows: [], total: 0, recipes: [], runs: [], sensors: [] }),
  serviceJSONResult: async () => ({ ok: false, status: 404 }),
}))
vi.mock('../lib/viewTabs', () => ({ useSidebarViewTabs: ({ tabs, onSelect }: { tabs: { id: string; label: string }[]; onSelect: (id: string) => void }) => <nav aria-label="View tabs">{tabs.map(tab => <Button variant="ghost" size="sm" key={tab.id} type="button" onClick={() => onSelect(tab.id)}>{tab.label}</Button>)}</nav> }))
vi.mock('../components/Investigate', () => ({
  InvestigateHeader: ({ title, chips }: { title: string; chips?: React.ReactNode }) => <header><h1>{title}</h1>{chips}</header>,
  MasterDetailTable: ({ rows }: { rows: unknown[] | null }) => <div data-testid="events">{rows?.length ?? 'loading'}</div>,
}))
vi.mock('../components/SensorEvents', () => ({ SensorEventsTable: ({ rows }: { rows: unknown[] | null }) => <div data-testid="sensor-events">{rows?.length ?? 'loading'}</div> }))
vi.mock('../components/CuratedSensorViews', () => ({ hasCuratedView: () => false, CuratedSensorView: () => null }))

import { Route as Sensor } from './sensors.$sensor'
import { Route as Session } from './sessions.$id'
import { Route as Payload } from './payload-analysis.$hash'
import { Route as Workbench } from './payload-workbench.results'

async function mount(route: { component: React.ComponentType }) {
  const previous = (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  const host = document.createElement('div')
  document.body.append(host)
  const root = createRoot(host)
  await act(async () => root.render(<route.component />))
  return { host, cleanup: async () => { await act(async () => root.unmount()); host.remove(); (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = previous } }
}

it('sensor displays loaded leaderboards and navigates from its source address', async () => {
  fixture.params = { sensor: 'citrix' }
  fixture.data = { overview: Promise.resolve({ sensor: 'citrix', events: 4, unique_sources: 1, first_seen: '', last_seen: '', hourly: [4], top_sources: [{ key: '203.0.113.7', count: 4 }], top_countries: [], top_lists: [], measures: [] }), events: Promise.resolve({ total: 1, rows: [{ id: 'one', when: '', src_ip: '203.0.113.7', fields: {} }] }), catalog: Promise.resolve({ sensors: [{ sensor: 'citrix', events: 4, last_seen: '' }] }) }
  const view = await mount(Sensor as any)
  try { expect(view.host.querySelector('h2')?.textContent).toBe('Activity'); expect(view.host.textContent).toContain('Who reached it'); expect(view.host.querySelector('a[href="/investigate/ip/203.0.113.7"]')).toBeTruthy(); expect(view.host.querySelector('[data-testid="sensor-events"]')?.textContent).toBe('1') } finally { await view.cleanup() }
})

it('session displays loaded ATT&CK evidence and export pivot', async () => {
  fixture.params = { id: 'sess-0' }
  fixture.data = { first: Promise.resolve({ state: 'session', session: { id: 'sess-0', ip: '203.0.113.7', country: 'CN', first: '', last: '', total: 1, sensors: [{ key: 'citrix', count: 1 }], commands: [], credentials: [], payloads: [], techniques: [{ id: 'T1110', name: 'Brute Force', domain: 'Enterprise', count: 1, evidence: 'login', url: 'https://attack.mitre.org/techniques/T1110/' }], sequences: [], events: [] } }) }
  const view = await mount(Session as any)
  try { expect(Array.from(view.host.querySelectorAll('h2')).some(heading => heading.textContent === 'MITRE ATT&CK behavior mapping')).toBe(true); expect(view.host.textContent).toContain('Brute Force'); expect(view.host.querySelector('a[href="/api/export/events.csv?session=sess-0"]')).toBeTruthy() } finally { await view.cleanup() }
})

it('payload displays loaded static findings with an accessible findings tab', async () => {
  const hash = 'a'.repeat(64)
  fixture.params = { hash }
  const classification = { Code: 'script', Label: 'Shell script', Platform: 'linux', Category: 'script', AnalysisPath: 'static', Dynamic: false }
  fixture.data = { first: Promise.resolve({ state: 'detail', detail: { hash, inventory: { Kind: 'script' }, analysis: { Analysis: { Classification: classification, Rules: [{ name: 'FixtureRule', severity: 'medium', description: 'signature' }] } }, yara: [], size_bytes: 1024, hex_preview: [] } }), golden: Promise.resolve({ state: 'status', status: { configured: false } }), user: { role: 'admin' } }
  const view = await mount(Payload as any)
  try { expect((await (fixture.data.first as Promise<{ detail: { analysis: { Analysis: { Classification: typeof classification } } } }>)).detail.analysis.Analysis.Classification.Label).toBe('Shell script'); expect(view.host.textContent).toContain('Shell script'); expect(Array.from(view.host.querySelectorAll('h2')).some(heading => heading.textContent === 'Operator actions')).toBe(true); expect(view.host.querySelector('#pl-tab-findings')?.getAttribute('aria-controls')).toBe('pl-panel-findings'); expect(view.host.textContent).toContain('FixtureRule') } finally { await view.cleanup() }
})

it('workbench shows a loaded static result after switching view', async () => {
  fixture.params = {}
  fixture.data = { workbench: Promise.resolve({ total: 0, rows: [] }), statics: Promise.resolve({ total: 1, rows: [{ Fingerprint: 'a'.repeat(64), Analysis: { Kind: 'script', Summary: 'Shell script' } }] }), yara: Promise.resolve({ total: 0, rows: [] }), sandbox: Promise.resolve({ total: 0, rows: [] }), ghidra: Promise.resolve({ total: 0, rows: [] }), gpuQueue: Promise.resolve([]), user: { username: 'operator', role: 'admin' } }
  const view = await mount(Workbench as any)
  try {
    expect(view.host.textContent).toContain('1 static analyses')
    expect(Array.from(view.host.querySelectorAll('h2')).some(heading => heading.textContent === 'Start a new analysis')).toBe(true)
    await act(async () => view.host.querySelectorAll<HTMLButtonElement>('nav[aria-label="View tabs"] button')[1].click())
    expect(view.host.querySelector('#wb-panel-static')?.hasAttribute('hidden')).toBe(false)
    expect(view.host.querySelector('input[aria-label="Filter static analyses"]')).toBeTruthy()
  } finally { await view.cleanup() }
})
