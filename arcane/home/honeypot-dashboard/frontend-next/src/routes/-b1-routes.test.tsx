import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { expect, it, vi } from 'vitest'

const fixtures = vi.hoisted(() => ({
  loaders: {} as Record<string, Record<string, unknown>>,
  responses: {} as Record<string, unknown>,
}))
vi.mock('@tanstack/react-router', () => ({
  Link: ({ to, children, ...props }: { to: string; children: React.ReactNode }) => <a href={to} {...props}>{children}</a>,
  useRouter: () => ({ invalidate: vi.fn() }),
  createFileRoute: (path: string) => (config: Record<string, unknown>) => ({ ...config, useLoaderData: () => fixtures.loaders[path] }),
}))
// Route GET functions are exercised through their real components; the
// network seam is replaced here because dynamic .server imports execute in a
// separate Vitest module graph and otherwise attempt to boot the BFF.
vi.mock('@tanstack/react-start', () => ({ createServerFn: ({ method }: { method: string }) => ({ validator() { return this }, handler: (fn: Function) => method === 'POST' ? fn : () => {
  const source = fn.toString()
  const path = source.includes('/api/v1/store/dead-letters') ? '/api/v1/store/dead-letters'
    : source.includes('/api/v1/canarytokens') ? '/api/v1/canarytokens'
    : '/api/v1/credentials'
  return Promise.resolve(path === '/api/v1/canarytokens' ? (fixtures.responses[path] as { tokens: unknown[] })?.tokens ?? [] : fixtures.responses[path] ?? null)
} }) }))
vi.mock('../lib/live', () => ({ useLiveInterval: () => undefined }))
vi.mock('../components/Investigate', () => ({
  InvestigateHeader: ({ title, chips }: { title: string; chips: React.ReactNode }) => <header><h1>{title}</h1>{chips}</header>,
  MasterDetailTable: ({ rows, columns, emptyState }: { rows: Record<string, unknown>[] | null; columns: { header: string; detail?: boolean; render: (row: Record<string, unknown>) => React.ReactNode }[]; emptyState?: { title: string } }) =>
    <section aria-label="Loaded records">{rows?.length === 0 ? <p>{emptyState?.title}</p> : rows?.map((row, i) => <div key={i}>{columns.filter(c => !c.detail).map((c, j) => <span key={j}>{c.render(row)}</span>)}</div>)}</section>,
}))

import { Route as Credentials } from './credentials'
import { Route as DeadLetters } from './dead-letters'
import { Route as Commands } from './commands'
import { Route as History } from './history'
import { Route as SourceHealth } from './source-health'

const event = { time: '2026-08-26T12:00:00Z', sensor: 'cowrie', src_ip: '203.0.113.7', country: 'CN', port: '22', proto: 'ssh', detail: 'login attempt root/admin', session: 'sess-0', record: { honeypot: { input: 'uname -a' } } }
const credential = { id: 'cred-1', target: 'cowrie', path: 'home/user/.aws/credentials', username: 'root', password: 'bait-secret', content_template: '{{username}}', memo: 'router-root', created_by: 'operator', created_at: event.time }
const health = { cluster_status: 'green', total_documents: 420, sensors: [{ sensor: 'cowrie', documents: 123, last_seen: event.time, state: 'ACTIVE' }], yara: { enabled: true, last_scan: event.time, rules_sha256: 'abc', samples: 12, matched: 1, errors: 0 }, runtime: { uptime_seconds: 3600, rss_bytes: 1024, vm_bytes: 2048 }, ingest: { state: 'running', last_ingest: event.time, age_seconds: 3, recent_dead_letters: 1 }, dead_letters: 1, unattributed_24h: 0, pipeline: { state: 'running', acked: 100, failed: 0, dropped: 0, active: 1, decode_failures: 0 } }

async function mount(route: { component: React.ComponentType }) {
  const previous = (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  const host = document.createElement('div')
  document.body.append(host)
  const root = createRoot(host)
  await act(async () => root.render(<route.component />))
  return { host, cleanup: async () => { await act(async () => root.unmount()); host.remove(); (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = previous } }
}

it('credentials renders the provision form, backend record, and shadcn empty/unavailable surfaces', async () => {
  fixtures.loaders['/credentials'] = { user: { role: 'admin' } }
  fixtures.responses['/api/v1/canarytokens'] = { tokens: [] }
  fixtures.responses['/api/v1/credentials'] = { available: true, credentials: [credential] }
  let view = await mount(Credentials as unknown as { component: React.ComponentType })
  expect(view.host.querySelector('h2')?.textContent).toBe('Provision a new credential')
  expect(view.host.querySelector('input[aria-label="Honeyfs path"]')).toBeTruthy()
  expect(view.host.textContent).toContain('router-root')
  await view.cleanup()
  fixtures.responses['/api/v1/credentials'] = { available: true, credentials: [] }
  view = await mount(Credentials as unknown as { component: React.ComponentType })
  expect(view.host.querySelector('[data-slot="empty"]')?.textContent).toContain('No credentials provisioned yet')
  await view.cleanup()
  fixtures.responses['/api/v1/credentials'] = { available: false, error: 'store offline', credentials: [] }
  view = await mount(Credentials as unknown as { component: React.ComponentType })
  expect(view.host.querySelector('[data-slot="empty"]')?.textContent).toContain('store offline')
  await view.cleanup()
})

it('dead letters preserves query filter and backend-shaped store row / healthy empty', async () => {
  fixtures.loaders['/dead-letters'] = { user: { role: 'admin' } }
  fixtures.responses['/api/v1/store/dead-letters'] = { rows: [{ '@timestamp': event.time, reason: 'mapping rejected', logset: 'cowrie' }], total: 1 }
  let view = await mount(DeadLetters as unknown as { component: React.ComponentType })
  expect(view.host.querySelector('h2')?.textContent).toBe('Filter dead letters')
  expect(view.host.querySelector('input[aria-label="Dead-letter query"]')).toBeTruthy()
  expect(view.host.textContent).toContain('mapping rejected')
  await view.cleanup()
  fixtures.responses['/api/v1/store/dead-letters'] = { rows: [], total: 0 }
  view = await mount(DeadLetters as unknown as { component: React.ComponentType })
  expect(view.host.textContent).toContain('No dead letters recorded')
  await view.cleanup()
})

it('commands loads backend event row and previews command; empty state remains', async () => {
  fixtures.loaders['/commands'] = { first: Promise.resolve({ total: 1, offset: 0, rows: [event] }) }
  let view = await mount(Commands as unknown as { component: React.ComponentType })
  expect(view.host.querySelector('h2')?.textContent).toBe('Command capture')
  expect(view.host.textContent).toContain('uname -a')
  await view.cleanup()
  fixtures.loaders['/commands'] = { first: Promise.resolve({ total: 0, offset: 0, rows: [] }) }
  view = await mount(Commands as unknown as { component: React.ComponentType })
  expect(view.host.textContent).toContain('No commands captured yet')
  await view.cleanup()
})

it('history preserves initial URL query, filter form, event and empty state', async () => {
  fixtures.loaders['/history'] = { first: Promise.resolve({ total: 1, offset: 0, rows: [event] }), initialQ: 'source.ip:203.0.113.7' }
  let view = await mount(History as unknown as { component: React.ComponentType })
  expect(view.host.querySelector('h2')?.textContent).toBe('Search archive')
  expect((view.host.querySelector('input[aria-label="History search query"]') as HTMLInputElement).value).toBe('source.ip:203.0.113.7')
  expect(view.host.textContent).toContain('login attempt root/admin')
  await view.cleanup()
  fixtures.loaders['/history'] = { first: Promise.resolve({ total: 0, offset: 0, rows: [] }), initialQ: '' }
  view = await mount(History as unknown as { component: React.ComponentType })
  expect(view.host.textContent).toContain('No history entries match this view')
  await view.cleanup()
})

it('source health shows shadcn metric and platform cards, ingestion table, sensor row and empty state', async () => {
  fixtures.loaders['/source-health'] = { first: Promise.resolve(health) }
  let view = await mount(SourceHealth as unknown as { component: React.ComponentType })
  expect(Array.from(view.host.querySelectorAll('h2')).map(h => h.textContent)).toContain('Configured feeds')
  expect(view.host.querySelectorAll('table tbody tr')).toHaveLength(4)
  expect(view.host.textContent).toContain('cowrie')
  expect(view.host.textContent).toContain('YARA scanner')
  await view.cleanup()
  fixtures.loaders['/source-health'] = { first: Promise.resolve({ ...health, sensors: [] }) }
  view = await mount(SourceHealth as unknown as { component: React.ComponentType })
  expect(view.host.textContent).toContain('No sensors are reporting yet')
  await view.cleanup()
})
