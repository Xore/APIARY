import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { expect, it, vi } from 'vitest'
import { Button } from '../components/ui/button'

const fixture = vi.hoisted(() => ({
  navigate: vi.fn(),
  search: {} as Record<string, string>,
  eventFirst: Promise.resolve(null) as Promise<unknown>,
  payloadFirst: Promise.resolve(null) as Promise<unknown>,
  eventPage: null as unknown,
  payloadPage: null as unknown,
  canaryPage: null as unknown,
  firedPage: null as unknown,
}))

vi.mock('@tanstack/react-router', () => ({
  createFileRoute: (path: string) => (config: Record<string, unknown>) => ({
    ...config,
    useSearch: () => fixture.search,
    useNavigate: () => fixture.navigate,
    useLoaderData: () => path === '/events'
      ? { first: fixture.eventFirst, investigationConfig: { kibana: '', evebox: '', arkime: '' } }
      : { first: fixture.payloadFirst },
  }),
}))

vi.mock('@tanstack/react-start', () => ({ createServerFn: () => ({
  validator() { return this },
  handler(fn: Function) {
    const source = fn.toString()
    if (source.includes('/api/v1/filter-values')) return () => Promise.resolve({ sensors: ['cowrie'], countries: ['CN'], cities: ['Shanghai'], protos: ['tcp'], ports: ['22'], kinds: ['cowrie.login.success'] })
    if (source.includes('HONEYPOT_DOMAIN')) return () => Promise.resolve({ kibana: '', evebox: '', arkime: '' })
    if (source.includes('/api/v1/store/github-analysis')) return () => Promise.resolve({ badges: [], scanned: 0, total: 0 })
    if (source.includes('aggs=sources')) return () => Promise.resolve({ counts: { cowrie: 1 }, other: 0 })
    if (source.includes('/api/v1/payloads?')) return () => Promise.resolve(fixture.payloadPage)
    if (source.includes('/api/v1/store/canarytokens')) return () => Promise.resolve(fixture.canaryPage)
    if (source.includes('sensor=canarytokens')) return () => Promise.resolve(fixture.firedPage)
    if (source.includes('/api/v1/canarytokens/types')) return () => Promise.resolve([{ token_type: 'ms_word', label: 'Word document', description: 'A document token.', requires_upload: false, supports_snippet: false }])
    if (source.includes('/api/v1/events?')) return () => Promise.resolve(fixture.eventPage)
    return () => Promise.resolve(null)
  },
}) }))

vi.mock('../lib/live', async () => {
  const React = await import('react')
  return {
    subscribeLiveEvents: () => () => undefined,
    useLiveState: () => ({ paused: false }),
    useLiveInterval: (callback: () => void) => React.useEffect(() => { void callback() }, [callback]),
  }
})
vi.mock('../components/FiltersModal', () => ({
  FiltersButton: ({ onClick, activeCount = 0 }: { onClick: () => void; activeCount?: number }) => <Button variant="outline" size="sm" onClick={onClick}>Filters{activeCount ? ` (${activeCount})` : ''}</Button>,
  FiltersModal: ({ children }: { children: React.ReactNode }) => <form>{children}</form>,
}))
vi.mock('../components/ConfirmDialog', () => ({ confirmAction: vi.fn() }))

import { Route as Events } from './events'
import { Route as Payloads } from './payloads'
import { Route as Canarytokens } from './canarytokens'

const now = '2026-09-18T10:00:00Z'
const pivots = { persona: 'edge-router', site: 'plant-7', asset: 'plc-2', fingerprint: 'hassh-fixture', fingerprint_kind: 'HASSH', command: 'uname -a', user: 'root', pass: 'admin', path: '/login', shasum: 'a'.repeat(64), asn: '4134', org: 'CHINANET', provider: 'blocklist:fixture', alert: 'Fixture signature', category: 'attempted-admin', tty_replay: '', ics_severity: 'high', payload_class: 'credential' }
const eventRow = { id: 'event-fixture-01', time: now, sensor: 'cowrie', src_ip: '203.0.113.7', country: 'CN', port: '22', proto: 'tcp', detail: 'login attempt root/admin', session: 'session-fixture', pivots, record: { '@timestamp': now, event: { sensor: 'cowrie' }, source: { ip: '203.0.113.7', geo: { country_iso_code: 'CN' }, as: { asn: 4134, organization_name: 'CHINANET', type: 'blocklist:fixture' } }, destination: { port: 22 }, network: { protocol: 'tcp', community_id: '1:fixture=' }, honeypot: { session: 'session-fixture', canonical_command: 'uname -a' } } }
const payloadRow = { Hash: 'b'.repeat(64), Size: 7, SizeH: '7 B', MtimeUTC: now, MIME: 'text/plain', Kind: 'script', Platform: 'linux', AnalysisPath: 'static', Dynamic: false, Sources: ['cowrie'], Copies: 1, Preview: 'uname -a', PreviewTruncated: false }
const firedRow = { time: now, src_ip: '203.0.113.9', country: 'DE', detail: 'canary fired', record: { honeypot: { token_type: 'ms_word', manage_url: 'https://canary.example/manage/fixture', memo: 'finance decoy' } } }

async function mount(route: { component: React.ComponentType }) {
  const previous = (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  const host = document.createElement('div')
  document.body.append(host)
  const root = createRoot(host)
  await act(async () => { root.render(<route.component />); await Promise.resolve(); await Promise.resolve() })
  return { host, cleanup: async () => { await act(async () => root.unmount()); host.remove(); (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = previous } }
}

it('renders the backend events.rs row shape, filter fields, pivots, and row actions', async () => {
  fixture.eventPage = { total: 1, offset: 0, rows: [eventRow], fingerprint_ips: null }
  fixture.eventFirst = Promise.resolve(fixture.eventPage)
  const view = await mount(Events as unknown as { component: React.ComponentType })
  try {
    expect(view.host.querySelector('h1')?.textContent).toBe('Event explorer')
    expect(view.host.textContent).toContain('login attempt root/admin')
    expect(view.host.querySelector('a[href="/event/event-fixture-01"]')?.getAttribute('aria-label')).toBe('Open full details')
    const filterButton = Array.from(view.host.querySelectorAll('button')).find(button => button.textContent?.startsWith('Filters'))
    await act(async () => filterButton?.click())
    expect(Array.from(view.host.querySelectorAll('label')).map(label => label.textContent)).toEqual(expect.arrayContaining(['Source IP', 'Sensor', 'Country', 'City', 'Protocol', 'Port', 'Kind', 'Since']))
    await act(async () => view.host.querySelector<HTMLTableRowElement>('tbody tr:not([aria-hidden])')?.click())
    expect(view.host.querySelector('h2')?.textContent).toBe('Normalized event')
    expect(view.host.textContent).toContain('CHINANET')
  } finally { await view.cleanup() }
})

it('renders a captured payload card with inventory metadata and every row action', async () => {
  fixture.payloadPage = { total: 1, rows: [payloadRow] }
  fixture.payloadFirst = Promise.resolve(fixture.payloadPage)
  const view = await mount(Payloads as unknown as { component: React.ComponentType })
  try {
    expect(view.host.querySelector('h1')?.textContent).toBe('Captured payloads')
    expect(view.host.querySelector('h2')?.textContent).toBe('Payload inventory')
    expect(view.host.textContent).toContain(payloadRow.Hash)
    expect(view.host.textContent).toContain('uname -a')
    for (const label of ['Analysis workbench', 'Static analysis', 'Download sample', 'Related events', 'VirusTotal', 'Publish to Xore/honeypot']) {
      expect(view.host.querySelector(`[aria-label="${label}"]`)).toBeTruthy()
    }
  } finally { await view.cleanup() }
})

it('renders the canary empty gallery and loaded fired-event row through shadcn tabs', async () => {
  fixture.canaryPage = { total: 0, rows: [] }
  fixture.firedPage = { total: 1, rows: [firedRow] }
  const view = await mount(Canarytokens as unknown as { component: React.ComponentType })
  try {
    expect(view.host.querySelector('h1')?.textContent).toBe('Canarytokens')
    expect(Array.from(view.host.querySelectorAll('h2')).map(h => h.textContent)).toEqual(expect.arrayContaining(['Mint a new token', 'Fake .docx', 'QR code', 'Windows folder', 'Web bug image']))
    const templateButton = Array.from(view.host.querySelectorAll('button')).find(button => button.textContent === 'Fake .docx')
    expect(templateButton).toBeTruthy()
    expect(templateButton?.querySelector('h2, p')).toBeNull()
    expect(templateButton?.className).toContain('focus-visible:ring-1')
    expect(Array.from(view.host.querySelectorAll('label')).map(label => label.textContent)).toEqual(expect.arrayContaining(['Token type', 'Memo']))
    const firedTab = Array.from(view.host.querySelectorAll<HTMLElement>('[role="tab"]')).find(tab => tab.textContent === 'Fired tokens')
    await act(async () => { firedTab?.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, button: 0 })); firedTab?.click(); await Promise.resolve() })
    expect(view.host.querySelector('h2')?.textContent).toBe('Fired tokens')
    expect(view.host.textContent).toContain('canary fired')
    expect(view.host.querySelector('a[href="https://canary.example/manage/fixture"]')).toBeTruthy()
  } finally { await view.cleanup() }
})
