import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { expect, it, vi } from 'vitest'
import { Button } from '../components/ui/button'

const fixture = vi.hoisted(() => ({
  responses: {} as Record<string, unknown>,
  first: Promise.resolve(null) as Promise<unknown>,
  category: undefined as string | undefined,
}))
vi.mock('@tanstack/react-router', () => ({
  Link: ({ to, search, children, ...props }: { to: string; search?: Record<string, string>; children: React.ReactNode }) =>
    <a href={`${to}${search?.category ? `?category=${search.category}` : ''}`} {...props}>{children}</a>,
  createFileRoute: () => (config: Record<string, unknown>) => ({
    ...config, useLoaderData: () => ({ first: fixture.first }), useSearch: () => ({ category: fixture.category }),
  }),
}))
vi.mock('@tanstack/react-start', () => ({ createServerFn: () => ({
  validator() { return this },
  handler: (fn: Function) => () => {
    const source = fn.toString()
    const key = source.includes('/api/v1/store/agent-campaigns') ? 'campaigns'
      : source.includes('/api/v1/ml-health') ? 'health'
      : source.includes('/api/v1/ml-anomalies/acks') ? 'acks'
      : source.includes('/api/v1/ml-anomalies/stats') ? 'backlog'
      : source.includes('total24h: first.total') ? 'stats' : 'anomalies'
    return Promise.resolve(fixture.responses[key] ?? null)
  },
}) }))
vi.mock('../components/Investigate', () => ({
  InvestigateHeader: ({ title, chips }: { title: string; chips: React.ReactNode }) => <header><h1>{title}</h1>{chips}</header>,
  MasterDetailTable: ({ rows, columns, inspectorExtra }: { rows: Record<string, unknown>[] | null; columns: { header: string; detail?: boolean; render: (row: Record<string, unknown>) => React.ReactNode }[]; inspectorExtra: (row: Record<string, unknown>) => React.ReactNode }) =>
    <section aria-label="Loaded records">{rows?.map((row, index) => <div key={index}>
      {columns.filter(column => !column.detail).map(column => <span key={column.header}>{column.render(row)}</span>)}
      {inspectorExtra(row)}
    </div>)}</section>,
}))
vi.mock('../components/EChart', () => ({ EChart: () => <div aria-label="Chart placeholder" /> }))
vi.mock('../components/AttackerGraph', () => ({ AttackerGraph: () => <div aria-label="Graph placeholder" /> }))
vi.mock('../components/FiltersModal', () => ({
  FiltersButton: ({ onClick }: { onClick: () => void }) => <Button variant="outline" size="sm" onClick={onClick}>Filters</Button>,
  FiltersModal: ({ children }: { children: React.ReactNode }) => <form>{children}</form>,
}))

import { Route as Campaigns } from './agent-campaigns'
import { Route as Anomalies } from './ml-anomalies'
import { Route as Attackers } from './attackers'

const now = '2026-09-18T10:00:00Z'
const campaign = { '@timestamp': now, campaign_id: 'campaign-fixture', start: now, end: now, severity: 'critical', matched_categories: ['encoded-egress-external'], correlation_identifiers: ['203.0.113.7'], event_count: 1, events: [{ event_id: 'evt-1', source_index: 'honeypot-v2-2026.09.18', timestamp: now, matched_rules: [{ rule: 'encoded-egress', reason: 'encoded request', trust_boundary: 'external egress', decode_chain: [] }] }] }
const anomaly = { '@timestamp': now, _doc_id: 'anomaly-fixture', severity: 'high', composite_score: 0.92, src_ip: '203.0.113.7', src_country: 'CN', event_type: 'ssh', status: 'open', explanation: 'fixture score anomaly', source_event_id: 'evt-1', source_index: 'honeypot-v2-2026.09.18', model_scores: { isolation_forest: 0.9, lstm_ae: 0.8, hbos: 0.7 } }
const attacker = { id: 'attacker-fixture', ips: ['203.0.113.7', '203.0.113.8'], fingerprints: ['mirai'], payloads: ['abcd'], credentials: ['root/admin'], sensors: ['cowrie'], events: 342, first: now, last: now, updated: now, verdicts: ['malicious'], techniques: ['T1059'], scan: 'horizontal', dest_ips: 25 }

async function mount(route: { component: React.ComponentType }) {
  const previous = (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  const host = document.createElement('div')
  document.body.append(host)
  const root = createRoot(host)
  await act(async () => root.render(<route.component />))
  return { host, cleanup: async () => { await act(async () => root.unmount()); host.remove(); (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = previous } }
}

it('loads campaign store shape, category metrics, and evidence timeline without changing category URL state', async () => {
  fixture.responses.campaigns = { rows: [campaign], total: 1 }
  fixture.category = 'encoded-egress-external'
  const view = await mount(Campaigns as unknown as { component: React.ComponentType })
  try {
    expect(view.host.querySelector('h1')?.textContent).toBe('Agent campaigns')
    expect(view.host.querySelector('h2')?.textContent).toBe('Encoded egress external campaign')
    expect(view.host.querySelector('a[title="clear this filter"]')).toBeTruthy()
    expect(view.host.textContent).toContain('campaign-fixture')
    expect(view.host.textContent).toContain('external egress')
    expect(view.host.querySelectorAll('table tbody tr')).toHaveLength(1)
  } finally { await view.cleanup(); fixture.category = undefined }
})

it('loads anomaly store row, severity metrics, health table, filter labels and chart chrome', async () => {
  fixture.responses.anomalies = { rows: [anomaly], total: 1 }
  fixture.responses.stats = { total24h: 1, scanned: 1, bySeverity: [{ key: 'high', count: 1 }], topSrcIPs: [{ key: '203.0.113.7', count: 1 }] }
  fixture.responses.backlog = { total: 1, open: 1 }
  fixture.responses.acks = {}
  fixture.responses.health = [{ model: 'hbos', timestamp: now, accepted: true, reason: 'stable', anomaly_rate_new: 0.1, anomaly_rate_previous: 0.2, train_samples: 100 }]
  const view = await mount(Anomalies as unknown as { component: React.ComponentType })
  try {
    expect(view.host.querySelector('h1')?.textContent).toBe('ML anomalies')
    expect(Array.from(view.host.querySelectorAll('h2')).map(h => h.textContent)).toEqual(expect.arrayContaining(['Anomalies, 24h', 'Open (all time)', 'high', 'Model scores over time', 'Model health', 'Top source IPs, 24h']))
    expect(view.host.textContent).toContain('fixture score anomaly')
    expect(view.host.textContent).toContain('stable')
    await act(async () => { view.host.querySelector<HTMLButtonElement>('#ml-filters button')?.click() })
    expect(Array.from(view.host.querySelectorAll('label')).map(label => label.textContent)).toEqual(expect.arrayContaining(['Severity', 'Event type', 'Status']))
  } finally { await view.cleanup() }
})

it('loads attacker entity, merged count, card evidence and associated tabs', async () => {
  fixture.first = Promise.resolve({ total: 1, rows: [attacker] })
  const view = await mount(Attackers as unknown as { component: React.ComponentType })
  try {
    expect(view.host.querySelector('h1')?.textContent).toBe('Attacker identities')
    expect(view.host.textContent).toContain('1 merged across >1 IP')
    expect(view.host.textContent).toContain('attacker-fixture')
    const overview = view.host.querySelector('[role="tab"][data-state="active"]')
    expect(overview?.getAttribute('aria-controls')).toBe('attacker-dossier-panel-overview')
    expect(view.host.querySelector('#attacker-dossier-panel-overview')?.getAttribute('aria-labelledby')).toBe('attacker-dossier-tab-overview')
    await act(async () => {
      const trigger = view.host.querySelector('#attacker-dossier-tab-indicators') as HTMLElement
      trigger.dispatchEvent(new MouseEvent('mousedown', { bubbles: true, button: 0 }))
      trigger.click()
    })
    expect(view.host.querySelector('#attacker-dossier-panel-indicators')?.textContent).toContain('root/admin')
    expect(view.host.querySelector('#attacker-dossier-panel-indicators')?.getAttribute('aria-labelledby')).toBe('attacker-dossier-tab-indicators')
  } finally { await view.cleanup() }
})
