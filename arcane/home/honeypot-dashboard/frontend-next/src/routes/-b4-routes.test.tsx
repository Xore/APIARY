import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { expect, it, vi } from 'vitest'

const fixture = vi.hoisted(() => ({
  pages: {} as Record<string, unknown>,
  reportsData: {} as Record<string, unknown>,
}))

vi.mock('@tanstack/react-router', () => ({
  createFileRoute: (path: string) => (config: Record<string, unknown>) => ({
    ...config,
    useLoaderData: () => path === '/reports'
      ? fixture.reportsData
      : path === '/problem-reports' ? { user: { role: 'admin' } } : {},
  }),
  Link: ({ children, to, params, ...props }: React.ComponentProps<'a'> & { to: string; params?: Record<string, string> }) => {
    const href = params ? Object.entries(params).reduce((value, [key, part]) => value.replace(`$${key}`, part), to) : to
    return <a href={href} {...props}>{children}</a>
  },
}))

vi.mock('@tanstack/react-start', () => ({ createServerFn: () => ({
  validator() { return this },
  handler(fn: Function) {
    const source = fn.toString()
    if (source.includes('/api/v1/store/auth-events?offset=0&size=200')) return () => Promise.resolve(fixture.pages.authStats)
    if (source.includes('/api/v1/store/auth-events')) return () => Promise.resolve(fixture.pages.auth)
    if (source.includes('/api/v1/store/llm-analysis')) return () => Promise.resolve(fixture.pages.llm)
    if (source.includes('/api/v1/store/problem-reports')) return () => Promise.resolve(fixture.pages.problems)
    return () => Promise.resolve(null)
  },
}) }))

vi.mock('../lib/auth', () => ({ getSessionUser: () => Promise.resolve({ role: 'admin' }) }))
vi.mock('../lib/viewTabs', () => ({ useSidebarViewTabs: () => null }))

import { Route as LlmAnalysis } from './llm-analysis'
import { Route as AuthEvents } from './auth-events'
import { Route as ProblemReports } from './problem-reports'
import { Route as Reports } from './reports'

const now = new Date().toISOString()
const llmRow = { analysis_id: 'analysis-fixture-01', '@timestamp': now, doc_type: 'session', severity: 'high', confidence: '0.91', intent: 'credential access', summary: 'Fixture model summary', session_id: 'session-fixture', model: 'qwen3:14b' }
const authRow = { event_id: 'auth-fixture-01', '@timestamp': now, type: 'LOGIN_ERROR', ip_address: '203.0.113.8', error: 'invalid_user_credentials', client_id: 'apiary-dashboard', realm: 'apiary', details: { username: 'fixture-user', redirect_uri: 'https://dashboard.example/callback' } }
const problemRow = { id: 'problem-fixture-01', submitted_at: now, submitted_by: 'operator-1', submitted_by_name: 'Fixture Operator', page: '/events', expected: 'filters remain open', actual: 'filters closed', status: 'open', action_trail: [{ at: now, kind: 'interaction', detail: 'opened filters' }], console_errors: ['fixture console error'], network_failures: ['GET /api/events failed'], api_calls: [{ at: now, method: 'GET', url: '/api/events', status: 502, response_body: 'bad gateway' }], user_agent: 'fixture-browser' }
const reportDefinition = { id: 'definition-fixture-01', name: 'Fixture daily digest', template: 'executive', theme: 'dark', branding: { title: '', author: '', header_left: '', header_right: '', footer_left: '', classification: '' }, scope: { window: '24h', ip: '', network: '', sensor: '', port: '', signature: '', country: '', asn: '', text: '', type: '', session: '', job: '', hash: '' }, elements: ['cover'], appendix_limit: 200, created: now, schedule: null }
const generatedReport = { id: 'report-fixture-01', definition_id: reportDefinition.id, name: 'fixture-daily-digest', template: 'executive', theme: 'dark', title: 'Fixture generated report', size_bytes: 4096, created_at: now, origin: 'manual' }

async function mount(route: { component: React.ComponentType }) {
  const previous = (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  const host = document.createElement('div')
  document.body.append(host)
  const root = createRoot(host)
  await act(async () => { root.render(<route.component />); await Promise.resolve(); await Promise.resolve() })
  return { host, cleanup: async () => { await act(async () => root.unmount()); host.remove(); (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = previous } }
}

it('renders loaded LLM analysis with semantic-search field and backend row', async () => {
  fixture.pages.llm = { total: 1, offset: 0, rows: [llmRow] }
  const view = await mount(LlmAnalysis as unknown as { component: React.ComponentType })
  try {
    expect(view.host.querySelector('h1')?.textContent).toBe('LLM analysis')
    expect(Array.from(view.host.querySelectorAll('h2')).map(node => node.textContent)).toContain('Semantic search')
    expect(view.host.querySelector('label')?.textContent).toBe('Semantic search query')
    expect(view.host.textContent).toContain('Fixture model summary')
  } finally { await view.cleanup() }
})

it('renders auth-event metrics, badges, and backend row fields', async () => {
  fixture.pages.auth = { total: 1, offset: 0, rows: [authRow] }
  fixture.pages.authStats = { total: 1, offset: 0, rows: [authRow] }
  const view = await mount(AuthEvents as unknown as { component: React.ComponentType })
  try {
    expect(view.host.querySelector('h1')?.textContent).toBe('Auth-failure events')
    expect(Array.from(view.host.querySelectorAll('h2')).map(node => node.textContent)).toEqual(expect.arrayContaining(['Failed logins, 24h', 'Failures by client, 24h', 'Top source IPs, 24h']))
    expect(view.host.textContent).toContain('fixture-user')
    expect(view.host.textContent).toContain('203.0.113.8')
  } finally { await view.cleanup() }
})

it('renders backend problem-report fields and capture counts', async () => {
  fixture.pages.problems = { total: 1, offset: 0, rows: [problemRow] }
  const view = await mount(ProblemReports as unknown as { component: React.ComponentType })
  try {
    expect(view.host.querySelector('h1')?.textContent).toBe('Problem reports')
    expect(view.host.textContent).toContain('/events')
    expect(view.host.textContent).toContain('filters remain open')
    expect(view.host.textContent).toContain('filters closed')
    await act(async () => { view.host.querySelector<HTMLButtonElement>('[aria-label="Toggle details for page 1"]')?.click(); await Promise.resolve() })
    expect(view.host.textContent).toContain('opened filters')
  } finally { await view.cleanup() }
})

it('renders report form labels, saved definition, and generated report shapes', async () => {
  fixture.reportsData = {
    generated: Promise.resolve({ total: 1, rows: [generatedReport] }),
    templates: Promise.resolve({ templates: [{ id: 'executive', name: 'Executive', description: 'Executive overview', title: 'Executive', theme: 'dark', window: '24h', elements: ['cover'], sandbox: false, payload: false, ghidra: false }], elements: [{ id: 'cover', label: 'Cover', description: 'Cover page' }] }),
    definitions: Promise.resolve({ definitions: [reportDefinition] }),
    user: { role: 'admin' },
  }
  const view = await mount(Reports as unknown as { component: React.ComponentType })
  try {
    expect(view.host.querySelector('h1')?.textContent).toBe('Reports studio')
    expect(view.host.textContent).toContain('Fixture daily digest')
    expect(view.host.textContent).toContain('Fixture generated report')
    expect(Array.from(view.host.querySelectorAll('label')).map(label => label.textContent)).toEqual(expect.arrayContaining(['Name', 'Theme', 'Window', 'Event appendix limit']))
  } finally { await view.cleanup() }
})
