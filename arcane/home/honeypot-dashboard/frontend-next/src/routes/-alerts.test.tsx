import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const fixture = vi.hoisted(() => ({ first: Promise.resolve({ rows: [] as any[], complete: true }), rows: [] as any[], failed: false, writes: [] as any[] }))
vi.mock('@tanstack/react-router', () => ({ createFileRoute: () => (config: any) => ({ ...config, useLoaderData: () => ({ first: fixture.first }) }) }))
vi.mock('@tanstack/react-start', () => ({ createServerFn: () => ({ validator() { return this }, handler: (fn: any) => (args: any = {}) => fn(args) }) }))
vi.mock('../lib/backend.server', () => ({
  serviceJSON: async () => ({ total: fixture.rows.length, rows: fixture.rows }),
  serviceFetch: async (path: string, init: RequestInit) => {
    fixture.writes.push({ path, ...JSON.parse(init.body as string) })
    if (fixture.failed) return { ok: false, status: 503 }
    const key = decodeURIComponent(path.split('/').at(-2)!)
    fixture.rows = fixture.rows.map(row => row.Key === key ? { ...row, Acknowledged: JSON.parse(init.body as string).ack } : row)
    return { ok: true }
  },
}))
vi.mock('../lib/auth', () => ({ getSessionUser: async () => ({ role: 'admin' }) }))
import { Route } from './alerts'
const Component = (Route as any).component
const member = (hash: string, ack = false) => ({ Key: 'yara:' + hash.repeat(64), Message: 'YARA payload match: ' + hash.repeat(64) + ' rules=fixture', Link: '/payloads', Count: hash === 'a' ? 12 : 3, FirstSeen: '2026-09-01T10:00:00Z', LastSeen: '2026-09-02T10:00:00Z', LastNotified: null, Acknowledged: ack })
let root: Root, host: HTMLDivElement
async function mount(rows = [member('a'), member('b'), member('c', true)], complete = true) {
  fixture.rows = rows
  fixture.first = Promise.resolve({ rows, complete })
  await act(async () => root.render(<Component />))
}
const button = (text: string) => [...document.querySelectorAll<HTMLButtonElement>('button')].find(el => el.textContent === text)!
async function click(el: HTMLElement) { await act(async () => { el.click() }) }
beforeEach(() => {
  ;(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true
  fixture.writes = []; fixture.failed = false
  host = document.createElement('div'); document.body.append(host); root = createRoot(host)
})
afterEach(async () => { await act(async () => root.unmount()); host.remove() })
describe('alerts board behavior', () => {
  it('groups hash variants, sums counts and partitions acknowledgements', async () => {
    await mount()
    expect(document.querySelector('[aria-label="New alert groups"]')?.textContent).toContain('15')
    expect(document.querySelectorAll('tbody tr')).toHaveLength(1)
    expect(document.body.textContent).toContain('2 members')
    expect(button('New 2')).toBeTruthy()
    expect(button('Acknowledged 1')).toBeTruthy()
  })
  it('group confirmation can cancel, reports failure, retries and updates the partition', async () => {
    await mount()
    await click(button('Acknowledge (2)'))
    expect(document.querySelector('[role="alertdialog"]')?.textContent).toContain('Acknowledge this alert group?')
    await click(button('Cancel'))
    expect(fixture.writes).toHaveLength(0)
    await click(button('Acknowledge (2)'))
    fixture.failed = true
    await click(button('Acknowledge all 2'))
    expect(document.querySelector('[role="alertdialog"]')?.textContent).toContain('Alert update failed (503)')
    fixture.failed = false
    await click(button('Try again'))
    expect(fixture.writes).toHaveLength(3)
    expect(button('New 0')).toBeTruthy()
    expect(document.body.textContent).toContain('2 alerts acknowledged.')
  })
  it('clears the previous success before another action so identical outcomes reannounce', async () => {
    await mount()
    const trigger = [...document.querySelectorAll<HTMLButtonElement>('button')].find(el => el.textContent?.startsWith('YARA payload match:'))!
    await click(trigger)
    await click(button('Acknowledge'))
    await click(button('Acknowledge alert'))
    const status = document.querySelector('section[aria-labelledby="alerts-title"] > [role="status"]')!
    expect(status.textContent).toBe('Alert acknowledged.')
    await click(document.querySelector<HTMLElement>('[role="dialog"] li button')!)
    expect(status.textContent).toBe('')
    await click(button('Acknowledge alert'))
    expect(status.textContent).toBe('Alert acknowledged.')
    expect(fixture.writes).toHaveLength(2)
    expect(fixture.writes[0].path).not.toBe(fixture.writes[1].path)
  })
  it('filters individual members before grouping and clears without refetch', async () => {
    await mount()
    const input = document.querySelector('input')!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(input, 'b'.repeat(64))
      input.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(document.body.textContent).toContain('1 groups · 1 matching alerts')
    expect(button('New 2')).toBeTruthy()
  })
  it('distinguishes empty, failed and partial board reads', async () => {
    await mount([], false)
    expect(document.body.textContent).toContain('The alert board failed to load')
    expect(document.body.textContent).not.toContain('No alerts recorded')
    await mount([member('a')], false)
    expect(document.body.textContent).toContain('Partial alert board')
    expect(document.querySelectorAll('tbody tr')).toHaveLength(1)
    await mount([])
    expect(document.body.textContent).toContain('No alerts recorded')
  })
  it('opens a keyboard-reachable inspector with member links and last-notified state', async () => {
    await mount()
    const trigger = [...document.querySelectorAll<HTMLButtonElement>('button')].find(el => el.textContent?.startsWith('YARA payload match:'))!
    await click(trigger)
    expect(document.querySelector('[role="dialog"]')?.textContent).toContain('Alert group details')
    expect(document.querySelectorAll('[role="dialog"] a[href="/payloads"]')).toHaveLength(2)
    expect(document.querySelector('[role="dialog"]')?.textContent).toContain('Never')
    await click(button('Acknowledge'))
    await click(button('Acknowledge alert'))
    expect(fixture.writes).toHaveLength(1)
    expect(button('New 1')).toBeTruthy()
  })
})
