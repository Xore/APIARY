import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { expect, it, vi } from 'vitest'
const fixture = vi.hoisted(() => ({ first: Promise.resolve({ state: 'failed' }), reads: 0 }))
vi.mock('@tanstack/react-router', () => ({ Link: 'a', createFileRoute: () => (config: any) => ({ ...config, useParams: () => ({ id: 'missing-fixture' }), useLoaderData: () => ({ first: fixture.first }) }) }))
vi.mock('@tanstack/react-start', () => ({ createServerFn: () => ({ validator() { return this }, handler: (fn: any) => fn }) }))
vi.mock('../lib/backend.server', () => ({ serviceJSONResult: async () => { fixture.reads++; return { ok: false, status: 404 } } }))
import { Route } from './event.$id'
it('distinguishes outage from absence and retries through the real handler', async () => {
  const prior = (globalThis as any).IS_REACT_ACT_ENVIRONMENT
  ;(globalThis as any).IS_REACT_ACT_ENVIRONMENT = true
  const host = document.createElement('div'); document.body.append(host)
  const root = createRoot(host), Component = (Route as any).component
  try {
    await act(async () => root.render(<Component />))
    expect(host.querySelector('[role="alert"]')?.textContent).toContain('This event failed to load')
    expect(host.textContent).not.toContain('Event not found')
    await act(async () => host.querySelector<HTMLButtonElement>('button')!.click())
    expect(fixture.reads).toBe(1)
    expect(host.querySelector('[data-slot="empty"]')?.textContent).toContain('Event not found')
    expect(host.textContent).toContain('missing-fixture')
    expect(host.querySelector('[role="alert"]')).toBeNull()
  } finally {
    await act(async () => root.unmount()); host.remove()
    ;(globalThis as any).IS_REACT_ACT_ENVIRONMENT = prior
  }
})
