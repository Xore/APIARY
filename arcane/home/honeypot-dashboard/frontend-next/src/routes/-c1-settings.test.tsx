import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { expect, it, vi } from 'vitest'

const fixture = vi.hoisted(() => ({ navigate: vi.fn(), confirm: vi.fn(), validate: vi.fn(), write: vi.fn(), conflict: false, config: { revision: 4, payload: { presentation: { app_name: 'Original' }, honeypot: {}, behavior: { rows_per_page_options: [25] }, report_presets: {} } } }))
vi.mock('@tanstack/react-router', () => ({
  Link: 'a',
  useNavigate: () => fixture.navigate,
  useBlocker: () => ({ status: 'idle' }),
  createFileRoute: () => (config: Record<string, unknown>) => ({ ...config }),
}))
vi.mock('@tanstack/react-start', () => ({ createServerFn: () => ({ validator() { return this }, handler: (fn: unknown) => fn }) }))
vi.mock('../lib/prefs', () => ({ useThemeMode: () => 'light', applyPalette: vi.fn(), applyTheme: vi.fn() }))
vi.mock('../components/ThemeGallery', () => ({ ThemeGallery: () => null }))
vi.mock('../components/ConfirmDialog', () => ({ confirmAction: fixture.confirm }))
vi.mock('../lib/auth', () => ({ getSessionUser: async () => ({ sub: 'operator', username: 'operator', role: 'admin' }) }))
vi.mock('../lib/backend.server', () => ({
  serviceJSON: async (path: string) => path === '/api/v1/config' ? fixture.config : path === '/api/v1/users' ? { users: [] } : { templates: [] },
  serviceFetch: async (path: string, options: RequestInit) => {
    if (path === '/api/v1/config/validate') return Response.json(fixture.validate())
    fixture.write(path, options)
    if (path === '/api/v1/preferences') return Response.json({ preferences: { timezone: 'Europe/Berlin', rows_per_page: 25 } })
    if (fixture.conflict) return new Response(null, { status: 409, headers: { 'x-current-revision': '5' } })
    return Response.json({ revision: 5 })
  },
}))
import { SettingsSurface } from './settings'

vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} })

it('settings renders loaded personal/admin controls, validates writes and retains search/pane interaction', async () => {
  const prior = (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT
  ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true
  const host = document.createElement('div')
  document.body.append(host)
  const root = createRoot(host)
  const data = {
    preferences: Promise.resolve({ timezone: 'utc', rows_per_page: 25 }), storage: Promise.resolve(null), admin: Promise.resolve({ revision: 4, presentation: fixture.config.payload.presentation, honeypot: {}, behavior: fixture.config.payload.behavior, reportPresets: {}, reportTemplates: [{ id: 'daily', name: 'Daily', description: 'Summary' }], users: [] }),
    services: Promise.resolve(null), history: Promise.resolve(null), audit: Promise.resolve(null),
    reporterStats: Promise.resolve(null),
  }
  const onPaneChange = vi.fn()
  fixture.validate.mockReset().mockReturnValue({ ok: true, problems: [] })
  fixture.write.mockReset()
  fixture.confirm.mockReset()
  fixture.conflict = false
  try {
    await act(async () => root.render(<SettingsSurface data={data as any} user={null} onPaneChange={onPaneChange} />))
    const search = host.querySelector<HTMLInputElement>('input[aria-label="Search settings"]')!
    expect(search).toBeTruthy()
    const nav = host.querySelector<HTMLElement>('[role="navigation"][aria-label="Settings sections"]')!
    expect(nav).toBeTruthy()
    await act(async () => nav.querySelector<HTMLButtonElement>('button[aria-current="page"]')?.click())
    expect(onPaneChange).toHaveBeenCalledWith('account')
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(search, 'timezone')
      search.dispatchEvent(new Event('input', { bubbles: true }))
    })
    expect(search.value).toBe('timezone')
    await act(async () => root.render(<SettingsSurface data={data as any} user={null} pane="time" onPaneChange={onPaneChange} />))
    const timezone = host.querySelector<HTMLInputElement>('#hp-pref-timezone')!
    expect(timezone.value).toBe('utc')
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(timezone, 'Europe/Berlin')
      timezone.dispatchEvent(new Event('input', { bubbles: true }))
    })
    const timePane = host.querySelector<HTMLElement>('[data-hp-pane="time"]')!
    await act(async () => [...timePane.querySelectorAll<HTMLButtonElement>('button')].find(button => button.textContent?.includes('Save changes'))!.click())
    expect(fixture.confirm).toHaveBeenCalledWith(expect.objectContaining({ title: 'Save preferences?' }))
    await act(async () => { await fixture.confirm.mock.lastCall![0].onConfirm() })
    expect(fixture.write).toHaveBeenCalledWith('/api/v1/preferences', expect.objectContaining({ body: expect.stringContaining('Europe/Berlin') }))
    await act(async () => root.render(<SettingsSurface data={data as any} user={null} pane="branding" onPaneChange={onPaneChange} />))
    const appName = host.querySelector<HTMLInputElement>('#presentation-app_name')!
    expect(appName.value).toBe('Original')
    expect(host.querySelector('label[for="presentation-app_name"]')?.textContent).toBe('Application name')
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(appName, 'Changed')
      appName.dispatchEvent(new Event('input', { bubbles: true }))
    })
    const save = [...host.querySelectorAll<HTMLButtonElement>('button')].find(button => button.textContent?.includes('Save presentation'))!
    expect(save.disabled).toBe(false)
    await act(async () => save.click())
    expect(fixture.confirm).toHaveBeenCalledWith(expect.objectContaining({ title: 'Save configuration?' }))
    await act(async () => { await fixture.confirm.mock.lastCall![0].onConfirm() })
    expect(fixture.validate).toHaveBeenCalled()
    expect(fixture.write).toHaveBeenCalledWith(expect.stringContaining('/api/v1/config/presentation'), expect.objectContaining({ headers: expect.objectContaining({ 'if-match': '4' }) }))
    await act(async () => root.render(<SettingsSurface data={data as any} user={null} pane="behavior" onPaneChange={onPaneChange} />))
    const rows = host.querySelector<HTMLInputElement>('#behavior-rows-per-page-options')!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(rows, '25, bad')
      rows.dispatchEvent(new Event('input', { bubbles: true }))
    })
    const behaviorSave = [...host.querySelectorAll<HTMLButtonElement>('button')].find(button => button.textContent?.includes('Save changes') && !button.disabled)!
    fixture.confirm.mockClear()
    await act(async () => behaviorSave.click())
    expect(host.textContent).toContain('Invalid values')
    expect(fixture.confirm).not.toHaveBeenCalled()
    await act(async () => root.render(<SettingsSurface data={data as any} user={null} pane="branding" onPaneChange={onPaneChange} />))
    const nameAgain = host.querySelector<HTMLInputElement>('#presentation-app_name')!
    await act(async () => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(nameAgain, 'Staged')
      nameAgain.dispatchEvent(new Event('input', { bubbles: true }))
    })
    fixture.conflict = true
    fixture.config = { ...fixture.config, revision: 5, payload: { ...fixture.config.payload, presentation: { app_name: 'Server update' } } }
    await act(async () => [...host.querySelectorAll<HTMLButtonElement>('button')].find(button => button.textContent?.includes('Save presentation'))!.click())
    await act(async () => { await fixture.confirm.mock.lastCall![0].onConfirm() })
    expect(host.querySelector<HTMLInputElement>('#presentation-app_name')?.value).toBe('Staged')
    expect(host.textContent).toContain('unsaved edits were kept')
  } finally {
    await act(async () => root.unmount())
    host.remove()
    ;(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = prior
  }
})
