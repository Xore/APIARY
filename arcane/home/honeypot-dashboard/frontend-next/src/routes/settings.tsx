// Settings — appearance (theme mode, accent palette presets, predictive
// prefetch), account, and ES storage. Theme/palette use the same
// localStorage contract as the legacy tier (hp-theme / hp-palette).
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { applyPalette, applyTheme, useThemeMode, type ThemeMode } from '../lib/prefs'
import { prefetchEnabled, setPrefetchEnabled } from '../lib/prefetch'
import { getSessionUser } from '../lib/auth'

type Storage = { cluster_status: string; index_count: number; doc_count: number; store_bytes: number }

type Presentation = {
  dashboard_title?: string
  dashboard_subtitle?: string
  footer_text?: string
  banner_text?: string
  banner_severity?: string
}

type Operator = { subject: string; username: string; role: string; first_seen_at: string; last_seen_at: string }

const fetchStorage = createServerFn({ method: 'GET' }).handler(async (): Promise<Storage | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<Storage>('/api/v1/settings/storage')
})

const fetchAdminData = createServerFn({ method: 'GET' }).handler(
  async (): Promise<{ presentation: Presentation; users: Operator[] } | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    const [config, roster] = await Promise.all([
      serviceJSON<{ payload?: { presentation?: Presentation } }>('/api/v1/config'),
      serviceJSON<{ users: Operator[] }>('/api/v1/users'),
    ])
    return { presentation: config?.payload?.presentation ?? {}, users: roster?.users ?? [] }
  },
)

const savePresentation = createServerFn({ method: 'POST' })
  .inputValidator((input: Presentation) => input)
  .handler(async ({ data }): Promise<boolean> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // Admin-gated at the BFF, same posture as the legacy settings API.
    if (user && user.role !== 'admin') return false
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/config/presentation', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(data),
    })
    return response.ok
  })

export const Route = createFileRoute('/settings')({
  loader: async () => ({ storage: fetchStorage(), admin: fetchAdminData(), user: await getSessionUser() }),
  component: Settings,
})

function PresentationCard({ initial, editable }: { initial: Presentation; editable: boolean }) {
  const [form, setForm] = useState<Presentation>(initial)
  const [message, setMessage] = useState('')
  const field = (key: keyof Presentation, label: string) => (
    <label className="note" style={{ display: 'block' }}>
      {label}
      <input
        className="input"
        style={{ width: '100%' }}
        type="text"
        value={(form[key] as string) ?? ''}
        disabled={!editable}
        onChange={(event) => setForm((current) => ({ ...current, [key]: event.target.value }))}
      />
    </label>
  )
  return (
    <div className="card half">
      <h2>Presentation</h2>
      <p className="note">Branding text across the dashboard — title, subtitle, footer, and an optional banner.</p>
      <form
        onSubmit={async (event) => {
          event.preventDefault()
          setMessage('Saving…')
          const ok = await savePresentation({ data: form })
          setMessage(ok ? 'Saved — refresh to see it everywhere.' : 'Save failed (admin role required).')
        }}
      >
        {field('dashboard_title', 'Dashboard title')}
        {field('dashboard_subtitle', 'Subtitle')}
        {field('footer_text', 'Footer')}
        {field('banner_text', 'Banner text')}
        {editable ? (
          <button className="btn btn-secondary btn-sm" type="submit" style={{ marginTop: 8 }}>
            Save presentation
          </button>
        ) : (
          <p className="note">Admin role required to edit.</p>
        )}
        {message ? <p className="note">{message}</p> : null}
      </form>
    </div>
  )
}

// The nine accent presets from theme.css (#32): claude is the default,
// the rest are data-hp-palette values. Swatch colors are the dark-theme
// accents; the applied palette resolves per-theme in CSS.
const PALETTES: { id: string; label: string; swatch: string }[] = [
  { id: 'claude', label: 'Claude', swatch: '#d97757' },
  { id: 'slate', label: 'Slate', swatch: '#8aa2c0' },
  { id: 'ocean', label: 'Ocean', swatch: '#55a7d8' },
  { id: 'sage', label: 'Sage', swatch: '#8fb27b' },
  { id: 'lavender', label: 'Lavender', swatch: '#ab93e3' },
  { id: 'rose', label: 'Rose', swatch: '#d98aa6' },
  { id: 'amber', label: 'Amber', swatch: '#deb36a' },
  { id: 'lime', label: 'Lime', swatch: '#b3c86a' },
  { id: 'neon', label: 'Neon', swatch: '#6adec2' },
]

function bytesHuman(bytes: number): string {
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`
  return `${bytes} B`
}

function Settings() {
  const { storage, admin, user } = Route.useLoaderData()
  const theme = useThemeMode()
  const [palette, setPalette] = useState('claude')
  const [prefetch, setPrefetch] = useState(true)
  const [storageData, setStorageData] = useState<Storage | null>(null)
  const [adminData, setAdminData] = useState<{ presentation: Presentation; users: Operator[] } | null>(null)

  useEffect(() => {
    setPalette(document.documentElement.dataset.hpPalette ?? 'claude')
    setPrefetch(prefetchEnabled())
    let cancelled = false
    storage.then((result) => {
      if (!cancelled && result) setStorageData(result)
    })
    admin.then((result) => {
      if (!cancelled && result) setAdminData(result)
    })
    return () => {
      cancelled = true
    }
  }, [storage, admin])

  const pickPalette = (id: string) => {
    applyPalette(id)
    setPalette(id)
  }

  const modes: { id: ThemeMode; label: string }[] = [
    { id: 'system', label: 'System' },
    { id: 'dark', label: 'Dark' },
    { id: 'light', label: 'Light' },
  ]

  return (
    <>
      <InvestigateHeader
        label="Operations"
        title="Settings"
        subtitle="Appearance, session, and storage — per-operator preferences apply instantly and follow you across devices on this browser."
      />
      <div className="card half">
        <h2>Appearance</h2>
        <p className="note">Theme mode</p>
        <div className="filters" role="radiogroup" aria-label="Theme mode">
          {modes.map((mode) => (
            <button
              key={mode.id}
              type="button"
              className={theme === mode.id ? 'chip is-active' : 'chip'}
              aria-pressed={theme === mode.id}
              onClick={() => applyTheme(mode.id)}
            >
              {mode.label}
            </button>
          ))}
        </div>
        <p className="note">Accent palette</p>
        <div className="filters" role="radiogroup" aria-label="Accent palette">
          {PALETTES.map((preset) => (
            <button
              key={preset.id}
              type="button"
              className={palette === preset.id ? 'chip is-active' : 'chip'}
              aria-pressed={palette === preset.id}
              onClick={() => pickPalette(preset.id)}
            >
              <span
                aria-hidden="true"
                style={{ display: 'inline-block', width: 10, height: 10, borderRadius: '50%', background: preset.swatch, marginRight: 6 }}
              />
              {preset.label}
            </button>
          ))}
        </div>
      </div>
      <div className="card half">
        <h2>Navigation</h2>
        <p className="note">
          Predictive prefetching warms the data for the pages you're most likely to open next, so navigation feels instant. Turn
          it off to only load pages on click.
        </p>
        <button
          type="button"
          className={prefetch ? 'chip is-active' : 'chip'}
          aria-pressed={prefetch}
          onClick={() => {
            setPrefetchEnabled(!prefetch)
            setPrefetch(!prefetch)
          }}
        >
          {prefetch ? 'Predictive prefetch: on' : 'Predictive prefetch: off'}
        </button>
      </div>
      <div className="card half">
        <h2>Account</h2>
        {user ? (
          <>
            <p className="note">
              Signed in as <strong>{user.displayName || user.username}</strong>
              {user.role ? <> · <span className="badge badge--muted">{user.role}</span></> : null}
            </p>
            <a className="btn btn-secondary btn-sm" href="/auth/logout">
              Sign out
            </a>
          </>
        ) : (
          <p className="note">No session (development mode).</p>
        )}
      </div>
      {adminData ? (
        <PresentationCard initial={adminData.presentation} editable={!user || user.role === 'admin'} />
      ) : null}
      {adminData ? (
        <div className="card half">
          <h2>Operators</h2>
          <p className="note">Everyone who has signed into this dashboard — accounts are managed in Keycloak.</p>
          <table className="data-table">
            <tbody>
              {adminData.users.map((operator) => (
                <tr key={operator.subject}>
                  <td className="v">{operator.username}</td>
                  <td>
                    <span className={operator.role === 'admin' ? 'badge badge--warning' : 'badge badge--muted'}>
                      {operator.role}
                    </span>
                  </td>
                  <td className="ago">{operator.last_seen_at.replace('T', ' ').slice(0, 19)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <div className="card half">
        <h2>Elasticsearch storage</h2>
        {storageData === null ? (
          <>
            <span className="skeleton-line" aria-hidden="true" />
            <span className="skeleton-line" aria-hidden="true" />
          </>
        ) : (
          <table className="data-table">
            <tbody>
              <tr>
                <td>Cluster</td>
                <td>
                  <span
                    className={
                      storageData.cluster_status === 'green'
                        ? 'badge badge--success'
                        : storageData.cluster_status === 'yellow'
                          ? 'badge badge--warning'
                          : 'badge badge--danger'
                    }
                  >
                    {storageData.cluster_status}
                  </span>
                </td>
              </tr>
              <tr>
                <td>Indices</td>
                <td className="n">{storageData.index_count.toLocaleString('en-US')}</td>
              </tr>
              <tr>
                <td>Documents</td>
                <td className="n">{storageData.doc_count.toLocaleString('en-US')}</td>
              </tr>
              <tr>
                <td>Store size</td>
                <td className="n">{bytesHuman(storageData.store_bytes)}</td>
              </tr>
            </tbody>
          </table>
        )}
      </div>
    </>
  )
}
