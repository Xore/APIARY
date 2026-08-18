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

const fetchStorage = createServerFn({ method: 'GET' }).handler(async (): Promise<Storage | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<Storage>('/api/v1/settings/storage')
})

export const Route = createFileRoute('/settings')({
  loader: async () => ({ storage: fetchStorage(), user: await getSessionUser() }),
  component: Settings,
})

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
  const { storage, user } = Route.useLoaderData()
  const theme = useThemeMode()
  const [palette, setPalette] = useState('claude')
  const [prefetch, setPrefetch] = useState(true)
  const [storageData, setStorageData] = useState<Storage | null>(null)

  useEffect(() => {
    setPalette(document.documentElement.dataset.hpPalette ?? 'claude')
    setPrefetch(prefetchEnabled())
    let cancelled = false
    storage.then((result) => {
      if (!cancelled && result) setStorageData(result)
    })
    return () => {
      cancelled = true
    }
  }, [storage])

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
