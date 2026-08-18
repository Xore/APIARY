// Settings — appearance (theme mode, accent palette presets, predictive
// prefetch), account, and ES storage, plus the admin operations panes
// ported from the legacy settings modal's Administration section: services
// (start/stop/restart honeypot sensors/probes/workers + logs), reporter
// stats, configuration history + rollback, and the settings audit log
// (#1612). Theme/palette use the same localStorage contract as the legacy
// tier (hp-theme / hp-palette).
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { str } from '../components/StoreList'
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

type ServiceRow = Record<string, unknown>
type ServicesResponse = { available: boolean; services: ServiceRow[]; reason?: string }

type HistoryEntry = { revision: number; time: string; actor_subject: string; actor_username: string; action: string; fields: string[] }
type HistoryResponse = { entries: HistoryEntry[] }

type AuditEvent = {
  time: string
  actor_subject: string
  actor_username: string
  action: string
  fields: string[]
  revision: number
  result: string
}
type AuditResponse = { events: AuditEvent[] }

type ReporterStats = { available: boolean; stats?: Record<string, unknown>; reason?: string }

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

const fetchServices = createServerFn({ method: 'GET' }).handler(async (): Promise<ServicesResponse | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<ServicesResponse>('/api/v1/services')
})

const fetchServiceLogs = createServerFn({ method: 'GET' })
  .inputValidator((input: { name: string }) => input)
  .handler(async ({ data }): Promise<{ name: string; lines: number; log: string } | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<{ name: string; lines: number; log: string }>(
      `/api/v1/services/${encodeURIComponent(data.name)}/logs?lines=200`,
    )
  })

const fetchHistory = createServerFn({ method: 'GET' }).handler(async (): Promise<HistoryResponse | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<HistoryResponse>('/api/v1/config/history')
})

const fetchAudit = createServerFn({ method: 'GET' })
  .inputValidator((input: { action: string }) => input)
  .handler(async ({ data }): Promise<AuditResponse | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    const query = data.action ? `?action=${encodeURIComponent(data.action)}` : ''
    return serviceJSON<AuditResponse>(`/api/v1/audit${query}`)
  })

const fetchReporterStats = createServerFn({ method: 'GET' }).handler(async (): Promise<ReporterStats | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<ReporterStats>('/api/v1/reporter-stats')
})

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

const runServiceAction = createServerFn({ method: 'POST' })
  .inputValidator((input: { name: string; action: 'start' | 'stop' | 'restart' }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // Admin-gated at the BFF — the Rust tier itself has no admin check.
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const params = new URLSearchParams({ actor_subject: user?.sub ?? '', actor_username: user?.username ?? '' })
    const response = await serviceFetch(
      `/api/v1/services/${encodeURIComponent(data.name)}/${data.action}?${params.toString()}`,
      { method: 'POST' },
    )
    const body = await response.json().catch(() => null)
    if (response.ok && body?.ok) return { ok: true }
    return { ok: false, error: body?.error || 'Action failed.' }
  })

const rollbackConfig = createServerFn({ method: 'POST' })
  .inputValidator((input: { revision: number }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/config/rollback', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ revision: data.revision, actor_subject: user?.sub ?? '', actor_username: user?.username ?? '' }),
    })
    if (response.ok) return { ok: true }
    return { ok: false, error: await response.text() }
  })

export const Route = createFileRoute('/settings')({
  loader: async () => ({
    storage: fetchStorage(),
    admin: fetchAdminData(),
    services: fetchServices(),
    history: fetchHistory(),
    audit: fetchAudit({ data: { action: '' } }),
    reporterStats: fetchReporterStats(),
    user: await getSessionUser(),
  }),
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

function stateBadge(state: string) {
  const cls =
    state === 'running'
      ? 'badge badge--success'
      : state === 'exited' || state === 'dead'
        ? 'badge badge--danger'
        : state === 'restarting' || state === 'paused' || state === 'created' || state === 'removing'
          ? 'badge badge--warning'
          : 'badge badge--muted' // not_found | unknown
  return <span className={cls}>{state}</span>
}

function ServicesCard({ initial, editable }: { initial: ServicesResponse | null; editable: boolean }) {
  const [data, setData] = useState<ServicesResponse | null>(initial)
  const [busyName, setBusyName] = useState<string | null>(null)
  const [message, setMessage] = useState('')
  const [logsFor, setLogsFor] = useState<string | null>(null)
  const [logsText, setLogsText] = useState('')
  const [logsBusy, setLogsBusy] = useState(false)

  useEffect(() => setData(initial), [initial])

  const refresh = async () => {
    const result = await fetchServices()
    if (result) setData(result)
  }

  const act = async (name: string, action: 'start' | 'stop' | 'restart') => {
    setBusyName(name)
    setMessage('')
    try {
      const result = await runServiceAction({ data: { name, action } })
      setMessage(result.ok ? `${action} sent to ${name}.` : result.error || 'Action failed.')
      if (result.ok) await refresh()
    } finally {
      setBusyName(null)
    }
  }

  const viewLogs = async (name: string) => {
    if (logsFor === name) {
      setLogsFor(null)
      return
    }
    setLogsFor(name)
    setLogsBusy(true)
    setLogsText('')
    try {
      const result = await fetchServiceLogs({ data: { name } })
      setLogsText(result?.log ?? '')
    } finally {
      setLogsBusy(false)
    }
  }

  return (
    <div className="card wide">
      <h2>Services</h2>
      <p className="note">
        Live container status for sensors, probes and workers. Actions cross a narrow allowlisted adapter — the dashboard
        never holds Docker access directly.
      </p>
      {data === null ? (
        <span className="skeleton-line" aria-hidden="true" />
      ) : !data.available ? (
        <p className="empty">{data.reason || 'Services adapter is not configured on this host.'}</p>
      ) : data.services.length === 0 ? (
        <p className="empty">No services reported.</p>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Service</th>
                <th>State</th>
                <th>Health</th>
                <th>Restarts</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.services.map((service) => {
                const name = str(service, 'name')
                return (
                  <tr key={name}>
                    <td className="v">{name}</td>
                    <td>{stateBadge(str(service, 'state'))}</td>
                    <td>{str(service, 'health') || '—'}</td>
                    <td className="n">{typeof service.restarts === 'number' ? service.restarts : '—'}</td>
                    <td>
                      <div className="filters">
                        <button
                          className="btn btn-secondary btn-sm"
                          type="button"
                          disabled={!editable || busyName !== null}
                          onClick={() => act(name, 'start')}
                        >
                          Start
                        </button>
                        <button
                          className="btn btn-secondary btn-sm"
                          type="button"
                          disabled={!editable || busyName !== null}
                          onClick={() => act(name, 'stop')}
                        >
                          Stop
                        </button>
                        <button
                          className="btn btn-secondary btn-sm"
                          type="button"
                          disabled={!editable || busyName !== null}
                          onClick={() => act(name, 'restart')}
                        >
                          Restart
                        </button>
                        <button className="btn btn-ghost btn-sm" type="button" onClick={() => viewLogs(name)}>
                          {logsFor === name ? 'Hide logs' : 'Logs'}
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      {!editable ? <p className="note">Admin role required to control services.</p> : null}
      {message ? <p className="note">{message}</p> : null}
      {logsFor ? (
        <>
          <p className="note">
            {logsFor} — most recent lines, newest at the bottom.
          </p>
          {logsBusy ? <span className="skeleton-line" aria-hidden="true" /> : <pre className="code">{logsText || 'No log output.'}</pre>}
        </>
      ) : null}
    </div>
  )
}

function ReporterStatsCard({ data }: { data: ReporterStats | null }) {
  const metric = (value: unknown): string => {
    if (typeof value === 'number') return value.toLocaleString('en-US')
    if (typeof value === 'boolean') return value ? 'yes' : 'no'
    if (typeof value === 'string' && value) return value
    return '—'
  }
  return (
    <div className="card half">
      <h2>Reporter stats</h2>
      <p className="note">The report-sender worker's own metrics — a quick glance at what it has attempted and sent.</p>
      {data === null ? (
        <>
          <span className="skeleton-line" aria-hidden="true" />
          <span className="skeleton-line" aria-hidden="true" />
        </>
      ) : !data.available ? (
        <p className="empty">{data.reason || 'No reporter metrics available.'}</p>
      ) : (
        <>
          <div className="metric-grid">
            <div className="metric">
              <div className="metric__label">Attempted</div>
              <div className="metric__value">{metric(data.stats?.attempted)}</div>
            </div>
            <div className="metric">
              <div className="metric__label">Sent</div>
              <div className="metric__value">{metric(data.stats?.sent)}</div>
            </div>
            <div className="metric">
              <div className="metric__label">Suppressed</div>
              <div className="metric__value">{metric(data.stats?.suppressed_cooldown)}</div>
            </div>
            <div className="metric">
              <div className="metric__label">Dry run</div>
              <div className="metric__value">{metric(data.stats?.dry_run)}</div>
            </div>
            <div className="metric">
              <div className="metric__label">Failed</div>
              <div className="metric__value">{metric(data.stats?.failed)}</div>
            </div>
          </div>
          {data.stats?.updated_at ? (
            <p className="note">Updated {String(data.stats.updated_at).replace('T', ' ').slice(0, 19)}</p>
          ) : null}
        </>
      )}
    </div>
  )
}

function ConfigHistoryCard({ initial, editable }: { initial: HistoryResponse | null; editable: boolean }) {
  const [data, setData] = useState<HistoryResponse | null>(initial)
  const [busy, setBusy] = useState<number | null>(null)
  const [message, setMessage] = useState('')

  useEffect(() => setData(initial), [initial])

  const rollback = async (revision: number) => {
    setBusy(revision)
    setMessage('')
    try {
      const result = await rollbackConfig({ data: { revision } })
      setMessage(result.ok ? `Rolled back to revision ${revision}.` : result.error || 'Rollback failed.')
      if (result.ok) {
        const fresh = await fetchHistory()
        if (fresh) setData(fresh)
      }
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="card wide">
      <h2>Configuration history</h2>
      <p className="note">Newest first. Rollback restores a retained revision as a new revision.</p>
      {data === null ? (
        <span className="skeleton-line" aria-hidden="true" />
      ) : data.entries.length === 0 ? (
        <p className="empty">No configuration changes recorded yet.</p>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Revision</th>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Fields</th>
                {editable ? <th>Rollback</th> : null}
              </tr>
            </thead>
            <tbody>
              {data.entries.map((entry) => (
                <tr key={entry.revision}>
                  <td className="n">{entry.revision}</td>
                  <td>{entry.time.replace('T', ' ').slice(0, 19)}</td>
                  <td>{entry.actor_username || entry.actor_subject || '—'}</td>
                  <td>
                    <span className="badge badge--muted">{entry.action}</span>
                  </td>
                  <td className="v">{entry.fields.join(', ')}</td>
                  {editable ? (
                    <td>
                      <button
                        className="btn btn-secondary btn-sm"
                        type="button"
                        disabled={busy !== null}
                        onClick={() => rollback(entry.revision)}
                      >
                        {busy === entry.revision ? 'Rolling back…' : 'Rollback'}
                      </button>
                    </td>
                  ) : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {message ? <p className="note">{message}</p> : null}
    </div>
  )
}

// Authoritative action strings, grepped from `action: "..."` across
// backend-service/src/*.rs (config.rs, services_control.rs, preferences.rs,
// credentials.rs, github_analysis_submit.rs, worker.rs).
const AUDIT_ACTIONS = [
  'config.update',
  'config.rollback',
  'services.start',
  'services.stop',
  'services.restart',
  'preferences.update',
  'credentials.create',
  'credentials.rotate',
  'github_analysis.submit',
  'users.retention',
]

function resultBadge(result: string) {
  const cls =
    result === 'success'
      ? 'badge badge--success'
      : result === 'conflict' || result === 'invalid'
        ? 'badge badge--warning'
        : 'badge badge--danger'
  return <span className={cls}>{result}</span>
}

function AuditLogCard({ initial }: { initial: AuditResponse | null }) {
  const [filter, setFilter] = useState('')
  const [data, setData] = useState<AuditResponse | null>(initial)

  useEffect(() => setData(initial), [initial])

  const applyFilter = async (action: string) => {
    setFilter(action)
    setData(null)
    const result = await fetchAudit({ data: { action } })
    setData(result ?? { events: [] })
  }

  return (
    <div className="card wide">
      <h2>Audit log</h2>
      <p className="note">Settings mutations, newest first. Sensitive values are never logged.</p>
      <select className="input" aria-label="Filter by action" value={filter} onChange={(event) => applyFilter(event.target.value)}>
        <option value="">All actions</option>
        {AUDIT_ACTIONS.map((action) => (
          <option key={action} value={action}>
            {action}
          </option>
        ))}
      </select>
      {data === null ? (
        <span className="skeleton-line" aria-hidden="true" />
      ) : data.events.length === 0 ? (
        <p className="empty">No audit events recorded yet.</p>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Fields</th>
                <th>Revision</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {data.events.map((event, index) => (
                <tr key={`${event.time}-${index}`}>
                  <td>{event.time.replace('T', ' ').slice(0, 19)}</td>
                  <td>{event.actor_username || event.actor_subject || '—'}</td>
                  <td>
                    <span className="badge badge--muted">{event.action}</span>
                  </td>
                  <td className="v">{event.fields.join(', ')}</td>
                  <td className="n">{event.revision || ''}</td>
                  <td>{resultBadge(event.result)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
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
  const { storage, admin, services, history, audit, reporterStats, user } = Route.useLoaderData()
  const theme = useThemeMode()
  const [palette, setPalette] = useState('claude')
  const [prefetch, setPrefetch] = useState(true)
  const [storageData, setStorageData] = useState<Storage | null>(null)
  const [adminData, setAdminData] = useState<{ presentation: Presentation; users: Operator[] } | null>(null)
  const [servicesData, setServicesData] = useState<ServicesResponse | null>(null)
  const [historyData, setHistoryData] = useState<HistoryResponse | null>(null)
  const [auditData, setAuditData] = useState<AuditResponse | null>(null)
  const [reporterStatsData, setReporterStatsData] = useState<ReporterStats | null>(null)

  const isAdmin = !user || user.role === 'admin'

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
    services.then((result) => {
      if (!cancelled) setServicesData(result)
    })
    history.then((result) => {
      if (!cancelled) setHistoryData(result)
    })
    audit.then((result) => {
      if (!cancelled) setAuditData(result)
    })
    reporterStats.then((result) => {
      if (!cancelled) setReporterStatsData(result)
    })
    return () => {
      cancelled = true
    }
  }, [storage, admin, services, history, audit, reporterStats])

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
      {adminData ? <PresentationCard initial={adminData.presentation} editable={isAdmin} /> : null}
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
      <ReporterStatsCard data={reporterStatsData} />
      <ServicesCard initial={servicesData} editable={isAdmin} />
      <ConfigHistoryCard initial={historyData} editable={isAdmin} />
      <AuditLogCard initial={auditData} />
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
