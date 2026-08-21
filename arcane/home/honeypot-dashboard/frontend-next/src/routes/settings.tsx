// Settings — appearance (theme mode, accent palette presets, predictive
// prefetch), account, and ES storage, plus the admin operations panes
// ported from the legacy settings modal's Administration section: services
// (start/stop/restart honeypot sensors/probes/workers + logs), reporter
// stats, configuration history + rollback, the settings audit log,
// Branding & text (full presentation.* field list), Honeypot operations
// (staged operational thresholds), Dashboard behavior (live global
// defaults + feature visibility), and Report Studio presets (#1612).
// Theme/palette use the same localStorage contract as the legacy tier
// (hp-theme / hp-palette) with a server write-through (see lib/prefs.ts).
// #1653 restores the rest of the legacy modal's personal-preference panes
// (settings_modal.html:103-381 / hp-settings.js:294-651) against the same
// preference store: per-pane dirty-gated saves through the shared confirm
// dialog, hp-settings-status status lines, and timezone/clock mirrored to
// localStorage (hp-tz / hp-clock) so lib/time.ts picks them up instantly.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { confirmAction } from '../components/ConfirmDialog'
import { InvestigateHeader } from '../components/Investigate'
import { str } from '../components/StoreList'
import { applyPalette, applyTheme, pullServerTheme, useThemeMode, type ThemeMode } from '../lib/prefs'
import type { JsonRecord } from '../lib/json'
import { prefetchEnabled, setPrefetchEnabled } from '../lib/prefetch'
import { getSessionUser } from '../lib/auth'
import { formatTimestamp, writeTimePrefs } from '../lib/time'

type Storage = { cluster_status: string; index_count: number; doc_count: number; store_bytes: number }

// The full presentation.* field list from the legacy settings modal's
// "Branding & text" pane (data-hp-pane="branding") — config.rs's
// put_presentation round-trips whatever JSON object it's given, so this
// widening is frontend-only.
type Presentation = {
  app_name?: string
  product_label?: string
  dashboard_title?: string
  dashboard_subtitle?: string
  org_name?: string
  overview_intro?: string
  help_link_label?: string
  help_link_url?: string
  banner_text?: string
  banner_severity?: string
  banner_expires?: string
  footer_text?: string
  ai_disclaimer?: string
  privacy_notice?: string
}

// Honeypot operations (data-hp-pane="honeypot"): staged thresholds — saving
// updates the config store only, the consuming services pick them up on
// their next restart. Numbers travel as strings in form state so an
// in-progress edit or an empty field never fights the input.
type HoneypotConfig = {
  alert_cooldown?: string
  alert_campaign_score?: number
  sandbox_alert_risk_score?: number
  ml_alert_threshold?: number
  yara_scan_interval_seconds?: number
  yara_max_bytes?: number
  payload_dedupe_interval_seconds?: number
}

// Dashboard behavior (data-hp-pane="behavior"): global defaults + feature
// visibility toggles, applied live for every user.
type BehaviorConfig = {
  default_landing?: string
  default_time_window?: string
  rows_per_page_options?: number[]
  max_export_rows?: number
  refresh_interval_seconds_options?: number[]
  source_stale_minutes?: number
  map_provider?: string
  default_timezone?: string
  show_ml_panels?: boolean
  maintenance_mode?: boolean
  read_only?: boolean
  show_problem_report_button?: boolean
}

// Report Studio presets (data-hp-pane="report-presets"): per-template
// name/description override, keyed by template id. An empty field falls
// back to the compiled default (shown as its placeholder).
type ReportPresetOverride = { name?: string; description?: string }
type ReportTemplate = { id: string; name: string; description: string }

type Operator = { subject: string; username: string; role: string; first_seen_at: string; last_seen_at: string }

type ServiceRow = JsonRecord
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

type ReporterStats = { available: boolean; stats?: JsonRecord; reason?: string }

const fetchStorage = createServerFn({ method: 'GET' }).handler(async (): Promise<Storage | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<Storage>('/api/v1/settings/storage')
})

type AdminConfig = {
  presentation: Presentation
  honeypot: HoneypotConfig
  behavior: BehaviorConfig
  reportPresets: Record<string, ReportPresetOverride>
  reportTemplates: ReportTemplate[]
  users: Operator[]
}

const fetchAdminData = createServerFn({ method: 'GET' }).handler(async (): Promise<AdminConfig | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  const [config, roster, reports] = await Promise.all([
    serviceJSON<{
      payload?: {
        presentation?: Presentation
        honeypot?: HoneypotConfig
        behavior?: BehaviorConfig
        report_presets?: Record<string, ReportPresetOverride>
      }
    }>('/api/v1/config'),
    serviceJSON<{ users: Operator[] }>('/api/v1/users'),
    serviceJSON<{ templates: ReportTemplate[] }>('/api/v1/reports/templates'),
  ])
  return {
    presentation: config?.payload?.presentation ?? {},
    honeypot: config?.payload?.honeypot ?? {},
    behavior: config?.payload?.behavior ?? {},
    reportPresets: config?.payload?.report_presets ?? {},
    reportTemplates: reports?.templates ?? [],
    users: roster?.users ?? [],
  }
})

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

// Personal preferences (#1653): the full field set the Rust tier's
// PreferencesPatch accepts (preferences.rs, ported from settings_api.go's
// preferencesPatch). Theme/palette also appear here — the appearance card
// above the panes owns those two — the panes own the rest.
type Prefs = {
  theme?: string
  palette?: string
  density?: string
  reduced_motion?: string
  collapsed_sidebar?: boolean
  landing_page?: string
  remember_filters?: boolean
  rows_per_page?: number
  wrap_long_values?: boolean
  timezone?: string
  clock?: string
  timestamps?: string
  auto_refresh?: boolean
  refresh_interval_seconds?: number
  live_toasts?: boolean
  map_basemap?: string
  map_clustering?: boolean
  map_animation?: boolean
  high_contrast?: boolean
  large_evidence_text?: boolean
  notify_severity?: string
  notify_sound?: boolean
  notify_desktop?: boolean
  default_event_window?: string
  preserve_filters?: boolean
  open_details_new_tab?: boolean
}
type PrefKey = keyof Prefs

const fetchPreferences = createServerFn({ method: 'GET' }).handler(async (): Promise<Prefs | null> => {
  const { getSessionUser } = await import('../lib/auth')
  const user = await getSessionUser()
  if (!user) return null
  const { serviceJSON } = await import('../lib/backend.server')
  // GET creates the projection with compiled defaults on first contact,
  // so a brand-new operator sees real values, not blanks.
  const params = new URLSearchParams({ subject: user.sub, username: user.username, role: user.role })
  const result = await serviceJSON<{ preferences?: Prefs }>(`/api/v1/preferences?${params.toString()}`)
  return result?.preferences ?? null
})

const putPreferences = createServerFn({ method: 'POST' })
  .inputValidator((input: { patch: Prefs }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; preferences?: Prefs; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user) return { ok: false, error: 'no session' }
    const { serviceFetch } = await import('../lib/backend.server')
    const body = JSON.stringify({ subject: user.sub, username: user.username, patch: data.patch })
    const put = () =>
      serviceFetch('/api/v1/preferences', { method: 'PUT', headers: { 'content-type': 'application/json' }, body })
    let response = await put()
    if (response.status === 404) {
      // No settings record yet: GET creates it, then retry once — the
      // same dance lib/prefs.ts's pushAppearancePreference does.
      const params = new URLSearchParams({ subject: user.sub, username: user.username, role: user.role })
      await serviceFetch(`/api/v1/preferences?${params.toString()}`)
      response = await put()
    }
    if (!response.ok) return { ok: false, error: await response.text().catch(() => 'save failed') }
    const result = (await response.json().catch(() => null)) as { preferences?: Prefs } | null
    return { ok: true, preferences: result?.preferences }
  })

const resetPreferences = createServerFn({ method: 'POST' }).handler(
  async (): Promise<{ ok: boolean; preferences?: Prefs; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user) return { ok: false, error: 'no session' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/preferences/reset', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ subject: user.sub, username: user.username }),
    })
    if (!response.ok) return { ok: false, error: await response.text().catch(() => 'reset failed') }
    const result = (await response.json().catch(() => null)) as { preferences?: Prefs } | null
    return { ok: true, preferences: result?.preferences }
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

// Backs the three new admin panes — targets PUT /api/v1/config/{section},
// mirroring savePresentation's admin gate and error handling exactly.
const saveConfigSection = createServerFn({ method: 'POST' })
  .inputValidator((input: { section: 'honeypot' | 'behavior' | 'report-presets'; value: unknown }) => input)
  .handler(async ({ data }): Promise<boolean> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return false
    const { serviceFetch } = await import('../lib/backend.server')
    const params = new URLSearchParams({ actor_subject: user?.sub ?? '', actor_username: user?.username ?? '' })
    const response = await serviceFetch(`/api/v1/config/${data.section}?${params.toString()}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(data.value),
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
    preferences: fetchPreferences(),
    admin: fetchAdminData(),
    services: fetchServices(),
    history: fetchHistory(),
    audit: fetchAudit({ data: { action: '' } }),
    reporterStats: fetchReporterStats(),
    user: await getSessionUser(),
  }),
  component: Settings,
})

const BANNER_SEVERITIES = ['', 'info', 'success', 'warning', 'danger']

function errorText(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).trim()
}

// The status-line contract from hp-settings.js's setStatus (:325-331):
// success announcements auto-clear after ~5s, errors persist until the
// next status replaces them. theme.css:3857's hp-settings-status classes.
function useSettingsStatus(): [ReactNode, (text: string, kind?: 'ok' | 'error') => void] {
  const [status, setStatusState] = useState<{ text: string; kind?: 'ok' | 'error' }>({ text: '' })
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const setStatus = useCallback((text: string, kind?: 'ok' | 'error') => {
    if (timer.current) clearTimeout(timer.current)
    setStatusState({ text, kind })
    if (kind === 'ok') timer.current = setTimeout(() => setStatusState({ text: '' }), 5000)
  }, [])
  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current)
    },
    [],
  )
  const node = (
    <p className={`hp-settings-status${status.kind ? ` is-${status.kind}` : ''}`} role="status">
      {status.text}
    </p>
  )
  return [node, setStatus]
}

function SwitchRow({
  label,
  desc,
  checked,
  disabled,
  onChange,
}: {
  label: string
  desc: string
  checked: boolean
  disabled?: boolean
  onChange: (value: boolean) => void
}) {
  return (
    <div className="card__row">
      <div>
        <div className="card__label">{label}</div>
        <div className="card__value">{desc}</div>
      </div>
      <label className="switch">
        <input
          type="checkbox"
          aria-label={label}
          checked={checked}
          disabled={disabled}
          onChange={(event) => onChange(event.target.checked)}
        />
        <span></span>
      </label>
    </div>
  )
}

// Segmented picker matching the Go markup exactly: role="group" of
// aria-pressed buttons (settings_modal.html:103-141) — theme.css styles
// the active option off [aria-pressed="true"].
function Segmented({
  label,
  value,
  options,
  onChange,
  desc,
}: {
  label: string
  value: string
  options: { value: string; label: string }[]
  onChange: (value: string) => void
  desc?: string
}) {
  return (
    <div className="settings-field">
      <span className="form-label">{label}</span>
      <div className="segmented" role="group" aria-label={label}>
        {options.map((option) => (
          <button
            key={option.value}
            type="button"
            data-value={option.value}
            aria-pressed={value === option.value}
            onClick={() => onChange(option.value)}
          >
            {option.label}
          </button>
        ))}
      </div>
      {desc ? <div className="settings-field__desc">{desc}</div> : null}
    </div>
  )
}

// Per-pane field lists — dirty tracking and the confirm dialog's
// "Apply these changes: …" copy both come from these, matching
// hp-settings.js's collectPatch/requestSave (:559-596).
const PREF_PANES = {
  navigation: ['landing_page', 'collapsed_sidebar', 'remember_filters', 'open_details_new_tab', 'rows_per_page', 'wrap_long_values'],
  time: ['timezone', 'clock', 'timestamps', 'auto_refresh', 'refresh_interval_seconds', 'live_toasts'],
  notifications: ['notify_severity', 'notify_sound', 'notify_desktop'],
  map: ['map_basemap', 'map_clustering', 'map_animation', 'default_event_window', 'preserve_filters'],
  appearance: ['density', 'reduced_motion', 'high_contrast', 'large_evidence_text'],
} satisfies Record<string, PrefKey[]>
type PaneName = keyof typeof PREF_PANES

// The personal landing-page choices from settings_modal.html:168-181 —
// wider than the admin default_landing list on purpose.
const PREF_LANDING_PAGES: [string, string][] = [
  ['/', 'Overview'],
  ['/events', 'Event explorer'],
  ['/alerts', 'Alerts'],
  ['/source-health', 'Sensor & pipeline health'],
  ['/ips', 'Attack sources'],
  ['/payloads', 'Captured payloads'],
  ['/payload-workbench/results', 'Analysis results'],
  ['/campaigns', 'Campaigns'],
  ['/clusters', 'Infrastructure clusters'],
  ['/commands', 'Executed commands'],
  ['/history', 'Elasticsearch history'],
  ['/dead-letters', 'Ingest dead letters'],
]

// IANA starting-point suggestions from settings_modal.html:242-269 — a
// datalist, not a closed enum: any real zone name is accepted.
const TZ_SUGGESTIONS: [string, string][] = [
  ['America/New_York', 'USA — Eastern'],
  ['America/Chicago', 'USA — Central'],
  ['America/Denver', 'USA — Mountain'],
  ['America/Los_Angeles', 'USA — Pacific'],
  ['Europe/Berlin', 'Germany'],
  ['Asia/Shanghai', 'China'],
  ['Europe/London', 'England (UK)'],
  ['Europe/Paris', 'France'],
  ['Europe/Madrid', 'Spain'],
  ['Europe/Rome', 'Italy'],
  ['Europe/Amsterdam', 'Netherlands'],
  ['Europe/Moscow', 'Russia — Moscow'],
  ['Asia/Tokyo', 'Japan'],
  ['Asia/Seoul', 'South Korea'],
  ['Asia/Kolkata', 'India'],
  ['Asia/Singapore', 'Singapore'],
  ['Asia/Dubai', 'UAE'],
  ['Australia/Sydney', 'Australia — Sydney'],
  ['Australia/Perth', 'Australia — Perth'],
  ['Pacific/Auckland', 'New Zealand'],
  ['America/Sao_Paulo', 'Brazil'],
  ['America/Mexico_City', 'Mexico'],
  ['America/Toronto', 'Canada — Eastern'],
  ['Africa/Johannesburg', 'South Africa'],
  ['browser', "browser — this device's own zone"],
  ['utc', 'utc'],
]

const REFRESH_INTERVALS: [number, string][] = [
  [10, 'Every 10 seconds'],
  [15, 'Every 15 seconds'],
  [30, 'Every 30 seconds'],
  [60, 'Every minute'],
  [120, 'Every 2 minutes'],
  [300, 'Every 5 minutes'],
]

// Preference side effects other parts of this frontend read from
// localStorage mirrors, applied immediately on save so the operator never
// has to reload to see their own change (hp-settings.js:519-544):
// timezone/clock feed lib/time.ts's formatTimestamp (hp-tz / hp-clock),
// the sidebar flag feeds AppShell's collapse boot check.
function applyPrefSideEffects(prefs: Prefs) {
  writeTimePrefs({
    tz: prefs.timezone || 'browser',
    clock: prefs.clock === 'h12' ? 'h12' : 'h24',
  })
  try {
    if (prefs.collapsed_sidebar) localStorage.setItem('hp-sidebar-collapsed', '1')
    else localStorage.removeItem('hp-sidebar-collapsed')
  } catch {
    /* storage unavailable */
  }
}

// The five personal-preference panes from the legacy settings modal
// (settings_modal.html:103-381), backed by GET/PUT /api/v1/preferences.
function PreferencesPanes({ initial, onReset }: { initial: Prefs; onReset: (prefs: Prefs) => void }) {
  const [snapshot, setSnapshot] = useState<Prefs>(initial)
  const [form, setForm] = useState<Prefs>(initial)
  const [navStatus, setNavStatus] = useSettingsStatus()
  const [timeStatus, setTimeStatus] = useSettingsStatus()
  const [notifyStatus, setNotifyStatus] = useSettingsStatus()
  const [mapStatus, setMapStatus] = useSettingsStatus()
  const [appearanceStatus, setAppearanceStatus] = useSettingsStatus()
  const [resetStatus, setResetStatus] = useSettingsStatus()

  const patch = <K extends PrefKey>(key: K, value: Prefs[K]) => setForm((current) => ({ ...current, [key]: value }))

  const changedFields = (pane: PaneName): PrefKey[] =>
    PREF_PANES[pane].filter((key) => JSON.stringify(form[key]) !== JSON.stringify(snapshot[key]))

  const requestSave = (pane: PaneName, setStatus: (text: string, kind?: 'ok' | 'error') => void) => {
    const fields = changedFields(pane)
    if (fields.length === 0) return
    const body: Prefs = {}
    const take = <K extends PrefKey>(key: K) => {
      body[key] = form[key]
    }
    fields.forEach(take)
    confirmAction({
      title: 'Save preferences?',
      description: `Apply these changes: ${fields.join(', ')}.`,
      confirmLabel: 'Save preferences',
      danger: false,
      onConfirm: async () => {
        setStatus('Saving…')
        try {
          const result = await putPreferences({ data: { patch: body } })
          if (!result.ok || !result.preferences) throw new Error(result.error?.trim() || 'save failed')
          setSnapshot(result.preferences)
          setForm(result.preferences)
          applyPrefSideEffects(result.preferences)
          setStatus('Preferences saved.', 'ok')
        } catch (error) {
          setStatus(`Preferences could not be saved — ${errorText(error)}`, 'error')
          throw error
        }
      },
    })
  }

  const requestReset = () => {
    confirmAction({
      title: 'Reset all preferences?',
      description: 'Every preference returns to its default. This cannot be undone.',
      warning: 'This resets appearance, navigation, time, and map preferences in one step.',
      confirmLabel: 'Reset everything',
      danger: true,
      onConfirm: async () => {
        setResetStatus('Resetting…')
        try {
          const result = await resetPreferences()
          if (!result.ok || !result.preferences) throw new Error(result.error?.trim() || 'reset failed')
          const prefs = result.preferences
          setSnapshot(prefs)
          setForm(prefs)
          applyPrefSideEffects(prefs)
          // The reset also returns theme/palette to their defaults; apply
          // locally without re-pushing what the server already holds.
          applyTheme(prefs.theme === 'dark' || prefs.theme === 'light' ? prefs.theme : 'system', { sync: false })
          applyPalette(prefs.palette ?? 'claude', { sync: false })
          onReset(prefs)
          setResetStatus('All preferences reset to defaults.', 'ok')
        } catch (error) {
          setResetStatus(`Preferences could not be reset — ${errorText(error)}`, 'error')
          throw error
        }
      },
    })
  }

  const saveButton = (pane: PaneName, setStatus: (text: string, kind?: 'ok' | 'error') => void) => (
    <div className="settings-actions">
      <button
        className="btn btn-primary"
        type="button"
        disabled={changedFields(pane).length === 0}
        onClick={() => requestSave(pane, setStatus)}
      >
        Save changes
      </button>
    </div>
  )

  return (
    <>
      <div className="card half">
        <h2>Navigation &amp; tables</h2>
        {navStatus}
        <div className="settings-grid">
          <div className="settings-field">
            <label className="form-label" htmlFor="hp-pref-landing">
              Landing page
            </label>
            <select
              className="form-input"
              id="hp-pref-landing"
              value={form.landing_page ?? '/'}
              onChange={(event) => patch('landing_page', event.target.value)}
            >
              {PREF_LANDING_PAGES.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
            <div className="settings-field__desc">First page after sign-in.</div>
          </div>
          <div className="settings-field">
            <label className="form-label" htmlFor="hp-pref-rows">
              Rows per page
            </label>
            <select
              className="form-input"
              id="hp-pref-rows"
              value={String(form.rows_per_page ?? 50)}
              onChange={(event) => patch('rows_per_page', Number(event.target.value))}
            >
              {[10, 25, 50, 100].map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </div>
        </div>
        <SwitchRow
          label="Collapsed sidebar"
          desc="Start with the navigation rail minimized on wide screens."
          checked={form.collapsed_sidebar ?? false}
          onChange={(value) => patch('collapsed_sidebar', value)}
        />
        <SwitchRow
          label="Remember filters"
          desc="Keep table filters when navigating between pages."
          checked={form.remember_filters ?? false}
          onChange={(value) => patch('remember_filters', value)}
        />
        <SwitchRow
          label="Open details in a new tab"
          desc="Sessions and payload analysis open alongside the current view."
          checked={form.open_details_new_tab ?? false}
          onChange={(value) => patch('open_details_new_tab', value)}
        />
        <SwitchRow
          label="Wrap long values"
          desc="Wrap commands and payloads instead of truncating them."
          checked={form.wrap_long_values ?? false}
          onChange={(value) => patch('wrap_long_values', value)}
        />
        {saveButton('navigation', setNavStatus)}
      </div>
      <div className="card half">
        <h2>Time &amp; live data</h2>
        {timeStatus}
        <div className="settings-grid">
          <div className="settings-field">
            <label className="form-label" htmlFor="hp-pref-timezone">
              Timezone
            </label>
            <input
              className="form-input"
              id="hp-pref-timezone"
              list="hp-tz-suggestions"
              autoComplete="off"
              spellCheck={false}
              placeholder="browser"
              value={form.timezone ?? ''}
              onChange={(event) => patch('timezone', event.target.value)}
            />
            <datalist id="hp-tz-suggestions">
              {TZ_SUGGESTIONS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </datalist>
            <div className="settings-field__desc">
              "browser", "utc", or an IANA zone such as Europe/Berlin — start typing to see suggestions.
            </div>
          </div>
          <div className="settings-field">
            <label className="form-label" htmlFor="hp-pref-refresh">
              Refresh interval
            </label>
            <select
              className="form-input"
              id="hp-pref-refresh"
              value={String(form.refresh_interval_seconds ?? 30)}
              onChange={(event) => patch('refresh_interval_seconds', Number(event.target.value))}
            >
              {REFRESH_INTERVALS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </div>
        </div>
        <Segmented
          label="Clock format"
          value={form.clock ?? 'h24'}
          options={[
            { value: 'h24', label: '24-hour' },
            { value: 'h12', label: '12-hour' },
          ]}
          onChange={(value) => patch('clock', value)}
        />
        <Segmented
          label="Timestamps"
          value={form.timestamps ?? 'relative'}
          options={[
            { value: 'relative', label: 'Relative' },
            { value: 'absolute', label: 'Absolute' },
          ]}
          onChange={(value) => patch('timestamps', value)}
        />
        <SwitchRow
          label="Auto-refresh"
          desc="Keep dashboard pages updating in the background."
          checked={form.auto_refresh ?? true}
          onChange={(value) => patch('auto_refresh', value)}
        />
        <SwitchRow
          label="Live event toasts"
          desc="Show a toast when new honeypot events arrive."
          checked={form.live_toasts ?? true}
          onChange={(value) => patch('live_toasts', value)}
        />
        {saveButton('time', setTimeStatus)}
      </div>
      <div className="card half">
        <h2>Notifications</h2>
        {notifyStatus}
        <div className="settings-grid">
          <div className="settings-field">
            <label className="form-label" htmlFor="hp-pref-severity">
              Minimum severity
            </label>
            <select
              className="form-input"
              id="hp-pref-severity"
              value={form.notify_severity ?? 'high'}
              onChange={(event) => patch('notify_severity', event.target.value)}
            >
              <option value="low">Low and above</option>
              <option value="medium">Medium and above</option>
              <option value="high">High and above</option>
              <option value="critical">Critical only</option>
            </select>
          </div>
        </div>
        <SwitchRow
          label="Notification sound"
          desc="Play a short tone for qualifying alerts."
          checked={form.notify_sound ?? false}
          onChange={(value) => patch('notify_sound', value)}
        />
        <SwitchRow
          label="Desktop notifications"
          desc="Uses the browser notification permission."
          checked={form.notify_desktop ?? false}
          onChange={(value) => patch('notify_desktop', value)}
        />
        {saveButton('notifications', setNotifyStatus)}
      </div>
      <div className="card half">
        <h2>Map &amp; investigation</h2>
        {mapStatus}
        <div className="settings-grid">
          <div className="settings-field">
            <label className="form-label" htmlFor="hp-pref-basemap">
              Basemap
            </label>
            <select
              className="form-input"
              id="hp-pref-basemap"
              value={form.map_basemap ?? 'osm'}
              onChange={(event) => patch('map_basemap', event.target.value)}
            >
              <option value="osm">OpenStreetMap</option>
            </select>
          </div>
          <div className="settings-field">
            <label className="form-label" htmlFor="hp-pref-window">
              Default event window
            </label>
            <select
              className="form-input"
              id="hp-pref-window"
              value={form.default_event_window ?? '24h'}
              onChange={(event) => patch('default_event_window', event.target.value)}
            >
              {WINDOW_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
        </div>
        <SwitchRow
          label="Cluster markers"
          desc="Group nearby attack origins at low zoom levels."
          checked={form.map_clustering ?? true}
          onChange={(value) => patch('map_clustering', value)}
        />
        <SwitchRow
          label="Map animation"
          desc="Animate zoom and pan transitions."
          checked={form.map_animation ?? true}
          onChange={(value) => patch('map_animation', value)}
        />
        <SwitchRow
          label="Preserve filters while drilling down"
          desc="Carry the current filter set into linked investigations."
          checked={form.preserve_filters ?? false}
          onChange={(value) => patch('preserve_filters', value)}
        />
        {saveButton('map', setMapStatus)}
      </div>
      <div className="card half">
        <h2>Readability &amp; density</h2>
        {appearanceStatus}
        <Segmented
          label="Density"
          value={form.density ?? 'comfortable'}
          options={[
            { value: 'comfortable', label: 'Comfortable' },
            { value: 'compact', label: 'Compact' },
          ]}
          onChange={(value) => patch('density', value)}
        />
        <Segmented
          label="Motion"
          value={form.reduced_motion ?? 'system'}
          options={[
            { value: 'system', label: 'System' },
            { value: 'on', label: 'Reduced' },
            { value: 'off', label: 'Full' },
          ]}
          onChange={(value) => patch('reduced_motion', value)}
          desc='"Reduced" minimizes non-essential animation.'
        />
        <SwitchRow
          label="High contrast"
          desc="Strengthens borders and text separation."
          checked={form.high_contrast ?? false}
          onChange={(value) => patch('high_contrast', value)}
        />
        <SwitchRow
          label="Larger evidence text"
          desc="Increases the font size of raw logs and payload evidence."
          checked={form.large_evidence_text ?? false}
          onChange={(value) => patch('large_evidence_text', value)}
        />
        {saveButton('appearance', setAppearanceStatus)}
      </div>
      <div className="card half">
        <h2>Reset preferences</h2>
        <p className="note">Returns every personal preference — appearance included — to its default.</p>
        {resetStatus}
        <div className="settings-actions">
          <button className="btn btn-danger btn-sm" type="button" onClick={requestReset}>
            Reset all preferences
          </button>
        </div>
      </div>
    </>
  )
}

const PRESENTATION_FIELDS: (keyof Presentation)[] = [
  'app_name',
  'product_label',
  'dashboard_title',
  'dashboard_subtitle',
  'org_name',
  'overview_intro',
  'help_link_label',
  'help_link_url',
  'banner_text',
  'banner_severity',
  'banner_expires',
  'footer_text',
  'ai_disclaimer',
  'privacy_notice',
]

function PresentationCard({ initial, editable }: { initial: Presentation; editable: boolean }) {
  const [form, setForm] = useState<Presentation>(initial)
  const [snapshot, setSnapshot] = useState<Presentation>(initial)
  const [status, setStatus] = useSettingsStatus()
  const changed = PRESENTATION_FIELDS.filter((key) => (form[key] ?? '') !== (snapshot[key] ?? ''))
  const set = (key: keyof Presentation, value: string) => setForm((current) => ({ ...current, [key]: value }))
  const field = (key: keyof Presentation, label: string, extra?: { type?: string; placeholder?: string }) => (
    <label className="note" style={{ display: 'block' }}>
      {label}
      <input
        className="form-input"
        style={{ width: '100%' }}
        type="text"
        value={(form[key] as string) ?? ''}
        disabled={!editable}
        onChange={(event) => set(key, event.target.value)}
        {...extra}
      />
    </label>
  )
  const textarea = (key: keyof Presentation, label: string) => (
    <label className="note" style={{ display: 'block' }}>
      {label}
      <textarea
        className="form-input"
        style={{ width: '100%' }}
        rows={2}
        value={(form[key] as string) ?? ''}
        disabled={!editable}
        onChange={(event) => set(key, event.target.value)}
      />
    </label>
  )
  return (
    <div className="card wide">
      <h2>Presentation</h2>
      <p className="note">Branding text across the dashboard, and the help/notice copy shown alongside it.</p>
      <form
        onSubmit={(event) => {
          event.preventDefault()
          if (changed.length === 0) return
          // hp-settings.js:831-835's exact copy convention: name the
          // changed fields in the confirmation.
          confirmAction({
            title: 'Save configuration?',
            description: `Apply these changes: ${changed.join(', ')}.`,
            confirmLabel: 'Save configuration',
            danger: false,
            onConfirm: async () => {
              setStatus('Saving…')
              try {
                const ok = await savePresentation({ data: form })
                if (!ok) throw new Error('save failed (admin role required)')
                setSnapshot(form)
                setStatus('Saved — refresh to see it everywhere.', 'ok')
              } catch (error) {
                setStatus(`Configuration could not be saved — ${errorText(error)}`, 'error')
                throw error
              }
            },
          })
        }}
      >
        <div className="settings-grid">
          {field('app_name', 'Application name')}
          {field('product_label', 'Product label')}
          {field('dashboard_title', 'Dashboard title')}
          {field('dashboard_subtitle', 'Subtitle')}
          {field('org_name', 'Organization name')}
          {field('help_link_label', 'Help link label')}
          {field('help_link_url', 'Help link URL (https only)', { type: 'url', placeholder: 'https://' })}
          {field('footer_text', 'Footer text')}
          {field('banner_text', 'Banner text')}
          <label className="note" style={{ display: 'block' }}>
            Banner severity
            <select
              className="form-input"
              style={{ width: '100%' }}
              value={form.banner_severity ?? ''}
              disabled={!editable}
              onChange={(event) => set('banner_severity', event.target.value)}
            >
              {BANNER_SEVERITIES.map((severity) => (
                <option key={severity} value={severity}>
                  {severity || 'None'}
                </option>
              ))}
            </select>
          </label>
          {field('banner_expires', 'Banner expiry (RFC 3339, empty = no expiry)', { placeholder: '2026-08-01T00:00:00Z' })}
        </div>
        {textarea('overview_intro', 'Overview introduction')}
        {textarea('ai_disclaimer', 'AI analysis disclaimer')}
        {textarea('privacy_notice', 'Evidence-handling / privacy notice')}
        {editable ? (
          <button className="btn btn-secondary btn-sm" type="submit" style={{ marginTop: 8 }} disabled={changed.length === 0}>
            Save presentation
          </button>
        ) : (
          <p className="note">Admin role required to edit.</p>
        )}
        {status}
      </form>
    </div>
  )
}

function HoneypotOperationsCard({ initial, editable }: { initial: HoneypotConfig; editable: boolean }) {
  const [form, setForm] = useState<Record<string, string>>({
    alert_cooldown: initial.alert_cooldown ?? '',
    alert_campaign_score: initial.alert_campaign_score?.toString() ?? '',
    sandbox_alert_risk_score: initial.sandbox_alert_risk_score?.toString() ?? '',
    ml_alert_threshold: initial.ml_alert_threshold?.toString() ?? '',
    yara_scan_interval_seconds: initial.yara_scan_interval_seconds?.toString() ?? '',
    yara_max_bytes: initial.yara_max_bytes?.toString() ?? '',
    payload_dedupe_interval_seconds: initial.payload_dedupe_interval_seconds?.toString() ?? '',
  })
  const [snapshot, setSnapshot] = useState(form)
  const [status, setStatus] = useSettingsStatus()
  const changed = Object.keys(form).filter((key) => form[key] !== snapshot[key])
  const field = (key: keyof typeof form, label: string, placeholder?: string) => (
    <label className="note" style={{ display: 'block' }}>
      {label}
      <input
        className="form-input"
        style={{ width: '100%' }}
        type="text"
        inputMode="numeric"
        placeholder={placeholder}
        value={form[key]}
        disabled={!editable}
        onChange={(event) => setForm((current) => ({ ...current, [key]: event.target.value }))}
      />
    </label>
  )
  return (
    <div className="card wide">
      <h2>Honeypot operations</h2>
      <p className="note">
        Staged thresholds: saving updates the configuration store, and the consuming services pick them up on their next
        restart — nothing here applies live.
      </p>
      <form
        onSubmit={(event) => {
          event.preventDefault()
          if (changed.length === 0) return
          // The "staged" variant of hp-settings.js:831-835's confirm copy:
          // these fields are all restart-required.
          confirmAction({
            title: 'Stage configuration?',
            description: `Apply these changes: ${changed.join(', ')}.`,
            warning:
              'Restart-required values are staged only. Saving never restarts a service — apply them with an operator-run restart.',
            confirmLabel: 'Stage changes',
            danger: false,
            onConfirm: async () => {
              setStatus('Staging…')
              try {
                const value: HoneypotConfig = {
                  alert_cooldown: form.alert_cooldown || undefined,
                  alert_campaign_score: form.alert_campaign_score ? Number(form.alert_campaign_score) : undefined,
                  sandbox_alert_risk_score: form.sandbox_alert_risk_score ? Number(form.sandbox_alert_risk_score) : undefined,
                  ml_alert_threshold: form.ml_alert_threshold ? Number(form.ml_alert_threshold) : undefined,
                  yara_scan_interval_seconds: form.yara_scan_interval_seconds
                    ? Number(form.yara_scan_interval_seconds)
                    : undefined,
                  yara_max_bytes: form.yara_max_bytes ? Number(form.yara_max_bytes) : undefined,
                  payload_dedupe_interval_seconds: form.payload_dedupe_interval_seconds
                    ? Number(form.payload_dedupe_interval_seconds)
                    : undefined,
                }
                const ok = await saveConfigSection({ data: { section: 'honeypot', value } })
                if (!ok) throw new Error('save failed (admin role required)')
                setSnapshot(form)
                setStatus('Staged — apply with a restart of the affected services.', 'ok')
              } catch (error) {
                setStatus(`Configuration could not be staged — ${errorText(error)}`, 'error')
                throw error
              }
            },
          })
        }}
      >
        <div className="settings-grid">
          {field('alert_cooldown', 'Alert cooldown (5m–168h)', '6h')}
          {field('alert_campaign_score', 'Alert campaign score (0–100)')}
          {field('sandbox_alert_risk_score', 'Sandbox alert risk score (0–100)')}
          {field('ml_alert_threshold', 'ML anomaly alert threshold (0.5–0.99)')}
          {field('yara_scan_interval_seconds', 'YARA scan interval in seconds (300–86400)')}
          {field('yara_max_bytes', 'YARA max bytes (1048576–1073741824)')}
          {field('payload_dedupe_interval_seconds', 'Payload dedupe interval in seconds (300–86400)')}
        </div>
        {editable ? (
          <button className="btn btn-secondary btn-sm" type="submit" style={{ marginTop: 8 }} disabled={changed.length === 0}>
            Stage changes
          </button>
        ) : (
          <p className="note">Admin role required to edit.</p>
        )}
        {status}
      </form>
    </div>
  )
}

const LANDING_OPTIONS = [
  { value: '/', label: 'Overview' },
  { value: '/events', label: 'Events' },
  { value: '/ips', label: 'Source IPs' },
  { value: '/campaigns', label: 'Campaigns' },
  { value: '/map', label: 'Map' },
  { value: '/alerts', label: 'Alerts' },
]
const WINDOW_OPTIONS = [
  { value: '1h', label: 'Last hour' },
  { value: '6h', label: 'Last 6 hours' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
]

function parseIntList(input: string): number[] {
  return input
    .split(',')
    .map((part) => Number(part.trim()))
    .filter((n) => Number.isFinite(n) && n > 0)
}

function BehaviorCard({ initial, editable }: { initial: BehaviorConfig; editable: boolean }) {
  const [form, setForm] = useState({
    default_landing: initial.default_landing ?? '/',
    default_time_window: initial.default_time_window ?? '24h',
    rows_per_page_options: (initial.rows_per_page_options ?? []).join(', '),
    max_export_rows: initial.max_export_rows?.toString() ?? '',
    refresh_interval_seconds_options: (initial.refresh_interval_seconds_options ?? []).join(', '),
    source_stale_minutes: initial.source_stale_minutes?.toString() ?? '',
    map_provider: initial.map_provider ?? 'osm',
    default_timezone: initial.default_timezone ?? '',
    show_ml_panels: initial.show_ml_panels ?? false,
    maintenance_mode: initial.maintenance_mode ?? false,
    read_only: initial.read_only ?? false,
    show_problem_report_button: initial.show_problem_report_button ?? false,
  })
  const [snapshot, setSnapshot] = useState(form)
  const [status, setStatus] = useSettingsStatus()
  const changed = (Object.keys(form) as (keyof typeof form)[]).filter(
    (key) => JSON.stringify(form[key]) !== JSON.stringify(snapshot[key]),
  )
  const toggle = (key: 'show_ml_panels' | 'maintenance_mode' | 'read_only' | 'show_problem_report_button', label: string, desc: string) => (
    <div className="card__row">
      <div>
        <div className="card__label">{label}</div>
        <div className="card__value">{desc}</div>
      </div>
      <label className="switch">
        <input
          type="checkbox"
          checked={form[key]}
          disabled={!editable}
          onChange={(event) => setForm((current) => ({ ...current, [key]: event.target.checked }))}
        />
        <span></span>
      </label>
    </div>
  )
  return (
    <div className="card wide">
      <h2>Dashboard behavior</h2>
      <p className="note">Global defaults users can still override per session, plus feature visibility applied live for every user.</p>
      <form
        onSubmit={(event) => {
          event.preventDefault()
          if (changed.length === 0) return
          confirmAction({
            title: 'Save configuration?',
            description: `Apply these changes: ${changed.join(', ')}.`,
            confirmLabel: 'Save configuration',
            danger: false,
            onConfirm: async () => {
              setStatus('Saving…')
              try {
                const value: BehaviorConfig = {
                  default_landing: form.default_landing,
                  default_time_window: form.default_time_window,
                  rows_per_page_options: parseIntList(form.rows_per_page_options),
                  max_export_rows: form.max_export_rows ? Number(form.max_export_rows) : undefined,
                  refresh_interval_seconds_options: parseIntList(form.refresh_interval_seconds_options),
                  source_stale_minutes: form.source_stale_minutes ? Number(form.source_stale_minutes) : undefined,
                  map_provider: form.map_provider,
                  default_timezone: form.default_timezone || undefined,
                  show_ml_panels: form.show_ml_panels,
                  maintenance_mode: form.maintenance_mode,
                  read_only: form.read_only,
                  show_problem_report_button: form.show_problem_report_button,
                }
                const ok = await saveConfigSection({ data: { section: 'behavior', value } })
                if (!ok) throw new Error('save failed (admin role required)')
                setSnapshot(form)
                setStatus('Saved — applies live for every user.', 'ok')
              } catch (error) {
                setStatus(`Configuration could not be saved — ${errorText(error)}`, 'error')
                throw error
              }
            },
          })
        }}
      >
        <div className="settings-grid">
          <label className="note" style={{ display: 'block' }}>
            Default landing page
            <select
              className="form-input"
              style={{ width: '100%' }}
              value={form.default_landing}
              disabled={!editable}
              onChange={(event) => setForm((current) => ({ ...current, default_landing: event.target.value }))}
            >
              {LANDING_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label className="note" style={{ display: 'block' }}>
            Default time window
            <select
              className="form-input"
              style={{ width: '100%' }}
              value={form.default_time_window}
              disabled={!editable}
              onChange={(event) => setForm((current) => ({ ...current, default_time_window: event.target.value }))}
            >
              {WINDOW_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label className="note" style={{ display: 'block' }}>
            Rows-per-page choices (comma-separated, from 10/25/50/100)
            <input
              className="form-input"
              style={{ width: '100%' }}
              type="text"
              placeholder="25, 50, 100"
              value={form.rows_per_page_options}
              disabled={!editable}
              onChange={(event) => setForm((current) => ({ ...current, rows_per_page_options: event.target.value }))}
            />
          </label>
          <label className="note" style={{ display: 'block' }}>
            Maximum export rows (100–100000)
            <input
              className="form-input"
              style={{ width: '100%' }}
              type="text"
              inputMode="numeric"
              value={form.max_export_rows}
              disabled={!editable}
              onChange={(event) => setForm((current) => ({ ...current, max_export_rows: event.target.value }))}
            />
          </label>
          <label className="note" style={{ display: 'block' }}>
            Refresh interval choices in seconds (from 10/15/30/60/120/300)
            <input
              className="form-input"
              style={{ width: '100%' }}
              type="text"
              placeholder="15, 30, 60, 300"
              value={form.refresh_interval_seconds_options}
              disabled={!editable}
              onChange={(event) => setForm((current) => ({ ...current, refresh_interval_seconds_options: event.target.value }))}
            />
          </label>
          <label className="note" style={{ display: 'block' }}>
            Source stale threshold in minutes (2–120)
            <input
              className="form-input"
              style={{ width: '100%' }}
              type="text"
              inputMode="numeric"
              value={form.source_stale_minutes}
              disabled={!editable}
              onChange={(event) => setForm((current) => ({ ...current, source_stale_minutes: event.target.value }))}
            />
          </label>
          <label className="note" style={{ display: 'block' }}>
            Default map provider
            <select
              className="form-input"
              style={{ width: '100%' }}
              value={form.map_provider}
              disabled={!editable}
              onChange={(event) => setForm((current) => ({ ...current, map_provider: event.target.value }))}
            >
              <option value="osm">OpenStreetMap</option>
            </select>
          </label>
          <label className="note" style={{ display: 'block' }}>
            Default timezone for new users
            <input
              className="form-input"
              style={{ width: '100%' }}
              type="text"
              placeholder="utc"
              value={form.default_timezone}
              disabled={!editable}
              onChange={(event) => setForm((current) => ({ ...current, default_timezone: event.target.value }))}
            />
          </label>
        </div>
        {toggle('show_ml_panels', 'Experimental ML/LLM panels', 'Show machine-learning analysis panels in investigations.')}
        {toggle('maintenance_mode', 'Maintenance mode', 'Announce maintenance across the dashboard.')}
        {toggle('read_only', 'Read-only mode', 'Freeze evidence-changing dashboard actions.')}
        {toggle('show_problem_report_button', '"Report a problem" button', 'Show a button on every page for reporting bugs.')}
        {editable ? (
          <button className="btn btn-secondary btn-sm" type="submit" style={{ marginTop: 8 }} disabled={changed.length === 0}>
            Save changes
          </button>
        ) : (
          <p className="note">Admin role required to edit.</p>
        )}
        {status}
      </form>
    </div>
  )
}

function ReportPresetsCard({
  templates,
  overrides,
  editable,
}: {
  templates: ReportTemplate[]
  overrides: Record<string, ReportPresetOverride>
  editable: boolean
}) {
  const [form, setForm] = useState<Record<string, ReportPresetOverride>>(overrides)
  const [snapshot, setSnapshot] = useState<Record<string, ReportPresetOverride>>(overrides)
  const [status, setStatus] = useSettingsStatus()

  // Normalized so an untouched empty field never reads as a change.
  const norm = (override?: ReportPresetOverride) => ({ name: override?.name ?? '', description: override?.description ?? '' })
  const changed = templates
    .filter((template) => JSON.stringify(norm(form[template.id])) !== JSON.stringify(norm(snapshot[template.id])))
    .map((template) => template.id)

  if (templates.length === 0) return null

  return (
    <div className="card wide">
      <h2>Report Studio presets</h2>
      <p className="note">Renamed/re-described copy for the compiled report-template catalog. Leave a field empty to use the compiled default.</p>
      <form
        onSubmit={(event) => {
          event.preventDefault()
          if (changed.length === 0) return
          // hp-settings.js:909-912's copy for the preset-text save.
          confirmAction({
            title: 'Save Report Studio preset text?',
            description: 'Apply the edited name/description overrides. Presets left blank keep their compiled default.',
            confirmLabel: 'Save changes',
            danger: false,
            onConfirm: async () => {
              setStatus('Saving…')
              try {
                const ok = await saveConfigSection({ data: { section: 'report-presets', value: form } })
                if (!ok) throw new Error('save failed (admin role required)')
                setSnapshot(form)
                setStatus('Saved.', 'ok')
              } catch (error) {
                setStatus(`Presets could not be saved — ${errorText(error)}`, 'error')
                throw error
              }
            },
          })
        }}
      >
        {templates.map((template) => {
          const override = form[template.id] ?? {}
          return (
            <div key={template.id} className="card" style={{ marginBottom: 12 }}>
              <div className="card__header">
                <div>
                  <h3>{template.name}</h3>
                </div>
              </div>
              <label className="note" style={{ display: 'block' }}>
                Name
                <input
                  className="form-input"
                  style={{ width: '100%' }}
                  type="text"
                  placeholder={template.name}
                  value={override.name ?? ''}
                  disabled={!editable}
                  onChange={(event) =>
                    setForm((current) => ({ ...current, [template.id]: { ...current[template.id], name: event.target.value } }))
                  }
                />
              </label>
              <label className="note" style={{ display: 'block' }}>
                Description
                <textarea
                  className="form-input"
                  style={{ width: '100%' }}
                  rows={2}
                  placeholder={template.description}
                  value={override.description ?? ''}
                  disabled={!editable}
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      [template.id]: { ...current[template.id], description: event.target.value },
                    }))
                  }
                />
              </label>
            </div>
          )
        })}
        {editable ? (
          <button className="btn btn-secondary btn-sm" type="submit" style={{ marginTop: 8 }} disabled={changed.length === 0}>
            Save changes
          </button>
        ) : (
          <p className="note">Admin role required to edit.</p>
        )}
        {status}
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
  const [status, setStatus] = useSettingsStatus()
  const [logsFor, setLogsFor] = useState<string | null>(null)
  const [logsText, setLogsText] = useState('')
  const [logsBusy, setLogsBusy] = useState(false)

  useEffect(() => setData(initial), [initial])

  const refresh = async () => {
    const result = await fetchServices()
    if (result) setData(result)
  }

  // hp-settings.js:1107-1126's requestServiceAction: confirm first (stop
  // gets the connection-loss warning, only start is non-danger), then the
  // container list reloads whether the action landed or not.
  const act = (name: string, action: 'start' | 'stop' | 'restart') => {
    const label = action[0].toUpperCase() + action.slice(1)
    confirmAction({
      title: `${label} ${name}?`,
      description: `This sends ${action} to the live container through the services adapter.`,
      warning: action === 'stop' ? `${name} stops accepting connections until it is started again.` : undefined,
      confirmLabel: label,
      danger: action !== 'start',
      onConfirm: async () => {
        setBusyName(name)
        try {
          const result = await runServiceAction({ data: { name, action } })
          if (!result.ok) throw new Error(result.error || 'action failed')
          setStatus(`${name}: ${action} succeeded.`, 'ok')
        } catch (error) {
          setStatus(`${name}: ${action} failed — ${errorText(error)}`, 'error')
          throw error
        } finally {
          setBusyName(null)
          void refresh()
        }
      },
    })
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
      {status}
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
            <p className="note">Updated {formatTimestamp(String(data.stats.updated_at))}</p>
          ) : null}
        </>
      )}
    </div>
  )
}

function ConfigHistoryCard({ initial, editable }: { initial: HistoryResponse | null; editable: boolean }) {
  const [data, setData] = useState<HistoryResponse | null>(initial)
  const [busy, setBusy] = useState<number | null>(null)
  const [status, setStatus] = useSettingsStatus()

  useEffect(() => setData(initial), [initial])

  // hp-settings.js:1513-1517's exact rollback copy.
  const rollback = (revision: number) => {
    confirmAction({
      title: 'Roll back configuration?',
      description: `Restore revision ${revision} as a new revision. The current state stays in history.`,
      warning: `Every configuration field returns to the retained snapshot of revision ${revision}.`,
      confirmLabel: 'Roll back',
      danger: true,
      onConfirm: async () => {
        setBusy(revision)
        try {
          const result = await rollbackConfig({ data: { revision } })
          if (!result.ok) throw new Error(result.error || 'rollback failed')
          setStatus(`Configuration rolled back to revision ${revision}.`, 'ok')
          const fresh = await fetchHistory()
          if (fresh) setData(fresh)
        } catch (error) {
          setStatus(`Rollback failed: ${errorText(error)}`, 'error')
          throw error
        } finally {
          setBusy(null)
        }
      },
    })
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
                  <td>{formatTimestamp(entry.time)}</td>
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
      {status}
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
      <select className="form-input" aria-label="Filter by action" value={filter} onChange={(event) => applyFilter(event.target.value)}>
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
                  <td>{formatTimestamp(event.time)}</td>
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

// The nine accent presets from theme.css (#32) in the legacy picker's
// order (settings_modal.html:115-125): claude is the default, the rest
// are data-hp-palette values. Swatch dots are colored by theme.css's
// .hp-palette-pick [data-value] rules, per-theme.
const PALETTES: { id: string; label: string }[] = [
  { id: 'claude', label: 'Claude' },
  { id: 'slate', label: 'Slate' },
  { id: 'ocean', label: 'Ocean' },
  { id: 'sage', label: 'Sage' },
  { id: 'lavender', label: 'Lavender' },
  { id: 'lime', label: 'Lime' },
  { id: 'amber', label: 'Amber' },
  { id: 'rose', label: 'Rose' },
  { id: 'neon', label: 'Neon' },
]

function bytesHuman(bytes: number): string {
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`
  return `${bytes} B`
}

function Settings() {
  const { storage, preferences, admin, services, history, audit, reporterStats, user } = Route.useLoaderData()
  const theme = useThemeMode()
  const [palette, setPalette] = useState('claude')
  const [prefetch, setPrefetch] = useState(true)
  const [prefsData, setPrefsData] = useState<Prefs | null | 'loading'>('loading')
  const [storageData, setStorageData] = useState<Storage | null>(null)
  const [adminData, setAdminData] = useState<AdminConfig | null>(null)
  const [servicesData, setServicesData] = useState<ServicesResponse | null>(null)
  const [historyData, setHistoryData] = useState<HistoryResponse | null>(null)
  const [auditData, setAuditData] = useState<AuditResponse | null>(null)
  const [reporterStatsData, setReporterStatsData] = useState<ReporterStats | null>(null)

  const isAdmin = !user || user.role === 'admin'

  useEffect(() => {
    setPalette(document.documentElement.dataset.hpPalette ?? 'claude')
    setPrefetch(prefetchEnabled())
    // Reconcile this device against the server-synced theme (another
    // device may have changed it since); local storage + instant apply
    // already happened at page load, this just catches this device up.
    pullServerTheme()
    let cancelled = false
    storage.then((result) => {
      if (!cancelled && result) setStorageData(result)
    })
    preferences.then((result) => {
      if (!cancelled) setPrefsData(result)
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
  }, [storage, preferences, admin, services, history, audit, reporterStats])

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
        subtitle="Appearance, personal preferences, session, and storage — preferences apply instantly and sync to your account across devices."
      />
      <div className="card half">
        <h2>Appearance</h2>
        {/* Go's segmented markup (settings_modal.html:103-125): a
            role="group" of aria-pressed buttons — never radiogroup, which
            aria-pressed is invalid inside. */}
        <p className="note">Theme mode</p>
        <div className="segmented" role="group" aria-label="Theme mode">
          {modes.map((mode) => (
            <button
              key={mode.id}
              type="button"
              data-value={mode.id}
              aria-pressed={theme === mode.id}
              onClick={() => applyTheme(mode.id)}
            >
              {mode.label}
            </button>
          ))}
        </div>
        <p className="note">Accent palette</p>
        <div className="segmented hp-palette-pick" role="group" aria-label="Accent palette">
          {PALETTES.map((preset) => (
            <button
              key={preset.id}
              type="button"
              data-value={preset.id}
              aria-pressed={palette === preset.id}
              onClick={() => pickPalette(preset.id)}
            >
              <span className="dot" aria-hidden="true" />
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
      {prefsData === 'loading' ? (
        <div className="card half">
          <h2>Preferences</h2>
          <span className="skeleton-line" aria-hidden="true" />
          <span className="skeleton-line" aria-hidden="true" />
        </div>
      ) : prefsData ? (
        <PreferencesPanes initial={prefsData} onReset={(prefs) => setPalette(prefs.palette ?? 'claude')} />
      ) : (
        <div className="card half">
          <h2>Preferences</h2>
          <p className="empty">Preferences could not be loaded — reload to retry.</p>
        </div>
      )}
      {adminData ? <PresentationCard initial={adminData.presentation} editable={isAdmin} /> : null}
      {adminData ? <HoneypotOperationsCard initial={adminData.honeypot} editable={isAdmin} /> : null}
      {adminData ? <BehaviorCard initial={adminData.behavior} editable={isAdmin} /> : null}
      {adminData ? (
        <ReportPresetsCard templates={adminData.reportTemplates} overrides={adminData.reportPresets} editable={isAdmin} />
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
                  <td className="ago">{formatTimestamp(operator.last_seen_at)}</td>
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
