// Settings — the full port of the legacy settings surface's pane anatomy
// (#1653 final items): the .settings-layout / .settings-layout__sidebar /
// .settings-layout__content composition from settings_modal.html:9-34
// rendered as a page (theme.css's #hp-settings.hp-dash-settings--page
// variant, "pick 13B"), with the sidebar's categorized pane rail, the
// cross-pane settings search (hp-settings.js:369-391: an active query
// filters .hp-field cards across every pane and the rail), deep-linkable
// panes via ?pane=, an aggregate unsaved-edits guard (useBlocker +
// beforeunload, hp-settings.js:317-321), and the config-save concurrency
// contract (If-Match revision → 409 recovery + pre-save validate,
// backend-service/src/config.rs).
//
// Every card/control from the previous flat layout is kept as-is — this
// is re-organization into panes, not a rebuild. Theme/palette use the
// same localStorage contract as the legacy tier (hp-theme / hp-palette)
// with a server write-through (see lib/prefs.ts); the personal-preference
// cards (settings_modal.html:103-381 / hp-settings.js:294-651) keep their
// per-pane dirty-gated saves through the shared confirm dialog and their
// timezone/clock localStorage mirrors (hp-tz / hp-clock).
import { createFileRoute, Link, useBlocker, useNavigate } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { confirmAction } from '../components/ConfirmDialog'
import { ErrorStateBlock } from '../components/ErrorState'
import { EsHistoryConsole, type EsStorage } from '../components/EsHistoryConsole'
import { str } from '../components/StoreList'
import { applyPalette, applyTheme, useThemeMode, type ThemeMode } from '../lib/prefs'
import { ThemeGallery } from '../components/ThemeGallery'
import { themeSearchTerms } from '../lib/themes'
import type { JsonRecord } from '../lib/json'
import { prefetchEnabled, setPrefetchEnabled } from '../lib/prefetch'
import { getSessionUser, getAccountActions, type User, type AccountActions } from '../lib/auth'
import { formatTimestamp, writeTimePrefs } from '../lib/time'

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

// fields is absent for a rejected write (e.g. result: "conflict") -- there's
// nothing to report, the update never computed a changed-field list.
type HistoryEntry = { revision: number; time: string; actor_subject: string; actor_username: string; action: string; fields: string[] | null }
type HistoryResponse = { entries: HistoryEntry[] }

type AuditEvent = {
  time: string
  actor_subject: string
  actor_username: string
  action: string
  fields: string[] | null
  revision: number
  result: string
}
type AuditResponse = { events: AuditEvent[] }

type ReporterStats = { available: boolean; stats?: JsonRecord; reason?: string }

const fetchStorage = createServerFn({ method: 'GET' }).handler(async (): Promise<EsStorage | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<EsStorage>('/api/v1/settings/storage')
})

type AdminConfig = {
  // Optimistic-concurrency baseline: the config doc's monotonic revision
  // from GET /api/v1/config — sent back as If-Match on every config save
  // (config.rs's expected_revision; a stale value 409s).
  revision: number
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
      revision?: number
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
  // #2311: a partly-dead fetch used to fall through to the all-defaults
  // object below — maintenance off, an empty roster, and above all
  // `revision: 0`, which as an If-Match baseline can only 409 against the
  // real config doc (blaming "another session" that never existed). An
  // admin panel built from partly-dead stores lies worse than a missing
  // one, so any failed leg fails whole: callers get null and hold no
  // editable config at all. (#2178 phase 3 reuses this same gate for its
  // rendering half; the write-path guards below are #2311's half.)
  if (!config || !roster || !reports) return null
  return {
    revision: config?.revision ?? 0,
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
  .validator((input: { name: string }) => input)
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
  .validator((input: { action: string }) => input)
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
  live_toast_interval_seconds?: number
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
  .validator((input: { patch: Prefs }) => input)
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

// #2512: a stale-revision 409 carries the stored document revision as
// X-Current-Revision so a stale client can re-sync directly. Parsed here
// once for both PUT sites; a tier without the header (or a non-numeric
// value) yields undefined, and callers degrade to the legacy recovery.
function conflictRevision(response: Response): { currentRevision?: number } {
  const header = response.headers.get('x-current-revision')
  if (header === null || header.trim() === '') return {}
  const current = Number(header)
  return Number.isFinite(current) && current >= 0 ? { currentRevision: current } : {}
}

// Config-save results carry the concurrency outcome explicitly: `conflict`
// is a 409 from config.rs's check_revision (someone else saved since our
// GET), `revision` is the new baseline after a successful write, and — on
// conflict only — `currentRevision` is the stored revision the backend now
// surfaces as X-Current-Revision on stale-revision 409s (#2512/#2513).
type ConfigSaveResult = {
  ok: boolean
  conflict?: boolean
  revision?: number
  currentRevision?: number
  error?: string
}

const savePresentation = createServerFn({ method: 'POST' })
  .validator((input: { value: Presentation; revision: number }) => input)
  .handler(async ({ data }): Promise<ConfigSaveResult> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // Admin-gated at the BFF, same posture as the legacy settings API.
    if (!user || user.role !== 'admin') return { ok: false, error: 'admin role required' }
    const { serviceFetch } = await import('../lib/backend.server')
    const params = new URLSearchParams({ actor_subject: user?.sub ?? '', actor_username: user?.username ?? '' })
    const response = await serviceFetch(`/api/v1/config/presentation?${params.toString()}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', 'if-match': String(data.revision) },
      body: JSON.stringify(data.value),
    })
    if (response.status === 409) return { ok: false, conflict: true, ...conflictRevision(response) }
    if (!response.ok) return { ok: false, error: await response.text().catch(() => 'save failed') }
    const doc = (await response.json().catch(() => null)) as { revision?: number } | null
    return { ok: true, revision: doc?.revision }
  })

// Backs the three other admin config panes — targets PUT
// /api/v1/config/{section}, mirroring savePresentation's admin gate,
// If-Match precondition and 409 handling exactly.
const saveConfigSection = createServerFn({ method: 'POST' })
  .validator((input: { section: 'honeypot' | 'behavior' | 'report-presets'; value: unknown; revision: number }) => input)
  .handler(async ({ data }): Promise<ConfigSaveResult> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user || user.role !== 'admin') return { ok: false, error: 'admin role required' }
    const { serviceFetch } = await import('../lib/backend.server')
    const params = new URLSearchParams({ actor_subject: user?.sub ?? '', actor_username: user?.username ?? '' })
    const response = await serviceFetch(`/api/v1/config/${data.section}?${params.toString()}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', 'if-match': String(data.revision) },
      body: JSON.stringify(data.value),
    })
    if (response.status === 409) return { ok: false, conflict: true, ...conflictRevision(response) }
    if (!response.ok) return { ok: false, error: await response.text().catch(() => 'save failed') }
    const doc = (await response.json().catch(() => null)) as { revision?: number } | null
    return { ok: true, revision: doc?.revision }
  })

// POST /api/v1/config/validate — persist-nothing preview (config.rs's
// validate). null means the validator itself was unreachable; the save
// still runs and decides (the backend applies the same rules on write).
const validateConfig = createServerFn({ method: 'POST' })
  .validator((input: { patch: unknown }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; problems: string[] } | null> => {
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/config/validate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(data.patch),
    })
    if (!response.ok) return null
    const body = (await response.json().catch(() => null)) as { ok?: boolean; problems?: string[] } | null
    if (!body) return null
    return { ok: body.ok ?? false, problems: body.problems ?? [] }
  })

const runServiceAction = createServerFn({ method: 'POST' })
  .validator((input: { name: string; action: 'start' | 'stop' | 'restart' }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // Admin-gated at the BFF — the Rust tier itself has no admin check.
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
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
  .validator((input: { revision: number }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/config/rollback', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ revision: data.revision, actor_subject: user?.sub ?? '', actor_username: user?.username ?? '' }),
    })
    if (response.ok) return { ok: true }
    return { ok: false, error: await response.text() }
  })

// The full data set the settings surface consumes, as in-flight promises —
// the route loader kicks these off; the anywhere-modal (SettingsModal.tsx)
// calls fetchSettingsData itself on open, so both hosts share one fetch
// path and one shape.
export type SettingsData = {
  storage: Promise<EsStorage | null>
  preferences: Promise<Prefs | null>
  admin: Promise<AdminConfig | null>
  services: Promise<ServicesResponse | null>
  history: Promise<HistoryResponse | null>
  audit: Promise<AuditResponse | null>
  reporterStats: Promise<ReporterStats | null>
}

export function fetchSettingsData(): SettingsData {
  return {
    storage: fetchStorage(),
    preferences: fetchPreferences(),
    admin: fetchAdminData(),
    services: fetchServices(),
    history: fetchHistory(),
    audit: fetchAudit({ data: { action: '' } }),
    reporterStats: fetchReporterStats(),
  }
}

export const Route = createFileRoute('/settings')({
  // Deep-linkable pane: /settings?pane=services etc. Unknown names — and
  // admin panes for non-admins — fall back to "account" in the component
  // (hp-settings.js:339-341's showPane fallback).
  validateSearch: (search: Record<string, unknown>): { pane?: string } => ({
    pane: typeof search.pane === 'string' && search.pane ? search.pane : undefined,
  }),
  loader: async () => ({
    ...fetchSettingsData(),
    user: await getSessionUser(),
    accountActions: await getAccountActions(),
  }),
  component: Settings,
})

/* ================= pane catalog & cross-pane search ================= */

type PaneId =
  | 'account'
  | 'appearance'
  | 'navigation'
  | 'time'
  | 'map'
  | 'branding'
  | 'report-presets'
  | 'behavior'
  | 'honeypot'
  | 'users'
  | 'services'
  | 'canarytokens'
  | 'elasticsearch'
  | 'dead-letters'
  | 'history'
  | 'audit'

// Titles/descriptions verbatim from hp-settings.js's PANE_META (:217-234).
const PANE_META: Record<PaneId, { title: string; desc: string; admin: boolean }> = {
  account: { title: 'Account', desc: 'Your identity as provided by the auth service. Credentials are managed there, never here.', admin: false },
  appearance: { title: 'Appearance', desc: 'Theme, density, motion, and readability of the dashboard.', admin: false },
  navigation: { title: 'Navigation & tables', desc: 'Where you land, how the sidebar behaves, and how tables render.', admin: false },
  time: { title: 'Time & live data', desc: 'Timezone, clock formats, refresh cadence, and notifications.', admin: false },
  map: { title: 'Map & investigation', desc: 'Basemap, clustering, and drill-down defaults for investigations.', admin: false },
  branding: { title: 'Branding & text', desc: 'Product labels, help links, notices, and footer copy. Plain text; https links only.', admin: true },
  'report-presets': { title: 'Report Studio presets', desc: 'Names and descriptions shown for each report template. Structural fields (theme, window, elements) are report logic, not editable here.', admin: true },
  behavior: { title: 'Dashboard behavior', desc: 'Safe bounded defaults and feature visibility for every user.', admin: true },
  honeypot: { title: 'Honeypot operations', desc: 'Staged operational thresholds. Saving never restarts anything — apply with an operator-run restart.', admin: true },
  users: { title: 'Users', desc: 'Read-only projection of dashboard activity. Accounts are managed in the auth service.', admin: true },
  services: { title: 'Services', desc: 'Live container status for sensors, probes, and analysis workers, with start/stop/restart and logs.', admin: true },
  canarytokens: { title: 'Canarytokens', desc: "Create PDF/Word/Excel/image/QR/folder honeytokens for use outside this honeypot — plant anywhere, alerted the instant one's opened.", admin: true },
  elasticsearch: { title: 'Elasticsearch history', desc: 'Raw query_string search across every indexed honeypot and Suricata document.', admin: true },
  'dead-letters': { title: 'Ingest dead letters', desc: 'Documents Elasticsearch rejected, with their original error and field shape.', admin: true },
  history: { title: 'Configuration history', desc: 'Retained configuration revisions with rollback.', admin: true },
  audit: { title: 'Audit log', desc: 'Settings changes with actor, fields, and result.', admin: true },
}

const PERSONAL_PANES: PaneId[] = ['account', 'appearance', 'navigation', 'time', 'map']
const ADMIN_PANES: PaneId[] = [
  'branding',
  'report-presets',
  'behavior',
  'honeypot',
  'users',
  'services',
  'canarytokens',
  'elasticsearch',
  'dead-letters',
  'history',
  'audit',
]

// The search corpus, one entry per .hp-field card: the Go tier matched
// data-hp-search keywords + the card's rendered text (hp-settings.js:376);
// here each entry bakes the card's title + field labels + the original
// data-hp-search keywords into one haystack.
const SEARCH_INDEX: Record<PaneId, Record<string, string>> = {
  account: {
    profile: 'account profile identity role capabilities signed in session keycloak sign out log out logout',
    reset: 'reset preferences defaults danger reset all preferences restores every preference',
  },
  appearance: {
    theme:
      `appearance theme dark light system color mode palette accent preset theme ${themeSearchTerms()}`,
    readability:
      'appearance readability density compact comfortable rows spacing motion animation reduced accessibility high contrast vision evidence font size text larger',
  },
  navigation: {
    preferences:
      'navigation tables landing page start home route sidebar collapse compact layout filters remember persist details new tab open rows per page size pagination wrap long values text evidence',
    prefetch: 'navigation predictive prefetch prefetching instant pages',
  },
  time: {
    time: 'time live data timezone iana zone clock 24 12 hour format timestamps relative absolute date refresh automatic polling interval seconds rate toast notification popup new events auto-refresh',
    notifications: 'notification severity threshold low medium high critical sound audio alert desktop browser push',
  },
  map: {
    map: 'map investigation basemap tiles openstreetmap provider cluster grouping markers density animation transitions zoom event window default range time 24h preserve filters keep drill down',
  },
  branding: {
    presentation:
      'branding text product identity application name product label dashboard title heading subtitle subheading organization site overview intro welcome help link label contact url https banner maintenance incident notice severity info warning danger expires expiry footer ai disclaimer analysis generated privacy notice evidence handling',
  },
  'report-presets': {
    presets: 'report studio presets template catalog name description override compiled default',
  },
  behavior: {
    behavior:
      'behavior defaults default landing page route time window range rows per page options sizes export rows maximum limit refresh interval options seconds source stale minutes threshold map provider basemap timezone iana zone new user feature visibility ml llm experimental panels machine learning maintenance mode banner read only freeze report a problem bug button feedback',
  },
  honeypot: {
    'reporter-stats': 'honeypot reporter stats attempted sent suppressed dry run failed send counters cooldown greynoise',
    operations:
      'honeypot staged restart apply operations alerting alert cooldown duration campaign score threshold sandbox risk score ml worker anomaly scanners yara scan interval seconds max bytes limit payload dedupe',
  },
  users: {
    users: 'users accounts activity role last seen first seen operators projected dashboard keycloak',
  },
  services: {
    services: 'services sensors probes containers workers start stop restart logs status health docker adapter refresh',
  },
  canarytokens: {
    canarytokens:
      'canarytokens honeytoken pdf word excel image qr folder external plant create token memo history download credentials bait usernames passwords honeyfs',
  },
  elasticsearch: {
    console: 'elasticsearch history query search documents indexed query_string storage cluster indices store size export json suricata',
  },
  'dead-letters': {
    'dead-letters': 'dead letters rejected ingest documents purge elasticsearch error field shape remediation',
  },
  history: {
    history: 'history revisions rollback configuration retained restore',
  },
  audit: {
    audit: 'audit log changes events actor action fields result preference config updates rollbacks',
  },
}

function matchesQuery(text: string, query: string): boolean {
  return text.toLowerCase().includes(query)
}

function paneMatches(id: PaneId, query: string): boolean {
  return Object.values(SEARCH_INDEX[id]).some((text) => matchesQuery(text, query))
}

// Shared pane/search state. `query` is trimmed + lowercased; empty means
// pane mode (one visible pane), non-empty means cross-pane filter mode.
const SettingsUi = createContext<{ query: string; active: PaneId }>({ query: '', active: 'account' })

// hp-field visibility for cards rendered inside child components (the
// Settings component itself computes this inline — it can't consume its
// own provider).
function useFieldHidden(pane: PaneId, field: string): boolean {
  const { query } = useContext(SettingsUi)
  return query !== '' && !matchesQuery(SEARCH_INDEX[pane][field] ?? '', query)
}

// One settings pane: hidden unless active (pane mode) or matching (search
// mode). In search mode a visible pane is prefixed with its name, so
// matches from every pane stay attributable (#1653 item 1).
function Pane({ id, children }: { id: PaneId; children: ReactNode }) {
  const { query, active } = useContext(SettingsUi)
  const searching = query !== ''
  const hidden = searching ? !paneMatches(id, query) : active !== id
  return (
    <section className="hp-settings-pane" data-hp-pane={id} aria-label={PANE_META[id].title} hidden={hidden}>
      {searching && !hidden ? <div className="label-section">{PANE_META[id].title}</div> : null}
      {children}
    </section>
  )
}

/* ================= shared bits ================= */

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

// The shared config-save path (#1653 item 5): pre-save validate (surfaced
// in the pane's status line), If-Match'd write, and the Go 409 recovery —
// error status, refetch, re-baseline (the caller's card rebases via its
// initial-prop effect once onConflict has refreshed the admin data).
// #2513: when the 409 carries X-Current-Revision (#2512), the recovery is
// a direct re-sync — the cards re-baseline onto the fresh server values
// but keep the operator's staged edits on top, so the next save is an
// If-Match'd retry of the merged form instead of a lost update.
async function runConfigSave(opts: {
  section: 'presentation' | 'honeypot' | 'behavior' | 'report-presets'
  value: unknown
  revision: number
  setStatus: (text: string, kind?: 'ok' | 'error') => void
  onSaved: (revision: number) => void
  onConflict: (currentRevision?: number) => void | Promise<void>
  successText: string
}): Promise<'saved' | 'invalid' | 'conflict'> {
  const { section, value, revision, setStatus, onSaved, onConflict, successText } = opts
  setStatus('Validating…')
  const patchKey = section === 'report-presets' ? 'report_presets' : section
  const validation = await validateConfig({ data: { patch: { [patchKey]: value } } })
  if (validation && !validation.ok) {
    setStatus(`Validation failed — ${validation.problems.join('; ')}`, 'error')
    return 'invalid'
  }
  setStatus('Saving…')
  const result =
    section === 'presentation'
      ? await savePresentation({ data: { value: value as Presentation, revision } })
      : await saveConfigSection({ data: { section, value, revision } })
  if (result.conflict) {
    if (typeof result.currentRevision === 'number') {
      setStatus(
        'Configuration changed in another session — your unsaved edits were kept on top of the reloaded values. Review and save again.',
        'error',
      )
    } else {
      setStatus('Configuration changed in another session — reloaded current values, reapply your edits', 'error')
    }
    await onConflict(result.currentRevision)
    return 'conflict'
  }
  if (!result.ok) throw new Error(result.error?.trim() || 'save failed (admin role required)')
  if (typeof result.revision === 'number') onSaved(result.revision)
  setStatus(successText, 'ok')
  return 'saved'
}

type ConfigCardProps<T> = {
  initial: T
  editable: boolean
  revision: number
  onSaved: (revision: number) => void
  onConflict: (currentRevision?: number) => void | Promise<void>
  onDirty: (dirty: boolean) => void
  /** Bumped on every X-Current-Revision-backed conflict re-sync (#2513):
   *  a change here tells the card the incoming fresh config should merge
   *  under its staged edits instead of discarding them. */
  conflictRebase: number
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
  disabled,
}: {
  label: string
  value: string
  options: { value: string; label: string }[]
  onChange: (value: string) => void
  desc?: string
  disabled?: boolean
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
            disabled={disabled}
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
  time: ['timezone', 'clock', 'timestamps', 'auto_refresh', 'refresh_interval_seconds', 'live_toasts', 'live_toast_interval_seconds'],
  notifications: ['notify_severity', 'notify_sound', 'notify_desktop'],
  map: ['map_basemap', 'map_clustering', 'map_animation', 'default_event_window', 'preserve_filters'],
  appearance: ['density', 'reduced_motion', 'high_contrast', 'large_evidence_text'],
} satisfies Record<string, PrefKey[]>
type PaneName = keyof typeof PREF_PANES

// Where each pref-card group lives in the pane rail: Notifications shares
// the "Time & live data" pane (Go put it there, settings_modal.html:312),
// Readability shares "Appearance".
const PREF_PANE_TARGET: Record<PaneName, PaneId> = {
  navigation: 'navigation',
  time: 'time',
  notifications: 'time',
  map: 'map',
  appearance: 'appearance',
}

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

// How often the shell checks for operational problems (#1900). This was a
// batching cadence for the old "N new events" toast -- #1684 added it
// because a fixed 3s batch meant a popup every few seconds around the
// clock on a busy sensor. That toast is gone; what the setting controls
// now is how often the health document is polled.
//
// The 3-second option came out with it. A sensor is stale after an hour
// without traffic and ingestion after fifteen minutes, so checking every
// three seconds cannot make a toast arrive meaningfully sooner -- it would
// only be twenty requests a minute for a figure that has not moved.
// LiveToasts enforces the same one-minute floor regardless.
const TOAST_INTERVALS: [number, string][] = [
  [60, 'Every minute'],
  [120, 'Every 2 minutes'],
  [300, 'Every 5 minutes'],
  [900, 'Every 15 minutes'],
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

// The five personal panes (settings_modal.html:46-382) as pane sections:
// account (profile + reset), appearance (theme card + readability),
// navigation (& tables + prefetch), time (& live data + notifications),
// map (& investigation). Preference state is shared across the panes so
// every card sees the same form — backed by GET/PUT /api/v1/preferences.
function PersonalPanes({
  prefsState,
  onReset,
  onDirty,
  profileCard,
  appearanceLead,
  navigationExtra,
}: {
  prefsState: Prefs | null | 'loading'
  onReset: (prefs: Prefs) => void
  onDirty: (pane: PaneId, key: string, dirty: boolean) => void
  profileCard: ReactNode
  appearanceLead: ReactNode
  navigationExtra: ReactNode
}) {
  const loaded = prefsState !== 'loading' && prefsState !== null ? prefsState : null
  const [snapshot, setSnapshot] = useState<Prefs>(loaded ?? {})
  const [form, setForm] = useState<Prefs>(loaded ?? {})
  const [navStatus, setNavStatus] = useSettingsStatus()
  const [timeStatus, setTimeStatus] = useSettingsStatus()
  const [notifyStatus, setNotifyStatus] = useSettingsStatus()
  const [mapStatus, setMapStatus] = useSettingsStatus()
  const [appearanceStatus, setAppearanceStatus] = useSettingsStatus()
  const [resetStatus, setResetStatus] = useSettingsStatus()

  // Rebase when the preferences actually arrive (the loader promise
  // resolves after first render).
  useEffect(() => {
    if (prefsState && prefsState !== 'loading') {
      setSnapshot(prefsState)
      setForm(prefsState)
    }
  }, [prefsState])

  const hideNav = useFieldHidden('navigation', 'preferences')
  const hideTime = useFieldHidden('time', 'time')
  const hideNotify = useFieldHidden('time', 'notifications')
  const hideMap = useFieldHidden('map', 'map')
  const hideReadability = useFieldHidden('appearance', 'readability')
  const hideReset = useFieldHidden('account', 'reset')

  const patch = <K extends PrefKey>(key: K, value: Prefs[K]) => setForm((current) => ({ ...current, [key]: value }))

  const changedFields = (pane: PaneName): PrefKey[] =>
    PREF_PANES[pane].filter((key) => JSON.stringify(form[key]) !== JSON.stringify(snapshot[key]))

  // Aggregate dirty reporting for the unsaved-edits guard and the rail's
  // is-dirty dots (hp-settings.js:298-315's computeDirty).
  useEffect(() => {
    ;(Object.keys(PREF_PANES) as PaneName[]).forEach((pane) =>
      onDirty(PREF_PANE_TARGET[pane], `prefs:${pane}`, loaded !== null && changedFields(pane).length > 0),
    )
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form, snapshot, loaded, onDirty])

  const requestSave = (pane: PaneName, setStatus: (text: string, kind?: 'ok' | 'error') => void) => {
    if (!loaded) return
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
    if (!loaded) return
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
        disabled={!loaded || changedFields(pane).length === 0}
        onClick={() => requestSave(pane, setStatus)}
      >
        Save changes
      </button>
    </div>
  )

  const placeholder =
    prefsState === 'loading' ? (
      <>
        <span className="skeleton-line" aria-hidden="true" />
        <span className="skeleton-line" aria-hidden="true" />
      </>
    ) : (
      <p className="empty">Preferences could not be loaded — reload to retry.</p>
    )

  return (
    <>
      <Pane id="account">
        {profileCard}
        <div className="card hp-field" hidden={hideReset}>
          <h2>Reset preferences</h2>
          <p className="note">Returns every personal preference — appearance included — to its default.</p>
          {resetStatus}
          <div className="settings-actions">
            <button className="btn btn-danger btn-sm" type="button" disabled={!loaded} onClick={requestReset}>
              Reset all preferences
            </button>
          </div>
        </div>
      </Pane>
      <Pane id="appearance">
        {appearanceLead}
        <div className="card hp-field" hidden={hideReadability}>
          <h2>Readability &amp; density</h2>
          {appearanceStatus}
          {loaded ? (
            <>
              {/* #1759: these four saved cleanly, round-tripped, showed a
                  success toast and changed nothing -- no CSS implements any
                  of them. Two of them described a specific effect that never
                  occurred, which is the worse half: a control that reports
                  success and does nothing is worse than one that is not
                  there. They stay visible and disabled rather than removed,
                  because they are wanted; what is removed is the claim that
                  they work. */}
              <p className="note hp-appearance-note">
                Density, high contrast and evidence text are not wired up yet. They are shown here because they are
                planned, not because they work — see #1759. Motion already follows your operating system's
                reduced-motion setting; the explicit choices below do not override it.
              </p>
              <Segmented
                label="Density"
                value={form.density ?? 'comfortable'}
                options={[
                  { value: 'comfortable', label: 'Comfortable' },
                  { value: 'compact', label: 'Compact' },
                ]}
                onChange={(value) => patch('density', value)}
                disabled
                desc="Not implemented — the stylesheet's spacing scale is defined but barely used, so this needs the spacing refactor in Xore/theme#105 before it can do anything."
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
                disabled
                desc="Follows your operating system. The explicit Reduced and Full choices are not wired up."
              />
              <SwitchRow
                label="High contrast"
                desc="Not implemented here on purpose — contrast is a whole token set, so it ships as a theme rather than a switch (#1753)."
                checked={form.high_contrast ?? false}
                disabled
                onChange={(value) => patch('high_contrast', value)}
              />
              <SwitchRow
                label="Larger evidence text"
                desc="Not implemented yet — needs a type-scale override scoped to tables, the terminal and payload views."
                checked={form.large_evidence_text ?? false}
                disabled
                onChange={(value) => patch('large_evidence_text', value)}
              />
              {saveButton('appearance', setAppearanceStatus)}
            </>
          ) : (
            placeholder
          )}
        </div>
      </Pane>
      <Pane id="navigation">
        <div className="card hp-field" hidden={hideNav}>
          <h2>Navigation &amp; tables</h2>
          {navStatus}
          {loaded ? (
            <>
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
            </>
          ) : (
            placeholder
          )}
        </div>
        {navigationExtra}
      </Pane>
      <Pane id="time">
        <div className="card hp-field" hidden={hideTime}>
          <h2>Time &amp; live data</h2>
          {timeStatus}
          {loaded ? (
            <>
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
                label="Operational alerts"
                desc="Show a toast when a sensor stops reporting, ingestion stalls, or the cluster degrades — and again when it recovers."
                checked={form.live_toasts ?? true}
                onChange={(value) => patch('live_toasts', value)}
              />
              {form.live_toasts ?? true ? (
                <div className="settings-field">
                  <label className="form-label" htmlFor="hp-pref-toast-interval">
                    Check frequency
                  </label>
                  <select
                    className="form-input"
                    id="hp-pref-toast-interval"
                    value={String(form.live_toast_interval_seconds ?? 3)}
                    onChange={(event) => patch('live_toast_interval_seconds', Number(event.target.value))}
                  >
                    {TOAST_INTERVALS.map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                  <div className="settings-field__desc">
                    How often the fleet is checked for problems. Each condition is announced once when it
                    starts and once when it clears, so an outage that lasts all afternoon is two toasts, not
                    one every check.
                  </div>
                </div>
              ) : null}
              {saveButton('time', setTimeStatus)}
            </>
          ) : (
            placeholder
          )}
        </div>
        <div className="card hp-field" hidden={hideNotify}>
          <h2>Notifications</h2>
          {notifyStatus}
          {loaded ? (
            <>
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
            </>
          ) : (
            placeholder
          )}
        </div>
      </Pane>
      <Pane id="map">
        <div className="card hp-field" hidden={hideMap}>
          <h2>Map &amp; investigation</h2>
          {mapStatus}
          {loaded ? (
            <>
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
            </>
          ) : (
            placeholder
          )}
        </div>
      </Pane>
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

function PresentationCard({ initial, editable, revision, onSaved, onConflict, onDirty, conflictRebase }: ConfigCardProps<Presentation>) {
  const [form, setForm] = useState<Presentation>(initial)
  const [snapshot, setSnapshot] = useState<Presentation>(initial)
  const [status, setStatus] = useSettingsStatus()
  const hidden = useFieldHidden('branding', 'presentation')
  // Re-baseline whenever fresh config arrives (initial load and the 409
  // conflict reload both replace the initial object). On a conflict
  // re-sync (#2513) the fresh server values go under the operator's
  // staged edits — fields still differing from the previous snapshot —
  // so the next save is a retry of the merged form, not a lost update.
  const lastRebase = useRef(0)
  useEffect(() => {
    const rebase = conflictRebase !== lastRebase.current
    lastRebase.current = conflictRebase
    if (!rebase) {
      setForm(initial)
      setSnapshot(initial)
      return
    }
    setForm((current) => {
      const staged: Partial<Presentation> = {}
      for (const key of PRESENTATION_FIELDS) {
        if ((current[key] ?? '') !== (snapshot[key] ?? '')) staged[key] = current[key]
      }
      return { ...initial, ...staged }
    })
    setSnapshot(initial)
    // `snapshot` is read deliberately stale here: the staged-edit diff is
    // against the baseline the operator edited on top of, not the incoming
    // one. Same for every card's rebase effect below.
  }, [initial, conflictRebase])
  const changed = PRESENTATION_FIELDS.filter((key) => (form[key] ?? '') !== (snapshot[key] ?? ''))
  useEffect(() => {
    onDirty(changed.length > 0)
  }, [changed.length, onDirty])
  const set = (key: keyof Presentation, value: string) => setForm((current) => ({ ...current, [key]: value }))
  const field = (key: keyof Presentation, label: string, extra?: { type?: string; placeholder?: string }) => (
    <label className="note hp-field">
      {label}
      <input
        className="form-input"
       
        type="text"
        value={(form[key] as string) ?? ''}
        disabled={!editable}
        onChange={(event) => set(key, event.target.value)}
        {...extra}
      />
    </label>
  )
  const textarea = (key: keyof Presentation, label: string) => (
    <label className="note hp-field">
      {label}
      <textarea
        className="form-input"
       
        rows={2}
        value={(form[key] as string) ?? ''}
        disabled={!editable}
        onChange={(event) => set(key, event.target.value)}
      />
    </label>
  )
  return (
    <div className="card hp-field" hidden={hidden}>
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
              try {
                const outcome = await runConfigSave({
                  section: 'presentation',
                  value: form,
                  revision,
                  setStatus,
                  onSaved,
                  onConflict,
                  successText: 'Saved — refresh to see it everywhere.',
                })
                if (outcome === 'saved') setSnapshot(form)
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
          <label className="note hp-field">
            Banner severity
            <select
              className="form-input"
             
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
          <button className="btn btn-secondary btn-sm hp-flow--tight" type="submit" disabled={changed.length === 0}>
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

// Form-state derivation for the honeypot card: numbers travel as strings
// so an in-progress edit never fights the input.
function honeypotForm(initial: HoneypotConfig): Record<string, string> {
  return {
    alert_cooldown: initial.alert_cooldown ?? '',
    alert_campaign_score: initial.alert_campaign_score?.toString() ?? '',
    sandbox_alert_risk_score: initial.sandbox_alert_risk_score?.toString() ?? '',
    ml_alert_threshold: initial.ml_alert_threshold?.toString() ?? '',
    yara_scan_interval_seconds: initial.yara_scan_interval_seconds?.toString() ?? '',
    yara_max_bytes: initial.yara_max_bytes?.toString() ?? '',
    payload_dedupe_interval_seconds: initial.payload_dedupe_interval_seconds?.toString() ?? '',
  }
}

function HoneypotOperationsCard({ initial, editable, revision, onSaved, onConflict, onDirty, conflictRebase }: ConfigCardProps<HoneypotConfig>) {
  const [form, setForm] = useState<Record<string, string>>(() => honeypotForm(initial))
  const [snapshot, setSnapshot] = useState(() => honeypotForm(initial))
  const [status, setStatus] = useSettingsStatus()
  const hidden = useFieldHidden('honeypot', 'operations')
  const lastRebase = useRef(0)
  useEffect(() => {
    const next = honeypotForm(initial)
    const rebase = conflictRebase !== lastRebase.current
    lastRebase.current = conflictRebase
    if (!rebase) {
      setForm(next)
      setSnapshot(next)
      return
    }
    // Conflict re-sync (#2513): staged edits survive on top of the fresh
    // server values.
    setForm((current) => {
      const merged = { ...next }
      for (const key of Object.keys(merged)) {
        if (current[key] !== snapshot[key]) merged[key] = current[key]
      }
      return merged
    })
    setSnapshot(next)
  }, [initial, conflictRebase])
  const changed = Object.keys(form).filter((key) => form[key] !== snapshot[key])
  useEffect(() => {
    onDirty(changed.length > 0)
  }, [changed.length, onDirty])
  const field = (key: keyof typeof form, label: string, placeholder?: string) => (
    <label className="note hp-field">
      {label}
      <input
        className="form-input"
       
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
    <div className="card hp-field" hidden={hidden}>
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
                const outcome = await runConfigSave({
                  section: 'honeypot',
                  value,
                  revision,
                  setStatus,
                  onSaved,
                  onConflict,
                  successText: 'Staged — apply with a restart of the affected services.',
                })
                if (outcome === 'saved') setSnapshot(form)
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
          <button className="btn btn-secondary btn-sm hp-flow--tight" type="submit" disabled={changed.length === 0}>
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

// #1653 item 6: everything parseIntList would silently drop — reported
// verbatim in the status line instead of vanishing from the saved value.
function invalidIntTokens(input: string): string[] {
  return input
    .split(',')
    .map((token) => token.trim())
    .filter((token) => token !== '')
    .filter((token) => !/^\d+$/.test(token) || Number(token) <= 0)
}

function behaviorForm(initial: BehaviorConfig) {
  return {
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
  }
}

function BehaviorCard({ initial, editable, revision, onSaved, onConflict, onDirty, conflictRebase }: ConfigCardProps<BehaviorConfig>) {
  const [form, setForm] = useState(() => behaviorForm(initial))
  const [snapshot, setSnapshot] = useState(() => behaviorForm(initial))
  const [status, setStatus] = useSettingsStatus()
  const hidden = useFieldHidden('behavior', 'behavior')
  const lastRebase = useRef(0)
  useEffect(() => {
    const next = behaviorForm(initial)
    const rebase = conflictRebase !== lastRebase.current
    lastRebase.current = conflictRebase
    if (!rebase) {
      setForm(next)
      setSnapshot(next)
      return
    }
    // Conflict re-sync (#2513): staged edits survive on top of the fresh
    // server values.
    setForm((current) => {
      const merged = { ...next }
      for (const key of Object.keys(merged) as (keyof typeof merged)[]) {
        if (JSON.stringify(current[key]) !== JSON.stringify(snapshot[key])) {
          ;(merged as Record<string, unknown>)[key] = current[key]
        }
      }
      return merged
    })
    setSnapshot(next)
  }, [initial, conflictRebase])
  const changed = (Object.keys(form) as (keyof ReturnType<typeof behaviorForm>)[]).filter(
    (key) => JSON.stringify(form[key]) !== JSON.stringify(snapshot[key]),
  )
  useEffect(() => {
    onDirty(changed.length > 0)
  }, [changed.length, onDirty])
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
    <div className="card hp-field" hidden={hidden}>
      <h2>Dashboard behavior</h2>
      <p className="note">Global defaults users can still override per session, plus feature visibility applied live for every user.</p>
      <form
        onSubmit={(event) => {
          event.preventDefault()
          if (changed.length === 0) return
          // Client-side pre-check before the confirm dialog even opens:
          // name the exact tokens parseIntList would drop, and abort.
          const badRows = invalidIntTokens(form.rows_per_page_options)
          const badRefresh = invalidIntTokens(form.refresh_interval_seconds_options)
          if (badRows.length > 0 || badRefresh.length > 0) {
            const parts: string[] = []
            if (badRows.length > 0) parts.push(`rows-per-page choices: ${badRows.join(', ')}`)
            if (badRefresh.length > 0) parts.push(`refresh interval choices: ${badRefresh.join(', ')}`)
            setStatus(`Invalid values in ${parts.join('; ')} — whole numbers greater than zero only.`, 'error')
            return
          }
          confirmAction({
            title: 'Save configuration?',
            description: `Apply these changes: ${changed.join(', ')}.`,
            confirmLabel: 'Save configuration',
            danger: false,
            onConfirm: async () => {
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
                const outcome = await runConfigSave({
                  section: 'behavior',
                  value,
                  revision,
                  setStatus,
                  onSaved,
                  onConflict,
                  successText: 'Saved — applies live for every user.',
                })
                if (outcome === 'saved') setSnapshot(form)
              } catch (error) {
                setStatus(`Configuration could not be saved — ${errorText(error)}`, 'error')
                throw error
              }
            },
          })
        }}
      >
        <div className="settings-grid">
          <label className="note hp-field">
            Default landing page
            <select
              className="form-input"
             
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
          <label className="note hp-field">
            Default time window
            <select
              className="form-input"
             
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
          <label className="note hp-field">
            Rows-per-page choices (comma-separated, from 10/25/50/100)
            <input
              className="form-input"
             
              type="text"
              placeholder="25, 50, 100"
              value={form.rows_per_page_options}
              disabled={!editable}
              onChange={(event) => setForm((current) => ({ ...current, rows_per_page_options: event.target.value }))}
            />
          </label>
          <label className="note hp-field">
            Maximum export rows (100–100000)
            <input
              className="form-input"
             
              type="text"
              inputMode="numeric"
              value={form.max_export_rows}
              disabled={!editable}
              onChange={(event) => setForm((current) => ({ ...current, max_export_rows: event.target.value }))}
            />
          </label>
          <label className="note hp-field">
            Refresh interval choices in seconds (from 10/15/30/60/120/300)
            <input
              className="form-input"
             
              type="text"
              placeholder="15, 30, 60, 300"
              value={form.refresh_interval_seconds_options}
              disabled={!editable}
              onChange={(event) => setForm((current) => ({ ...current, refresh_interval_seconds_options: event.target.value }))}
            />
          </label>
          <label className="note hp-field">
            Source stale threshold in minutes (2–120)
            <input
              className="form-input"
             
              type="text"
              inputMode="numeric"
              value={form.source_stale_minutes}
              disabled={!editable}
              onChange={(event) => setForm((current) => ({ ...current, source_stale_minutes: event.target.value }))}
            />
          </label>
          <label className="note hp-field">
            Default map provider
            <select
              className="form-input"
             
              value={form.map_provider}
              disabled={!editable}
              onChange={(event) => setForm((current) => ({ ...current, map_provider: event.target.value }))}
            >
              <option value="osm">OpenStreetMap</option>
            </select>
          </label>
          <label className="note hp-field">
            Default timezone for new users
            <input
              className="form-input"
             
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
          <button className="btn btn-secondary btn-sm hp-flow--tight" type="submit" disabled={changed.length === 0}>
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
  revision,
  onSaved,
  onConflict,
  onDirty,
  conflictRebase,
}: {
  templates: ReportTemplate[]
  overrides: Record<string, ReportPresetOverride>
} & Omit<ConfigCardProps<Record<string, ReportPresetOverride>>, 'initial'>) {
  const [form, setForm] = useState<Record<string, ReportPresetOverride>>(overrides)
  const [snapshot, setSnapshot] = useState<Record<string, ReportPresetOverride>>(overrides)
  const [status, setStatus] = useSettingsStatus()
  const hidden = useFieldHidden('report-presets', 'presets')
  const lastRebase = useRef(0)
  useEffect(() => {
    const rebase = conflictRebase !== lastRebase.current
    lastRebase.current = conflictRebase
    if (!rebase) {
      setForm(overrides)
      setSnapshot(overrides)
      return
    }
    // Conflict re-sync (#2513): staged overrides survive on top of the
    // fresh server values.
    setForm((current) => {
      const merged = { ...overrides }
      for (const template of templates) {
        if (
          current[template.id] !== undefined &&
          JSON.stringify(norm(current[template.id])) !== JSON.stringify(norm(snapshot[template.id]))
        ) {
          merged[template.id] = current[template.id]
        }
      }
      return merged
    })
    setSnapshot(overrides)
    // `norm` is declared just below; the effect body only runs after render.
  }, [overrides, conflictRebase, templates])

  // Normalized so an untouched empty field never reads as a change.
  const norm = (override?: ReportPresetOverride) => ({ name: override?.name ?? '', description: override?.description ?? '' })
  const changed = templates
    .filter((template) => JSON.stringify(norm(form[template.id])) !== JSON.stringify(norm(snapshot[template.id])))
    .map((template) => template.id)
  useEffect(() => {
    onDirty(changed.length > 0)
  }, [changed.length, onDirty])

  if (templates.length === 0) return null

  return (
    <div className="card hp-field" hidden={hidden}>
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
              try {
                const outcome = await runConfigSave({
                  section: 'report-presets',
                  value: form,
                  revision,
                  setStatus,
                  onSaved,
                  onConflict,
                  successText: 'Saved.',
                })
                if (outcome === 'saved') setSnapshot(form)
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
            <div key={template.id} className="card hp-flow">
              <div className="card__header">
                <div>
                  <h3>{template.name}</h3>
                </div>
              </div>
              <label className="note hp-field">
                Name
                <input
                  className="form-input"
                 
                  type="text"
                  placeholder={template.name}
                  value={override.name ?? ''}
                  disabled={!editable}
                  onChange={(event) =>
                    setForm((current) => ({ ...current, [template.id]: { ...current[template.id], name: event.target.value } }))
                  }
                />
              </label>
              <label className="note hp-field">
                Description
                <textarea
                  className="form-input"
                 
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
          <button className="btn btn-secondary btn-sm hp-flow--tight" type="submit" disabled={changed.length === 0}>
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
  const hidden = useFieldHidden('services', 'services')

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
    <div className="card hp-field" hidden={hidden}>
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
  const hidden = useFieldHidden('honeypot', 'reporter-stats')
  const metric = (value: unknown): string => {
    if (typeof value === 'number') return value.toLocaleString('en-US')
    if (typeof value === 'boolean') return value ? 'yes' : 'no'
    if (typeof value === 'string' && value) return value
    return '—'
  }
  return (
    <div className="card hp-field" hidden={hidden}>
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
  const hidden = useFieldHidden('history', 'history')

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
    <div className="card hp-field" hidden={hidden}>
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
                  <td className="v">{(entry.fields ?? []).join(', ')}</td>
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
  // #2178: the filter path collapsed a failed query into `{ events: [] }`,
  // rendering "No audit events recorded yet." — erasing the audit trail on
  // exactly the box that is failing. The initial path's settled-null sat on
  // its skeleton line forever. Both are named now.
  const [failed, setFailed] = useState(initial === null)
  const hidden = useFieldHidden('audit', 'audit')

  useEffect(() => {
    if (initial !== null) setData(initial)
  }, [initial])

  const applyFilter = async (action: string) => {
    setFilter(action)
    setData(null)
    setFailed(false)
    const result = await fetchAudit({ data: { action } })
    if (!result) {
      setFailed(true)
      return
    }
    setData(result)
  }

  return (
    <div className="card hp-field" hidden={hidden}>
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
      {data === null && failed ? (
        // Retrying re-issues whatever scope is selected; resubmitting via
        // the select is an equivalent retry.
        <ErrorStateBlock
          title="Audit log failed to load"
          hint="The backend request failed — this says nothing about what has been recorded."
          onRetry={() => void applyFilter(filter)}
        />
      ) : data === null ? (
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
                  <td className="v">{(event.fields ?? []).join(', ')}</td>
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


function Settings() {
  const { user, accountActions, ...data } = Route.useLoaderData()
  const searchParams = Route.useSearch()
  const navigate = useNavigate()
  return (
    <SettingsSurface
      data={data}
      user={user ?? null}
      accountActions={accountActions ?? null}
      pane={searchParams.pane}
      onPaneChange={(id) => void navigate({ to: '/settings', search: id === 'account' ? {} : { pane: id } })}
    />
  )
}

// The settings surface itself — the export seam (#1653 settings-as-modal):
// the /settings route above renders it in page mode (pane ↔ ?pane= search
// param, "pick 13B"); components/SettingsModal.tsx renders the same surface
// with `onClose` set, which swaps the permanently-open page chrome for the
// theme's centered-modal contract (settings_modal.html's
// .modal.hp-dash-settings + .modal__close).
export function SettingsSurface({
  data,
  user,
  accountActions = null,
  pane,
  onPaneChange,
  onClose,
}: {
  data: SettingsData
  user: User | null
  /** Keycloak account-console deep links (null when OIDC is disabled). */
  accountActions?: AccountActions
  /** Requested pane name (unvalidated — falls back to "account"). */
  pane?: string
  onPaneChange: (id: string) => void
  /** Present in modal mode: renders modal chrome and the close button. */
  onClose?: () => void
}) {
  const { storage, preferences, admin, services, history, audit, reporterStats } = data
  const theme = useThemeMode()
  const [prefetch, setPrefetch] = useState(true)
  const [prefsData, setPrefsData] = useState<Prefs | null | 'loading'>('loading')
  const [storageData, setStorageData] = useState<EsStorage | null>(null)
  const [adminData, setAdminData] = useState<AdminConfig | null>(null)
  // #2311: the write-side companion of adminData — true means fetchAdminData
  // settled to null and no real config has been loaded (or a reload of one
  // failed). While it stands, every admin pane parks behind an honest
  // failure card instead of offering mutation affordances built from
  // fabricated state; saving from synthetic data is what manufactured the
  // poisoned If-Match: "0" in the first place.
  const [adminFailed, setAdminFailed] = useState(false)
  const [servicesData, setServicesData] = useState<ServicesResponse | null>(null)
  const [historyData, setHistoryData] = useState<HistoryResponse | null>(null)
  const [auditData, setAuditData] = useState<AuditResponse | null>(null)
  const [reporterStatsData, setReporterStatsData] = useState<ReporterStats | null>(null)

  const isAdmin = !user || user.role === 'admin'

  // ?pane= deep link; unknown names and admin panes for non-admins fall
  // back to "account" (hp-settings.js:339-341).
  const requested = pane as PaneId | undefined
  const active: PaneId =
    requested && PANE_META[requested] && (isAdmin || !PANE_META[requested].admin) ? requested : 'account'

  // Cross-pane search: the raw input mirrors the rail's search field; the
  // trimmed lowercase form drives all matching.
  const [rawQuery, setRawQuery] = useState('')
  const query = rawQuery.trim().toLowerCase()

  const showPane = (id: PaneId) => {
    // Selecting a pane leaves search mode, like hp-settings.js:346-347.
    setRawQuery('')
    onPaneChange(id)
  }

  /* ---- aggregate dirty state (#1653 item 4) ---- */
  const [dirtyMap, setDirtyMap] = useState<Record<string, { pane: PaneId; dirty: boolean }>>({})
  const reportDirty = useCallback((pane: PaneId, key: string, dirty: boolean) => {
    setDirtyMap((prev) => (prev[key]?.dirty === dirty ? prev : { ...prev, [key]: { pane, dirty } }))
  }, [])
  const brandingDirty = useCallback((dirty: boolean) => reportDirty('branding', 'branding', dirty), [reportDirty])
  const honeypotDirty = useCallback((dirty: boolean) => reportDirty('honeypot', 'honeypot', dirty), [reportDirty])
  const behaviorDirty = useCallback((dirty: boolean) => reportDirty('behavior', 'behavior', dirty), [reportDirty])
  const presetsDirty = useCallback((dirty: boolean) => reportDirty('report-presets', 'report-presets', dirty), [reportDirty])
  const paneDirty = (pane: PaneId) => Object.values(dirtyMap).some((entry) => entry.pane === pane && entry.dirty)
  const anyDirty = Object.values(dirtyMap).some((entry) => entry.dirty)
  const dirtyRef = useRef(anyDirty)
  dirtyRef.current = anyDirty

  // In-app navigation guard + beforeunload for hard reloads
  // (hp-settings.js:317-321). Pane switches stay inside /settings and are
  // never blocked. In modal mode router navigation is never blocked (the
  // overlay just closes with the page changing underneath, like the Go
  // modal); the beforeunload guard still covers hard reloads.
  const inModal = onClose !== undefined
  const blocker = useBlocker({
    shouldBlockFn: ({ next }) => (inModal || next.pathname === '/settings' ? false : dirtyRef.current),
    enableBeforeUnload: () => dirtyRef.current,
    withResolver: true,
  })
  useEffect(() => {
    if (blocker.status !== 'blocked') return
    const { proceed, reset } = blocker
    let decided = false
    confirmAction({
      title: 'Discard unsaved settings changes?',
      description: 'You have unsaved settings edits — leaving this page discards them.',
      confirmLabel: 'Discard and leave',
      danger: true,
      onConfirm: () => {
        decided = true
        proceed()
      },
    })
    // confirmAction has no cancel callback: watch the shared dialog host —
    // once it has appeared and then closed without a decision, stay here.
    let seen = false
    const timer = window.setInterval(() => {
      const open = document.getElementById('hp-confirm-backdrop') !== null
      if (open) {
        seen = true
        return
      }
      if (seen && !decided) {
        decided = true
        reset()
      }
    }, 150)
    return () => window.clearInterval(timer)
  }, [blocker])

  /* ---- config revision plumbing (#1653 item 5, #2513 re-sync) ---- */
  const bumpRevision = useCallback((revision: number) => {
    setAdminData((current) => (current ? { ...current, revision } : current))
  }, [])
  const reloadAdminConfig = useCallback(async () => {
    const fresh = await fetchAdminData()
    if (!fresh) {
      // #2311: a failed reload used to be silently ignored, leaving the
      // operator on whatever state the last successful load had while the
      // status line said nothing. Name it: already-loaded cards keep their
      // real data, but a page that never loaded anything parks on the
      // failure card instead of skeletons-forever.
      setAdminFailed(true)
      return
    }
    setAdminFailed(false)
    setAdminData(fresh)
  }, [])
  // #2513: bumped whenever a 409 arrives carrying X-Current-Revision
  // (#2512) — the cards read it to keep their staged edits during the
  // re-baseline instead of discarding them. Rollback and header-less
  // conflicts reload without arming it, keeping the legacy recovery.
  const [conflictRebase, setConflictRebase] = useState(0)
  const handleConfigConflict = useCallback(
    async (currentRevision?: number) => {
      await reloadAdminConfig()
      if (typeof currentRevision === 'number') setConflictRebase((n) => n + 1)
    },
    [reloadAdminConfig],
  )

  useEffect(() => {
    setPrefetch(prefetchEnabled())
    // The reconcile against server-stored appearance moved to the root
    // route's mount in #1755, so it now happens once per session on every
    // page rather than only when this one is opened.
    let cancelled = false
    storage.then((result) => {
      if (!cancelled && result) setStorageData(result)
    })
    preferences.then((result) => {
      if (!cancelled) setPrefsData(result)
    })
    admin.then((result) => {
      if (cancelled) return
      // #2311: settled-null means the fetch failed whole — name it instead
      // of leaving every admin pane on its skeleton forever. Nothing is
      // stored: adminData stays null, so no mutation affordance can exist.
      if (result) setAdminData(result)
      else setAdminFailed(true)
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

  const modes: { id: ThemeMode; label: string }[] = [
    { id: 'system', label: 'System' },
    { id: 'dark', label: 'Dark' },
    { id: 'light', label: 'Light' },
  ]

  // hp-field visibility for cards built right here (Settings can't consume
  // its own provider, so it matches directly).
  const fieldHidden = (pane: PaneId, field: string) =>
    query !== '' && !matchesQuery(SEARCH_INDEX[pane][field] ?? '', query)

  const loadingCard = (
    <div className="card">
      <span className="skeleton-line" aria-hidden="true" />
      <span className="skeleton-line" aria-hidden="true" />
    </div>
  )

  // #2311: shared across every admin pane — the parked state an outage
  // renders instead of mutation affordances built from fabricated config.
  // If-Match never fires from here because no editable card mounts while
  // adminData is null; Retry refetches the whole admin bundle. #2178 phase
  // 3 will carry this exact ErrorStateBlock usage into its render sweep.
  const adminLoadFailure = (
    <ErrorStateBlock
      title="Administration settings failed to load"
      hint="The backend request failed — nothing on these panes reflects real configuration, so saving is unavailable."
      onRetry={() => void reloadAdminConfig()}
    />
  )

  const profileCard = (
    <div className="card hp-field" hidden={fieldHidden('account', 'profile')}>
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
      {accountActions ? (
        <>
          <hr className="empty-state__divider" />
          <p className="note">
            Password, passkeys, two-factor authentication, and sessions are managed by Keycloak. These protected pages open
            in a new tab and are never embedded.
          </p>
          <div className="card__row">
            <div>
              <div className="card__label">Profile &amp; password</div>
              <div className="card__value">Account details, password change, and recovery email.</div>
            </div>
            <a className="btn btn-secondary btn-sm" href={accountActions.profile} target="_blank" rel="noopener noreferrer">
              Open
            </a>
          </div>
          <div className="card__row">
            <div>
              <div className="card__label">Passkeys &amp; two-factor authentication</div>
              <div className="card__value">Register hardware keys, authenticator apps, and WebAuthn credentials.</div>
            </div>
            <a className="btn btn-secondary btn-sm" href={accountActions.security} target="_blank" rel="noopener noreferrer">
              Open
            </a>
          </div>
          <div className="card__row">
            <div>
              <div className="card__label">Sessions &amp; devices</div>
              <div className="card__value">Active sessions and trusted devices; revoke any of them.</div>
            </div>
            <a className="btn btn-secondary btn-sm" href={accountActions.sessions} target="_blank" rel="noopener noreferrer">
              Open
            </a>
          </div>
          <div className="card__row">
            <div>
              <div className="card__label">Security settings</div>
              <div className="card__value">Open the Keycloak Account Console in a new tab.</div>
            </div>
            <a
              className="btn btn-secondary btn-sm"
              href={accountActions.manageAccount}
              target="_blank"
              rel="noopener noreferrer"
            >
              Manage account
            </a>
          </div>
        </>
      ) : null}
    </div>
  )

  const themeCard = (
    <div className="card hp-field" hidden={fieldHidden('appearance', 'theme')}>
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
      <p className="note">Theme</p>
      {/* #1758: was nine 11px dots whose colours were hardcoded dark-mode
          accents, so in light mode they previewed colours that appeared
          nowhere on screen. Each tile now renders that theme's real tokens
          in the mode you are actually in. */}
      <ThemeGallery />
    </div>
  )

  const prefetchCard = (
    <div className="card hp-field" hidden={fieldHidden('navigation', 'prefetch')}>
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
  )

  const sidebarItem = (id: PaneId) => (
    <button
      key={id}
      className={`sidebar__item${active === id ? ' active' : ''}${paneDirty(id) ? ' is-dirty' : ''}`}
      type="button"
      hidden={query !== '' && !paneMatches(id, query)}
      onClick={() => showPane(id)}
    >
      {PANE_META[id].title}
    </button>
  )

  return (
    <SettingsUi.Provider value={{ query, active }}>
      {/* The page-mode settings surface (theme.css "pick 13B",
          #hp-settings.hp-dash-settings--page): the modal fragment's exact
          rail/pane composition, permanently open, minus the overlay
          chrome — matching what hp-settings.js:88-99 builds on /settings.
          In modal mode the same fragment keeps its overlay chrome
          (settings_modal.html:8-9): the centered .modal.hp-dash-settings
          box with its absolute .modal__close. */}
      <section
        className={inModal ? 'modal hp-dash-settings open' : 'modal hp-dash-settings hp-dash-settings--page open'}
        id={inModal ? undefined : 'hp-settings'}
        role={inModal ? 'dialog' : undefined}
        aria-modal={inModal ? true : undefined}
        aria-labelledby="hp-dash-settings-title"
      >
        {inModal ? (
          <button className="modal__close" type="button" aria-label="Close settings" onClick={onClose}>
            {'✕'}
          </button>
        ) : null}
        <div className="settings-layout">
          <aside className="settings-layout__sidebar" aria-label="Settings sections">
            <div className="sidebar__search">
              <span aria-hidden="true">{'⌖'}</span>
              <input
                aria-label="Search settings"
                placeholder="Search settings"
                type="search"
                autoComplete="off"
                value={rawQuery}
                onChange={(event) => setRawQuery(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Escape') {
                    setRawQuery('')
                    event.stopPropagation()
                  }
                }}
              />
            </div>
            <div className="sidebar__section-label">Personal</div>
            {PERSONAL_PANES.map(sidebarItem)}
            {isAdmin ? (
              <>
                <div className="sidebar__section-label">Administration</div>
                {ADMIN_PANES.map(sidebarItem)}
              </>
            ) : null}
          </aside>
          <div className="settings-layout__content">
            <div className="hp-settings-column">
              <header className="hp-settings-head">
                <div>
                  <h1 id="hp-dash-settings-title">{PANE_META[active].title}</h1>
                  <p>{PANE_META[active].desc}</p>
                </div>
              </header>
              {/* onReset applies the theme rather than only moving the
                  picker's selection: it used to call setPalette, so resetting
                  preferences changed the highlight and left the page styled
                  as before. The gallery follows automatically because it
                  reads the DOM rather than a local mirror. */}
              <PersonalPanes
                prefsState={prefsData}
                onReset={(prefs) => applyPalette(prefs.palette ?? 'claude')}
                onDirty={reportDirty}
                profileCard={profileCard}
                appearanceLead={themeCard}
                navigationExtra={prefetchCard}
              />
              {isAdmin ? (
                <>
                  <Pane id="branding">
                    {adminData ? (
                      <PresentationCard
                        initial={adminData.presentation}
                        editable={isAdmin}
                        revision={adminData.revision}
                        onSaved={bumpRevision}
                        onConflict={handleConfigConflict}
                        onDirty={brandingDirty}
                        conflictRebase={conflictRebase}
                      />
                    ) : adminFailed ? (
                      adminLoadFailure
                    ) : (
                      loadingCard
                    )}
                  </Pane>
                  <Pane id="report-presets">
                    {adminData ? (
                      <ReportPresetsCard
                        templates={adminData.reportTemplates}
                        overrides={adminData.reportPresets}
                        editable={isAdmin}
                        revision={adminData.revision}
                        onSaved={bumpRevision}
                        onConflict={handleConfigConflict}
                        onDirty={presetsDirty}
                        conflictRebase={conflictRebase}
                      />
                    ) : adminFailed ? (
                      adminLoadFailure
                    ) : (
                      loadingCard
                    )}
                  </Pane>
                  <Pane id="behavior">
                    {adminData ? (
                      <BehaviorCard
                        initial={adminData.behavior}
                        editable={isAdmin}
                        revision={adminData.revision}
                        onSaved={bumpRevision}
                        onConflict={handleConfigConflict}
                        onDirty={behaviorDirty}
                        conflictRebase={conflictRebase}
                      />
                    ) : adminFailed ? (
                      adminLoadFailure
                    ) : (
                      loadingCard
                    )}
                  </Pane>
                  <Pane id="honeypot">
                    <ReporterStatsCard data={reporterStatsData} />
                    {adminData ? (
                      <HoneypotOperationsCard
                        initial={adminData.honeypot}
                        editable={isAdmin}
                        revision={adminData.revision}
                        onSaved={bumpRevision}
                        onConflict={handleConfigConflict}
                        onDirty={honeypotDirty}
                        conflictRebase={conflictRebase}
                      />
                    ) : adminFailed ? (
                      adminLoadFailure
                    ) : (
                      loadingCard
                    )}
                  </Pane>
                  <Pane id="users">
                    <div className="card hp-field" hidden={fieldHidden('users', 'users')}>
                      <h2>Projected dashboard users</h2>
                      <p className="note">Diagnostic projection of who used the dashboard. Account management lives in the auth service.</p>
                      {adminData ? (
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
                      ) : adminFailed ? (
                        // #2311: an outage used to render an empty roster —
                        // reading as "no one has ever used the dashboard".
                        adminLoadFailure
                      ) : (
                        <span className="skeleton-line" aria-hidden="true" />
                      )}
                    </div>
                  </Pane>
                  <Pane id="services">
                    <ServicesCard initial={servicesData} editable={isAdmin} />
                  </Pane>
                  {/* Canarytokens + dead letters (#1653 item 3): the full
                      tools live on their own routes now (/canarytokens,
                      /credentials, /dead-letters) — these panes are
                      deliberately thin admin surfaces that carry the Go
                      panes' copy and hand off to the full pages, never a
                      duplicate of the tools themselves. */}
                  <Pane id="canarytokens">
                    <div className="card hp-field" hidden={fieldHidden('canarytokens', 'canarytokens')}>
                      <h2>Create a Canarytoken</h2>
                      <p className="note">
                        The resulting artifact is yours to plant anywhere — an email, a fileshare, a USB drive. It phones home
                        the instant it's opened, wherever that is.
                      </p>
                      <div className="card__row">
                        <div>
                          <div className="card__label">Canarytokens</div>
                          <div className="card__value">Create tokens and re-download previously created artifacts.</div>
                        </div>
                        <Link className="btn btn-secondary btn-sm" to="/canarytokens">
                          Open full page {'→'}
                        </Link>
                      </div>
                      <div className="card__row">
                        <div>
                          <div className="card__label">Planted credentials</div>
                          <div className="card__value">
                            Bait usernames and passwords implanted into honeypot filesystems, optionally linked to a
                            canarytoken.
                          </div>
                        </div>
                        <Link className="btn btn-secondary btn-sm" to="/credentials">
                          Open full page {'→'}
                        </Link>
                      </div>
                    </div>
                  </Pane>
                  <Pane id="elasticsearch">
                    <EsHistoryConsole storage={storageData} hidden={fieldHidden('elasticsearch', 'console')} />
                  </Pane>
                  <Pane id="dead-letters">
                    <div className="card hp-field" hidden={fieldHidden('dead-letters', 'dead-letters')}>
                      <h2>Ingest dead letters</h2>
                      <p className="note">
                        Documents Elasticsearch rejected, with their original error and field shape for remediation.
                      </p>
                      <div className="card__row">
                        <div>
                          <div className="card__label">Dead letters</div>
                          <div className="card__value">List, search, and purge rejected documents.</div>
                        </div>
                        <Link className="btn btn-secondary btn-sm" to="/dead-letters">
                          Open full page {'→'}
                        </Link>
                      </div>
                    </div>
                  </Pane>
                  <Pane id="history">
                    <ConfigHistoryCard initial={historyData} editable={isAdmin} />
                  </Pane>
                  <Pane id="audit">
                    <AuditLogCard initial={auditData} />
                  </Pane>
                </>
              ) : null}
            </div>
          </div>
        </div>
      </section>
    </SettingsUi.Provider>
  )
}
