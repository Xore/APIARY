// Reports studio — generated PDF reports and the report definitions
// behind them: full CRUD plus on-demand generation, now that the worker
// port (#1610) and the reports API port (#1612) have both landed
// server-side (backend-service/src/reports_api.rs, reports_store.rs).
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState, type ReactNode } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { getSessionUser } from '../lib/auth'
import { pathString, type JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'
import { useSidebarViewTabs } from '../lib/viewTabs'

type StoreRow = JsonRecord
type Page = { total: number; rows: StoreRow[] }

type ReportTemplate = {
  id: string
  name: string
  description: string
  title: string
  theme: string
  window: string
  elements: string[]
  sandbox: boolean
  payload: boolean
  ghidra: boolean
}
type ReportElementInfo = { id: string; label: string; description: string }
type TemplatesResponse = { templates: ReportTemplate[]; elements: ReportElementInfo[] }

type ReportBranding = {
  title: string
  author: string
  header_left: string
  header_right: string
  footer_left: string
  classification: string
}
// Scope fields exposed in this form: window, ip, sensor, port, signature
// (the ones with an obvious single-line-text UI), plus job/hash for the
// sandbox/payload/ghidra templates. network, country, asn, text, type and
// session stay at their unscoped empty default — a 13-field scope builder
// is more than this pass's CRUD form needs; the skipped fields are still
// round-tripped untouched when editing an existing definition.
type ReportScope = {
  window: string
  ip: string
  network: string
  sensor: string
  port: string
  signature: string
  country: string
  asn: string
  text: string
  type: string
  session: string
  job: string
  hash: string
}
type ReportSchedule = {
  enabled: boolean
  frequency: string
  hour: number
  minute: number
  weekday: number
  month_day: number
  last_run_at: string
  next_run_at: string
}
type ReportDefinition = {
  id: string
  name: string
  template: string
  theme: string
  branding: ReportBranding
  scope: ReportScope
  elements: string[]
  appendix_limit: number
  schedule?: ReportSchedule | null
  created: string
  updated?: string
}
type DefinitionsResponse = { definitions: ReportDefinition[] }

const fetchGenerated = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<Page | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/store/generated-reports?offset=${data.offset}&size=25`)
  })

// Sandbox-job dropdown options (hp-reports.js loadSandboxJobs, /api/sandbox):
// recent sandbox-analysis-v1 runs, labeled job — sha… (risk). A null result
// renders the picker's honest "sandbox results unavailable" state before the
// operator builds a definition around a job that can't resolve.
type SandboxJobOption = { job: string; sha256: string; risk: string }
const fetchSandboxJobs = createServerFn({ method: 'GET' }).handler(async (): Promise<SandboxJobOption[] | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  const page = await serviceJSON<Page>('/api/v1/store/sandbox-runs?offset=0&size=25')
  if (!page) return null
  return page.rows
    .map((row) => ({
      job: pathString(row, 'sandbox', 'job') || pathString(row, 'job'),
      sha256: pathString(row, 'file', 'hash', 'sha256'),
      risk: pathString(row, 'risk_level'),
    }))
    .filter((row) => row.job !== '')
})

// Payload picker rows (hp-reports.js searchPayloads, /api/reports/
// payload-options): captured-payload inventory matched by hash prefix or
// file kind. The Go endpoint's per-payload analysis-source badges
// (sandbox/ghidra/github) have no Rust equivalent yet, so rows carry the
// inventory's own capture sources instead.
type PayloadOption = { hash: string; kind: string; size: string; sources: string[] }
const searchPayloads = createServerFn({ method: 'GET' })
  .inputValidator((input: { q: string }) => input)
  .handler(async ({ data }): Promise<PayloadOption[] | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    // /api/v1/payloads' q is a Lucene query_string passthrough; the term is
    // stripped to hash/kind-safe characters before being spliced in.
    const term = data.q.replace(/[^\w.-]/g, '')
    const filter = term ? `&q=${encodeURIComponent(`Hash:${term}* OR Kind:${term}*`)}` : ''
    const page = await serviceJSON<Page>(`/api/v1/payloads?offset=0&size=8${filter}`)
    if (!page) return null
    return page.rows
      .map((row) => ({
        hash: pathString(row, 'Hash'),
        kind: pathString(row, 'Kind'),
        size: pathString(row, 'SizeH'),
        sources: Array.isArray(row.Sources) ? (row.Sources as unknown[]).filter((s): s is string => typeof s === 'string') : [],
      }))
      .filter((row) => row.hash !== '')
  })

const fetchTemplates = createServerFn({ method: 'GET' }).handler(async (): Promise<TemplatesResponse | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<TemplatesResponse>('/api/v1/reports/templates')
})

const fetchDefinitions = createServerFn({ method: 'GET' }).handler(async (): Promise<DefinitionsResponse | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<DefinitionsResponse>('/api/v1/reports/definitions')
})

// Every definition mutation is admin-gated at the BFF — this crate's own
// trust boundary is the service token, so the BFF-side check is the only
// one that exists (same posture as settings.tsx's savePresentation).
const createDefinition = createServerFn({ method: 'POST' })
  .inputValidator((input: ReportDefinition) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/reports/definitions', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(data),
    })
    if (response.ok) return { ok: true }
    return { ok: false, error: await response.text() }
  })

const updateDefinition = createServerFn({ method: 'POST' })
  .inputValidator((input: { id: string; definition: ReportDefinition }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/reports/definitions/${encodeURIComponent(data.id)}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(data.definition),
    })
    if (response.ok) return { ok: true }
    return { ok: false, error: await response.text() }
  })

const deleteDefinition = createServerFn({ method: 'POST' })
  .inputValidator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/reports/definitions/${encodeURIComponent(data.id)}`, { method: 'DELETE' })
    if (response.ok) return { ok: true }
    return { ok: false, error: await response.text() }
  })

const generateDefinition = createServerFn({ method: 'POST' })
  .inputValidator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/reports/definitions/${encodeURIComponent(data.id)}/generate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ origin: 'manual' }),
    })
    if (response.ok) return { ok: true }
    // 501 (sandbox/payload/ghidra not yet rendered here) and 422 (scope
    // doesn't resolve) both arrive as plain-text bodies that already read
    // as a clear inline message — surfaced as-is, not a generic toast.
    return { ok: false, error: await response.text() }
  })

export const Route = createFileRoute('/reports')({
  loader: async () => ({
    generated: fetchGenerated({ data: { offset: 0 } }),
    templates: fetchTemplates(),
    definitions: fetchDefinitions(),
    user: await getSessionUser(),
  }),
  component: Reports,
})

const str = (row: StoreRow, key: string): string => (typeof row[key] === 'string' ? (row[key] as string) : '')
const num = (row: StoreRow, key: string): number => (typeof row[key] === 'number' ? (row[key] as number) : 0)

const COLUMNS: Column<StoreRow>[] = [
  { header: 'created', render: (row) => formatTimestamp(str(row, 'created_at')) },
  {
    header: 'title',
    className: 'v',
    primary: true,
    render: (row) => str(row, 'title') || str(row, 'name') || <span className="tw:text-muted">(untitled report)</span>,
  },
  { header: 'template', render: (row) => <span className="badge badge--muted">{str(row, 'template')}</span> },
  { header: 'origin', render: (row) => str(row, 'origin') },
  { header: 'size', className: 'n', render: (row) => `${(num(row, 'size_bytes') / 1024).toFixed(0)} KB` },
  {
    header: 'pdf',
    render: (row) => (
      <a
        className="lnk"
        href={`/api/report/${encodeURIComponent(str(row, 'id'))}/pdf`}
        target="_blank"
        rel="noopener noreferrer"
        onClick={(event) => event.stopPropagation()}
      >
        open PDF →
      </a>
    ),
  },
]

// reports.html:38-43's wizard steps — the studio reads as five views:
// four form steps plus the Library of saved definitions and finished PDFs.
const STEPS = [
  { id: 'design', label: 'Design' },
  { id: 'scope', label: 'Scope' },
  { id: 'schedule', label: 'Schedule' },
  { id: 'branding', label: 'Branding' },
  { id: 'library', label: 'Library' },
] as const

type StepId = (typeof STEPS)[number]['id']

function emptyBranding(): ReportBranding {
  return { title: '', author: '', header_left: '', header_right: '', footer_left: '', classification: '' }
}
function emptyScope(): ReportScope {
  return {
    window: '',
    ip: '',
    network: '',
    sensor: '',
    port: '',
    signature: '',
    country: '',
    asn: '',
    text: '',
    type: '',
    session: '',
    job: '',
    hash: '',
  }
}
// Defaults mirror reports.html:164-170's fresh form: weekly on Monday,
// monthly on the 1st, both adjustable below.
function emptySchedule(): ReportSchedule {
  return { enabled: false, frequency: 'daily', hour: 6, minute: 30, weekday: 1, month_day: 1, last_run_at: '', next_run_at: '' }
}
function emptyDefinition(): ReportDefinition {
  return {
    id: '',
    name: '',
    template: '',
    theme: 'dark',
    branding: emptyBranding(),
    scope: emptyScope(),
    elements: [],
    appendix_limit: 120,
    schedule: null,
    created: '',
  }
}
function hydrateDefinition(def: ReportDefinition): ReportDefinition {
  return {
    ...emptyDefinition(),
    ...def,
    branding: { ...emptyBranding(), ...def.branding },
    scope: { ...emptyScope(), ...def.scope },
    elements: def.elements ?? [],
    schedule: def.schedule ? { ...emptySchedule(), ...def.schedule } : null,
  }
}

function pad2(value: number): string {
  return String(value).padStart(2, '0')
}

// reports.html:169's weekday select, Monday-first with Go's 0=Sunday values.
const WEEKDAYS: [number, string][] = [
  [1, 'Monday'],
  [2, 'Tuesday'],
  [3, 'Wednesday'],
  [4, 'Thursday'],
  [5, 'Friday'],
  [6, 'Saturday'],
  [0, 'Sunday'],
]

// hp-reports.js:566-587's schedule starter presets, one per cadence.
type SchedulePreset = {
  id: string
  name: string
  desc: string
  chip: string
  frequency: string
  hour: number
  minute: number
  weekday?: number
  monthDay?: number
  icon: ReactNode
}
const SCHEDULE_PRESETS: SchedulePreset[] = [
  {
    id: 'weekly-board',
    name: 'Weekly board briefing',
    desc: 'A high-level roundup for leadership, once a week.',
    chip: 'Weekly · Mon 06:00 UTC',
    frequency: 'weekly',
    hour: 6,
    minute: 0,
    weekday: 1,
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <rect x="3" y="4" width="18" height="18" rx="2" />
        <line x1="16" y1="2" x2="16" y2="6" />
        <line x1="8" y1="2" x2="8" y2="6" />
        <line x1="3" y1="10" x2="21" y2="10" />
      </svg>
    ),
  },
  {
    id: 'daily-ops',
    name: 'Daily ops digest',
    desc: 'A daily pulse for the operations team.',
    chip: 'Daily · 06:00 UTC',
    frequency: 'daily',
    hour: 6,
    minute: 0,
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <circle cx="12" cy="12" r="5" />
        <line x1="12" y1="1" x2="12" y2="3" />
        <line x1="12" y1="21" x2="12" y2="23" />
        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
        <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
        <line x1="1" y1="12" x2="3" y2="12" />
        <line x1="21" y1="12" x2="23" y2="12" />
      </svg>
    ),
  },
  {
    id: 'monthly-exec',
    name: 'Monthly executive summary',
    desc: 'One consolidated report, first of the month.',
    chip: 'Monthly · day 1',
    frequency: 'monthly',
    hour: 6,
    minute: 0,
    monthDay: 1,
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M12 20V10" />
        <path d="M18 20V4" />
        <path d="M6 20v-4" />
      </svg>
    ),
  },
]

function DefinitionForm({
  step,
  templates,
  elements,
  initial,
  anyScheduled,
  onCancel,
  onSaved,
}: {
  /** Which wizard step is active — the form keeps every step mounted
   * (hidden panels) so state survives moving between steps. */
  step: StepId
  templates: ReportTemplate[]
  elements: ReportElementInfo[]
  initial: ReportDefinition
  /** Whether any saved definition already has an active schedule — gates
   * the starter-preset gallery, matching hp-reports.js'
   * updateScheduleEmptyState (not this form's own schedule fields). */
  anyScheduled: boolean
  onCancel: () => void
  onSaved: () => void
}) {
  const isCreate = !initial.id
  const [name, setName] = useState(initial.name)
  const [template, setTemplate] = useState(initial.template || templates[0]?.id || '')
  const [theme, setTheme] = useState(initial.theme || 'dark')
  const [scope, setScope] = useState<ReportScope>(initial.scope)
  const [selectedElements, setSelectedElements] = useState<string[]>(initial.elements)
  const [branding, setBranding] = useState<ReportBranding>(initial.branding)
  const [appendixLimit, setAppendixLimit] = useState(initial.appendix_limit || 120)
  const [schedule, setSchedule] = useState<ReportSchedule>(initial.schedule ?? emptySchedule())
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  const activeTemplate = templates.find((entry) => entry.id === template)
  const isSpecial = Boolean(activeTemplate?.sandbox || activeTemplate?.payload || activeTemplate?.ghidra)

  // Sandbox-job dropdown (hp-reports.js loadSandboxJobs): loaded once, the
  // first time a sandbox template is active; null = still loading, [] with
  // jobsFailed = the honest unavailable state.
  const [sandboxJobs, setSandboxJobs] = useState<SandboxJobOption[] | null>(null)
  const [jobsFailed, setJobsFailed] = useState(false)
  const [jobsRequested, setJobsRequested] = useState(false)
  useEffect(() => {
    if (!activeTemplate?.sandbox || jobsRequested) return
    setJobsRequested(true)
    fetchSandboxJobs()
      .then((rows) => {
        setSandboxJobs(rows ?? [])
        setJobsFailed(rows === null)
      })
      .catch(() => {
        setSandboxJobs([])
        setJobsFailed(true)
      })
  }, [activeTemplate?.sandbox, jobsRequested])

  // Payload picker (hp-reports.js searchPayloads/loadPayloadByHash):
  // debounced search over the captured-payload inventory. On edit, one
  // exact-hash search prefills the selected line with real kind/size.
  const wantsHash = Boolean(activeTemplate?.payload || activeTemplate?.ghidra)
  const [payloadQuery, setPayloadQuery] = useState('')
  const [payloadResults, setPayloadResults] = useState<PayloadOption[] | null>(null)
  const [payloadError, setPayloadError] = useState(false)
  const [selectedPayload, setSelectedPayload] = useState<PayloadOption | null>(
    initial.scope.hash ? { hash: initial.scope.hash, kind: '', size: '', sources: [] } : null,
  )
  useEffect(() => {
    if (!wantsHash) return
    const timer = window.setTimeout(() => {
      searchPayloads({ data: { q: payloadQuery.trim() } })
        .then((rows) => {
          setPayloadResults(rows ?? [])
          setPayloadError(rows === null)
        })
        .catch(() => {
          setPayloadResults([])
          setPayloadError(true)
        })
    }, 250)
    return () => window.clearTimeout(timer)
  }, [wantsHash, payloadQuery])
  useEffect(() => {
    if (!wantsHash || !initial.scope.hash) return
    searchPayloads({ data: { q: initial.scope.hash } })
      .then((rows) => {
        const row = rows?.find((candidate) => candidate.hash === initial.scope.hash)
        if (row) setSelectedPayload(row)
      })
      .catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps -- prefill once per edited definition
  }, [wantsHash, initial.scope.hash])

  const pickPayload = (row: PayloadOption) => {
    setSelectedPayload(row)
    setScope((current) => ({ ...current, hash: row.hash }))
  }

  // Prefill elements from the chosen template's defaults — only on a fresh
  // (create) definition, and only for templates that use elements at all.
  const pickTemplate = (id: string) => {
    setTemplate(id)
    const picked = templates.find((entry) => entry.id === id)
    if (isCreate && picked && !picked.sandbox && !picked.payload && !picked.ghidra) {
      setSelectedElements(picked.elements)
    }
  }

  const toggleElement = (id: string) => {
    setSelectedElements((current) => (current.includes(id) ? current.filter((entry) => entry !== id) : [...current, id]))
  }

  const scopeField = (key: 'ip' | 'sensor' | 'port' | 'signature' | 'job' | 'hash', label: string, maxLength: number) => (
    <label className="note" style={{ display: 'block', minWidth: 180 }}>
      {label}
      <input
        className="form-input"
        style={{ width: '100%' }}
        type="text"
        maxLength={maxLength}
        value={scope[key]}
        onChange={(event) => setScope((current) => ({ ...current, [key]: event.target.value }))}
      />
    </label>
  )

  const brandingField = (key: keyof ReportBranding, label: string, maxLength: number) => (
    <label className="note" style={{ display: 'block', minWidth: 180 }}>
      {label}
      <input
        className="form-input"
        style={{ width: '100%' }}
        type="text"
        maxLength={maxLength}
        value={branding[key]}
        onChange={(event) => setBranding((current) => ({ ...current, [key]: event.target.value }))}
      />
    </label>
  )

  return (
    <form
      hidden={step === 'library'}
      onSubmit={async (event) => {
          event.preventDefault()
          if (busy) return
          setBusy(true)
          setMessage('')
          const payload: ReportDefinition = {
            ...initial,
            name: name.trim(),
            template,
            theme,
            branding,
            scope: isSpecial ? { ...emptyScope(), job: scope.job, hash: scope.hash } : { ...scope, job: '', hash: '' },
            elements: isSpecial ? [] : selectedElements,
            appendix_limit: appendixLimit,
            schedule: schedule.enabled ? schedule : null,
          }
          try {
            const result = isCreate
              ? await createDefinition({ data: payload })
              : await updateDefinition({ data: { id: initial.id, definition: payload } })
            if (result.ok) {
              onSaved()
            } else {
              setMessage(result.error || 'Save failed.')
            }
          } finally {
            setBusy(false)
          }
      }}
    >
      {/* 01 Design — template, basics, theme, elements (reports.html:47-85). */}
      <div className="dashboard-panel" role="tabpanel" id="rp-panel-design" aria-labelledby="rp-design" hidden={step !== 'design'}>
        <div className="card wide">
        <h2>{isCreate ? 'New report definition' : `Edit — ${initial.name}`}</h2>
        <div className="filters">
          <label className="note" style={{ display: 'block', minWidth: 200 }}>
            Name
            <input
              className="form-input"
              style={{ width: '100%' }}
              type="text"
              required
              maxLength={60}
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </label>
          <label className="note" style={{ display: 'block', minWidth: 200 }}>
            Template
            <select className="form-input" style={{ width: '100%' }} value={template} onChange={(event) => pickTemplate(event.target.value)} required>
              <option value="" disabled>
                Select a template…
              </option>
              {templates.map((entry) => (
                <option key={entry.id} value={entry.id}>
                  {entry.name}
                </option>
              ))}
            </select>
          </label>
          <label className="note" style={{ display: 'block', minWidth: 140 }}>
            Theme
            <select className="form-input" style={{ width: '100%' }} value={theme} onChange={(event) => setTheme(event.target.value)}>
              <option value="dark">Dark</option>
              <option value="light">Light</option>
            </select>
          </label>
        </div>
        {activeTemplate ? <p className="note">{activeTemplate.description}</p> : null}
        <div className="filters">
          {!isSpecial ? (
            // reports.html:61 — the observation window is a Design-step
            // basic, not a scope filter.
            <label className="note" style={{ display: 'block', minWidth: 160 }}>
              Window
              <select
                className="form-input"
                style={{ width: '100%' }}
                value={scope.window}
                onChange={(event) => setScope((current) => ({ ...current, window: event.target.value }))}
              >
                <option value="">Template default</option>
                <option value="1h">1 hour</option>
                <option value="6h">6 hours</option>
                <option value="24h">24 hours</option>
                <option value="7d">7 days</option>
                <option value="30d">30 days</option>
              </select>
            </label>
          ) : null}
          <label className="note" style={{ display: 'block', maxWidth: 220 }}>
            Event appendix limit
            <input
              className="form-input"
              style={{ width: '100%' }}
              type="number"
              min={0}
              max={500}
              value={appendixLimit}
              onChange={(event) => setAppendixLimit(Number(event.target.value))}
            />
          </label>
        </div>
        {!isSpecial ? (
          <>
            <p className="note">Elements</p>
            <div className="filters" role="group" aria-label="Report elements">
              {elements.map((element) => (
                <button
                  key={element.id}
                  type="button"
                  className={selectedElements.includes(element.id) ? 'chip is-active' : 'chip'}
                  aria-pressed={selectedElements.includes(element.id)}
                  title={element.description}
                  onClick={() => toggleElement(element.id)}
                >
                  {element.label}
                </button>
              ))}
            </div>
          </>
        ) : null}
        </div>
      </div>

      {/* 02 Scope — search criteria, or the sandbox/payload reference
          pickers for the fixed-structure templates (reports.html:87-126). */}
      <div className="dashboard-panel" role="tabpanel" id="rp-panel-scope" aria-labelledby="rp-scope" hidden={step !== 'scope'}>
        <div className="card wide">
        <h2>Scope &amp; search criteria</h2>
        {isSpecial ? (
          // reports.html:109-125's sandbox/payload scope pickers. The old
          // blanket "not yet implemented" note is gone on purpose: the
          // artifact renderers landed in reports_api.rs'
          // render_definition_to_stored, so the only honest limitation left
          // is a picker whose source endpoint is genuinely unavailable —
          // probed here by the picker's own load, before a definition is
          // built around an unresolvable reference.
          <>
            {activeTemplate?.sandbox ? (
              <label className="note" style={{ display: 'block', maxWidth: 480 }}>
                Analysis job
                <select
                  className="form-input"
                  style={{ width: '100%' }}
                  value={scope.job}
                  onChange={(event) => setScope((current) => ({ ...current, job: event.target.value }))}
                >
                  {jobsFailed ? (
                    <option value="">sandbox results unavailable</option>
                  ) : sandboxJobs === null ? (
                    <option value="">loading analysis runs…</option>
                  ) : (
                    <option value="">select an analysis run…</option>
                  )}
                  {scope.job && !(sandboxJobs ?? []).some((row) => row.job === scope.job) ? (
                    <option value={scope.job}>{scope.job} (saved)</option>
                  ) : null}
                  {(sandboxJobs ?? []).map((row) => (
                    <option key={row.job} value={row.job}>
                      {row.job} — {row.sha256.slice(0, 12)}… ({row.risk || 'unrated'})
                    </option>
                  ))}
                </select>
              </label>
            ) : null}
            {wantsHash ? (
              <>
                <label className="note" style={{ display: 'block', maxWidth: 480 }}>
                  Search captured payloads
                  <input
                    className="form-input"
                    style={{ width: '100%' }}
                    type="search"
                    placeholder="hash or file kind…"
                    autoComplete="off"
                    value={payloadQuery}
                    onChange={(event) => setPayloadQuery(event.target.value)}
                  />
                </label>
                <div className="hp-rp-payload-results" role="listbox" aria-label="Captured payloads">
                  {payloadError ? (
                    <p className="note">payload search unavailable</p>
                  ) : payloadResults === null ? (
                    <p className="note">loading captured payloads…</p>
                  ) : payloadResults.length === 0 ? (
                    <p className="note">no captured payloads match that search</p>
                  ) : (
                    payloadResults.map((row) => (
                      <button
                        key={row.hash}
                        type="button"
                        className="hp-rp-payload-row"
                        aria-pressed={selectedPayload?.hash === row.hash}
                        onClick={() => pickPayload(row)}
                      >
                        <code>{row.hash.slice(0, 16)}…</code>
                        <span>
                          {row.kind || 'unknown'} · {row.size}
                        </span>
                        <span className="hp-rp-payload-badges">
                          {row.sources.length ? (
                            row.sources.map((source) => (
                              <span key={source} className="hp-rp-tag hp-rp-tag--light">
                                {source}
                              </span>
                            ))
                          ) : (
                            <span className="hp-rp-tag">inventory</span>
                          )}
                        </span>
                      </button>
                    ))
                  )}
                </div>
                {selectedPayload ? (
                  <p className="hp-rp-status">
                    Selected: <code>{selectedPayload.hash}</code>
                    {selectedPayload.kind || selectedPayload.size ? ` (${selectedPayload.kind || 'unknown'}, ${selectedPayload.size})` : ''}
                  </p>
                ) : null}
              </>
            ) : null}
            <p className="note">
              {activeTemplate?.sandbox ? 'Sandbox' : 'Payload'} reports have a fixed evidence structure; theme and branding
              still apply.
            </p>
          </>
        ) : (
          <>
            <div className="filters">
              {scopeField('ip', 'IP', 64)}
              {scopeField('sensor', 'Sensor', 64)}
              {scopeField('port', 'Port', 16)}
              {scopeField('signature', 'Signature', 120)}
            </div>
            <p className="note">
              Scope narrows what the report covers; leave fields blank for an unscoped report. Network, country, ASN, text,
              type, and session scope aren't exposed here and stay unscoped.
            </p>
          </>
        )}
        </div>
      </div>

      {/* 03 Schedule — cadence + the starter presets (reports.html:128-174). */}
      <div className="dashboard-panel" role="tabpanel" id="rp-panel-schedule" aria-labelledby="rp-schedule" hidden={step !== 'schedule'}>
        <div className="card wide">
        <h2>Schedule</h2>
        {!anyScheduled ? (
          // #1575 (reports.html:136-163): schedule starter cards, shown
          // while no saved definition has an active schedule. A click fills
          // the name (only if still untouched) and the cadence fields below.
          <div className="empty-state" role="status" aria-live="polite">
            <div>
              <div className="empty-state__icon" aria-hidden="true">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                  <circle cx="12" cy="12" r="9" />
                  <polyline points="12 7 12 12 15.5 14" />
                </svg>
              </div>
              <div className="empty-state__title">Nothing scheduled yet</div>
              <p className="empty-state__hint">Pick a cadence below, or start from one of these and adjust it.</p>
              <hr className="empty-state__divider" />
              <div className="template-gallery" role="group" aria-label="Schedule starters">
                {SCHEDULE_PRESETS.map((preset) => (
                  <button
                    key={preset.id}
                    type="button"
                    className="template-card"
                    onClick={() => {
                      if (!name.trim()) setName(preset.name)
                      setSchedule((current) => ({
                        ...current,
                        enabled: true,
                        frequency: preset.frequency,
                        hour: preset.hour,
                        minute: preset.minute,
                        weekday: preset.weekday ?? current.weekday,
                        month_day: preset.monthDay ?? current.month_day,
                      }))
                      setMessage(`“${preset.name}” schedule loaded — adjust anything, then save.`)
                    }}
                  >
                    <span className="template-card__icon" aria-hidden="true">
                      {preset.icon}
                    </span>
                    <span className="template-card__title">{preset.name}</span>
                    <span className="template-card__desc">{preset.desc}</span>
                    <span className="chip">{preset.chip}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>
        ) : null}
        <div className="filters">
          <button
            type="button"
            className={schedule.enabled ? 'chip is-active' : 'chip'}
            aria-pressed={schedule.enabled}
            onClick={() => setSchedule((current) => ({ ...current, enabled: !current.enabled }))}
          >
            {schedule.enabled ? 'Schedule: on' : 'Schedule: off'}
          </button>
          {schedule.enabled ? (
            <>
              <select
                className="form-input"
                value={schedule.frequency}
                onChange={(event) => setSchedule((current) => ({ ...current, frequency: event.target.value }))}
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
              <input
                className="form-input"
                type="number"
                min={0}
                max={23}
                aria-label="Hour (UTC)"
                value={schedule.hour}
                onChange={(event) => setSchedule((current) => ({ ...current, hour: Number(event.target.value) }))}
                style={{ width: 80 }}
              />
              <input
                className="form-input"
                type="number"
                min={0}
                max={59}
                aria-label="Minute"
                value={schedule.minute}
                onChange={(event) => setSchedule((current) => ({ ...current, minute: Number(event.target.value) }))}
                style={{ width: 80 }}
              />
              {schedule.frequency === 'weekly' ? (
                <select
                  className="form-input"
                  aria-label="Weekday"
                  value={schedule.weekday}
                  onChange={(event) => setSchedule((current) => ({ ...current, weekday: Number(event.target.value) }))}
                >
                  {WEEKDAYS.map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
              ) : null}
              {schedule.frequency === 'monthly' ? (
                <input
                  className="form-input"
                  type="number"
                  min={1}
                  max={28}
                  aria-label="Day of month"
                  value={schedule.month_day}
                  onChange={(event) => setSchedule((current) => ({ ...current, month_day: Number(event.target.value) }))}
                  style={{ width: 80 }}
                />
              ) : null}
            </>
          ) : null}
        </div>
        {schedule.enabled ? (
          <p className="note">
            Times are UTC. Scheduled reports render through the same pipeline as manual ones and appear in the history with
            origin <em>schedule</em>; the retention cap prunes the oldest artifacts automatically.
          </p>
        ) : null}
        </div>
      </div>

      {/* 04 Branding — headers, footer, classification (reports.html:176-190). */}
      <div className="dashboard-panel" role="tabpanel" id="rp-panel-branding" aria-labelledby="rp-branding" hidden={step !== 'branding'}>
        <div className="card wide">
        <h2>Branding</h2>
        <div className="filters">
          {brandingField('title', 'Title (defaults to template title)', 80)}
          {brandingField('author', 'Author', 60)}
          {brandingField('header_left', 'Header left', 60)}
          {brandingField('header_right', 'Header right', 60)}
          {brandingField('footer_left', 'Footer left', 80)}
          {brandingField('classification', 'Classification', 120)}
        </div>
        </div>
      </div>

      {/* Shared action row — visible on every form step, hp-rp-actions
          style: the wizard is one definition, saved once. */}
      <div className="filters" style={{ marginTop: 8 }}>
        <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !name.trim() || !template}>
          {busy ? 'Saving…' : isCreate ? 'Create definition' : 'Save changes'}
        </button>
        <button className="btn btn-ghost btn-sm" type="button" onClick={onCancel}>
          {isCreate ? 'Reset' : 'Cancel edit'}
        </button>
      </div>
      {message ? <p className="note">{message}</p> : null}
    </form>
  )
}

function DefinitionsCard({
  definitions,
  editable,
  onEdit,
  onNew,
  onChanged,
  onGenerated,
}: {
  definitions: ReportDefinition[] | null
  editable: boolean
  /** Load a saved definition into the wizard (jumps to the Design step). */
  onEdit: (definition: ReportDefinition) => void
  /** Reset the wizard to a fresh definition (jumps to the Design step). */
  onNew: () => void
  onChanged: () => Promise<void> | void
  onGenerated: () => Promise<void> | void
}) {
  const [busyId, setBusyId] = useState<string | null>(null)
  const [rowMessage, setRowMessage] = useState<Record<string, string>>({})

  const generate = async (id: string) => {
    setBusyId(id)
    try {
      const result = await generateDefinition({ data: { id } })
      setRowMessage((current) => ({
        ...current,
        [id]: result.ok ? 'Generated — see the Generated reports table below.' : result.error || 'Generation failed.',
      }))
      if (result.ok) await onGenerated()
    } finally {
      setBusyId(null)
    }
  }

  const remove = async (id: string) => {
    if (typeof window !== 'undefined' && !window.confirm('Delete this report definition? This cannot be undone.')) return
    setBusyId(id)
    try {
      const result = await deleteDefinition({ data: { id } })
      if (result.ok) {
        await onChanged()
      } else {
        setRowMessage((current) => ({ ...current, [id]: result.error || 'Delete failed.' }))
      }
    } finally {
      setBusyId(null)
    }
  }

  return (
    <>
      <div className="card wide">
        <h2>Saved definitions</h2>
        <p className="note">Definitions drive the scheduler and on-demand generation.</p>
        {editable ? (
          <button className="btn btn-secondary btn-sm" type="button" onClick={onNew} style={{ marginBottom: 12 }}>
            New definition
          </button>
        ) : null}
        {definitions === null ? (
          <span className="skeleton-line" aria-hidden="true" />
        ) : definitions.length === 0 ? (
          <p className="empty">No report definitions yet.</p>
        ) : (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Template</th>
                  <th>Theme</th>
                  <th>Schedule</th>
                  <th>Created</th>
                  {editable ? <th>Actions</th> : null}
                </tr>
              </thead>
              <tbody>
                {definitions.map((definition) => (
                  <tr key={definition.id}>
                    <td className="v">{definition.name}</td>
                    <td>
                      <span className="badge badge--muted">{definition.template}</span>
                    </td>
                    <td>{definition.theme}</td>
                    <td>
                      {definition.schedule?.enabled
                        ? `${definition.schedule.frequency} @ ${pad2(definition.schedule.hour)}:${pad2(definition.schedule.minute)} UTC`
                        : '—'}
                    </td>
                    <td>{formatTimestamp((definition.created || ''))}</td>
                    {editable ? (
                      <td>
                        <div className="filters">
                          <button
                            className="btn btn-secondary btn-sm"
                            type="button"
                            disabled={busyId === definition.id}
                            onClick={() => onEdit(definition)}
                          >
                            Edit
                          </button>
                          <button
                            className="btn btn-secondary btn-sm"
                            type="button"
                            disabled={busyId === definition.id}
                            onClick={() => generate(definition.id)}
                          >
                            {busyId === definition.id ? 'Working…' : 'Generate'}
                          </button>
                          <button
                            className="btn btn-danger btn-sm"
                            type="button"
                            disabled={busyId === definition.id}
                            onClick={() => remove(definition.id)}
                          >
                            Delete
                          </button>
                        </div>
                        {rowMessage[definition.id] ? <p className="note">{rowMessage[definition.id]}</p> : null}
                      </td>
                    ) : null}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}

function Reports() {
  const data = Route.useLoaderData()
  const [generated, setGenerated] = useState<Page | null>(null)
  const [templatesData, setTemplatesData] = useState<TemplatesResponse | null>(null)
  const [definitions, setDefinitions] = useState<ReportDefinition[] | null>(null)
  // Wizard state: which step is showing, and which saved definition (if
  // any) is loaded into the form. formSeed remounts the form so "New
  // definition" / cancel always reset to a blank draft.
  const [step, setStep] = useState<StepId>('design')
  const [editing, setEditing] = useState<ReportDefinition | null>(null)
  const [formSeed, setFormSeed] = useState(0)
  // Design pick 7D: the studio's five step-tabs relocate into the sidebar
  // rail (inline below 520px, where the sidebar is off-canvas).
  const viewTabs = useSidebarViewTabs({
    label: 'Reports studio steps',
    tabs: STEPS,
    active: step,
    onSelect: (id) => setStep(id as StepId),
    idPrefix: 'rp',
  })

  useEffect(() => {
    let cancelled = false
    data.generated.then((page) => {
      if (!cancelled && page) setGenerated(page)
    })
    data.templates.then((result) => {
      if (!cancelled) setTemplatesData(result)
    })
    data.definitions.then((result) => {
      if (!cancelled) setDefinitions(result?.definitions ?? [])
    })
    return () => {
      cancelled = true
    }
  }, [data])

  const isAdmin = !data.user || data.user.role === 'admin'
  const editable = isAdmin && templatesData !== null

  const refreshDefinitions = async () => {
    const result = await fetchDefinitions()
    const next = result?.definitions ?? []
    setDefinitions(next)
    // The definition being edited may have been deleted from the library —
    // fall back to a fresh draft rather than resurrecting it on save.
    setEditing((current) => (current && !next.some((entry) => entry.id === current.id) ? null : current))
  }

  const refreshGenerated = async () => {
    const page = await fetchGenerated({ data: { offset: 0 } })
    if (page) setGenerated(page)
  }

  const startEdit = (definition: ReportDefinition) => {
    setEditing(definition)
    setFormSeed((seed) => seed + 1)
    setStep('design')
  }

  const startNew = () => {
    setEditing(null)
    setFormSeed((seed) => seed + 1)
    setStep('design')
  }

  return (
    <>
      <InvestigateHeader
        label="Reports"
        title="Reports studio"
        subtitle="Finished PDF reports and the definitions that produce them — scheduled and on-demand runs land here."
        chips={<span className="chip">{(generated?.total ?? 0).toLocaleString('en-US')} generated reports</span>}
      />
      {viewTabs}
      {/* Steps 01-04 are the wizard form — always mounted (hidden panels)
          so a half-built definition survives a detour through the Library. */}
      {editable ? (
        <DefinitionForm
          key={`${editing?.id ?? 'new'}:${formSeed}`}
          step={step}
          templates={templatesData?.templates ?? []}
          elements={templatesData?.elements ?? []}
          anyScheduled={(definitions ?? []).some((definition) => definition.schedule?.enabled)}
          initial={hydrateDefinition(editing ?? emptyDefinition())}
          onCancel={startNew}
          onSaved={async () => {
            setEditing(null)
            setFormSeed((seed) => seed + 1)
            await refreshDefinitions()
            setStep('library')
          }}
        />
      ) : step !== 'library' ? (
        templatesData === null ? (
          <span className="skeleton-line" aria-hidden="true" />
        ) : (
          <p className="empty">Admin role required to design report definitions — the Library step is read-only browsing.</p>
        )
      ) : null}

      {/* 05 Library — saved definitions + finished PDFs (reports.html:193-232). */}
      <div className="dashboard-panel" role="tabpanel" id="rp-panel-library" aria-labelledby="rp-library" hidden={step !== 'library'}>
        <DefinitionsCard
          definitions={definitions}
          editable={editable}
          onEdit={startEdit}
          onNew={startNew}
          onChanged={refreshDefinitions}
          onGenerated={refreshGenerated}
        />
        <h2 className="label-section">Generated reports</h2>
        <MasterDetailTable
          rows={generated ? generated.rows : null}
          columns={COLUMNS}
          rowKey={(row, index) => `${str(row, 'id')}-${index}`}
          inspectorTitle="Report details"
          layout="cards"
          gridId="hp-rp-generated"
        />
      </div>
    </>
  )
}
