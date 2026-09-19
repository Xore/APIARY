// Reports studio — generated PDF reports and the report definitions
// behind them: full CRUD plus on-demand generation, now that the worker
// port (#1610) and the reports API port (#1612) have both landed
// server-side (backend-service/src/reports_api.rs, reports_store.rs).
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'
import { ReportIcon } from '../components/CardIcons'
import { getSessionUser } from '../lib/auth'
import { pathString, type JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'
import { useSidebarViewTabs } from '../lib/viewTabs'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader } from '../components/ui/card'
import { Dialog, DialogContent, DialogTitle } from '../components/ui/dialog'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '../components/ui/alert-dialog'
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from '../components/ui/empty'
import { Field, FieldLabel } from '../components/ui/field'
import { Input } from '../components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select'
import { Skeleton } from '../components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'

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
  .validator((input: { offset: number }) => input)
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
  .validator((input: { q: string }) => input)
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
  .validator((input: ReportDefinition) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
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
  .validator((input: { id: string; definition: ReportDefinition }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
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
  .validator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/reports/definitions/${encodeURIComponent(data.id)}`, { method: 'DELETE' })
    if (response.ok) return { ok: true }
    return { ok: false, error: await response.text() }
  })

const deleteGenerated = createServerFn({ method: 'POST' })
  .validator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/reports/generated/${encodeURIComponent(data.id)}`, { method: 'DELETE' })
    if (response.ok) return { ok: true }
    return { ok: false, error: await response.text() }
  })

const generateDefinition = createServerFn({ method: 'POST' })
  .validator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
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

// reports.html's #hp-rp-viewer was an in-app focus-trapped modal + iframe;
// the port reduced this to a plain new-tab link. buildGeneratedColumns
// restores the inline viewer plus the per-report delete the Library grid
// never had client-side support for.
function buildGeneratedColumns(
  onView: (row: StoreRow) => void,
  onDelete: (row: StoreRow) => void,
  busyId: string | null,
): Column<StoreRow>[] {
  return [
    { header: 'created', render: (row) => formatTimestamp(str(row, 'created_at')) },
    {
      header: 'title',
      className: 'v',
      primary: true,
      render: (row) => str(row, 'title') || str(row, 'name') || <span className="text-muted-foreground">(untitled report)</span>,
    },
    { header: 'template', render: (row) => <Badge variant="secondary">{str(row, 'template')}</Badge> },
    { header: 'origin', render: (row) => str(row, 'origin') },
    { header: 'size', className: 'n', render: (row) => `${(num(row, 'size_bytes') / 1024).toFixed(0)} KB` },
    {
      header: 'pdf',
      // #1898: these were .lnk -- link styling on controls that act. View
      // opens a modal and delete destroys a report, and the two read
      // identically, which is the worst version of this: an operator cannot
      // tell from looking which one is destructive. A control that acts is a
      // button with the variant that says what it does; download navigates,
      // so it stays an anchor.
      //
      // .hp-rp-row-actions is the theme's own class for this row, and it
      // already carries a rule for .btn-danger inside it -- the design
      // expected buttons here all along and the port used .lnk.
      render: (row) => (
        <div className="flex flex-wrap gap-2" onClick={(event) => event.stopPropagation()}>
          <Button variant="secondary" size="sm" type="button" onClick={() => onView(row)}>
            view
          </Button>
          <Button asChild variant="ghost" size="sm"><a
            href={`/api/report/${encodeURIComponent(str(row, 'id'))}/pdf`}
            target="_blank"
            rel="noopener noreferrer"
          >
            download
          </a></Button>
          <Button
            variant="destructive"
            size="sm"
            type="button"
            disabled={busyId === str(row, 'id')}
            onClick={() => onDelete(row)}
          >
            delete
          </Button>
        </div>
      ),
    },
  ]
}

// Same application-managed .modal.pdf-viewer-modal overlay as
// payload-analysis.$hash.tsx's PayloadReportViewer / github-analysis's
// ReportViewer — focus moves to the close button on open, Tab cycles
// inside the dialog, Escape and backdrop clicks close, focus returns to
// the trigger on unmount.
function ReportViewerModal({ id, title, onClose }: { id: string; title: string; onClose: () => void }) {
  const url = `/api/report/${encodeURIComponent(id)}/pdf`
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="flex h-[90vh] flex-col">
        <DialogTitle asChild><h2>{title || 'Report'}</h2></DialogTitle>
        <Button asChild variant="ghost" size="sm"><a href={url} target="_blank" rel="noopener noreferrer">open in new tab ↗</a></Button>
        <iframe className="min-h-0 flex-1 rounded-md border" title={title || 'Report'} src={url} />
      </DialogContent>
    </Dialog>
  )
}

// reports.html:38-43's wizard steps — the studio reads as six views: five
// steps that build one definition, plus the Library of saved definitions
// and finished PDFs.
//
// #1858: these were five equal tabs and a save button repeated on each,
// so the studio read as one dense form split five ways rather than as the
// click-through the redesign specified. `lede` is what the step changes,
// stated before the controls; Review reads every choice back before
// anything is generated. The order below is the order of the sequence,
// and `buildSteps` is that same list minus the Library — the Library is
// where finished work lives, not a step on the way to it.
const STEPS = [
  { id: 'design', label: 'Design', lede: 'What kind of report this is, and which sections it contains.' },
  { id: 'scope', label: 'Scope', lede: 'Which captured activity the report covers.' },
  { id: 'schedule', label: 'Schedule', lede: 'Whether it runs on its own, and how often.' },
  { id: 'branding', label: 'Branding', lede: 'What appears on every page of the PDF.' },
  { id: 'review', label: 'Review', lede: 'Everything chosen so far. Nothing has been generated yet.' },
  { id: 'library', label: 'Library', lede: 'Saved definitions and the PDFs they have produced.' },
] as const

type StepId = (typeof STEPS)[number]['id']

/** The steps that build a definition, in order. The Library is excluded:
 *  it is the destination, not a stage on the way there. */
const BUILD_STEPS = STEPS.filter((entry) => entry.id !== 'library')

function stepLede(id: StepId): string {
  return STEPS.find((entry) => entry.id === id)?.lede ?? ''
}

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

/** The observation-window select's own option labels, so the Review step
 *  reads back the words the operator picked rather than the wire value. */
const WINDOW_LABELS: Record<string, string> = {
  '': 'template default',
  '1h': '1 hour',
  '6h': '6 hours',
  '24h': '24 hours',
  '7d': '7 days',
  '30d': '30 days',
}

/** A schedule in one line, matching the Library card's phrasing so the
 *  same cadence does not read two different ways in the same studio. */
function describeSchedule(schedule: ReportSchedule): string {
  const at = `${pad2(schedule.hour)}:${pad2(schedule.minute)} UTC`
  if (schedule.frequency === 'weekly') {
    const day = WEEKDAYS.find(([value]) => value === schedule.weekday)?.[1] ?? 'Monday'
    return `weekly on ${day} @ ${at}`
  }
  if (schedule.frequency === 'monthly') return `monthly on day ${schedule.month_day} @ ${at}`
  return `${schedule.frequency} @ ${at}`
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
  onStep,
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
  /** Move to another step. The form owns Back/Next because only it knows
   * the draft; the sidebar rail calls the same setter from outside. */
  onStep: (id: StepId) => void
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
  // Position in the sequence. Falls back to the first step rather than -1
  // so the Library (which is not a build step) never renders "Step 0".
  const stepIndex = Math.max(
    0,
    BUILD_STEPS.findIndex((entry) => entry.id === step),
  )
  const previousStep = stepIndex > 0 ? BUILD_STEPS[stepIndex - 1] : null
  const nextStep = stepIndex < BUILD_STEPS.length - 1 ? BUILD_STEPS[stepIndex + 1] : null
  const onReview = step === 'review'

  // The read-back on the Review step. Every row carries the step that owns
  // it, so "change" lands where the value was set.
  //
  // `unset` is deliberate: a value the operator never touched shows the
  // word the report will actually act on -- "everything captured", "no
  // schedule" -- rather than an empty cell, which does not distinguish a
  // field that was skipped from one that was never offered. That
  // distinction is the whole point of reading the definition back before
  // generating anything from it.
  const summaryRows: { key: string; value: string; step: StepId; unset?: boolean }[] = (() => {
    const rows: { key: string; value: string; step: StepId; unset?: boolean }[] = []
    rows.push({ key: 'Name', value: name.trim() || 'not named yet', step: 'design', unset: !name.trim() })
    rows.push({
      key: 'Template',
      value: activeTemplate?.name || 'none chosen',
      step: 'design',
      unset: !activeTemplate,
    })
    rows.push({ key: 'PDF theme', value: theme === 'light' ? 'Light' : 'Dark', step: 'design' })
    if (!isSpecial) {
      rows.push({
        key: 'Window',
        value: WINDOW_LABELS[scope.window] ?? (scope.window || 'template default'),
        step: 'design',
        unset: !scope.window,
      })
      const chosen = elements.filter((entry) => selectedElements.includes(entry.id)).map((entry) => entry.label)
      rows.push({
        key: 'Sections',
        value: chosen.length > 0 ? chosen.join(', ') : 'none selected',
        step: 'design',
        unset: chosen.length === 0,
      })
    } else {
      rows.push({ key: 'Sections', value: 'fixed by this template', step: 'design', unset: true })
    }
    rows.push({ key: 'Appendix limit', value: `${appendixLimit} rows`, step: 'design' })

    const scopeTerms = isSpecial
      ? ([['job', scope.job], ['hash', scope.hash]] as [string, string][])
      : ([
          ['ip', scope.ip],
          ['sensor', scope.sensor],
          ['port', scope.port],
          ['signature', scope.signature],
        ] as [string, string][])
    const active = scopeTerms.filter(([, value]) => value.trim() !== '')
    rows.push({
      key: 'Scope',
      value: active.length > 0 ? active.map(([label, value]) => `${label} ${value}`).join(' · ') : 'everything captured',
      step: 'scope',
      unset: active.length === 0,
    })

    rows.push({
      key: 'Schedule',
      value: schedule.enabled ? describeSchedule(schedule) : 'no schedule — generated on demand',
      step: 'schedule',
      unset: !schedule.enabled,
    })

    const brandingSet = (Object.keys(branding) as (keyof ReportBranding)[]).filter(
      (key) => branding[key].trim() !== '',
    )
    rows.push({
      key: 'Branding',
      value:
        brandingSet.length > 0
          ? `${branding.title.trim() || activeTemplate?.title || 'template title'}${
              brandingSet.length > 1 ? ` (+${brandingSet.length - 1} more field${brandingSet.length > 2 ? 's' : ''})` : ''
            }`
          : 'template defaults',
      step: 'branding',
      unset: brandingSet.length === 0,
    })
    return rows
  })()

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
    <Field>
      <FieldLabel htmlFor={`report-scope-${key}`}>{label}</FieldLabel>
      <Input
        id={`report-scope-${key}`}
        type="text"
        maxLength={maxLength}
        value={scope[key]}
        onChange={(event) => setScope((current) => ({ ...current, [key]: event.target.value }))}
      />
    </Field>
  )

  const brandingField = (key: keyof ReportBranding, label: string, maxLength: number) => (
    <Field>
      <FieldLabel htmlFor={`report-branding-${key}`}>{label}</FieldLabel>
      <Input
        id={`report-branding-${key}`}
        type="text"
        maxLength={maxLength}
        value={branding[key]}
        onChange={(event) => setBranding((current) => ({ ...current, [key]: event.target.value }))}
      />
    </Field>
  )

  return (
    <form
      hidden={step === 'library'}
      onSubmit={async (event) => {
          event.preventDefault()
          if (busy) return
          // The template picker is a button gallery rather than a
          // <select required>, so its "must choose one" rule is enforced
          // here instead of by the browser.
          if (!template) {
            setMessage('Pick a report template first.')
            return
          }
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
      {/* #1858: where the studio is in its own sequence. The sidebar rail
          still lets an operator jump anywhere -- useful when editing a
          saved definition -- but five equal tabs never said which comes
          first or how much is left. Rendered on every build step, and the
          <ol> carries the order the tab rail cannot. */}
      {step !== 'library' ? (
        <div className="hp-rp-progress">
          <span className="hp-rp-progress__position">
            Step {stepIndex + 1} of {BUILD_STEPS.length} — {BUILD_STEPS[stepIndex]?.label}
          </span>
          <ol className="hp-rp-progress__steps">
            {BUILD_STEPS.map((entry, index) => (
              <li
                key={entry.id}
                aria-current={entry.id === step ? 'step' : undefined}
                data-state={index < stepIndex ? 'done' : undefined}
              >
                {entry.label}
              </li>
            ))}
          </ol>
        </div>
      ) : null}

      {/* 01 Design — template, basics, theme, elements (reports.html:47-85). */}
      <div className="dashboard-panel" role="tabpanel" id="rp-panel-design" aria-labelledby="rp-design" hidden={step !== 'design'}>
        <Card className="col-span-full">
        <CardHeader><h2 className="font-semibold leading-none tracking-tight">{isCreate ? 'New report definition' : `Edit — ${initial.name}`}</h2>
        {/* reports.html:47 / hp-reports.js:renderTemplates — a gallery of
            pressable cards, each showing what the template actually
            produces. The port reduced it to a <select> of bare names, so
            the descriptions were only reachable one at a time after
            choosing, which is backwards for a picker. theme.css still
            carries .hp-rp-templates/.hp-rp-template including the
            aria-pressed selected state. */}
        <CardDescription>
          {stepLede('design')} Pick the closest starting point — the steps that follow adjust it, and nothing is
          generated until the Review step.
        </CardDescription></CardHeader>
        <CardContent className="space-y-6">
        <div className="hp-rp-templates" role="group" aria-label="Report template">
          {templates.length > 0 ? (
            templates.map((entry) => (
              <Button
                key={entry.id}
                type="button"
                variant={template === entry.id ? 'default' : 'outline'}
                className="h-auto min-h-24 flex-col items-start whitespace-normal p-4 text-left"
                aria-pressed={template === entry.id}
                onClick={() => pickTemplate(entry.id)}
              >
                <strong>{entry.name}</strong>
                <span>{entry.description}</span>
              </Button>
            ))
          ) : (
            <Empty><EmptyHeader><EmptyTitle>No report templates are available</EmptyTitle></EmptyHeader></Empty>
          )}
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field className="sm:col-span-2">
            <FieldLabel htmlFor="report-definition-name">Name</FieldLabel>
            <Input
              id="report-definition-name"
              type="text"
              required
              maxLength={60}
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </Field>
          {/* reports.html:64-66 — the swatch shows what each PDF theme
              actually looks like; a two-option <select> of the words
              "Dark"/"Light" showed nothing. */}
          <Field>
            <FieldLabel htmlFor="report-theme-dark">Theme</FieldLabel>
            <div className="hp-rp-theme" role="group" aria-label="PDF theme">
              <Button id="report-theme-dark" variant={theme === 'dark' ? 'default' : 'outline'} type="button" aria-pressed={theme === 'dark'} onClick={() => setTheme('dark')}>
                <span className="hp-rp-swatch hp-rp-swatch--dark" aria-hidden="true" />
                Dark
              </Button>
              <Button variant={theme === 'light' ? 'default' : 'outline'} type="button" aria-pressed={theme === 'light'} onClick={() => setTheme('light')}>
                <span className="hp-rp-swatch hp-rp-swatch--light" aria-hidden="true" />
                Light
              </Button>
            </div>
          </Field>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          {!isSpecial ? (
            // reports.html:61 — the observation window is a Design-step
            // basic, not a scope filter.
            <Field><FieldLabel htmlFor="report-window">Window</FieldLabel><Select value={scope.window || 'default'} onValueChange={(value) => setScope((current) => ({ ...current, window: value === 'default' ? '' : value }))}>
              <SelectTrigger id="report-window" aria-label="Window"><SelectValue /></SelectTrigger><SelectContent>
                <SelectItem value="default">Template default</SelectItem><SelectItem value="1h">1 hour</SelectItem><SelectItem value="6h">6 hours</SelectItem><SelectItem value="24h">24 hours</SelectItem><SelectItem value="7d">7 days</SelectItem><SelectItem value="30d">30 days</SelectItem>
              </SelectContent></Select></Field>
          ) : null}
          <Field><FieldLabel htmlFor="report-appendix-limit">Event appendix limit</FieldLabel>
            <Input id="report-appendix-limit"
              type="number"
              min={0}
              max={500}
              value={appendixLimit}
              onChange={(event) => setAppendixLimit(Number(event.target.value))}
            />
          </Field>
        </div>
        {!isSpecial ? (
          <>
            <p className="text-sm font-medium">Elements</p>
            <p className="text-sm text-muted-foreground">Each element becomes a section of the PDF, in this order.</p>
            <div className="flex flex-wrap gap-2" role="group" aria-label="Report elements">
              {elements.map((element) => (
                <Button
                  key={element.id}
                  type="button"
                  variant={selectedElements.includes(element.id) ? 'default' : 'outline'}
                  aria-pressed={selectedElements.includes(element.id)}
                  title={element.description}
                  onClick={() => toggleElement(element.id)}
                >
                  {element.label}
                </Button>
              ))}
            </div>
          </>
        ) : null}
        </CardContent></Card>
      </div>

      {/* 02 Scope — search criteria, or the sandbox/payload reference
          pickers for the fixed-structure templates (reports.html:87-126). */}
      <div className="dashboard-panel" role="tabpanel" id="rp-panel-scope" aria-labelledby="rp-scope" hidden={step !== 'scope'}>
        <Card className="col-span-full">
        <CardHeader><h2 className="font-semibold leading-none tracking-tight">Scope &amp; search criteria</h2>
        <CardDescription>
          Leave a field empty to place no restriction on it. The report covers exactly what these criteria match.
        </CardDescription></CardHeader><CardContent className="space-y-6">
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
              <Field><FieldLabel htmlFor="report-analysis-job">Analysis job</FieldLabel><Select value={scope.job || 'none'} onValueChange={(value) => setScope((current) => ({ ...current, job: value === 'none' ? '' : value }))}>
                <SelectTrigger id="report-analysis-job" aria-label="Analysis job"><SelectValue /></SelectTrigger><SelectContent>
                  <SelectItem value="none">{jobsFailed ? 'sandbox results unavailable' : sandboxJobs === null ? 'loading analysis runs…' : 'select an analysis run…'}</SelectItem>
                  {scope.job && !(sandboxJobs ?? []).some((row) => row.job === scope.job) ? <SelectItem value={scope.job}>{scope.job} (saved)</SelectItem> : null}
                  {(sandboxJobs ?? []).map((row) => <SelectItem key={row.job} value={row.job}>{row.job} — {row.sha256.slice(0, 12)}… ({row.risk || 'unrated'})</SelectItem>)}
                </SelectContent></Select></Field>
            ) : null}
            {wantsHash ? (
              <>
                <Field><FieldLabel htmlFor="report-payload-search">Search captured payloads</FieldLabel>
                  <Input id="report-payload-search"
                    type="search"
                    placeholder="hash or file kind…"
                    autoComplete="off"
                    value={payloadQuery}
                    onChange={(event) => setPayloadQuery(event.target.value)}
                  />
                </Field>
                <div className="hp-rp-payload-results" role="listbox" aria-label="Captured payloads">
                  {payloadError ? (
                    <p className="text-sm text-destructive">payload search unavailable</p>
                  ) : payloadResults === null ? (
                    <p className="text-sm text-muted-foreground">loading captured payloads…</p>
                  ) : payloadResults.length === 0 ? (
                    <p className="text-sm text-muted-foreground">no captured payloads match that search</p>
                  ) : (
                    payloadResults.map((row) => (
                      <Button
                        key={row.hash}
                        type="button"
                        variant={selectedPayload?.hash === row.hash ? 'default' : 'outline'}
                        className="h-auto w-full justify-between whitespace-normal p-3"
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
                              <Badge key={source} variant="secondary">{source}</Badge>
                            ))
                          ) : (
                            <Badge variant="outline">inventory</Badge>
                          )}
                        </span>
                      </Button>
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
            <p className="text-sm text-muted-foreground">
              {activeTemplate?.sandbox ? 'Sandbox' : 'Payload'} reports have a fixed evidence structure; theme and branding
              still apply.
            </p>
          </>
        ) : (
          <>
            <div className="grid gap-4 sm:grid-cols-2">
              {scopeField('ip', 'IP', 64)}
              {scopeField('sensor', 'Sensor', 64)}
              {scopeField('port', 'Port', 16)}
              {scopeField('signature', 'Signature', 120)}
            </div>
            <p className="text-sm text-muted-foreground">
              Scope narrows what the report covers; leave fields blank for an unscoped report. Network, country, ASN, text,
              type, and session scope aren't exposed here and stay unscoped.
            </p>
          </>
        )}
        </CardContent></Card>
      </div>

      {/* 03 Schedule — cadence + the starter presets (reports.html:128-174). */}
      <div className="dashboard-panel" role="tabpanel" id="rp-panel-schedule" aria-labelledby="rp-schedule" hidden={step !== 'schedule'}>
        <Card className="col-span-full">
        <CardHeader><h2 className="font-semibold leading-none tracking-tight">Schedule</h2></CardHeader><CardContent className="space-y-6">
        {!anyScheduled ? (
          // #1575 (reports.html:136-163): schedule starter cards, shown
          // while no saved definition has an active schedule. A click fills
          // the name (only if still untouched) and the cadence fields below.
          <Empty role="status" aria-live="polite">
            <EmptyHeader><EmptyTitle>Nothing scheduled yet</EmptyTitle><EmptyDescription>Pick a cadence below, or start from one of these and adjust it.</EmptyDescription></EmptyHeader>
              <div className="template-gallery" role="group" aria-label="Schedule starters">
                {SCHEDULE_PRESETS.map((preset) => (
                  <Button
                    key={preset.id}
                    type="button"
                    variant="outline"
                    className="h-auto flex-col whitespace-normal p-4"
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
                    <span aria-hidden="true">
                      {preset.icon}
                    </span>
                    <strong>{preset.name}</strong>
                    <span className="text-xs text-muted-foreground">{preset.desc}</span>
                    <Badge variant="secondary">{preset.chip}</Badge>
                  </Button>
                ))}
              </div>
          </Empty>
        ) : null}
        <div className="flex flex-wrap items-end gap-3">
          <Button
            type="button"
            variant={schedule.enabled ? 'default' : 'outline'}
            aria-pressed={schedule.enabled}
            onClick={() => setSchedule((current) => ({ ...current, enabled: !current.enabled }))}
          >
            {schedule.enabled ? 'Schedule: on' : 'Schedule: off'}
          </Button>
          {schedule.enabled ? (
            <>
              <Select value={schedule.frequency} onValueChange={(value) => setSchedule((current) => ({ ...current, frequency: value }))}><SelectTrigger className="w-36" aria-label="Frequency"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="daily">Daily</SelectItem><SelectItem value="weekly">Weekly</SelectItem><SelectItem value="monthly">Monthly</SelectItem></SelectContent></Select>
              <Input className="w-24"
                type="number"
                min={0}
                max={23}
                aria-label="Hour (UTC)"
                value={schedule.hour}
                onChange={(event) => setSchedule((current) => ({ ...current, hour: Number(event.target.value) }))}
              />
              <Input className="w-24"
                type="number"
                min={0}
                max={59}
                aria-label="Minute"
                value={schedule.minute}
                onChange={(event) => setSchedule((current) => ({ ...current, minute: Number(event.target.value) }))}
              />
              {schedule.frequency === 'weekly' ? (
                <Select value={String(schedule.weekday)} onValueChange={(value) => setSchedule((current) => ({ ...current, weekday: Number(value) }))}><SelectTrigger className="w-36" aria-label="Weekday"><SelectValue /></SelectTrigger><SelectContent>
                  {WEEKDAYS.map(([value, label]) => (
                    <SelectItem key={value} value={String(value)}>{label}</SelectItem>
                  ))}
                </SelectContent></Select>
              ) : null}
              {schedule.frequency === 'monthly' ? (
                <Input className="w-24"
                  type="number"
                  min={1}
                  max={28}
                  aria-label="Day of month"
                  value={schedule.month_day}
                  onChange={(event) => setSchedule((current) => ({ ...current, month_day: Number(event.target.value) }))}
                />
              ) : null}
            </>
          ) : null}
        </div>
        {schedule.enabled ? (
          <p className="text-sm text-muted-foreground">
            Times are UTC. Scheduled reports render through the same pipeline as manual ones and appear in the history with
            origin <em>schedule</em>; the retention cap prunes the oldest artifacts automatically.
          </p>
        ) : null}
        </CardContent></Card>
      </div>

      {/* 04 Branding — headers, footer, classification (reports.html:176-190). */}
      <div className="dashboard-panel" role="tabpanel" id="rp-panel-branding" aria-labelledby="rp-branding" hidden={step !== 'branding'}>
        <Card className="col-span-full">
        <CardHeader><h2 className="font-semibold leading-none tracking-tight">Branding</h2><CardDescription>Applied to every page of the PDF. Empty fields fall back to the template defaults.</CardDescription></CardHeader><CardContent>
        <div className="grid gap-4 sm:grid-cols-2">
          {brandingField('title', 'Title (defaults to template title)', 80)}
          {brandingField('author', 'Author', 60)}
          {brandingField('header_left', 'Header left', 60)}
          {brandingField('header_right', 'Header right', 60)}
          {brandingField('footer_left', 'Footer left', 80)}
          {brandingField('classification', 'Classification', 120)}
        </div>
        </CardContent></Card>
      </div>

      {/* 05 Review — every choice read back before anything is generated
          (#1858). This is what made the studio a sequence rather than a
          form split five ways: the four steps ask, this one answers, and
          the answer is where the definition is finally committed. Each
          row links to the step that owns the value, so a wrong-looking
          entry is one click from where it was set rather than a hunt. */}
      <div className="dashboard-panel" role="tabpanel" id="rp-panel-review" aria-labelledby="rp-review" hidden={!onReview}>
        <Card className="col-span-full">
          <CardHeader><h2 className="font-semibold leading-none tracking-tight">Review</h2><CardDescription>{stepLede('review')}</CardDescription></CardHeader><CardContent>
          <div className="hp-rp-review">
            {summaryRows.map((row) => (
              <div className="hp-rp-review__row" key={`${row.step}:${row.key}`}>
                <span className="hp-rp-review__key">{row.key}</span>
                <span className="hp-rp-review__value" data-unset={row.unset ? '' : undefined}>
                  {row.value}
                </span>
                <Button variant="ghost" size="sm"
                  type="button"
                  onClick={() => onStep(row.step)}
                  title={`Change this on the ${STEPS.find((entry) => entry.id === row.step)?.label} step`}
                >
                  change
                </Button>
              </div>
            ))}
          </div>
          </CardContent></Card>
      </div>

      {/* The sequence's controls. Back and Next move through the steps;
          the definition is committed on Review and nowhere else -- a save
          button repeated on every step is what made this read as one page
          of controls rather than a click-through (#1858). Cancel stays
          available throughout, because abandoning a draft should never
          require walking to the end of it first. */}
      <div className="hp-rp-actions" hidden={step === 'library'}>
        <Button variant="ghost" size="sm"
          type="button"
          disabled={!previousStep}
          onClick={() => previousStep && onStep(previousStep.id)}
        >
          Back{previousStep ? ` — ${previousStep.label}` : ''}
        </Button>
        {nextStep ? (
          <Button size="sm" type="button" onClick={() => onStep(nextStep.id)}>
            Next — {nextStep.label}
          </Button>
        ) : (
          <Button size="sm" type="submit" disabled={busy || !name.trim() || !template}>
            {busy ? 'Saving…' : isCreate ? 'Create definition' : 'Save changes'}
          </Button>
        )}
        <Button variant="ghost" size="sm" type="button" onClick={onCancel}>
          {isCreate ? 'Reset' : 'Cancel edit'}
        </Button>
        {message ? <span className="hp-rp-status" data-state="error">{message}</span> : null}
      </div>
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
  failed,
}: {
  definitions: ReportDefinition[] | null
  editable: boolean
  /** Load a saved definition into the wizard (jumps to the Design step). */
  onEdit: (definition: ReportDefinition) => void
  /** Reset the wizard to a fresh definition (jumps to the Design step). */
  onNew: () => void
  onChanged: () => Promise<void> | void
  onGenerated: () => Promise<void> | void
  failed?: boolean
}) {
  const [busyId, setBusyId] = useState<string | null>(null)
  const [rowMessage, setRowMessage] = useState<Record<string, string>>({})
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null)

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
      setDeleteConfirmId(null)
    }
  }

  return (
    <>
      <Card className="col-span-full">
        <CardHeader><h2 className="font-semibold leading-none tracking-tight">Saved definitions</h2>
        <CardDescription>
          Definitions drive the scheduler and on-demand generation — saved designs you can re-generate, refine, or
          schedule.
        </CardDescription></CardHeader>
        <CardContent className="space-y-4">
        {editable ? (
          <Button variant="secondary" size="sm" type="button" onClick={onNew}>
            New definition
          </Button>
        ) : null}
        {definitions === null ? (
          failed ? (
            /* #2178: the studio's own library must not answer an outage
               with "No report definitions yet". */
            <Empty role="alert"><EmptyHeader><EmptyTitle>Definitions failed to load</EmptyTitle><EmptyDescription>The backend request didn’t answer.</EmptyDescription></EmptyHeader></Empty>
          ) : (
            <Skeleton className="h-24 w-full" aria-hidden="true" />
          )
        ) : definitions.length === 0 ? (
          <Empty><EmptyHeader><EmptyTitle>No report definitions yet</EmptyTitle></EmptyHeader></Empty>
        ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Template</TableHead>
                  <TableHead>Theme</TableHead>
                  <TableHead>Schedule</TableHead>
                  <TableHead>Created</TableHead>
                  {editable ? <TableHead>Actions</TableHead> : null}
                </TableRow>
              </TableHeader>
              <TableBody>
                {definitions.map((definition) => (
                  <TableRow key={definition.id}>
                    <TableCell>{definition.name}</TableCell>
                    <TableCell><Badge variant="secondary">{definition.template}</Badge></TableCell>
                    <TableCell>{definition.theme}</TableCell>
                    <TableCell>
                      {definition.schedule?.enabled
                        ? `${definition.schedule.frequency} @ ${pad2(definition.schedule.hour)}:${pad2(definition.schedule.minute)} UTC`
                        : '—'}
                    </TableCell>
                    <TableCell>{formatTimestamp((definition.created || ''))}</TableCell>
                    {editable ? (
                      <TableCell>
                        <div className="flex flex-wrap gap-2">
                          <Button variant="secondary" size="sm"
                            type="button"
                            disabled={busyId === definition.id}
                            onClick={() => onEdit(definition)}
                          >
                            Edit
                          </Button>
                          <Button variant="secondary" size="sm"
                            type="button"
                            disabled={busyId === definition.id}
                            onClick={() => generate(definition.id)}
                          >
                            {busyId === definition.id ? 'Working…' : 'Generate'}
                          </Button>
                          <Button variant="destructive" size="sm"
                            type="button"
                            disabled={busyId === definition.id}
                            onClick={() => setDeleteConfirmId(definition.id)}
                          >
                            Delete
                          </Button>
                        </div>
                        {rowMessage[definition.id] ? <p className="text-sm text-destructive">{rowMessage[definition.id]}</p> : null}
                      </TableCell>
                    ) : null}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
        )}
        </CardContent>
      </Card>
      <AlertDialog open={deleteConfirmId !== null} onOpenChange={(open) => !open && setDeleteConfirmId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete report definition?</AlertDialogTitle>
            <AlertDialogDescription>This cannot be undone.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => deleteConfirmId && remove(deleteConfirmId)}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

function Reports() {
  const data = Route.useLoaderData()
  const [generated, setGenerated] = useState<Page | null>(null)
  const [templatesData, setTemplatesData] = useState<TemplatesResponse | null>(null)
  const [definitions, setDefinitions] = useState<ReportDefinition[] | null>(null)
  // #2178: every one of the three loader promises collapses failure to
  // null, and the old effects either kept the skeleton up forever or — for
  // definitions — manufactured an empty library out of a dead read.
  // #2179 disclosure zones (jobsFailed/payloadError in the sandbox and
  // payload pickers) are separate channels and untouched here.
  const [generatedFailed, setGeneratedFailed] = useState(false)
  const [templatesFailed, setTemplatesFailed] = useState(false)
  const [definitionsFailed, setDefinitionsFailed] = useState(false)
  // Wizard state: which step is showing, and which saved definition (if
  // any) is loaded into the form. formSeed remounts the form so "New
  // definition" / cancel always reset to a blank draft.
  const [step, setStep] = useState<StepId>('design')
  const [editing, setEditing] = useState<ReportDefinition | null>(null)
  const [formSeed, setFormSeed] = useState(0)
  const [viewingReport, setViewingReport] = useState<StoreRow | null>(null)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [deleteGeneratedConfirmId, setDeleteGeneratedConfirmId] = useState<string | null>(null)
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
    data.generated
      .then((page) => {
        if (cancelled) return
        if (!page) {
          setGeneratedFailed(true)
          return
        }
        setGenerated(page)
      })
      .catch(() => {
        if (!cancelled) setGeneratedFailed(true)
      })
    data.templates
      .then((result) => {
        if (cancelled) return
        if (!result) {
          setTemplatesFailed(true)
          return
        }
        setTemplatesData(result)
      })
      .catch(() => {
        if (!cancelled) setTemplatesFailed(true)
      })
    data.definitions
      .then((result) => {
        if (cancelled) return
        // A null collapse is a failed read, not an empty library — and so
        // is a body that doesn't carry its definitions array at all: shape
        // drift upstream, or a catch-all answer from a fixture/misroute.
        // Storing result.definitions directly let an undefined through the
        // `definitions === null` gate and crashed on definitions.length
        // (the client render death the browser matrix caught on /reports).
        // A truthy-but-non-array `definitions` (an object or string from
        // the same drift) passed a bare `!next` check just as wrongly, so
        // the gate checks the shape, not just presence.
        const next = result?.definitions
        if (!Array.isArray(next)) {
          setDefinitionsFailed(true)
          return
        }
        setDefinitions(next)
      })
      .catch(() => {
        if (!cancelled) setDefinitionsFailed(true)
      })
    return () => {
      cancelled = true
    }
  }, [data])

  const isAdmin = !data.user || data.user.role === 'admin'
  const editable = isAdmin && templatesData !== null

  const refreshDefinitions = async () => {
    const result = await fetchDefinitions()
    // #2178: a failed refetch keeps the list on screen; blanking it to []
    // read as "every definition vanished" exactly when the store was
    // merely unreachable. A body without its definitions array counts as
    // failed too — only a real response may redraw. That includes a
    // truthy non-array (#2573): a bare `!next` check let it through to
    // `next.some(...)` below.
    const next = result?.definitions
    if (!Array.isArray(next)) return
    setDefinitions(next)
    // The definition being edited may have been deleted from the library —
    // fall back to a fresh draft rather than resurrecting it on save.
    setEditing((current) => (current && !next.some((entry) => entry.id === current.id) ? null : current))
  }

  // #2178: the wizard's template catalog has no other retry path -- the
  // designer is unusable until it answers.
  const retryTemplates = useCallback(() => {
    setTemplatesFailed(false)
    fetchTemplates()
      .then((result) => {
        if (result) setTemplatesData(result)
        else setTemplatesFailed(true)
      })
      .catch(() => setTemplatesFailed(true))
  }, [])

  const refreshGenerated = async () => {
    const page = await fetchGenerated({ data: { offset: 0 } })
    if (page) setGenerated(page)
  }

  const removeGenerated = async (row: StoreRow) => {
    const id = str(row, 'id')
    setDeletingId(id)
    try {
      const result = await deleteGenerated({ data: { id } })
      if (result.ok) await refreshGenerated()
    } finally {
      setDeletingId(null)
      setDeleteGeneratedConfirmId(null)
    }
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
        chips={<Badge variant="outline">{generatedFailed && !generated ? 'load failed' : `${(generated?.total ?? 0).toLocaleString('en-US')} generated reports`}</Badge>}
      />
      {viewTabs}
      {/* Steps 01-04 are the wizard form — always mounted (hidden panels)
          so a half-built definition survives a detour through the Library. */}
      {editable ? (
        <DefinitionForm
          key={`${editing?.id ?? 'new'}:${formSeed}`}
          step={step}
          onStep={setStep}
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
          templatesFailed ? (
            /* #2178: an admin stared at a bare skeleton through any
               template-catalog outage, with no signal and no way forward. */
            <ErrorStateBlock title="Report templates failed to load" hint="The designer needs its template catalog — the request failed." onRetry={retryTemplates} />
          ) : (
            <Skeleton className="h-24 w-full" aria-hidden="true" />
          )
        ) : (
          <Empty><EmptyHeader><EmptyTitle>Admin role required</EmptyTitle><EmptyDescription>The Library step remains available for read-only browsing.</EmptyDescription></EmptyHeader></Empty>
        )
      ) : null}

      {/* 05 Library — saved definitions + finished PDFs (reports.html:193-232). */}
      <div className="dashboard-panel" role="tabpanel" id="rp-panel-library" aria-labelledby="rp-library" hidden={step !== 'library'}>
        <DefinitionsCard
          definitions={definitions}
          editable={editable}
          failed={definitionsFailed && definitions === null ? true : undefined}
          onEdit={startEdit}
          onNew={startNew}
          onChanged={refreshDefinitions}
          onGenerated={refreshGenerated}
        />
        <h2 className="label-section">Generated reports</h2>
        <p className="text-sm text-muted-foreground">Newest first. Select a card to view inline, download the PDF, or delete stale artifacts.</p>
        {generatedFailed && !generated ? (
          /* #2178: the library's finished-PDF list also stood as ghost
             cards forever under an outage. */
          <ErrorStateBlock
            title="Generated reports failed to load"
            hint="The backend request failed — nothing here is cached."
            onRetry={() => void refreshGenerated()}
          />
        ) : (
        <MasterDetailTable
          rows={generated ? generated.rows : null}
          columns={buildGeneratedColumns(setViewingReport, (row) => setDeleteGeneratedConfirmId(str(row, 'id')), deletingId)}
          rowKey={(row, index) => `${str(row, 'id')}-${index}`}
          emptyState={{
            title: 'No reports generated yet',
            hint: 'Build one above and it will be listed here with its download links.',
          }}
          inspectorTitle="Report details"
          layout="cards"
          gridId="hp-rp-generated"
          cardIcon={() => ReportIcon}
          cardBadges={(row) => {
            const format = str(row, 'format') || str(row, 'kind')
            return format ? <Badge variant="secondary">{format}</Badge> : null
          }}
        />
        )}
      </div>
      {viewingReport ? (
        <ReportViewerModal
          id={str(viewingReport, 'id')}
          title={str(viewingReport, 'title') || str(viewingReport, 'name')}
          onClose={() => setViewingReport(null)}
        />
      ) : null}
      <AlertDialog open={deleteGeneratedConfirmId !== null} onOpenChange={(open) => !open && setDeleteGeneratedConfirmId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete generated report?</AlertDialogTitle>
            <AlertDialogDescription>This cannot be undone.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => {
              const row = generated?.rows.find(r => str(r, 'id') === deleteGeneratedConfirmId)
              if (row) void removeGenerated(row)
            }}>Delete</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
