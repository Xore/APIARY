// Reports studio — generated PDF reports and the report definitions
// behind them: full CRUD plus on-demand generation, now that the worker
// port (#1610) and the reports API port (#1612) have both landed
// server-side (backend-service/src/reports_api.rs, reports_store.rs).
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { getSessionUser } from '../lib/auth'
import type { JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'

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
  { header: 'title', className: 'v', render: (row) => str(row, 'title') || str(row, 'name') },
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
// Fixed defaults for the schedule granularity this form doesn't expose:
// weekly fires on Sunday (weekday 0), monthly fires on the 1st.
function emptySchedule(): ReportSchedule {
  return { enabled: false, frequency: 'daily', hour: 3, minute: 0, weekday: 0, month_day: 1, last_run_at: '', next_run_at: '' }
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

function DefinitionForm({
  templates,
  elements,
  initial,
  onCancel,
  onSaved,
}: {
  templates: ReportTemplate[]
  elements: ReportElementInfo[]
  initial: ReportDefinition
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
    <div className="card wide">
      <h2>{isCreate ? 'New report definition' : `Edit — ${initial.name}`}</h2>
      <form
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

        {isSpecial ? (
          <>
            <p className="note">
              This template renders through a dedicated artifact renderer this tier doesn't implement yet — saving works, but
              Generate will report "not yet implemented" until that renderer ports.
            </p>
            <div className="filters">
              {activeTemplate?.sandbox ? scopeField('job', 'Sandbox job id', 128) : null}
              {activeTemplate?.payload || activeTemplate?.ghidra ? scopeField('hash', 'Payload hash (sha256 or md5)', 64) : null}
            </div>
          </>
        ) : (
          <>
            <div className="filters">
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
              {scopeField('ip', 'IP', 64)}
              {scopeField('sensor', 'Sensor', 64)}
              {scopeField('port', 'Port', 16)}
              {scopeField('signature', 'Signature', 120)}
            </div>
            <p className="note">
              Scope narrows what the report covers; leave fields blank for an unscoped report. Network, country, ASN, text,
              type, and session scope aren't exposed here and stay unscoped.
            </p>
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
        )}

        <p className="note">Branding</p>
        <div className="filters">
          {brandingField('title', 'Title (defaults to template title)', 80)}
          {brandingField('author', 'Author', 60)}
          {brandingField('header_left', 'Header left', 60)}
          {brandingField('header_right', 'Header right', 60)}
          {brandingField('footer_left', 'Footer left', 80)}
          {brandingField('classification', 'Classification', 120)}
        </div>

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

        <p className="note">Schedule</p>
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
            </>
          ) : null}
        </div>
        {schedule.enabled ? (
          <p className="note">
            Fires at the given hour:minute UTC. Weekday/day-of-month aren't exposed here — weekly fires on Sunday, monthly
            fires on the 1st.
          </p>
        ) : null}

        <div className="filters" style={{ marginTop: 8 }}>
          <button className="btn btn-primary btn-sm" type="submit" disabled={busy || !name.trim() || !template}>
            {busy ? 'Saving…' : isCreate ? 'Create definition' : 'Save changes'}
          </button>
          <button className="btn btn-ghost btn-sm" type="button" onClick={onCancel}>
            Cancel
          </button>
        </div>
        {message ? <p className="note">{message}</p> : null}
      </form>
    </div>
  )
}

function DefinitionsCard({
  templates,
  elements,
  definitions,
  editable,
  onChanged,
  onGenerated,
}: {
  templates: ReportTemplate[]
  elements: ReportElementInfo[]
  definitions: ReportDefinition[] | null
  editable: boolean
  onChanged: () => Promise<void> | void
  onGenerated: () => Promise<void> | void
}) {
  const [editingId, setEditingId] = useState<string | 'new' | null>(null)
  const [busyId, setBusyId] = useState<string | null>(null)
  const [rowMessage, setRowMessage] = useState<Record<string, string>>({})

  const generate = async (id: string) => {
    setBusyId(id)
    try {
      const result = await generateDefinition({ data: { id } })
      setRowMessage((current) => ({
        ...current,
        [id]: result.ok ? 'Generated — see the reports table above.' : result.error || 'Generation failed.',
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
        if (editingId === id) setEditingId(null)
        await onChanged()
      } else {
        setRowMessage((current) => ({ ...current, [id]: result.error || 'Delete failed.' }))
      }
    } finally {
      setBusyId(null)
    }
  }

  const editing = editingId === 'new' ? emptyDefinition() : (definitions ?? []).find((entry) => entry.id === editingId)

  return (
    <>
      <div className="card wide">
        <h2>Report definitions</h2>
        <p className="note">Definitions drive the scheduler and on-demand generation below.</p>
        {editable ? (
          <button className="btn btn-secondary btn-sm" type="button" onClick={() => setEditingId('new')} style={{ marginBottom: 12 }}>
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
                            onClick={() => setEditingId(definition.id)}
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
      {editingId !== null && editing ? (
        <DefinitionForm
          templates={templates}
          elements={elements}
          initial={hydrateDefinition(editing)}
          onCancel={() => setEditingId(null)}
          onSaved={async () => {
            setEditingId(null)
            await onChanged()
          }}
        />
      ) : null}
    </>
  )
}

function Reports() {
  const data = Route.useLoaderData()
  const [generated, setGenerated] = useState<Page | null>(null)
  const [templatesData, setTemplatesData] = useState<TemplatesResponse | null>(null)
  const [definitions, setDefinitions] = useState<ReportDefinition[] | null>(null)

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

  const refreshDefinitions = async () => {
    const result = await fetchDefinitions()
    setDefinitions(result?.definitions ?? [])
  }

  const refreshGenerated = async () => {
    const page = await fetchGenerated({ data: { offset: 0 } })
    if (page) setGenerated(page)
  }

  return (
    <>
      <InvestigateHeader
        label="Reports"
        title="Reports studio"
        subtitle="Finished PDF reports and the definitions that produce them — scheduled and on-demand runs land here."
        chips={<span className="chip">{(generated?.total ?? 0).toLocaleString('en-US')} generated reports</span>}
      />
      <MasterDetailTable
        rows={generated ? generated.rows : null}
        columns={COLUMNS}
        rowKey={(row, index) => `${str(row, 'id')}-${index}`}
        inspectorTitle="Report details"
      />
      <DefinitionsCard
        templates={templatesData?.templates ?? []}
        elements={templatesData?.elements ?? []}
        definitions={definitions}
        editable={isAdmin && templatesData !== null}
        onChanged={refreshDefinitions}
        onGenerated={refreshGenerated}
      />
    </>
  )
}
