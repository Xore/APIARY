// Payload analysis — one captured artifact's full picture, restored to the
// Go dashboard's structured layout (#1653; payloads.html's
// "payload-analysis" template + hp-payload-analysis.js): KPI tiles,
// Identity/Findings/Content tabs, prior-analysis correlation cards, and
// the operator actions that queue further work on this same artifact
// (#1608 workstream L): sandbox detonation, Ghidra decompilation, and
// GitHub-analysis publication. Static analysis itself never executes the
// payload; the actions below hand off to the sensor host's own async
// workers (sandbox_submit.rs/ghidra_submit.rs/github_analysis_submit.rs) —
// this page only ever queues a request marker, same trust boundary as
// every other mutation here.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useMemo, useRef, useState } from 'react'
import { confirmAction } from '../components/ConfirmDialog'
import { InvestigateHeader } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'
import { RowActions, RowIcons } from '../components/RowActions'
import { getSessionUser, type User } from '../lib/auth'
import { flash } from '../lib/flash'
import { useResolved } from '../lib/hooks'
import type { Json, JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'

type PayloadDetail = {
  hash: string
  inventory: JsonRecord | null
  analysis: JsonRecord | null
  yara: JsonRecord[]
  size_bytes: number
  hex_preview: string[]
}

// #2178: serviceJSON collapsed "no analysis exists for this hash" (a real
// 404) and "the request failed" into one null, so an outage read as "No
// analysis found for <hash>" — asserting absence about a sample that may
// simply be unreachable. Tri-state now; the handler never rejects.
type DetailFetch =
  | { state: 'detail'; detail: PayloadDetail }
  | { state: 'missing' }
  | { state: 'failed' }

const fetchDetail = createServerFn({ method: 'GET' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<DetailFetch> => {
    const { serviceJSONResult } = await import('../lib/backend.server')
    const result = await serviceJSONResult<PayloadDetail>(`/api/v1/payloads/${encodeURIComponent(data.hash)}`)
    if (result.ok) return { state: 'detail', detail: result.body }
    return result.status === 404 ? { state: 'missing' } : { state: 'failed' }
  })

// #86 Windows golden-image staleness report — informational only.
// sandbox_submit.rs's own submit handler never consults this (it only
// checks classification + spool-dir configuration), so this page doesn't
// gate the Detonate button on it either; it just surfaces the state so a
// detonation that is likely to come back empty isn't a silent surprise.
type GoldenImageStatus = {
  configured: boolean
  built_at?: string
  age_days?: number
  checksum_written?: boolean
  checksum_verified?: boolean
  stale_monthly?: boolean
  stale_iso_eval?: boolean
  checked_at?: string
  error?: string
}

// #2178: serviceJSON collapsed a failed status read into the same null the
// unconfigured-sandbox path produces downstream, so an outage rendered as
// quiet "no news" from a report whose whole job is surfacing bad news.
// Tagged now; a 404 keeps the legacy nil posture (no report is not an outage).
type GoldenImageFetch = { state: 'status'; status: GoldenImageStatus } | { state: 'unavailable' }

const fetchGoldenImageStatus = createServerFn({ method: 'GET' }).handler(async (): Promise<GoldenImageFetch> => {
  const { serviceJSONResult } = await import('../lib/backend.server')
  const result = await serviceJSONResult<GoldenImageStatus>('/api/v1/sandbox/golden-image-status', { mounted: true })
  if (result.ok) return { state: 'status', status: result.body }
  return result.status === 404 ? { state: 'status', status: { configured: false } } : { state: 'unavailable' }
})

type SubmitResult = { ok: boolean; target?: string; error?: string }

// All three submissions are admin-gated at the BFF, same posture as every
// other mutation in this app (settings.tsx's runServiceAction) — the Rust
// tier's own trust boundary is the service token, so this check is the
// only one that exists. Each handler below fetches the session once and
// passes it in, rather than this helper fetching its own — submitGithubAnalysis
// needs that same user for its actor_subject/actor_username fields.
async function submitAnalysisJob(user: User | null, path: string, body: Record<string, unknown>, failMessage: string): Promise<SubmitResult> {
  if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
  const { serviceFetch } = await import('../lib/backend.server')
  const response = await serviceFetch(
    path,
    { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) },
    { mounted: true },
  )
  const responseBody = await response.json().catch(() => null)
  if (response.ok && responseBody?.queued) {
    return { ok: true, target: typeof responseBody?.target === 'string' ? responseBody.target : undefined }
  }
  return { ok: false, error: responseBody?.error || failMessage }
}

const submitSandbox = createServerFn({ method: 'POST' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<SubmitResult> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    return submitAnalysisJob(user, '/api/v1/sandbox/submit', { hash: data.hash }, 'Sandbox submission failed.')
  })

const submitGhidra = createServerFn({ method: 'POST' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<SubmitResult> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    return submitAnalysisJob(user, '/api/v1/ghidra/submit', { hash: data.hash }, 'Ghidra submission failed.')
  })

// github_analysis_submit.rs refuses anything but the literal string
// "publish" in `confirm` and audits every outcome — publication is
// external and irreversible (a public repo + third-party scanners), so
// the operator must have actually confirmed in the UI before this is
// ever called; every caller (this page's External-publication card, and
// payloads.tsx's own copy behind its per-card action menu) wraps it in
// confirmAction with the publication wording from payloads.html's
// data-hp-confirm-* attributes.
const submitGithubAnalysis = createServerFn({ method: 'POST' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<SubmitResult> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    return submitAnalysisJob(
      user,
      '/api/v1/github-analysis/submit',
      { hash: data.hash, confirm: 'publish', actor_subject: user?.sub ?? '', actor_username: user?.username ?? '' },
      'GitHub-analysis submission failed.',
    )
  })

// One-click "Generate PDF report" (#474, hp-payload-report.js): POSTs
// reports_api.rs's generate_payload_report, which renders an ephemeral
// payload-template definition through the same pipeline as every
// Reports-studio PDF and returns the stored record's id. No background
// job, no polling — the in-process PDF emitter finishes within this one
// request, so the trigger's own busy state is the whole "spinner".
// Admin-gated at the BFF like every other mutation on this page; errors
// come back as the Rust tier's plain-text body, surfaced verbatim.
const generatePdfReport = createServerFn({ method: 'POST' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; id?: string; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user || user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(
      `/api/v1/payloads/${encodeURIComponent(data.hash)}/report`,
      { method: 'POST' },
      { mounted: true },
    )
    if (!response.ok) {
      const text = (await response.text().catch(() => '')).trim()
      return { ok: false, error: text || `Report generation failed (${response.status}).` }
    }
    const body = (await response.json().catch(() => null)) as { id?: unknown } | null
    const id = typeof body?.id === 'string' ? body.id : ''
    if (!id) return { ok: false, error: 'Report generation returned no report id.' }
    return { ok: true, id }
  })

// ── Prior-analysis correlation (hp-payload-analysis.js's aggregation
//    pass, #1142) — the Rust tier has no aggregation endpoint, so this
//    reads the same result stores the Go backend aggregated
//    (sandbox-analysis-v1 / ghidra-analysis-v1 / github-analysis-v1 via
//    /api/v1/store/*) and filters by hash with the store's own Lucene `q`.
type SandboxRunRow = { job: string; completed_at: string; exit_status: string; changed: number }
type GithubView = { sha256: string; exit_status: string; malicious: number | null; total: number | null; level: string; family: string }
type GhidraView = { exit_status: string; completed_at: string }
type Correlation = { sandbox_runs: SandboxRunRow[]; github: GithubView | null; ghidra: GhidraView | null }

type StorePage = { total: number; rows: JsonRecord[] }

function jobj(value: Json | undefined | null): JsonRecord | null {
  return value !== null && value !== undefined && typeof value === 'object' && !Array.isArray(value) ? (value as JsonRecord) : null
}
function jarr(value: Json | undefined | null): Json[] {
  return Array.isArray(value) ? value : []
}
function jstr(value: Json | undefined | null): string {
  return typeof value === 'string' ? value : typeof value === 'number' ? String(value) : ''
}
function jnum(value: Json | undefined | null): number | null {
  return typeof value === 'number' ? value : null
}

// #2178: the three store lookups behind this all resolve empty through
// serviceJSON when their request fails, which used to compose into a
// confident "not seen elsewhere" verdict for a sample whose stores were
// simply unreachable. Any failing leg now fails the whole correlation.
type CorrelationFetch = { state: 'data'; correlation: Correlation } | { state: 'failed' }

const fetchCorrelation = createServerFn({ method: 'GET' })
  .inputValidator((input: { key: string }) => input)
  .handler(async ({ data }): Promise<CorrelationFetch> => {
    const { serviceJSON } = await import('../lib/backend.server')
    const key = data.key.toLowerCase()
    const q = encodeURIComponent(key)
    const [sandbox, ghidra, github] = await Promise.all([
      serviceJSON<StorePage>(`/api/v1/store/sandbox-runs?offset=0&size=25&q=${q}`),
      serviceJSON<StorePage>(`/api/v1/store/ghidra-runs?offset=0&size=5&q=${q}`),
      serviceJSON<StorePage>(`/api/v1/store/github-analysis?offset=0&size=5&q=${q}`),
    ])
    if (!sandbox || !ghidra || !github) return { state: 'failed' }
    // Result documents are namespaced by the es-results-importer source
    // label ("sandbox"/"ghidra"/"github_analysis" sub-objects) — read the
    // namespaced object first, fall back to the row itself, same
    // defensive shape detail.rs's own sandbox_run query takes.
    const sandboxRuns: SandboxRunRow[] = []
    for (const row of sandbox?.rows ?? []) {
      const run = jobj(row.sandbox) ?? row
      const sha = jstr(run.sha256).toLowerCase()
      if (sha && sha !== key) continue
      const job = jstr(run.job)
      if (!job || !jstr(run.completed_at)) continue
      sandboxRuns.push({
        job,
        completed_at: jstr(run.completed_at),
        exit_status: jstr(run.exit_status),
        changed: jarr(run.changed_files).length,
      })
    }
    let githubView: GithubView | null = null
    for (const row of github?.rows ?? []) {
      const result = jobj(row.github_analysis) ?? row
      const sha = jstr(result.sha256).toLowerCase()
      if (!sha || (sha !== key && jstr(jobj(jobj(row.file)?.hash ?? null)?.sha256).toLowerCase() !== key)) continue
      const verdict = jobj(result.verdict)
      githubView = {
        sha256: sha,
        exit_status: jstr(result.exit_status),
        malicious: verdict ? jnum(verdict.malicious) : null,
        total: verdict ? jnum(verdict.total) : null,
        level: verdict ? jstr(verdict.level) : '',
        family: jstr(result.family),
      }
      break
    }
    let ghidraView: GhidraView | null = null
    for (const row of ghidra?.rows ?? []) {
      const sha = jstr(jobj(jobj(row.file)?.hash ?? null)?.sha256).toLowerCase()
      if (sha && sha !== key) continue
      const run = jobj(row.ghidra) ?? row
      ghidraView = { exit_status: jstr(run.exit_status) || 'completed', completed_at: jstr(run.completed_at) }
      break
    }
    return { state: 'data', correlation: { sandbox_runs: sandboxRuns, github: githubView, ghidra: ghidraView } }
  })

// Related-event sightings + capture origin, recovered from the event feed
// the same way Go's earliestEventByShasum did (payloads_data.go) — the
// feed sorts newest-first, so the earliest sighting is the last row of
// the filtered result set (bounded by ES's from+size window).
type RelatedEvents = {
  total: number
  earliest: { time: string; sensor: string; session: string } | null
}
// #2178 companion channel so a failed sighting lookup can't read as
// "total: 0".
type RelatedFetch = { state: 'data'; related: RelatedEvents } | { state: 'failed' }

const fetchRelatedEvents = createServerFn({ method: 'GET' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<RelatedFetch> => {
    const { serviceJSON } = await import('../lib/backend.server')
    type EventsPage = { total: number; rows: { time: string; sensor: string; session: string }[] }
    const base = `/api/v1/events?shasum=${encodeURIComponent(data.hash)}&size=1`
    const first = await serviceJSON<EventsPage>(base)
    // #2178: `first?.total ?? 0` on a failed query used to read as "no
    // sightings anywhere"; a failed lookup is no answer at all.
    if (!first) return { state: 'failed' }
    if (first.total === 0) return { state: 'data', related: { total: 0, earliest: null } }
    let row = first.rows[0] ?? null
    if (first.total > 1 && first.total <= 10000) {
      const last = await serviceJSON<EventsPage>(`${base}&offset=${first.total - 1}`)
      row = last?.rows[0] ?? row
    }
    return {
      state: 'data',
      related: {
        total: first.total,
        earliest: row ? { time: row.time, sensor: row.sensor, session: row.session } : null,
      },
    }
  })

export const Route = createFileRoute('/payload-analysis/$hash')({
  loader: async ({ params }) => ({
    first: fetchDetail({ data: { hash: params.hash } }),
    golden: fetchGoldenImageStatus(),
    user: await getSessionUser(),
  }),
  component: PayloadAnalysis,
})

// ── Static-analysis view — the structured half hp-payload-analysis.js's
//    loadStaticAnalysis() rendered. The dashboard-static-analysis-v1
//    document is Go's staticAnalysisCacheDoc ({Fingerprint, Analysis}),
//    whose payloadStaticAnalysis fields serialize with Go-capitalized
//    names except the json-tagged nested structs (classification/rules/
//    decoded items are lowercase) — read both spellings defensively.
type DecodedItem = { kind: string; source: string; preview: string }
type RuleItem = { name: string; severity: string; description: string }
type StaticView = {
  classification: { code: string; label: string; platform: string; category: string; analysisPath: string; dynamic: boolean } | null
  magic: string
  mime: string
  size: string
  entropy: string
  sha256: string
  sha1: string
  md5: string
  packedLikely: boolean | null
  riskScore: number | null
  riskLevel: string
  truncated: boolean
  hexdump: string
  ascii: string[]
  utf16: string[]
  formatInfo: string[]
  decoded: DecodedItem[]
  scriptType: string
  indicators: string[]
  iocs: string[]
  rules: RuleItem[]
  yaraMatches: string[]
}

function buildStaticView(analysis: JsonRecord | null): StaticView | null {
  if (!analysis) return null
  const doc = jobj(analysis.Analysis) ?? analysis
  const pick = (...keys: string[]): Json | undefined => {
    for (const key of keys) if (doc[key] !== undefined) return doc[key]
    return undefined
  }
  const strings = (value: Json | undefined): string[] => jarr(value).map(jstr).filter(Boolean)
  const c = jobj(pick('Classification', 'classification'))
  const packedRaw = pick('PackedLikely', 'packed_likely')
  const entropyText = jstr(pick('Entropy'))
  const entropyValue = jnum(pick('EntropyValue', 'entropy'))
  return {
    classification: c
      ? {
          code: jstr(c.code),
          label: jstr(c.label),
          platform: jstr(c.platform),
          category: jstr(c.category),
          analysisPath: jstr(c.analysis_path),
          dynamic: c.dynamic === true,
        }
      : null,
    magic: jstr(pick('Magic', 'magic')),
    mime: jstr(pick('MIME', 'mime')),
    size: jstr(pick('Size', 'size')),
    entropy: entropyText || (entropyValue !== null ? entropyValue.toFixed(2) : ''),
    sha256: jstr(pick('SHA256', 'sha256')),
    sha1: jstr(pick('SHA1', 'sha1')),
    md5: jstr(pick('MD5', 'md5')),
    packedLikely: typeof packedRaw === 'boolean' ? packedRaw : null,
    riskScore: jnum(pick('StaticRiskScore', 'risk_score')),
    riskLevel: jstr(pick('StaticRiskLevel', 'risk_level')),
    truncated: pick('Truncated', 'truncated') === true,
    hexdump: jstr(pick('Hexdump', 'hexdump')),
    ascii: strings(pick('ASCII', 'ascii')),
    utf16: strings(pick('UTF16', 'utf16')),
    formatInfo: strings(pick('FormatInfo', 'format_info')),
    decoded: jarr(pick('Decoded', 'decoded')).map((item) => {
      const record = jobj(item)
      return record
        ? { kind: jstr(record.kind), source: jstr(record.source), preview: jstr(record.preview) }
        : { kind: '', source: '', preview: '' }
    }),
    scriptType: jstr(pick('ScriptType', 'script_type')),
    indicators: strings(pick('Indicators', 'indicators')),
    iocs: strings(pick('IOCs', 'iocs')),
    rules: jarr(pick('Rules', 'rules')).map((item) => {
      const record = jobj(item)
      return record
        ? { name: jstr(record.name), severity: jstr(record.severity), description: jstr(record.description) }
        : { name: '', severity: '', description: '' }
    }),
    yaraMatches: strings(pick('YARAMatches', 'yara_matches')),
  }
}

// yara-analysis-v1 samples arrive namespaced under a "yara" sub-object
// (es-results-importer's label contract, dashboard/yara.go's yaraSample).
function buildYaraView(rows: JsonRecord[]): { matches: string[]; scanned: string; error: string } {
  const matches: string[] = []
  let scanned = ''
  let error = ''
  for (const row of rows) {
    const sample = jobj(row.yara) ?? row
    for (const match of jarr(sample.matches)) {
      const name = jstr(match)
      if (name && !matches.includes(name)) matches.push(name)
    }
    const at = jstr(sample.scanned_at)
    if (at > scanned) scanned = at
    if (!error) error = jstr(sample.error)
  }
  return { matches, scanned, error }
}

// Badge + note for the Detonate row, derived from golden-image-status.
// Missing/unreadable/unconfigured is not an error (see golden_image_status
// in sandbox_submit.rs) — no badge at all in that case, same "no news" as
// the legacy sandbox.html detail page shows nothing when GoldenImage is nil.
function goldenImageNote(golden: GoldenImageStatus | null): { cls: string; label: string; detail: string } | null {
  if (!golden || !golden.configured) return null
  if (golden.error) {
    return { cls: 'badge badge--danger', label: 'Golden image missing', detail: golden.error }
  }
  if (golden.stale_iso_eval) {
    return {
      cls: 'badge badge--danger',
      label: `Golden image ${golden.age_days ?? '?'}d old`,
      detail: 'The evaluation ISO it was built from has likely expired (90-day limit) — a full rebuild is due.',
    }
  }
  if (golden.stale_monthly) {
    return {
      cls: 'badge badge--warning',
      label: `Golden image ${golden.age_days ?? '?'}d old`,
      detail: 'Past the monthly rebuild cadence.',
    }
  }
  if (golden.checksum_written && !golden.checksum_verified) {
    return {
      cls: 'badge badge--muted',
      label: 'Checksum unverified',
      detail: 'Not yet verified against a live clone this build.',
    }
  }
  return null
}

// Page-level numbered tab strip — theme.css's .tabs/.tab vocabulary
// (payloads.html:247-251), which the shared Tabs component can't emit (it
// speaks .segmented and can't put the .tab class on its buttons), so the
// markup is inlined here with the same roving-tabindex/Arrow/Home/End
// semantics hp-app.js's dashboard-tab handler had.
function PageTabs({
  tabs,
  active,
  onSelect,
  label,
}: {
  tabs: { id: string; label: string }[]
  active: string
  onSelect: (id: string) => void
  label: string
}) {
  const move = (event: React.KeyboardEvent, index: number) => {
    let target: number | null = null
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') target = (index + 1) % tabs.length
    else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') target = (index - 1 + tabs.length) % tabs.length
    else if (event.key === 'Home') target = 0
    else if (event.key === 'End') target = tabs.length - 1
    if (target === null) return
    event.preventDefault()
    onSelect(tabs[target].id)
    document.getElementById(`pl-tab-${tabs[target].id}`)?.focus()
  }
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((tab, index) => (
        <button
          key={tab.id}
          id={`pl-tab-${tab.id}`}
          className={tab.id === active ? 'tab active' : 'tab'}
          type="button"
          role="tab"
          aria-selected={tab.id === active}
          aria-controls={`pl-panel-${tab.id}`}
          tabIndex={tab.id === active ? 0 : -1}
          onClick={() => onSelect(tab.id)}
          onKeyDown={(event) => move(event, index)}
        >
          <span>0{index + 1}</span>
          {tab.label}
        </button>
      ))}
    </div>
  )
}

// Searchable evidence pane — the port of hp-payload-analysis.js's
// renderSearchableEvidence: count note, filter input, bounded <pre>.
function SearchablePane({
  entries,
  empty,
  placeholder,
  itemLabel,
  note,
}: {
  entries: { label: string; value: string }[]
  empty: string
  placeholder: string
  itemLabel: string
  note: string
}) {
  const [query, setQuery] = useState('')
  if (entries.length === 0) return <p className="empty">{empty}</p>
  const trimmed = query.trim().toLowerCase()
  const shown = trimmed
    ? entries.filter((entry) => `${entry.label} ${entry.value}`.toLowerCase().includes(trimmed))
    : entries
  return (
    <>
      <p className="note">
        {shown.length} of {entries.length} {itemLabel}
        {entries.length === 1 ? '' : 's'} shown — {note}
      </p>
      <input
        className="search"
        type="search"
        placeholder={placeholder}
        aria-label={placeholder}
        value={query}
        onChange={(event) => setQuery(event.target.value)}
      />
      <div className="card__scroll">
        <pre className="code">
          {shown.length
            ? shown.map((entry) => (entry.label ? `[${entry.label}]\n${entry.value}` : entry.value)).join('\n\n')
            : 'No entries match this filter.'}
        </pre>
      </div>
    </>
  )
}

function OperatorActionsCard({
  hash,
  golden,
  goldenUnavailable,
  editable,
}: {
  hash: string
  golden: GoldenImageStatus | null
  /** #2178: the status read itself failed — distinct from "not configured". */
  goldenUnavailable: boolean
  editable: boolean
}) {
  const [sandboxBusy, setSandboxBusy] = useState(false)
  const [sandboxMessage, setSandboxMessage] = useState('')
  const [ghidraBusy, setGhidraBusy] = useState(false)
  const [ghidraMessage, setGhidraMessage] = useState('')

  // The Go dashboard's one sandbox confirm surface (hp-modals.js:143-150)
  // — same title/description/warning/label copy verbatim.
  const detonate = () =>
    confirmAction({
      title: 'Submit payload to the sandbox?',
      description: 'This queues the captured artifact for execution in the isolated malware-analysis environment.',
      warning: `The payload ${hash} will be detonated and may generate network, process, and filesystem activity.`,
      confirmLabel: 'Submit to sandbox',
      onConfirm: async () => {
        setSandboxBusy(true)
        try {
          const result = await submitSandbox({ data: { hash } })
          if (!result.ok) {
            const message = result.error || 'Sandbox submission failed.'
            setSandboxMessage(message)
            throw new Error(message)
          }
          const message = `Queued${result.target ? ` for the ${result.target} sandbox` : ''} — see the sandbox queue once the job starts.`
          setSandboxMessage(message)
          return message
        } finally {
          setSandboxBusy(false)
        }
      },
    })

  // Ghidra deliberately has no confirm — hp-modals.js's own comment: a
  // modal per read-only decompilation is confirmation fatigue.
  const decompile = async () => {
    setGhidraBusy(true)
    setGhidraMessage('')
    try {
      const result = await submitGhidra({ data: { hash } })
      setGhidraMessage(result.ok ? 'Queued — see the Ghidra results once the job finishes.' : result.error || 'Ghidra submission failed.')
    } finally {
      setGhidraBusy(false)
    }
  }

  const goldenNote = goldenImageNote(golden)

  return (
    <div className="card wide">
      <h2>Operator actions</h2>
      <p className="note">
        Each action queues asynchronous work on the sensor host — nothing here executes inline. Results appear on the
        sandbox and Ghidra pages once the matching worker finishes.
      </p>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>Action</th>
              <th>Notes</th>
              <th>Result</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td className="v">
                <button
                  className="btn btn-primary btn-sm"
                  type="button"
                  disabled={!editable || sandboxBusy}
                  onClick={detonate}
                >
                  {sandboxBusy ? 'Queuing…' : 'Detonate in sandbox'}
                </button>
              </td>
              <td>
                {goldenNote ? (
                  <>
                    <span className={goldenNote.cls}>{goldenNote.label}</span>{' '}
                    <span className="note">{goldenNote.detail}</span>
                  </>
                ) : goldenUnavailable ? (
                  <span className="badge badge--muted" title="#2178: the staleness report could not be loaded right now — this says so rather than implying no news is good news.">
                    Golden-image status unavailable
                  </span>
                ) : (
                  <span className="note">Routes to the Windows or Linux sandbox automatically, based on classification.</span>
                )}
              </td>
              <td className="v">{sandboxMessage ? <span className="note">{sandboxMessage}</span> : '—'}</td>
            </tr>
            <tr>
              <td className="v">
                <button
                  className="btn btn-secondary btn-sm"
                  type="button"
                  disabled={!editable || ghidraBusy}
                  onClick={decompile}
                >
                  {ghidraBusy ? 'Queuing…' : 'Decompile with Ghidra'}
                </button>
              </td>
              <td>
                <span className="note">Headless decompilation — works on any sample with code in it, executes nothing.</span>
              </td>
              <td className="v">{ghidraMessage ? <span className="note">{ghidraMessage}</span> : '—'}</td>
            </tr>
          </tbody>
        </table>
      </div>
      {!editable ? <p className="note">Admin role required to submit for analysis.</p> : null}
    </div>
  )
}

// GitHub publication kept apart from the local-analysis actions above,
// with the distinct trust-boundary framing payload_workbench.html:112
// gives it — it leaves the local trust boundary (public repo +
// third-party scanners), which detonation and decompilation never do.
function ExternalPublicationCard({ hash, editable }: { hash: string; editable: boolean }) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  const publish = () =>
    confirmAction({
      title: 'Publish to Xore/honeypot?',
      description: 'This uploads the sample to the public Xore/honeypot repository and to third-party scanner APIs.',
      warning: 'This cannot be undone.',
      confirmLabel: 'Publish sample',
      onConfirm: async () => {
        setBusy(true)
        try {
          const result = await submitGithubAnalysis({ data: { hash } })
          if (!result.ok) {
            const failed = result.error || 'GitHub-analysis submission failed.'
            setMessage(failed)
            throw new Error(failed)
          }
          const queued = 'Queued — see GitHub analysis once it completes.'
          setMessage(queued)
          return queued
        } finally {
          setBusy(false)
        }
      },
    })

  return (
    <div className="card wide">
      <div className="filters">
        <h2 className="hp-push-end">External publication</h2>
        <span className="badge badge--red">leaves local trust boundary</span>
      </div>
      <p className="note">
        GitHub analysis uploads captured material externally — to the public Xore/honeypot repository and third-party
        scanner APIs. It is a separate administrator-only workflow with its own confirmation and audit trail, unlike the
        local analyses above, which never leave this host.
      </p>
      <div className="filters">
        <button className="btn btn-danger btn-sm" type="button" disabled={!editable || busy} onClick={publish}>
          {busy ? 'Publishing…' : 'Publish to Xore/honeypot'}
        </button>
        {message ? <span className="note">{message}</span> : null}
      </div>
    </div>
  )
}

// Payload PDF viewer (payloads.html:326-331 + hp-payload-report.js's
// openViewer/closeViewer): the same application-managed
// .modal.pdf-viewer-modal overlay as github-analysis.$sha.tsx's
// ReportViewer — focus moves to the close button on open, Tab cycles
// inside the dialog, Escape and backdrop clicks close, and focus returns
// to the trigger on unmount. The iframe is same-origin (the BFF's
// /api/report/{id}/pdf streaming proxy in front of the Rust tier's
// /api/v1/reports/{id}/pdf), so no sandbox attribute; the plain link is
// the browsers-without-inline-PDF fallback.
function PayloadReportViewer({ id, onClose }: { id: string; onClose: () => void }) {
  const closeRef = useRef<HTMLButtonElement>(null)
  const panelRef = useRef<HTMLElement>(null)
  const url = `/api/report/${encodeURIComponent(id)}/pdf`
  useEffect(() => {
    const previous = document.activeElement
    closeRef.current?.focus()
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault()
        onClose()
        return
      }
      if (event.key !== 'Tab' || !panelRef.current) return
      const focusables = panelRef.current.querySelectorAll<HTMLElement>('button, a[href], iframe')
      if (!focusables.length) return
      const first = focusables[0]
      const last = focusables[focusables.length - 1]
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault()
        first.focus()
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus()
    }
  }, [onClose])
  return (
    <>
      <div className="modal-backdrop open" aria-hidden="true" onClick={onClose} />
      <section
        className="modal pdf-viewer-modal open"
        role="dialog"
        aria-modal="true"
        aria-label="Payload report"
        ref={panelRef}
      >
        <button className="modal__close" type="button" aria-label="Close report viewer" onClick={onClose} ref={closeRef}>
          ✕
        </button>
        <h2 className="pdf-viewer-title">
          Payload report{' '}
          <a className="btn btn-ghost btn-sm" href={url} target="_blank" rel="noopener noreferrer">
            open in new tab ↗
          </a>
        </h2>
        <iframe className="pdf-viewer-frame" title="Payload PDF report preview" src={url} />
      </section>
    </>
  )
}

function PayloadAnalysis() {
  const { first, golden, user } = Route.useLoaderData()
  const { hash } = Route.useParams()
  // #2178: `resolved ?? 'missing'` let a failed detail fetch assert "No
  // analysis found for this hash". Tri-state now; a retry re-issues the
  // server fn once the streamed loader promise is spent.
  const [detailFetch, setDetailFetch] = useState<DetailFetch | null>(null)
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    let cancelled = false
    setDetailFetch(null)
    ;(attempt === 0 ? first : fetchDetail({ data: { hash } })).then((result) => {
      if (!cancelled) setDetailFetch(result)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caller-owned loader stream
  }, [first, attempt])
  const detail = detailFetch?.state === 'detail' ? detailFetch.detail : null
  const goldenResolved = useResolved(golden)
  // #2178: unavailable is rendered, not absorbed — the note cell says so
  // rather than implying the sandbox fleet is simply fine.
  const goldenUnavailable = goldenResolved?.state === 'unavailable'
  const goldenStatus: GoldenImageStatus | null = goldenResolved?.state === 'status' ? goldenResolved.status : null
  const [tab, setTab] = useState('identity')
  const [correlation, setCorrelation] = useState<Correlation | null>(null)
  const [related, setRelated] = useState<RelatedEvents | null>(null)
  // #2178: a failed lookup used to be indistinguishable from "still
  // loading" here (and, since the fns composed their own empties out of
  // failed sub-fetches, from "checked and found nothing") — an outage
  // could read as "not seen elsewhere". Named flags keep absence
  // truthful without reshaping every consumer below.
  const [corrFailed, setCorrFailed] = useState(false)
  const [relFailed, setRelFailed] = useState(false)
  const [reportBusy, setReportBusy] = useState(false)
  const [reportId, setReportId] = useState<string | null>(null)

  // hp-payload-report.js's trigger flow: disable + relabel while the one
  // synchronous generate request runs, surface progress and failure in
  // the flash line, and open the viewer on the returned id.
  const generateReport = async () => {
    if (reportBusy) return
    setReportBusy(true)
    flash('Generating PDF report…')
    try {
      const result = await generatePdfReport({ data: { hash } })
      if (!result.ok || !result.id) {
        flash(result.error || 'Report generation failed.', { error: true })
        return
      }
      flash('PDF report ready.', { duration: 1600 })
      setReportId(result.id)
    } finally {
      setReportBusy(false)
    }
  }

  const view = useMemo(() => buildStaticView(detail?.analysis ?? null), [detail])
  const yara = useMemo(() => buildYaraView(detail?.yara ?? []), [detail])

  // The correlation pass keys result stores by sha256; Dionaea captures
  // are MD5-addressed, so wait for the static-analysis doc to resolve the
  // real sha256 before querying (hp-payload-analysis.js's own re-fire-
  // with-sha256 dance, collapsed to one fetch since both arrive together).
  // #2178: a failed leg now lands in the 'failed' channel instead of
  // sitting at null forever.
  useEffect(() => {
    if (detail === null) return
    const key = view?.sha256 || hash
    let cancelled = false
    setCorrFailed(false)
    setRelFailed(false)
    fetchCorrelation({ data: { key } }).then((result) => {
      if (cancelled) return
      if (result.state === 'data') setCorrelation(result.correlation)
      else {
        setCorrFailed(true)
        setCorrelation(null)
      }
    })
    fetchRelatedEvents({ data: { hash } }).then((result) => {
      if (cancelled) return
      if (result.state === 'data') setRelated(result.related)
      else {
        setRelFailed(true)
        setRelated(null)
      }
    })
    return () => {
      cancelled = true
    }
  }, [detail, view, hash])

  // Same "no session (dev mode)" posture as settings.tsx: treat a missing
  // session as admin so local/dev runs aren't blocked, and gate on role
  // once a real session exists.
  const isAdmin = !user || user.role === 'admin'

  if (detailFetch?.state === 'missing') {
    return (
      <InvestigateHeader
        label="Evidence"
        title="Payload analysis"
        subtitle={`No analysis found for ${hash.slice(0, 24)}…`}
      />
    )
  }
  if (detailFetch?.state === 'failed') {
    return (
      <>
        <InvestigateHeader
          label="Evidence"
          title="Payload analysis"
          subtitle="The analysis could not be loaded."
        />
        <ErrorStateBlock
          title="The payload analysis failed to load"
          hint="The backend request failed — this says nothing about whether an analysis exists for this hash."
          onRetry={() => setAttempt((n) => n + 1)}
        />
      </>
    )
  }

  const inventory = detail && detail.inventory ? detail.inventory : null
  const kind = view?.classification?.label || jstr(inventory?.Kind)
  const sha256 = view?.sha256 || (hash.length === 64 ? hash : '')
  const allMatches = [...new Set([...(view?.yaraMatches ?? []), ...yara.matches])]
  const iocs = view?.iocs ?? []
  // #2178: settled data vs the failed flags — only settled data may feed
  // the "known elsewhere" verdict or the origin chip.
  const lookupFailed = corrFailed || relFailed
  const origin = related?.earliest ?? null
  const originLabel = origin ? `${origin.sensor} · ${formatTimestamp(origin.time)}` : ''
  const known = !!correlation && (correlation.sandbox_runs.length > 0 || !!correlation.github || !!correlation.ghidra || (related?.total ?? 0) > 0)

  const skeleton = (
    <>
      <span className="skeleton-line" aria-hidden="true" />
      <span className="skeleton-line" aria-hidden="true" />
    </>
  )

  return (
    <>
      <InvestigateHeader
        label="Evidence"
        title="Payload analysis"
        subtitle="Bounded static analysis — the sample is never executed."
        chips={
          detail ? (
            <>
              <Link className="chip" to="/payloads">← payloads</Link>
              <span className="chip"><code>{detail.hash.slice(0, 32)}</code></span>
              {kind ? <span className="badge badge--muted">{kind}</span> : null}
              <span className="chip">{(detail.size_bytes / 1024).toFixed(1)} KB</span>
              {/* #673: origin as a labeled disclosure, matching the
                  action-menu pattern (payloads.html:200-206). */}
              {origin ? (
                <details className="action-menu hp-pl-label-trigger">
                  <summary aria-label="Origin" title="Where this payload was captured">Origin</summary>
                  <div className="action-menu__popover hp-pl-info-popover" role="menu">
                    <div className="hp-pl-info-row">
                      <span className="k">captured by</span>
                      <span className="v">{originLabel}</span>
                    </div>
                    {origin.session ? (
                      <a className="action-menu__item" role="menuitem" href={`/sessions/${encodeURIComponent(origin.session)}`}>
                        Open capturing session →
                      </a>
                    ) : (
                      <div className="hp-pl-info-row">
                        <span className="k">session</span>
                        <span className="v">none recorded for this capture</span>
                      </div>
                    )}
                  </div>
                </details>
              ) : null}
              {/* #1140 folded every payload action into one ⋮ menu,
                  matching /payloads' card menu of the time. #1899 took that
                  menu off the cards and #1898 takes it off here: the same
                  RowActions strip, with everything resting on screen.

                  This page is about one payload, so its actions are not
                  competing for width with anything -- there is no reason to
                  make them cost a click to discover.

                  Generate PDF stays a <button> rather than a link to
                  /reports because it POSTs in place (#474); RowActions
                  draws an onClick action exactly like an href one. */}
              <RowActions
                expanded
                actions={[
                  {
                    label: 'Analysis workbench',
                    icon: RowIcons.workbench,
                    href: `/payload-workbench/results?hash=${encodeURIComponent(detail.hash)}#workbench-builder`,
                  },
                  {
                    label: 'Related events',
                    icon: RowIcons.events,
                    href: `/events?shasum=${encodeURIComponent(detail.hash)}`,
                  },
                  {
                    label: 'VirusTotal',
                    icon: RowIcons.openIn,
                    href: `https://www.virustotal.com/gui/file/${encodeURIComponent(detail.hash)}`,
                    external: true,
                  },
                  isAdmin
                    ? {
                        label: 'Download sample',
                        icon: RowIcons.download,
                        href: `/api/payload/${encodeURIComponent(detail.hash)}/download`,
                      }
                    : null,
                  isAdmin
                    ? {
                        label: reportBusy ? 'Generating PDF report…' : 'Generate PDF report',
                        icon: RowIcons.detail,
                        onClick: reportBusy ? () => {} : generateReport,
                      }
                    : null,
                ]}
              />
            </>
          ) : undefined
        }
      />
      {detail === null ? (
        <div className="card wide">{skeleton}</div>
      ) : (
        <>
          {view?.classification && !view.classification.dynamic ? (
            <p className="note">
              {view.classification.label} has no dynamic detonation path — {view.classification.analysisPath}. The
              evidence below is the whole analysis for this artifact.
            </p>
          ) : null}

          <div className="metric-grid">
            <div className="metric">
              <div className="metric__value">
                {view?.riskScore !== null && view?.riskScore !== undefined ? `${view.riskScore} / 100 • ${view.riskLevel}` : '—'}
              </div>
              <div className="metric__label">Static risk</div>
            </div>
            <div className="metric">
              <div className="metric__value metric__value--text">
                {view?.packedLikely === null || view === null ? '—' : view.packedLikely ? 'elevated' : 'not indicated'}
              </div>
              <div className="metric__label">Packing likelihood</div>
            </div>
            <div className="metric">
              <div className="metric__value">{view ? iocs.length : '—'}</div>
              <div className="metric__label">Extracted IOCs</div>
            </div>
          </div>

          <PageTabs
            tabs={[
              { id: 'identity', label: 'Identity' },
              { id: 'findings', label: 'Findings' },
              { id: 'content', label: 'Content' },
            ]}
            active={tab}
            onSelect={setTab}
            label="Payload analysis views"
          />

          <div
            className="dashboard-panel"
            id="pl-panel-identity"
            role="tabpanel"
            aria-labelledby="pl-tab-identity"
            hidden={tab !== 'identity'}
          >
            <div className="section-heading">
              <div>
                <h2>What this file is</h2>
                <p>Type, hashes, and whether it has been detonated in the isolated sandbox.</p>
              </div>
            </div>
            <div className="card wide">
              <h2>Identity and selected analysis path</h2>
              {view ? (
                <>
                  {view.classification ? (
                    <>
                      <div className="card__row">
                        <span className="card__label">identified type</span>
                        <span className="card__value">
                          <strong>{view.classification.label}</strong>{' '}
                          <span className="badge badge--muted">{view.classification.code}</span>
                        </span>
                      </div>
                      <div className="card__row">
                        <span className="card__label">platform / category</span>
                        <span className="card__value card__value--mono">
                          {view.classification.platform} / {view.classification.category}
                        </span>
                      </div>
                      <div className="card__row">
                        <span className="card__label">sandbox route</span>
                        <span className="card__value card__value--mono">{view.classification.analysisPath}</span>
                      </div>
                      <div className="card__row">
                        <span className="card__label">dynamic execution</span>
                        <span className="card__value">
                          {view.classification.dynamic ? 'supported for this type' : 'not automatic; static analysis only'}
                        </span>
                      </div>
                    </>
                  ) : null}
                  <div className="card__row">
                    <span className="card__label">magic</span>
                    <span className="card__value">{view.magic || '—'}</span>
                  </div>
                  <div className="card__row">
                    <span className="card__label">MIME</span>
                    <span className="card__value card__value--mono">{view.mime || jstr(inventory?.MIME) || '—'}</span>
                  </div>
                  <div className="card__row">
                    <span className="card__label">size</span>
                    <span className="card__value card__value--mono">{view.size || jstr(inventory?.SizeH) || '—'}</span>
                  </div>
                  <div className="card__row">
                    <span className="card__label">entropy</span>
                    <span className="card__value card__value--mono">{view.entropy || '—'}</span>
                  </div>
                  <div className="card__row">
                    <span className="card__label">SHA-256</span>
                    <span className="card__value card__value--mono">{view.sha256 || '—'}</span>
                  </div>
                  <div className="card__row">
                    <span className="card__label">SHA-1</span>
                    <span className="card__value card__value--mono">{view.sha1 || '—'}</span>
                  </div>
                  <div className="card__row">
                    <span className="card__label">MD5</span>
                    <span className="card__value card__value--mono">{view.md5 || '—'}</span>
                  </div>
                  {view.truncated ? (
                    <p className="note">deep inspection capped at 16 MiB; hashes cover the complete file</p>
                  ) : null}
                </>
              ) : inventory ? (
                <>
                  <div className="card__row">
                    <span className="card__label">identified type</span>
                    <span className="card__value">
                      <strong>{jstr(inventory.Kind) || 'unknown'}</strong>
                    </span>
                  </div>
                  <div className="card__row">
                    <span className="card__label">platform</span>
                    <span className="card__value card__value--mono">{jstr(inventory.Platform) || '—'}</span>
                  </div>
                  <div className="card__row">
                    <span className="card__label">sandbox route</span>
                    <span className="card__value card__value--mono">{jstr(inventory.AnalysisPath) || '—'}</span>
                  </div>
                  <div className="card__row">
                    <span className="card__label">MIME</span>
                    <span className="card__value card__value--mono">{jstr(inventory.MIME) || '—'}</span>
                  </div>
                  <div className="card__row">
                    <span className="card__label">size</span>
                    <span className="card__value card__value--mono">{jstr(inventory.SizeH) || '—'}</span>
                  </div>
                  <p className="note">No static-analysis record for this hash yet — inventory metadata only.</p>
                </>
              ) : (
                <p className="empty">No static-analysis record for this hash yet.</p>
              )}
            </div>
            {view && (view.scriptType || view.indicators.length > 0) ? (
              <div className="card half">
                <h2>Script classification</h2>
                {view.scriptType ? (
                  <div className="card__row">
                    <span className="card__label">language/type</span>
                    <span className="card__value card__value--mono">{view.scriptType}</span>
                  </div>
                ) : null}
                {view.indicators.length > 0 ? (
                  <div className="card__row">
                    <span className="card__label">behavior indicators</span>
                    <span className="card__value">
                      {view.indicators.map((indicator) => (
                        <span key={indicator} className="chip">
                          {indicator}
                        </span>
                      ))}
                    </span>
                  </div>
                ) : null}
                <p className="note">Heuristic static findings only. Captured content is never interpreted or executed.</p>
              </div>
            ) : null}
            <div className="card half">
              <h2>Isolated dynamic analysis</h2>
              {correlation === null ? (
                skeleton
              ) : correlation.sandbox_runs.length === 0 ? (
                <p className="empty">
                  No completed KVM sandbox run for this payload. Queue one from the{' '}
                  <a className="btn btn-ghost btn-sm" href={`/payload-workbench/results?hash=${encodeURIComponent(detail.hash)}#workbench-builder`}>
                    analysis workbench
                  </a>
                  .
                </p>
              ) : (
                <div className="card__scroll">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>completed</th>
                        <th>exit</th>
                        <th>changed paths</th>
                        <th>details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {correlation.sandbox_runs.map((run) => (
                        <tr key={run.job}>
                          <td>{formatTimestamp(run.completed_at)}</td>
                          <td className="n">{run.exit_status}</td>
                          <td className="n">{run.changed}</td>
                          <td>
                            <a className="btn btn-ghost btn-sm" href={`/sandbox/${encodeURIComponent(run.job)}`}>
                              sandbox report →
                            </a>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
            <div className="card half">
              <h2>GitHub analysis</h2>
              {correlation === null ? (
                skeleton
              ) : correlation.github === null ? (
                <p className="empty">
                  Not published to Xore/honeypot. Use <strong>Publish to Xore/honeypot</strong> below to queue one.
                </p>
              ) : (
                <>
                  <div className="card__row">
                    <span className="card__label">exit status</span>
                    <span className="card__value card__value--mono">{correlation.github.exit_status || '—'}</span>
                  </div>
                  {correlation.github.total !== null ? (
                    <div className="card__row">
                      <span className="card__label">detections</span>
                      <span className="card__value card__value--mono">
                        {correlation.github.malicious ?? 0} / {correlation.github.total} • {correlation.github.level}
                      </span>
                    </div>
                  ) : null}
                  {correlation.github.family ? (
                    <div className="card__row">
                      <span className="card__label">family</span>
                      <span className="card__value">
                        <a
                          className="lnk"
                          href={`/events?q=${encodeURIComponent(correlation.github.family)}`}
                          title="Other sessions that delivered this family"
                        >
                          {correlation.github.family}
                        </a>
                      </span>
                    </div>
                  ) : null}
                  <a className="btn btn-ghost btn-sm" href={`/github-analysis/${encodeURIComponent(correlation.github.sha256)}`}>
                    full result →
                  </a>
                </>
              )}
            </div>
            <div className="card wide">
              <h2>
                Known elsewhere{' '}
                {lookupFailed ? (
                  // #2178: an outage must not wear the "not seen
                  // elsewhere" verdict it never checked for.
                  <span className="badge badge--danger">lookup failed</span>
                ) : correlation !== null && related !== null ? (
                  known ? (
                    <span className="badge badge--green">already analyzed</span>
                  ) : (
                    <span className="badge badge--muted">not seen elsewhere</span>
                  )
                ) : null}
              </h2>
              <p className="note">
                Advisory only — checked before queueing a new run so you know if this hash was already analyzed. Never
                blocks a fresh submission.
              </p>
              {lookupFailed ? (
                <p className="note text-danger" role="alert">
                  The cross-store lookup failed this load — rows shown here say nothing about stores that were never
                  reached.{' '}
                  <button type="button" className="lnk" onClick={() => setAttempt((n) => n + 1)}>
                    Retry
                  </button>
                </p>
              ) : correlation === null || related === null ? (
                skeleton
              ) : (
                <>
                  <div className="card__row">
                    <span className="card__label">Ghidra</span>
                    <span className="card__value">
                      {correlation.ghidra ? (
                        <>
                          <span className="badge badge--muted">{correlation.ghidra.exit_status}</span>
                          {correlation.ghidra.completed_at ? ` completed ${formatTimestamp(correlation.ghidra.completed_at)} — ` : ' — '}
                          <a className="btn btn-ghost btn-sm" href={`/ghidra/${encodeURIComponent(sha256 || detail.hash)}`}>
                            full result →
                          </a>
                        </>
                      ) : (
                        <>
                          <span className="empty">not yet analyzed</span> —{' '}
                          <a className="btn btn-secondary btn-sm" href={`/payload-workbench/results?hash=${encodeURIComponent(detail.hash)}#workbench-builder`}>
                            queue Ghidra →
                          </a>
                        </>
                      )}
                    </span>
                  </div>
                  <div className="card__row">
                    <span className="card__label">Elasticsearch sightings</span>
                    <span className="card__value">
                      {related.total} event(s)
                      {related.earliest ? `, first seen ${formatTimestamp(related.earliest.time)}` : ''} —{' '}
                      <a className="btn btn-ghost btn-sm" href={`/events?shasum=${encodeURIComponent(detail.hash)}`}>
                        related events →
                      </a>
                    </span>
                  </div>
                </>
              )}
            </div>
          </div>

          <div
            className="dashboard-panel"
            id="pl-panel-findings"
            role="tabpanel"
            aria-labelledby="pl-tab-findings"
            hidden={tab !== 'findings'}
          >
            <div className="section-heading">
              <div>
                <h2>What the scanners found</h2>
                <p>YARA matches, built-in heuristics, and the indicators worth pivoting on.</p>
              </div>
            </div>
            <div className="card wide">
              <h2>YARA static scan</h2>
              {allMatches.length > 0 ? (
                <div className="card__scroll">
                  <table className="data-table">
                    <tbody>
                      {allMatches.map((match) => (
                        <tr key={match}>
                          <td>
                            <span className="badge badge--red">match</span>
                          </td>
                          <td className="v">{match}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="empty">{yara.scanned ? 'No YARA rules matched this sample.' : 'Waiting for the isolated YARA scanner.'}</p>
              )}
              {yara.error ? <p className="note text-danger">{yara.error}</p> : null}
              {yara.scanned ? (
                <p className="note">
                  Scanned {formatTimestamp(yara.scanned)} by the networkless YARA sidecar. A match is a triage signal, not
                  attribution.
                </p>
              ) : null}
            </div>
            <div className="card half">
              <h2>Rule matches</h2>
              {view && view.rules.length > 0 ? (
                <div className="card__scroll">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>severity</th>
                        <th>rule</th>
                        <th>reason</th>
                      </tr>
                    </thead>
                    <tbody>
                      {view.rules.map((rule) => (
                        <tr key={rule.name}>
                          <td>
                            <span className="badge badge--muted">{rule.severity}</span>
                          </td>
                          <td className="v">{rule.name}</td>
                          <td className="v">{rule.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="empty">No built-in static rules matched.</p>
              )}
              <p className="note">Deterministic YARA-style heuristics; no sample execution or attribution.</p>
            </div>
            <div className="card half">
              <h2>Extracted indicators</h2>
              {iocs.length > 0 ? (
                <div className="card__scroll">
                  <table className="data-table">
                    <tbody>
                      {iocs.map((ioc) => (
                        <tr key={ioc}>
                          <td className="v">
                            <a href={`/search?q=${encodeURIComponent(ioc)}`} title="search telemetry for this indicator">
                              {ioc}
                            </a>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="empty">No URL, domain, or IP indicators found.</p>
              )}
            </div>
          </div>

          <div
            className="dashboard-panel"
            id="pl-panel-content"
            role="tabpanel"
            aria-labelledby="pl-tab-content"
            hidden={tab !== 'content'}
          >
            <div className="section-heading">
              <div>
                <h2>What is inside the file</h2>
                <p>Raw bytes, metadata, and extracted text are visible below in bounded, searchable regions.</p>
              </div>
            </div>
            <div className="card wide">
              <h2>Bytes and metadata</h2>
              <p className="note">The sample is read, never interpreted or executed.</p>
              <h3>Hex / ASCII preview — first 512 bytes</h3>
              <pre className="code hp-code-results">
                {view?.hexdump || detail.hex_preview.join('\n') || 'No byte preview is available.'}
              </pre>
              <h3>Executable metadata</h3>
              {view && view.formatInfo.length > 0 ? (
                <pre className="code hp-code-results">{view.formatInfo.join('\n')}</pre>
              ) : (
                <p className="empty">Not a recognized PE or ELF file.</p>
              )}
              {view?.truncated ? (
                <p className="note">Deep inspection is capped at 16 MiB; hashes cover the complete file.</p>
              ) : null}
            </div>
            <div className="card half">
              <h2>Extracted text</h2>
              <SearchablePane
                entries={[
                  ...(view?.ascii ?? []).map((value) => ({ label: 'ASCII', value })),
                  ...(view?.utf16 ?? []).map((value) => ({ label: 'UTF-16LE', value })),
                ]}
                empty="No printable sequences extracted."
                placeholder="Filter printable strings"
                itemLabel="sequence"
                note="bounded static extraction; sample content is never executed"
              />
            </div>
            <div className="card half">
              <h2>Decoded candidates</h2>
              <SearchablePane
                entries={(view?.decoded ?? []).map((item) => ({
                  label: item.kind || 'decoded',
                  value: `source: ${item.source || 'unknown'}\n${item.preview}`,
                }))}
                empty="No bounded Base64, hex, URL or UTF-16 candidates found."
                placeholder="Filter decoded candidates"
                itemLabel="candidate"
                note="bounded decodes only; recovered content is never executed"
              />
            </div>
          </div>

          <OperatorActionsCard hash={detail.hash} golden={goldenStatus} goldenUnavailable={goldenUnavailable} editable={isAdmin} />
          <ExternalPublicationCard hash={detail.hash} editable={isAdmin} />
        </>
      )}
      {reportId ? <PayloadReportViewer id={reportId} onClose={() => setReportId(null)} /> : null}
    </>
  )
}
