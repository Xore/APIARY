// Analysis results — every analyzer's output over the captured payloads:
// workbench runs, static analysis, YARA matches, sandbox detonations,
// Ghidra decompilations. Each analyzer keeps its own table; rows open
// the full result document in the inspector.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { confirmAction } from '../components/ConfirmDialog'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { ArtifactList } from '../components/ArtifactList'
import { CodeIcon, FileIcon, SandboxIcon, ShieldIcon, WorkbenchIcon } from '../components/CardIcons'
import { getSessionUser } from '../lib/auth'
import { pathString, type JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'
import { useSidebarViewTabs } from '../lib/viewTabs'

type StoreRow = JsonRecord
type Page = { total: number; rows: StoreRow[] }

// Workbench builder types — mirror backend-service/src/workbench_domain.rs's
// WorkbenchOptions/WorkbenchSelection/WorkbenchAnalyzer/WorkbenchChild/
// WorkbenchRun/WorkbenchRecipe JSON shapes exactly (including the analyzer's
// serde renames: concurrency -> concurrency_class, externally_sends ->
// externally_publishing, gpu -> gpu_consuming).
type WorkbenchOptions = { timeout_seconds: number; max_queue_age_seconds: number; retry_limit: number }
type WorkbenchSelection = { analyzer_id: string; options: WorkbenchOptions }
type WorkbenchOptionSchema = {
  timeout_min_seconds: number
  timeout_max_seconds: number
  queue_age_min_seconds: number
  queue_age_max_seconds: number
  retry_limit_max: number
}
type Classification = { code: string; label: string; platform: string; category: string; analysis_path: string; dynamic: boolean }
type WorkbenchAnalyzer = {
  id: string
  display_name: string
  description: string
  accepted_kinds: string[]
  availability: string
  available: boolean
  applicable: boolean
  reason: string
  required_role: string
  confirmation: string
  local_only: boolean
  detonates: boolean
  gpu_consuming: boolean
  requires_opt_in: boolean
  default_options: WorkbenchOptions
  option_schema: WorkbenchOptionSchema
}
type AnalyzersResponse = { classification: Classification; analyzers: WorkbenchAnalyzer[] }
type WorkbenchChild = {
  analyzer_id: string
  display_name: string
  state: string
  reason: string
  summary: string
  result_url: string
  created_at: string
  updated_at: string
  attempts: number
  retryable: boolean
  cancelable: boolean
}
type WorkbenchRun = {
  id: string
  payload_sha256: string
  payload_kind: string
  owner: string
  recipe_id: string
  recipe_name: string
  state: string
  created_at: string
  updated_at: string
  children: WorkbenchChild[]
}
type WorkbenchRecipe = {
  id: string
  revision: number
  name: string
  description: string
  owner: string
  scope: string
  created_at: string
  analyzers: WorkbenchSelection[]
}
type RunResult = { ok: boolean; run?: WorkbenchRun; reused?: boolean; error?: string }

// One explicit server fn per store — the createServerFn compiler can't
// extract functions built inside a factory, so the factory form leaks
// the server import into the client graph.
const fetchWorkbench = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<Page | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/store/workbench-runs?offset=${data.offset}&size=25`)
  })

const fetchStatic = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<Page | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/store/static-analysis?offset=${data.offset}&size=25`)
  })

const fetchYara = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<Page | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/store/yara?offset=${data.offset}&size=25`)
  })

const fetchSandbox = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<Page | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/store/sandbox-runs?offset=${data.offset}&size=25`)
  })

const fetchGhidra = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<Page | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/store/ghidra-runs?offset=${data.offset}&size=25`)
  })

// Payload workbench builder — the missing "create a run" half the legacy
// dashboard/ui/payload_workbench.html covered. Catalog is a plain hash-scoped
// GET (no ownership); recipes/runs/mutations are always scoped to the signed-
// in operator's own username, derived server-side from getSessionUser() —
// never accepted as client input, so one operator can't read or cancel
// another's runs by editing the request.
const fetchAnalyzerCatalog = createServerFn({ method: 'GET' })
  .inputValidator((input: { hash: string }) => input)
  .handler(async ({ data }): Promise<AnalyzersResponse | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<AnalyzersResponse>(`/api/v1/workbench/analyzers?hash=${encodeURIComponent(data.hash)}`, { mounted: true })
  })

const fetchRecipes = createServerFn({ method: 'GET' }).handler(async (): Promise<{ recipes: WorkbenchRecipe[] } | null> => {
  const { getSessionUser } = await import('../lib/auth')
  const user = await getSessionUser()
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<{ recipes: WorkbenchRecipe[] }>(`/api/v1/workbench/recipes?owner=${encodeURIComponent(user?.username ?? '')}`, {
    mounted: true,
  })
})

const fetchOwnRuns = createServerFn({ method: 'GET' }).handler(async (): Promise<{ runs: WorkbenchRun[] } | null> => {
  const { getSessionUser } = await import('../lib/auth')
  const user = await getSessionUser()
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<{ runs: WorkbenchRun[] }>(`/api/v1/workbench/runs?owner=${encodeURIComponent(user?.username ?? '')}&limit=25`, {
    mounted: true,
  })
})

// Bypasses serviceJSON's short-TTL cache on purpose — a status refresh right
// after cancel/retry (or a manual "Refresh status" click) needs the live
// reconciled state, not a 15s-old copy.
const refreshRunFn = createServerFn({ method: 'GET' })
  .inputValidator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<RunResult> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(
      `/api/v1/workbench/runs/${encodeURIComponent(data.id)}?owner=${encodeURIComponent(user?.username ?? '')}`,
      undefined,
      { mounted: true },
    )
    if (!response.ok) return { ok: false, error: await response.text() }
    const body = (await response.json()) as { run: WorkbenchRun }
    return { ok: true, run: body.run }
  })

// Every mutation below is admin-gated at the BFF, same posture as
// reports.tsx's definition CRUD and settings.tsx's savePresentation —
// workbench_api.rs itself has no role check, so this is the only gate.
const submitRun = createServerFn({ method: 'POST' })
  .inputValidator((input: { payload_sha256: string; recipe_name: string; analyzers: WorkbenchSelection[] }) => input)
  .handler(async ({ data }): Promise<RunResult> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(
      '/api/v1/workbench/runs',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          payload_sha256: data.payload_sha256,
          owner: user?.username ?? '',
          recipe_name: data.recipe_name,
          analyzers: data.analyzers,
        }),
      },
      { mounted: true },
    )
    if (!response.ok) return { ok: false, error: await response.text() }
    const body = (await response.json()) as { run: WorkbenchRun; reused: boolean }
    return { ok: true, run: body.run, reused: body.reused }
  })

const saveRecipeFn = createServerFn({ method: 'POST' })
  .inputValidator(
    (input: { id: string; name: string; description: string; scope: string; analyzers: WorkbenchSelection[]; base_revision: number }) =>
      input,
  )
  .handler(async ({ data }): Promise<{ ok: boolean; recipe?: WorkbenchRecipe; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(
      '/api/v1/workbench/recipes',
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...data, owner: user?.username ?? '' }) },
      { mounted: true },
    )
    if (!response.ok) return { ok: false, error: await response.text() }
    const body = (await response.json()) as { recipe: WorkbenchRecipe }
    return { ok: true, recipe: body.recipe }
  })

const childActionFn = createServerFn({ method: 'POST' })
  .inputValidator((input: { runId: string; analyzerId: string; action: 'cancel' | 'retry' }) => input)
  .handler(async ({ data }): Promise<RunResult> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(
      `/api/v1/workbench/runs/${encodeURIComponent(data.runId)}/children/${encodeURIComponent(data.analyzerId)}/${encodeURIComponent(data.action)}`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ owner: user?.username ?? '' }),
      },
      { mounted: true },
    )
    if (!response.ok) return { ok: false, error: await response.text() }
    const body = (await response.json()) as { run: WorkbenchRun }
    return { ok: true, run: body.run }
  })

// No validateSearch here on purpose: TanStack Router 307-redirects a bare
// hit to the canonical "?hash=" URL once a route declares search defaults
// (search.tsx's /search has the same behavior) — fine for a route nobody
// hits bare, but this one is smoke-tested bare by port-tests/frontend-ssr.sh.
// The "?hash=" prefill from payloads.tsx's Analyze link is instead read
// client-side after mount (see WorkbenchBuilder below), which needs no
// router-level search schema at all.

// GPU job queue (#1611 workstream E.6) — ported from dashboard/gpu_queue.go,
// which rendered this same card on the legacy /ghidra page (now redirected
// here). The legacy abort action (ghidra.html:44's confirm-gated
// POST /gpu-queue/abort) is restored in #1692.
type GpuJob = {
  job_id: string
  job_type: string
  ref: string
  model: string
  estimated_vram_mib: number
  status: string
  requested_at: string
  started_at: string
  finished_at: string
  abort_requested: boolean
  error: string
  attempts: number
}

const fetchGpuQueue = createServerFn({ method: 'GET' }).handler(async (): Promise<GpuJob[] | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<GpuJob[]>('/api/v1/gpu-queue')
})

// #1692: restores ghidra.html:44's abort. Admin-gated like every other
// operator write on this page. Sets the queue document's `abort_requested`,
// which is only consulted while a job is still `queued` — the drainer checks
// it once before committing to the Ollama call
// (analysis/ghidra/worker/gpu-queue-drain.py:53). Cancelling an in-flight
// generation is a separate, worker-side problem by the contract at
// analysis/gpu-queue/gpu_queue.py:51.
const abortGpuJob = createServerFn({ method: 'POST' })
  .inputValidator((input: { job_id: string }) => input)
  .handler(async ({ data }): Promise<{ ok: boolean; error?: string }> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (user && user.role !== 'admin') return { ok: false, error: 'Admin role required.' }
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(
      `/api/v1/gpu-queue/${encodeURIComponent(data.job_id)}/abort`,
      { method: 'POST' },
      { mounted: true },
    )
    if (!response.ok) return { ok: false, error: await response.text() }
    return { ok: true }
  })

// "Approved local-model health" (payload_workbench.html:89 +
// hp-workbench.js's renderModel), advisory only. The legacy model-status
// adapter has no Rust equivalent; ml_health.rs's per-model retrain history
// is the surface that replaced it, so the card renders that instead:
// latest retrain outcome per approved local model.
type ModelHealth = {
  model: string
  timestamp: string
  accepted: boolean
  reason: string
  anomaly_rate_new: number
  anomaly_rate_previous: number
  train_samples: number
}

const fetchModelHealth = createServerFn({ method: 'GET' }).handler(async (): Promise<ModelHealth[] | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<ModelHealth[]>('/api/v1/ml-health')
})

export const Route = createFileRoute('/payload-workbench/results')({
  loader: async () => ({
    workbench: fetchWorkbench({ data: { offset: 0 } }),
    statics: fetchStatic({ data: { offset: 0 } }),
    yara: fetchYara({ data: { offset: 0 } }),
    sandbox: fetchSandbox({ data: { offset: 0 } }),
    ghidra: fetchGhidra({ data: { offset: 0 } }),
    gpuQueue: fetchGpuQueue(),
    user: await getSessionUser(),
  }),
  component: Results,
})

const when = (iso: string) => formatTimestamp(iso)

const recordColumn: Column<StoreRow> = {
  header: 'result',
  detail: true,
  render: (row) => <pre className="hp-md__preview">{JSON.stringify(row, null, 2)}</pre>,
}

// The legacy result cards (ui/payload_workbench.html, ui/sandbox.html,
// ui/ghidra.html) each carried an icon, a badge row and a one-line
// description alongside the title. Those three slots are restored here;
// the columns they duplicate are marked detail-only so a card does not
// print the same value twice.
function childCount(row: StoreRow): number {
  const children = row.children
  return Array.isArray(children) ? children.length : 0
}

const WORKBENCH_COLUMNS: Column<StoreRow>[] = [
  {
    header: 'recipe',
    className: 'v',
    primary: true,
    render: (row) => pathString(row, 'recipe_name') || <span className="text-muted">one-off</span>,
  },
  { header: 'state', detail: true, render: (row) => <span className="badge badge--muted">{pathString(row, 'state')}</span> },
  { header: 'payload', className: 'v', render: (row) => <span className="mono">{pathString(row, 'payload_sha256').slice(0, 16)}</span> },
  { header: 'created', render: (row) => when(pathString(row, 'created_at')) },
  { header: 'owner', render: (row) => pathString(row, 'owner') },
  recordColumn,
]

const STATIC_COLUMNS: Column<StoreRow>[] = [
  {
    header: 'fingerprint',
    className: 'v',
    primary: true,
    render: (row) => <span className="mono">{pathString(row, 'Fingerprint').slice(0, 24)}</span>,
  },
  { header: 'kind', detail: true, render: (row) => pathString(row, 'Analysis', 'Kind') },
  { header: 'summary', detail: true, className: 'v', render: (row) => pathString(row, 'Analysis', 'Summary') },
  recordColumn,
]

const YARA_COLUMNS: Column<StoreRow>[] = [
  {
    header: 'file',
    className: 'v',
    primary: true,
    render: (row) => <span className="mono">{pathString(row, 'file', 'hash', 'sha256').slice(0, 16) || pathString(row, 'file', 'name')}</span>,
  },
  { header: 'matches', className: 'v', render: (row) => pathString(row, 'yara', 'match_count') || (Array.isArray((row.yara as StoreRow | undefined)?.matches) ? String(((row.yara as StoreRow).matches as unknown[]).length) : '') },
  { header: 'analyzed', render: (row) => when(pathString(row, '@timestamp')) },
  recordColumn,
]

function sandboxJob(row: StoreRow): string {
  return pathString(row, 'sandbox', 'job') || pathString(row, 'job')
}

const SANDBOX_COLUMNS: Column<StoreRow>[] = [
  {
    header: 'job',
    className: 'v',
    render: (row) => {
      const job = sandboxJob(row)
      return job ? <span className="mono">{job.slice(0, 28)}</span> : <span className="text-muted">no job id</span>
    },
  },
  { header: 'detonated', render: (row) => when(pathString(row, '@timestamp')) },
  { header: 'platform', detail: true, render: (row) => <span className="badge badge--muted">{pathString(row, 'platform')}</span> },
  {
    header: 'risk',
    render: (row) => {
      const level = pathString(row, 'risk_level')
      const cls = level === 'high' || level === 'critical' ? 'badge badge--danger' : level === 'medium' ? 'badge badge--warning' : 'badge badge--muted'
      return <span className={cls}>{level} {pathString(row, 'risk_score')}</span>
    },
  },
  {
    header: 'file',
    className: 'v',
    primary: true,
    render: (row) => <code>{pathString(row, 'file', 'hash', 'sha256').slice(0, 16) || pathString(row, 'file', 'name')}</code>,
  },
  { header: 'exit', detail: true, render: (row) => pathString(row, 'exit_status') },
  recordColumn,
]

const GHIDRA_COLUMNS: Column<StoreRow>[] = [
  { header: 'analyzed', render: (row) => when(pathString(row, '@timestamp')) },
  {
    header: 'file',
    className: 'v',
    primary: true,
    render: (row) => {
      const sha = pathString(row, 'file', 'hash', 'sha256')
      return sha ? (
        <code>{sha.slice(0, 16)}</code>
      ) : (
        <code>{pathString(row, 'file', 'name')}</code>
      )
    },
  },
  { header: 'exit', detail: true, render: (row) => pathString(row, 'exit_status') },
  recordColumn,
]

const HASH_RE = /^[0-9a-fA-F]{32,64}$/

function stateBadgeClass(state: string): string {
  switch (state) {
    case 'completed':
      return 'badge badge--success'
    case 'failed':
    case 'timed_out':
      return 'badge badge--danger'
    case 'partial':
    case 'running':
    case 'queued':
    case 'claimed':
      return 'badge badge--warning'
    default:
      return 'badge badge--muted'
  }
}

function analyzerBadgeClass(analyzer: WorkbenchAnalyzer): string {
  if (!analyzer.applicable) return 'badge badge--muted'
  return analyzer.availability === 'configured' ? 'badge badge--success' : 'badge badge--warning'
}

// Per-run child status + cancel/retry — driven entirely by the server-
// computed cancelable/retryable flags on each child (workbench_domain.rs's
// state machine), never re-derived here, so a still-running or already-
// terminal child never shows an action it can't take.
function RunDetail({ run, currentOwner, onChanged }: { run: WorkbenchRun; currentOwner: string; onChanged: (run: WorkbenchRun) => void }) {
  const [busyChild, setBusyChild] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [message, setMessage] = useState('')
  const canMutate = Boolean(currentOwner) && run.owner === currentOwner

  const act = async (analyzerId: string, action: 'cancel' | 'retry') => {
    setBusyChild(analyzerId)
    setMessage('')
    try {
      const result = await childActionFn({ data: { runId: run.id, analyzerId, action } })
      if (result.ok && result.run) onChanged(result.run)
      else setMessage(result.error || `${action} failed.`)
    } finally {
      setBusyChild(null)
    }
  }

  const refresh = async () => {
    setRefreshing(true)
    setMessage('')
    try {
      const result = await refreshRunFn({ data: { id: run.id } })
      if (result.ok && result.run) onChanged(result.run)
      else setMessage(result.error || 'Refresh failed.')
    } finally {
      setRefreshing(false)
    }
  }

  return (
    <div>
      <div className="filters hp-flow--tight">
        <span className={stateBadgeClass(run.state)}>{run.state}</span>
        <span className="chip">recipe: {run.recipe_name || run.recipe_id || 'one-off'}</span>
        <code>{run.payload_sha256}</code>
        <button className="btn btn-secondary btn-sm" type="button" onClick={refresh} disabled={refreshing}>
          {refreshing ? 'Refreshing…' : 'Refresh status'}
        </button>
      </div>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>Analyzer</th>
              <th>State</th>
              <th>Reason / summary</th>
              <th>Attempts</th>
              {canMutate ? <th>Actions</th> : null}
            </tr>
          </thead>
          <tbody>
            {run.children.map((child) => (
              <tr key={child.analyzer_id}>
                <td className="v">{child.display_name || child.analyzer_id}</td>
                <td>
                  <span className={stateBadgeClass(child.state)}>{child.state}</span>
                </td>
                <td>{child.summary || child.reason || '—'}</td>
                <td className="n">{child.attempts}</td>
                {canMutate ? (
                  <td>
                    <div className="filters">
                      <button
                        className="btn btn-secondary btn-sm"
                        type="button"
                        disabled={!child.cancelable || busyChild === child.analyzer_id}
                        onClick={() => act(child.analyzer_id, 'cancel')}
                      >
                        Cancel
                      </button>
                      <button
                        className="btn btn-secondary btn-sm"
                        type="button"
                        disabled={!child.retryable || busyChild === child.analyzer_id}
                        onClick={() => act(child.analyzer_id, 'retry')}
                      >
                        Retry
                      </button>
                    </div>
                  </td>
                ) : null}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {message ? <p className="note">{message}</p> : null}
    </div>
  )
}

function RecentRunsCard({ owner, refreshToken }: { owner: string; refreshToken: number }) {
  const [runs, setRuns] = useState<WorkbenchRun[] | null>(null)
  const [selected, setSelected] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    fetchOwnRuns().then((result) => {
      if (!cancelled) setRuns(result?.runs ?? [])
    })
    return () => {
      cancelled = true
    }
    // refreshToken bumps after every submit/save so this list stays current.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refreshToken])

  const updateRun = (updated: WorkbenchRun) => {
    setRuns((current) => (current ?? []).map((run) => (run.id === updated.id ? updated : run)))
  }

  return (
    <div className="card wide">
      <h2>My recent runs</h2>
      {runs === null ? (
        <span className="skeleton-line" aria-hidden="true" />
      ) : runs.length === 0 ? (
        <p className="empty">No workbench runs submitted yet.</p>
      ) : (
        <>
          <div className="project-grid" id="workbench-results-list">
            {runs.map((run) => (
              <div key={run.id} className="project-card" onClick={() => setSelected(selected === run.id ? null : run.id)}>
                <div className="project-card__header">
                  <span className="project-card__title">{run.recipe_name || run.recipe_id || 'one-off'}</span>
                  <div className="project-card__badges">
                    <span className={stateBadgeClass(run.state)}>{run.state}</span>
                  </div>
                </div>
                <div className="project-card__meta">
                  <span>{formatTimestamp(run.created_at)}</span>
                  <span className="mono">{run.payload_sha256.slice(0, 16)}</span>
                </div>
              </div>
            ))}
          </div>
          {(() => {
            const run = runs.find((candidate) => candidate.id === selected)
            return run ? (
              <div className="card wide hp-flow--tight">
                <RunDetail run={run} currentOwner={owner} onChanged={updateRun} />
              </div>
            ) : null
          })()}
        </>
      )}
    </div>
  )
}

function ModelHealthCard() {
  const [models, setModels] = useState<ModelHealth[] | null | 'unavailable'>(null)

  useEffect(() => {
    let cancelled = false
    fetchModelHealth().then((result) => {
      if (!cancelled) setModels(result ?? 'unavailable')
    })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div className="card wide">
      <div className="filters">
        <h2 className="hp-push-end">Approved local-model health</h2>
        <span className="badge badge--muted">advisory only</span>
      </div>
      {models === null ? (
        <span className="skeleton-line" aria-hidden="true" />
      ) : models === 'unavailable' || models.length === 0 ? (
        <p className="note">
          {models === 'unavailable' ? 'Model-status adapter is unavailable' : 'No retrain history recorded yet'}. Drift or unavailability
          never disables deterministic analysis.
        </p>
      ) : (
        <>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Last retrain</th>
                  <th>Outcome</th>
                  <th>Anomaly rate</th>
                  <th>Samples</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {models.map((model) => (
                  <tr key={model.model}>
                    <td className="v">{model.model}</td>
                    <td>{model.timestamp ? formatTimestamp(model.timestamp) : '—'}</td>
                    <td>
                      <span className={model.accepted ? 'badge badge--success' : 'badge badge--danger'}>
                        {model.accepted ? 'accepted' : 'rejected'}
                      </span>
                    </td>
                    <td className="n">
                      {(model.anomaly_rate_previous * 100).toFixed(2)}% → {(model.anomaly_rate_new * 100).toFixed(2)}%
                    </td>
                    <td className="n">{model.train_samples.toLocaleString('en-US')}</td>
                    <td className="v">{model.reason || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="note">
            Latest retrain decision per approved local model, through the read-only ml-health surface. Drift or unavailability never
            disables deterministic analysis.
          </p>
        </>
      )}
    </div>
  )
}

function WorkbenchBuilder({ owner, onRunCreated }: { owner: string; onRunCreated: (run: WorkbenchRun) => void }) {
  const [hash, setHash] = useState('')
  const [catalog, setCatalog] = useState<AnalyzersResponse | null>(null)
  const [catalogError, setCatalogError] = useState('')
  const [loadingCatalog, setLoadingCatalog] = useState(false)
  const [selected, setSelected] = useState<string[]>([])
  // Per-analyzer orchestration options (hp-workbench.js:99-129), seeded
  // from the catalog's server-computed defaults and clamped to its schema
  // at submit — all-zeros is the backend's "use defaults" sentinel, so an
  // analyzer with no edited options still round-trips correctly.
  const [options, setOptions] = useState<Record<string, WorkbenchOptions>>({})
  const [confirmed, setConfirmed] = useState(false)
  const [recipeName, setRecipeName] = useState('')
  const [recipes, setRecipes] = useState<WorkbenchRecipe[] | null>(null)
  const [pickedRecipeId, setPickedRecipeId] = useState('')
  const [saveAsRecipe, setSaveAsRecipe] = useState(false)
  const [recipeDescription, setRecipeDescription] = useState('')
  const [recipeScope, setRecipeScope] = useState('private')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [lastRun, setLastRun] = useState<WorkbenchRun | null>(null)

  useEffect(() => {
    let cancelled = false
    fetchRecipes().then((result) => {
      if (!cancelled) setRecipes(result?.recipes ?? [])
    })
    return () => {
      cancelled = true
    }
  }, [])

  const loadCatalog = async (candidate?: string) => {
    const clean = (candidate ?? hash).trim().toLowerCase()
    if (!HASH_RE.test(clean)) {
      setCatalogError('Enter a valid 32-64 character hex hash.')
      setCatalog(null)
      return
    }
    setLoadingCatalog(true)
    setCatalogError('')
    try {
      const result = await fetchAnalyzerCatalog({ data: { hash: clean } })
      if (result) {
        setCatalog(result)
        setSelected([])
        setOptions({})
        setLastRun(null)
      } else {
        setCatalog(null)
        setCatalogError('Captured payload not found or unreadable.')
      }
    } finally {
      setLoadingCatalog(false)
    }
  }

  // Auto-load once when arriving with a hash pre-filled from the payloads
  // page's "Analyze" link — read client-side from the URL (not a route
  // search schema, which would 307-redirect a bare hit; see the Route
  // definition's comment above).
  useEffect(() => {
    if (typeof window === 'undefined') return
    const fromUrl = new URLSearchParams(window.location.search).get('hash')
    if (fromUrl) {
      setHash(fromUrl)
      void loadCatalog(fromUrl)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const analyzerById = (id: string) => catalog?.analyzers.find((entry) => entry.id === id)

  const selectionOptions = (id: string): WorkbenchOptions =>
    options[id] ?? analyzerById(id)?.default_options ?? { timeout_seconds: 0, max_queue_age_seconds: 0, retry_limit: 0 }

  const setOption = (id: string, field: keyof WorkbenchOptions, value: number) => {
    setOptions((current) => ({ ...current, [id]: { ...selectionOptions(id), [field]: Number.isFinite(value) ? value : 0 } }))
  }

  const toggleAnalyzer = (id: string) => {
    setSelected((current) => (current.includes(id) ? current.filter((entry) => entry !== id) : [...current, id]))
    setOptions((current) => (current[id] ? current : { ...current, [id]: selectionOptions(id) }))
    setPickedRecipeId('')
  }

  const pickRecipe = (id: string) => {
    setPickedRecipeId(id)
    const recipe = (recipes ?? []).find((entry) => entry.id === id)
    if (recipe) {
      setSelected(recipe.analyzers.map((entry) => entry.analyzer_id))
      setOptions(Object.fromEntries(recipe.analyzers.map((entry) => [entry.analyzer_id, entry.options])))
      setRecipeName(recipe.name)
      setRecipeDescription(recipe.description)
      setRecipeScope(recipe.scope)
    }
  }

  // hp-workbench.js:328-332 — bulk-select every applicable local analyzer;
  // opt-in analyzers (real internet egress) stay a deliberate click.
  const runAllApplicable = () => {
    if (!catalog) return
    setSelected(catalog.analyzers.filter((entry) => entry.applicable && entry.available && !entry.requires_opt_in).map((entry) => entry.id))
    setPickedRecipeId('')
    setMessage('All currently applicable local analyzers selected.')
  }

  const needsConfirmation = selected.some((id) => catalog?.analyzers.find((entry) => entry.id === id)?.confirmation === 'detonation')
  const canSubmit = catalog !== null && selected.length > 0 && (!needsConfirmation || confirmed) && !busy

  const submit = async () => {
    if (!canSubmit || !catalog) return
    setBusy(true)
    setMessage('')
    try {
      const analyzers: WorkbenchSelection[] = selected.map((analyzer_id) => ({
        analyzer_id,
        options: selectionOptions(analyzer_id),
      }))
      if (saveAsRecipe) {
        const savedName = recipeName.trim()
        if (savedName.length < 2) {
          setMessage('Recipe name must be at least 2 characters to save.')
          setBusy(false)
          return
        }
        const existing = (recipes ?? []).find((entry) => entry.id === pickedRecipeId)
        const saveResult = await saveRecipeFn({
          data: {
            id: existing ? existing.id : '',
            name: savedName,
            description: recipeDescription,
            scope: recipeScope,
            analyzers,
            base_revision: existing ? existing.revision : 0,
          },
        })
        if (!saveResult.ok) {
          setMessage(saveResult.error || 'Recipe save failed.')
          setBusy(false)
          return
        }
        const refreshed = await fetchRecipes()
        setRecipes(refreshed?.recipes ?? [])
      }
      const runResult = await submitRun({
        data: {
          payload_sha256: hash.trim().toLowerCase(),
          recipe_name: recipeName.trim(),
          analyzers,
        },
      })
      if (runResult.ok && runResult.run) {
        setLastRun(runResult.run)
        setMessage(runResult.reused ? 'An identical run already existed — showing it below.' : 'Analysis run submitted.')
        onRunCreated(runResult.run)
      } else {
        setMessage(runResult.error || 'Run submission failed.')
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card wide" id="workbench-builder">
      <h2>Start a new analysis</h2>
      <p className="note">
        Static checks and detonation are different trust decisions. Running every applicable analyzer does not make a payload
        safe — dynamic backends stay isolated and cannot reach the protected live VM or the internet from here.
      </p>
      <div className="filters">
        <label className="note" style={{ display: 'block', minWidth: 320 }}>
          Payload hash (sha256 or md5)
          <input
            className="form-input"
           
            type="text"
            maxLength={64}
            value={hash}
            onChange={(event) => setHash(event.target.value)}
            placeholder="full payload hash"
          />
        </label>
        <button className="btn btn-secondary btn-sm" type="button" onClick={() => loadCatalog()} disabled={loadingCatalog}>
          {loadingCatalog ? 'Loading…' : 'Load catalog'}
        </button>
      </div>
      {catalogError ? <p className="note">{catalogError}</p> : null}

      {catalog ? (
        <>
          <div className="filters">
            <span className="chip">{catalog.classification.label || catalog.classification.code}</span>
            <span className="chip">{catalog.classification.platform}</span>
            <span className="chip">{catalog.classification.category}</span>
            {catalog.classification.dynamic ? <span className="chip">dynamic-capable</span> : null}
          </div>

          {(recipes?.length ?? 0) > 0 ? (
            <label className="note" style={{ display: 'block', maxWidth: 380 }}>
              Load from saved recipe
              <select className="form-input" value={pickedRecipeId} onChange={(event) => pickRecipe(event.target.value)}>
                <option value="">Custom selection…</option>
                {(recipes ?? []).map((recipe) => (
                  <option key={`${recipe.id}:${recipe.revision}`} value={recipe.id}>
                    {recipe.name} ({recipe.scope}, rev {recipe.revision})
                  </option>
                ))}
              </select>
            </label>
          ) : null}

          <div className="filters">
            <button className="btn btn-sm btn-secondary" type="button" onClick={runAllApplicable}>
              Run all applicable
            </button>
          </div>
          {/* payload_workbench.html — says why an analyzer may be greyed
              out, which is otherwise guesswork. */}
          <p className="note">
            Availability and applicability are derived on the server from this captured sample and operator configuration.
          </p>

          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Select</th>
                  <th>Analyzer</th>
                  <th>Status</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                {catalog.analyzers.map((analyzer) => (
                  <tr key={analyzer.id}>
                    <td>
                      <button
                        type="button"
                        className={selected.includes(analyzer.id) ? 'chip is-active' : 'chip'}
                        aria-pressed={selected.includes(analyzer.id)}
                        disabled={!analyzer.applicable || !analyzer.available}
                        title={analyzer.reason}
                        onClick={() => toggleAnalyzer(analyzer.id)}
                      >
                        {selected.includes(analyzer.id) ? 'selected' : 'select'}
                      </button>
                    </td>
                    <td className="v">
                      <strong>{analyzer.display_name}</strong>
                      <p className="note">{analyzer.description}</p>
                      {selected.includes(analyzer.id) ? (
                        <details className="wb-options">
                          <summary>Orchestration options</summary>
                          <div className="wb-option-grid">
                            <label>
                              Timeout (seconds)
                              <input
                                className="form-input"
                                type="number"
                                min={analyzer.option_schema?.timeout_min_seconds}
                                max={analyzer.option_schema?.timeout_max_seconds}
                                value={selectionOptions(analyzer.id).timeout_seconds}
                                onChange={(event) => setOption(analyzer.id, 'timeout_seconds', event.target.valueAsNumber)}
                              />
                            </label>
                            <label>
                              Maximum queue age (seconds)
                              <input
                                className="form-input"
                                type="number"
                                min={analyzer.option_schema?.queue_age_min_seconds}
                                max={analyzer.option_schema?.queue_age_max_seconds}
                                value={selectionOptions(analyzer.id).max_queue_age_seconds}
                                onChange={(event) => setOption(analyzer.id, 'max_queue_age_seconds', event.target.valueAsNumber)}
                              />
                            </label>
                            <label>
                              Retry allowance
                              <input
                                className="form-input"
                                type="number"
                                min={0}
                                max={analyzer.option_schema?.retry_limit_max}
                                value={selectionOptions(analyzer.id).retry_limit}
                                onChange={(event) => setOption(analyzer.id, 'retry_limit', event.target.valueAsNumber)}
                              />
                            </label>
                          </div>
                        </details>
                      ) : null}
                    </td>
                    <td>
                      <span className={analyzerBadgeClass(analyzer)}>{!analyzer.applicable ? 'not applicable' : analyzer.availability}</span>
                      {analyzer.reason ? <p className="note">{analyzer.reason}</p> : null}
                    </td>
                    <td>
                      {analyzer.detonates ? <span className="badge badge--danger">detonates</span> : null}{' '}
                      {analyzer.gpu_consuming ? <span className="badge badge--muted">gpu</span> : null}{' '}
                      {analyzer.local_only ? <span className="badge badge--muted">local-only</span> : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {needsConfirmation ? (
            <>
              <p className="note">
                One or more selected analyzers detonate this payload in an isolated sandbox. Detonation cannot reach the
                protected live VM or the internet.
              </p>
              <button
                type="button"
                className={confirmed ? 'chip is-active' : 'chip'}
                aria-pressed={confirmed}
                onClick={() => setConfirmed((current) => !current)}
              >
                {confirmed ? 'Detonation confirmed' : 'Confirm detonation'}
              </button>
            </>
          ) : null}

          <div className="filters hp-flow--tight">
            <label className="note" style={{ display: 'block', minWidth: 220 }}>
              Run / recipe name
              <input
                className="form-input"
               
                type="text"
                maxLength={80}
                value={recipeName}
                onChange={(event) => setRecipeName(event.target.value)}
                placeholder="One-off analysis"
              />
            </label>
            <button
              type="button"
              className={saveAsRecipe ? 'chip is-active' : 'chip'}
              aria-pressed={saveAsRecipe}
              onClick={() => setSaveAsRecipe((current) => !current)}
            >
              {saveAsRecipe ? 'Will save as recipe' : 'Save as recipe'}
            </button>
          </div>
          {saveAsRecipe ? (
            <div className="filters">
              <label className="note" style={{ display: 'block', minWidth: 240 }}>
                Recipe description
                <input
                  className="form-input"
                 
                  type="text"
                  maxLength={400}
                  value={recipeDescription}
                  onChange={(event) => setRecipeDescription(event.target.value)}
                />
              </label>
              <label className="note hp-field">
                Scope
                <select className="form-input" value={recipeScope} onChange={(event) => setRecipeScope(event.target.value)}>
                  <option value="private">Private</option>
                  <option value="shared">Shared with analysts</option>
                </select>
              </label>
            </div>
          ) : null}

          <div className="filters hp-flow--tight">
            <button className="btn btn-primary btn-sm" type="button" onClick={submit} disabled={!canSubmit}>
              {busy ? 'Submitting…' : 'Start analysis run'}
            </button>
          </div>
        </>
      ) : null}
      {message ? <p className="note">{message}</p> : null}

      {lastRun ? (
        <div style={{ marginTop: 16 }}>
          <h3 className="label-section">Run {lastRun.id}</h3>
          <RunDetail run={lastRun} currentOwner={owner} onChanged={setLastRun} />
        </div>
      ) : null}
    </div>
  )
}

// Client-side text search over one analyzer's result list — matches
// anywhere in the row document (hash, rule name, classification, ...).
function filterRows(rows: StoreRow[] | null, query: string): StoreRow[] | null {
  if (!rows || !query.trim()) return rows
  const needle = query.trim().toLowerCase()
  return rows.filter((row) => JSON.stringify(row).toLowerCase().includes(needle))
}

function FilterInput({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <div className="filters">
      <input
        className="form-input"
        type="search"
        placeholder={`Filter ${label}…`}
        aria-label={`Filter ${label}`}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </div>
  )
}

function usePage(promise: Promise<Page | null>): Page | null {
  const [page, setPage] = useState<Page | null>(null)
  useEffect(() => {
    let cancelled = false
    promise.then((result) => {
      if (!cancelled && result) setPage(result)
    })
    return () => {
      cancelled = true
    }
  }, [promise])
  return page
}

function gpuStatusBadge(status: string) {
  const cls =
    status === 'completed' || status === 'done'
      ? 'badge badge--success'
      : status === 'failed' || status === 'error'
        ? 'badge badge--danger'
        : status === 'running'
          ? 'badge badge--warning'
          : 'badge badge--muted' // queued, aborted, unknown
  return <span className={cls}>{status || 'unknown'}</span>
}

const gpuQueueColumns = (onAbort: (job: GpuJob) => void): Column<GpuJob>[] => [
  { header: 'requested', render: (row) => (row.requested_at ? when(row.requested_at) : '—') },
  { header: 'type', className: 'v', render: (row) => row.job_type },
  { header: 'model', className: 'v', render: (row) => row.model },
  { header: 'status', render: (row) => gpuStatusBadge(row.status) },
  { header: 'attempts', className: 'n', render: (row) => String(row.attempts) },
  {
    header: 'abort requested',
    render: (row) => (row.abort_requested ? <span className="badge badge--warning">yes</span> : '—'),
  },
  { header: 'ref', detail: true, className: 'v', render: (row) => <code>{row.ref}</code> },
  { header: 'estimated VRAM', detail: true, render: (row) => (row.estimated_vram_mib ? `${row.estimated_vram_mib} MiB` : '—') },
  { header: 'started', detail: true, render: (row) => (row.started_at ? when(row.started_at) : '—') },
  { header: 'finished', detail: true, render: (row) => (row.finished_at ? when(row.finished_at) : '—') },
  { header: 'error', detail: true, render: (row) => row.error || '—' },
  { header: 'job id', detail: true, render: (row) => <code>{row.job_id}</code> },
  {
    // #1698: queued *and* running. The drainer checks the flag before it
    // starts, and the worker checks it again between streamed chunks, so a
    // job that is already generating can now be stopped too — abandoning the
    // stream is what frees the GPU. Finished rows still get no control, and
    // `abort_requested` already-set collapses to the existing badge rather
    // than a second, useless button.
    header: '',
    render: (row) =>
      (row.status === 'queued' || row.status === 'running') && !row.abort_requested ? (
        <button type="button" className="btn btn-danger btn-sm" onClick={() => onAbort(row)}>
          Abort
        </button>
      ) : null,
  },
]

// payload_workbench.html:16-20's tablist, extended to one view per
// analyzer result family this port shows (static analysis and YARA have
// their own stores here; GitHub's list folded into the workbench store).
const RESULT_TABS = [
  { id: 'workbench', label: 'Workbench' },
  { id: 'static', label: 'Static analysis' },
  { id: 'yara', label: 'YARA' },
  { id: 'sandbox', label: 'Sandbox' },
  { id: 'ghidra', label: 'Ghidra' },
] as const

type ResultTabId = (typeof RESULT_TABS)[number]['id']

function Results() {
  const data = Route.useLoaderData()
  const workbench = usePage(data.workbench)
  const statics = usePage(data.statics)
  const yara = usePage(data.yara)
  const sandbox = usePage(data.sandbox)
  const ghidra = usePage(data.ghidra)
  const [gpuQueue, setGpuQueue] = useState<GpuJob[] | null>(null)
  useEffect(() => {
    let cancelled = false
    data.gpuQueue.then((result) => {
      if (!cancelled) setGpuQueue(result ?? [])
    })
    return () => {
      cancelled = true
    }
  }, [data.gpuQueue])
  // #1692: abort a queued job. Re-reads the queue afterwards rather than
  // patching the row locally — the drainer may have moved the job on in the
  // meantime, and the authoritative status is worth the one extra request.
  const onAbortGpuJob = useCallback((job: GpuJob) => {
    confirmAction({
      title: 'Abort this queued job?',
      description: `${job.job_type} job for ${job.ref || 'an unnamed reference'}, ${job.status} on model ${job.model || 'unknown'}.`,
      warning:
        'The job stops and its AI triage is skipped. A job that is already generating is cut off mid-answer and the GPU freed. The rest of that analysis is unaffected.',
      confirmLabel: 'Abort job',
      onConfirm: async () => {
        const result = await abortGpuJob({ data: { job_id: job.job_id } })
        if (!result.ok) throw new Error(result.error || 'Abort failed.')
        setGpuQueue((await fetchGpuQueue()) ?? [])
        return 'Abort requested.'
      },
    })
  }, [])
  const gpuColumns = useMemo(() => gpuQueueColumns(onAbortGpuJob), [onAbortGpuJob])
  const owner = data.user?.username ?? ''
  const [runsToken, setRunsToken] = useState(0)
  const [tab, setTab] = useState<ResultTabId>('workbench')
  // Design pick 7D: the page's view tabs relocate into the sidebar rail
  // (inline below 520px, where the sidebar is off-canvas). Panels hide
  // via the hidden attribute instead of unmounting so the builder's
  // in-progress selections survive a look at another analyzer's results.
  const viewTabs = useSidebarViewTabs({
    label: 'Analysis results views',
    tabs: RESULT_TABS,
    active: tab,
    onSelect: (id) => setTab(id as ResultTabId),
    idPrefix: 'wb',
  })
  const [workbenchQuery, setWorkbenchQuery] = useState('')
  const [staticQuery, setStaticQuery] = useState('')
  const [yaraQuery, setYaraQuery] = useState('')
  const [sandboxQuery, setSandboxQuery] = useState('')
  const [ghidraQuery, setGhidraQuery] = useState('')

  return (
    <>
      <InvestigateHeader
        label="Evidence"
        title="Analysis results"
        subtitle="Build and submit a workbench recipe against a captured payload, then follow every analyzer's verdict — static analysis, YARA, sandbox detonations, and Ghidra decompilation."
        chips={
          <>
            <span className="chip">{(workbench?.total ?? 0).toLocaleString('en-US')} workbench runs</span>
            <span className="chip">{(statics?.total ?? 0).toLocaleString('en-US')} static analyses</span>
            <span className="chip">{(yara?.total ?? 0).toLocaleString('en-US')} YARA results</span>
            <span className="chip">{(sandbox?.total ?? 0).toLocaleString('en-US')} detonations</span>
            <span className="chip">{(ghidra?.total ?? 0).toLocaleString('en-US')} ghidra runs</span>
          </>
        }
      />
      {viewTabs}
      <div className="dashboard-panel" role="tabpanel" id="wb-panel-workbench" aria-labelledby="wb-workbench" hidden={tab !== 'workbench'}>
        <WorkbenchBuilder owner={owner} onRunCreated={() => setRunsToken((token) => token + 1)} />
        <ModelHealthCard />
        <RecentRunsCard owner={owner} refreshToken={runsToken} />
        <h2 className="label-section">Workbench runs</h2>
        <FilterInput label="workbench runs" value={workbenchQuery} onChange={setWorkbenchQuery} />
        <MasterDetailTable
          rows={filterRows(workbench ? workbench.rows : null, workbenchQuery)}
          columns={WORKBENCH_COLUMNS}
          rowKey={(row, i) => `wb-${pathString(row, 'id')}-${i}`}
          inspectorTitle="Workbench run"
          cardIcon={() => WorkbenchIcon}
          cardBadges={(row) => {
            const state = pathString(row, 'state')
            return state ? <span className={`badge wb-state wb-state--${state}`}>{state}</span> : null
          }}
          cardDesc={(row) => {
            const kind = pathString(row, 'payload_kind')
            const analyzers = childCount(row)
            const parts = []
            if (kind) parts.push(`${kind} payload`)
            parts.push(`${analyzers} analyzer${analyzers === 1 ? '' : 's'}`)
            return parts.join(' • ')
          }}
          emptyState={{
            title: 'No workbench runs match this view',
            hint: 'Clear the filter above, or start a run from the workbench tab.',
          }}
          layout="cards"
          gridId="workbench-runs-results"
          cardHref={(row) => {
            const sha = pathString(row, 'payload_sha256')
            return sha ? `/payload-analysis/${encodeURIComponent(sha)}` : undefined
          }}
        />
      </div>
      <div className="dashboard-panel" role="tabpanel" id="wb-panel-static" aria-labelledby="wb-static" hidden={tab !== 'static'}>
        <h2 className="label-section">Static analysis</h2>
        <FilterInput label="static analyses" value={staticQuery} onChange={setStaticQuery} />
        <MasterDetailTable
          rows={filterRows(statics ? statics.rows : null, staticQuery)}
          columns={STATIC_COLUMNS}
          rowKey={(row, i) => `st-${pathString(row, 'Fingerprint')}-${i}`}
          inspectorTitle="Static analysis"
          cardIcon={() => FileIcon}
          cardBadges={(row) => {
            const kind = pathString(row, 'Analysis', 'Kind')
            return kind ? <span className="badge badge--muted">{kind}</span> : null
          }}
          cardDesc={(row) => pathString(row, 'Analysis', 'Summary') || null}
          emptyState={{
            title: 'No static analyses match this view',
            hint: 'Clear the filter above to see every static analysis on record.',
          }}
          layout="cards"
          gridId="static-analysis-results"
          cardHref={(row) => {
            const fingerprint = pathString(row, 'Fingerprint')
            return fingerprint ? `/payload-analysis/${encodeURIComponent(fingerprint)}` : undefined
          }}
        />
      </div>
      <div className="dashboard-panel" role="tabpanel" id="wb-panel-yara" aria-labelledby="wb-yara" hidden={tab !== 'yara'}>
        <h2 className="label-section">YARA</h2>
        <FilterInput label="YARA results" value={yaraQuery} onChange={setYaraQuery} />
        <MasterDetailTable
          rows={filterRows(yara ? yara.rows : null, yaraQuery)}
          columns={YARA_COLUMNS}
          rowKey={(_, i) => `ya-${i}`}
          inspectorTitle="YARA result"
          cardIcon={() => ShieldIcon}
          cardBadges={(row) => {
            const matches = Array.isArray((row.yara as StoreRow | undefined)?.matches)
              ? ((row.yara as StoreRow).matches as unknown[]).length
              : Number(pathString(row, 'yara', 'match_count')) || 0
            return <span className={matches > 0 ? 'badge badge--warning' : 'badge badge--muted'}>{matches} match{matches === 1 ? '' : 'es'}</span>
          }}
          emptyState={{
            title: 'No YARA results match this view',
            hint: 'Clear the filter above to see every YARA result on record.',
          }}
          layout="cards"
          gridId="yara-results"
          cardHref={(row) => {
            const sha = pathString(row, 'file', 'hash', 'sha256')
            return sha ? `/payload-analysis/${encodeURIComponent(sha)}` : undefined
          }}
        />
      </div>
      <div className="dashboard-panel" role="tabpanel" id="wb-panel-sandbox" aria-labelledby="wb-sandbox" hidden={tab !== 'sandbox'}>
        <h2 className="label-section">Sandbox detonations</h2>
        <FilterInput label="sandbox detonations" value={sandboxQuery} onChange={setSandboxQuery} />
        <MasterDetailTable
          rows={filterRows(sandbox ? sandbox.rows : null, sandboxQuery)}
          columns={SANDBOX_COLUMNS}
          rowKey={(_, i) => `sb-${i}`}
          inspectorTitle="Sandbox run"
          cardIcon={() => SandboxIcon}
          cardBadges={(row) => {
            const platform = pathString(row, 'platform')
            const exit = pathString(row, 'exit_status')
            return (
              <>
                {platform ? <span className="badge badge--muted">{platform}</span> : null}
                {exit === 'error' ? <span className="badge badge--muted text-danger">error</span> : null}
              </>
            )
          }}
          cardDesc={(row) => {
            const score = pathString(row, 'risk_score')
            const level = pathString(row, 'risk_level')
            if (!score && !level) return null
            return `risk ${score || '?'} / 100${level ? ` • ${level}` : ''}`
          }}
          emptyState={{
            title: 'No completed sandbox exports match this view',
            hint: 'Clear the filter above, or queue a detonation from the workbench.',
          }}
          inspectorExtra={(row) => {
            const job = pathString(row, 'sandbox', 'job') || pathString(row, 'job')
            return job ? <ArtifactList kind="sandbox" artifactKey={job} /> : null
          }}
          layout="cards"
          gridId="sandbox-results"
          cardHref={(row) => {
            const job = sandboxJob(row)
            return job ? `/sandbox/${encodeURIComponent(job)}` : undefined
          }}
        />
      </div>
      <div className="dashboard-panel" role="tabpanel" id="wb-panel-ghidra" aria-labelledby="wb-ghidra" hidden={tab !== 'ghidra'}>
        {/* GPU queue lives with Ghidra — the legacy /ghidra page rendered
            this card (dashboard/gpu_queue.go), and that page folded in
            here. */}
        {gpuQueue === null || gpuQueue.length > 0 ? (
          <>
            <h2 className="label-section">GPU queue</h2>
            <p className="note">
              Jobs deferred because there wasn't enough free GPU headroom when they were submitted — a queued job's AI triage
              runs automatically once the card frees up; the rest of that analysis is unaffected and already completed.
            </p>
            <MasterDetailTable
              rows={gpuQueue}
              columns={gpuColumns}
              rowKey={(row, i) => `gq-${row.job_id}-${i}`}
              inspectorTitle="GPU queue job"
            />
          </>
        ) : null}
        <h2 className="label-section">Ghidra decompilation</h2>
        <FilterInput label="Ghidra runs" value={ghidraQuery} onChange={setGhidraQuery} />
        <MasterDetailTable
          rows={filterRows(ghidra ? ghidra.rows : null, ghidraQuery)}
          columns={GHIDRA_COLUMNS}
          rowKey={(_, i) => `gh-${i}`}
          inspectorTitle="Ghidra run"
          cardIcon={() => CodeIcon}
          cardBadges={(row) => {
            const exit = pathString(row, 'exit_status')
            return exit ? <span className={exit === 'error' ? 'badge badge--muted text-danger' : 'badge badge--muted'}>{exit}</span> : null
          }}
          emptyState={{
            title: 'No Ghidra analyses match this view',
            hint: 'Clear the filter above to see every Ghidra run on record.',
          }}
          inspectorExtra={(row) => {
            const sha = pathString(row, 'file', 'hash', 'sha256')
            return sha ? <ArtifactList kind="ghidra" artifactKey={sha} /> : null
          }}
          layout="cards"
          gridId="ghidra-results"
          cardHref={(row) => {
            const sha = pathString(row, 'file', 'hash', 'sha256')
            return sha ? `/ghidra/${encodeURIComponent(sha)}` : undefined
          }}
        />
      </div>
    </>
  )
}
