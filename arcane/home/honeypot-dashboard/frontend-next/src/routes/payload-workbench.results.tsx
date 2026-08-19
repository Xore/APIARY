// Analysis results — every analyzer's output over the captured payloads:
// workbench runs, static analysis, YARA matches, sandbox detonations,
// Ghidra decompilations. Each analyzer keeps its own table; rows open
// the full result document in the inspector.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { Fragment, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { ArtifactList } from '../components/ArtifactList'
import { getSessionUser } from '../lib/auth'

type StoreRow = Record<string, unknown>
type Page = { total: number; rows: StoreRow[] }

// Workbench builder types — mirror backend-service/src/workbench_domain.rs's
// WorkbenchOptions/WorkbenchSelection/WorkbenchAnalyzer/WorkbenchChild/
// WorkbenchRun/WorkbenchRecipe JSON shapes exactly (including the analyzer's
// serde renames: concurrency -> concurrency_class, externally_sends ->
// externally_publishing, gpu -> gpu_consuming).
type WorkbenchOptions = { timeout_seconds: number; max_queue_age_seconds: number; retry_limit: number }
type WorkbenchSelection = { analyzer_id: string; options: WorkbenchOptions }
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
    return serviceJSON<AnalyzersResponse>(`/api/v1/workbench/analyzers?hash=${encodeURIComponent(data.hash)}`)
  })

const fetchRecipes = createServerFn({ method: 'GET' }).handler(async (): Promise<{ recipes: WorkbenchRecipe[] } | null> => {
  const { getSessionUser } = await import('../lib/auth')
  const user = await getSessionUser()
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<{ recipes: WorkbenchRecipe[] }>(`/api/v1/workbench/recipes?owner=${encodeURIComponent(user?.username ?? '')}`)
})

const fetchOwnRuns = createServerFn({ method: 'GET' }).handler(async (): Promise<{ runs: WorkbenchRun[] } | null> => {
  const { getSessionUser } = await import('../lib/auth')
  const user = await getSessionUser()
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<{ runs: WorkbenchRun[] }>(`/api/v1/workbench/runs?owner=${encodeURIComponent(user?.username ?? '')}&limit=25`)
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
    const response = await serviceFetch(`/api/v1/workbench/runs/${encodeURIComponent(data.id)}?owner=${encodeURIComponent(user?.username ?? '')}`)
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
    const response = await serviceFetch('/api/v1/workbench/runs', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        payload_sha256: data.payload_sha256,
        owner: user?.username ?? '',
        recipe_name: data.recipe_name,
        analyzers: data.analyzers,
      }),
    })
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
    const response = await serviceFetch('/api/v1/workbench/recipes', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...data, owner: user?.username ?? '' }),
    })
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
export const Route = createFileRoute('/payload-workbench/results')({
  loader: async () => ({
    workbench: fetchWorkbench({ data: { offset: 0 } }),
    statics: fetchStatic({ data: { offset: 0 } }),
    yara: fetchYara({ data: { offset: 0 } }),
    sandbox: fetchSandbox({ data: { offset: 0 } }),
    ghidra: fetchGhidra({ data: { offset: 0 } }),
    user: await getSessionUser(),
  }),
  component: Results,
})

const str = (row: StoreRow, ...path: string[]): string => {
  let value: unknown = row
  for (const key of path) {
    if (typeof value !== 'object' || value === null) return ''
    value = (value as StoreRow)[key]
  }
  return typeof value === 'string' ? value : typeof value === 'number' ? String(value) : ''
}

const when = (iso: string) => iso.replace('T', ' ').slice(0, 19)

const recordColumn: Column<StoreRow> = {
  header: 'result',
  detail: true,
  render: (row) => <pre className="hp-md__preview">{JSON.stringify(row, null, 2)}</pre>,
}

const WORKBENCH_COLUMNS: Column<StoreRow>[] = [
  { header: 'created', render: (row) => when(str(row, 'created_at')) },
  { header: 'state', render: (row) => <span className="badge badge--muted">{str(row, 'state')}</span> },
  { header: 'recipe', className: 'v', render: (row) => str(row, 'recipe_name') },
  { header: 'payload', className: 'v', render: (row) => <code>{str(row, 'payload_sha256').slice(0, 16)}</code> },
  { header: 'owner', render: (row) => str(row, 'owner') },
  recordColumn,
]

const STATIC_COLUMNS: Column<StoreRow>[] = [
  { header: 'fingerprint', className: 'v', render: (row) => <code>{str(row, 'Fingerprint').slice(0, 24)}</code> },
  { header: 'kind', render: (row) => str(row, 'Analysis', 'Kind') },
  { header: 'summary', className: 'v', render: (row) => str(row, 'Analysis', 'Summary') },
  recordColumn,
]

const YARA_COLUMNS: Column<StoreRow>[] = [
  { header: 'analyzed', render: (row) => when(str(row, '@timestamp')) },
  { header: 'file', className: 'v', render: (row) => <code>{str(row, 'file', 'hash', 'sha256').slice(0, 16) || str(row, 'file', 'name')}</code> },
  { header: 'matches', className: 'v', render: (row) => str(row, 'yara', 'match_count') || (Array.isArray((row.yara as StoreRow | undefined)?.matches) ? String(((row.yara as StoreRow).matches as unknown[]).length) : '') },
  recordColumn,
]

const SANDBOX_COLUMNS: Column<StoreRow>[] = [
  {
    header: 'job',
    className: 'v',
    render: (row) => {
      const job = str(row, 'sandbox', 'job') || str(row, 'job')
      return job ? (
        <a className="lnk" href={`/sandbox/${encodeURIComponent(job)}`} onClick={(event) => event.stopPropagation()}>
          {job.slice(0, 28)} →
        </a>
      ) : (
        ''
      )
    },
  },
  { header: 'detonated', render: (row) => when(str(row, '@timestamp')) },
  { header: 'platform', render: (row) => <span className="badge badge--muted">{str(row, 'platform')}</span> },
  {
    header: 'risk',
    render: (row) => {
      const level = str(row, 'risk_level')
      const cls = level === 'high' || level === 'critical' ? 'badge badge--danger' : level === 'medium' ? 'badge badge--warning' : 'badge badge--muted'
      return <span className={cls}>{level} {str(row, 'risk_score')}</span>
    },
  },
  { header: 'file', className: 'v', render: (row) => <code>{str(row, 'file', 'hash', 'sha256').slice(0, 16) || str(row, 'file', 'name')}</code> },
  { header: 'exit', render: (row) => str(row, 'exit_status') },
  recordColumn,
]

const GHIDRA_COLUMNS: Column<StoreRow>[] = [
  { header: 'analyzed', render: (row) => when(str(row, '@timestamp')) },
  {
    header: 'file',
    className: 'v',
    render: (row) => {
      const sha = str(row, 'file', 'hash', 'sha256')
      return sha ? (
        <a className="lnk" href={`/ghidra/${encodeURIComponent(sha)}`} onClick={(event) => event.stopPropagation()}>
          <code>{sha.slice(0, 16)}</code> →
        </a>
      ) : (
        <code>{str(row, 'file', 'name')}</code>
      )
    },
  },
  { header: 'exit', render: (row) => str(row, 'exit_status') },
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
      <div className="filters" style={{ marginBottom: 8 }}>
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
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>Created</th>
                <th>Payload</th>
                <th>Recipe</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <Fragment key={run.id}>
                  <tr onClick={() => setSelected(selected === run.id ? null : run.id)} style={{ cursor: 'pointer' }}>
                    <td>{run.created_at.replace('T', ' ').slice(0, 19)}</td>
                    <td className="v">
                      <code>{run.payload_sha256.slice(0, 16)}</code>
                    </td>
                    <td>{run.recipe_name || run.recipe_id || 'one-off'}</td>
                    <td>
                      <span className={stateBadgeClass(run.state)}>{run.state}</span>
                    </td>
                  </tr>
                  {selected === run.id ? (
                    <tr>
                      <td colSpan={4}>
                        <RunDetail run={run} currentOwner={owner} onChanged={updateRun} />
                      </td>
                    </tr>
                  ) : null}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
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

  const toggleAnalyzer = (id: string) => {
    setSelected((current) => (current.includes(id) ? current.filter((entry) => entry !== id) : [...current, id]))
    setPickedRecipeId('')
  }

  const pickRecipe = (id: string) => {
    setPickedRecipeId(id)
    const recipe = (recipes ?? []).find((entry) => entry.id === id)
    if (recipe) {
      setSelected(recipe.analyzers.map((entry) => entry.analyzer_id))
      setRecipeName(recipe.name)
      setRecipeDescription(recipe.description)
      setRecipeScope(recipe.scope)
    }
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
        options: { timeout_seconds: 0, max_queue_age_seconds: 0, retry_limit: 0 },
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
            className="input"
            style={{ width: '100%' }}
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
              <select className="input" style={{ width: '100%' }} value={pickedRecipeId} onChange={(event) => pickRecipe(event.target.value)}>
                <option value="">Custom selection…</option>
                {(recipes ?? []).map((recipe) => (
                  <option key={`${recipe.id}:${recipe.revision}`} value={recipe.id}>
                    {recipe.name} ({recipe.scope}, rev {recipe.revision})
                  </option>
                ))}
              </select>
            </label>
          ) : null}

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

          <div className="filters" style={{ marginTop: 8 }}>
            <label className="note" style={{ display: 'block', minWidth: 220 }}>
              Run / recipe name
              <input
                className="input"
                style={{ width: '100%' }}
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
                  className="input"
                  style={{ width: '100%' }}
                  type="text"
                  maxLength={400}
                  value={recipeDescription}
                  onChange={(event) => setRecipeDescription(event.target.value)}
                />
              </label>
              <label className="note" style={{ display: 'block', minWidth: 160 }}>
                Scope
                <select className="input" style={{ width: '100%' }} value={recipeScope} onChange={(event) => setRecipeScope(event.target.value)}>
                  <option value="private">Private</option>
                  <option value="shared">Shared with analysts</option>
                </select>
              </label>
            </div>
          ) : null}

          <div className="filters" style={{ marginTop: 8 }}>
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

function Results() {
  const data = Route.useLoaderData()
  const workbench = usePage(data.workbench)
  const statics = usePage(data.statics)
  const yara = usePage(data.yara)
  const sandbox = usePage(data.sandbox)
  const ghidra = usePage(data.ghidra)
  const owner = data.user?.username ?? ''
  const [runsToken, setRunsToken] = useState(0)

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
      <WorkbenchBuilder owner={owner} onRunCreated={() => setRunsToken((token) => token + 1)} />
      <RecentRunsCard owner={owner} refreshToken={runsToken} />
      <h2 className="label-section">Workbench runs</h2>
      <MasterDetailTable rows={workbench ? workbench.rows : null} columns={WORKBENCH_COLUMNS} rowKey={(row, i) => `wb-${str(row, 'id')}-${i}`} inspectorTitle="Workbench run" />
      <h2 className="label-section">Static analysis</h2>
      <MasterDetailTable rows={statics ? statics.rows : null} columns={STATIC_COLUMNS} rowKey={(row, i) => `st-${str(row, 'Fingerprint')}-${i}`} inspectorTitle="Static analysis" />
      <h2 className="label-section">YARA</h2>
      <MasterDetailTable rows={yara ? yara.rows : null} columns={YARA_COLUMNS} rowKey={(_, i) => `ya-${i}`} inspectorTitle="YARA result" />
      <h2 className="label-section">Sandbox detonations</h2>
      <MasterDetailTable
        rows={sandbox ? sandbox.rows : null}
        columns={SANDBOX_COLUMNS}
        rowKey={(_, i) => `sb-${i}`}
        inspectorTitle="Sandbox run"
        inspectorExtra={(row) => {
          const job = str(row, 'sandbox', 'job') || str(row, 'job')
          return job ? <ArtifactList kind="sandbox" artifactKey={job} /> : null
        }}
      />
      <h2 className="label-section">Ghidra decompilation</h2>
      <MasterDetailTable
        rows={ghidra ? ghidra.rows : null}
        columns={GHIDRA_COLUMNS}
        rowKey={(_, i) => `gh-${i}`}
        inspectorTitle="Ghidra run"
        inspectorExtra={(row) => {
          const sha = str(row, 'file', 'hash', 'sha256')
          return sha ? <ArtifactList kind="ghidra" artifactKey={sha} /> : null
        }}
      />
    </>
  )
}
