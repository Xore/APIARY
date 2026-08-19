// Analysis results — every analyzer's output over the captured payloads:
// workbench runs, static analysis, YARA matches, sandbox detonations,
// Ghidra decompilations. Each analyzer keeps its own table; rows open
// the full result document in the inspector.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { ArtifactList } from '../components/ArtifactList'

type StoreRow = Record<string, unknown>
type Page = { total: number; rows: StoreRow[] }

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

// GPU job queue (#1611 workstream E.6) — ported from dashboard/gpu_queue.go,
// which rendered this same card on the legacy /ghidra page (now redirected
// here). Read-only: the legacy abort action is an operator write against a
// queue/spool, out of scope for this pass — this only closes the "can't
// even see it" gap the issue's live audit found (2 stuck queued jobs with
// nothing surfacing them).
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

export const Route = createFileRoute('/payload-workbench/results')({
  loader: async () => ({
    workbench: fetchWorkbench({ data: { offset: 0 } }),
    statics: fetchStatic({ data: { offset: 0 } }),
    yara: fetchYara({ data: { offset: 0 } }),
    sandbox: fetchSandbox({ data: { offset: 0 } }),
    ghidra: fetchGhidra({ data: { offset: 0 } }),
    gpuQueue: fetchGpuQueue(),
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

const GPU_QUEUE_COLUMNS: Column<GpuJob>[] = [
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
]

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

  return (
    <>
      <InvestigateHeader
        label="Evidence"
        title="Analysis results"
        subtitle="Every analyzer's verdicts over the captured payloads — workbench recipes, static analysis, YARA, sandbox detonations, and Ghidra decompilation."
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
      {gpuQueue === null || gpuQueue.length > 0 ? (
        <>
          <h2 className="label-section">GPU queue</h2>
          <p className="note">
            Jobs deferred because there wasn't enough free GPU headroom when they were submitted — a queued job's AI triage
            runs automatically once the card frees up; the rest of that analysis is unaffected and already completed.
          </p>
          <MasterDetailTable
            rows={gpuQueue}
            columns={GPU_QUEUE_COLUMNS}
            rowKey={(row, i) => `gq-${row.job_id}-${i}`}
            inspectorTitle="GPU queue job"
          />
        </>
      ) : null}
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
