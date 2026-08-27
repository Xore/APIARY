// ML anomalies — the ml-worker's composite-scored outliers.
// #1653 fidelity pass restores ml_anomalies.html's settled UX: KPI tile
// row (#1566), bulk acknowledge-all (#1566), severity/type/status filters,
// per-model score breakdown, source-event pivot (#173) and the 24h
// top-source-IPs card, on top of the existing store-paged table.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { str, num, when, type StorePage, type StoreRow } from '../components/StoreList'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'
import { confirmAction } from '../components/ConfirmDialog'
import { EChart } from '../components/EChart'
import { FiltersButton, FiltersModal } from '../components/FiltersModal'
import { formatTimestamp } from '../lib/time'
import { collapseRuns, foldedCount, idsFor } from '../lib/mlGrouping'
import { countryName } from '../lib/country'

type AckRecord = { Acknowledged: boolean; AckedBy?: string; AckedAt?: string }

// #1968's closed operator vocabulary. Unlike acks (a sidecar index keyed by
// doc id), these land ON the anomaly document itself — verdicts beside
// scores — because they feed the labelled corpus (#1794/#1797). "open" is
// the worker-set default plus the explicit retraction value, not a choice.
const DISPOSITIONS = ['false_positive', 'true_positive', 'benign_known'] as const
type Disposition = (typeof DISPOSITIONS)[number]

function dispositionBadge(status: string) {
  switch (status) {
    case 'true_positive':
      return <span className="badge badge--danger">true positive</span>
    case 'false_positive':
      return <span className="badge badge--success">false positive</span>
    case 'benign_known':
      return <span className="badge badge--info">benign known</span>
  }
  return <span className="badge badge--muted">{status}</span>
}

const fetchAcks = createServerFn({ method: 'GET' }).handler(async (): Promise<Record<string, AckRecord> | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<Record<string, AckRecord>>('/api/v1/ml-anomalies/acks')
})

// Per-model retrain history (#1611 workstream E.5) — a drifting or
// silently-rejected model is otherwise invisible; this is the one place
// that surfaces each detector's most recent retrain outcome.
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

function outcomeBadge(accepted: boolean) {
  return <span className={accepted ? 'badge badge--success' : 'badge badge--danger'}>{accepted ? 'accepted' : 'rejected'}</span>
}

function ModelHealthCard() {
  const [models, setModels] = useState<ModelHealth[] | null>(null)
  // #2178: `result ?? []` made a failed /api/v1/ml-health call render as
  // "No retrain history recorded yet." -- asserting quiet models during an
  // outage. Tri-state it.
  const [failed, setFailed] = useState(false)
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    let cancelled = false
    setModels(null)
    setFailed(false)
    fetchModelHealth().then((result) => {
      if (cancelled) return
      if (!result) {
        setFailed(true)
        return
      }
      setModels(result)
    })
    return () => {
      cancelled = true
    }
  }, [attempt])
  return (
    <div className="card wide" id="ml-model-health-card">
      <h2>Model health</h2>
      <p className="note">Each detector model's most recent retrain decision — accepted or rejected, and why.</p>
      {models === null && failed ? (
        <ErrorStateBlock
          title="Model health failed to load"
          hint="The backend request failed — this says nothing about whether models are healthy."
          onRetry={() => setAttempt((n) => n + 1)}
        />
      ) : models === null ? (
        <span className="skeleton-line" aria-hidden="true" />
      ) : models.length === 0 ? (
        <p className="empty">No retrain history recorded yet.</p>
      ) : (
        <div className="card__scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th>model</th>
                <th>outcome</th>
                <th>reason</th>
                <th>anomaly rate (prev → new)</th>
                <th>train samples</th>
                <th>last retrain</th>
              </tr>
            </thead>
            <tbody>
              {models.map((model) => (
                <tr key={model.model}>
                  <td className="v">{model.model}</td>
                  <td>{outcomeBadge(model.accepted)}</td>
                  <td className="v">{model.reason || '—'}</td>
                  <td className="n">
                    {model.anomaly_rate_previous.toFixed(4)} → {model.anomaly_rate_new.toFixed(4)}
                  </td>
                  <td className="n">{model.train_samples.toLocaleString('en-US')}</td>
                  <td>{model.timestamp ? formatTimestamp(model.timestamp) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

const setAck = createServerFn({ method: 'POST' })
  .inputValidator((input: { key: string; ack: boolean }) => input)
  .handler(async ({ data }): Promise<boolean> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user || user.role !== 'admin') return false
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/ml-anomalies/ack', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...data, actor: user?.username ?? '' }),
    })
    return response.ok
  })

// #1968 operator disposition — same admin gate as setAck, different write:
// detail.rs's ml_anomaly_disposition does a partial `_update` on the
// anomaly document (reason free-text, valued for the labelled corpus).
const setDisposition = createServerFn({ method: 'POST' })
  .inputValidator((input: { key: string; status: string; reason?: string }) => input)
  .handler(async ({ data }): Promise<boolean> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    if (!user || user.role !== 'admin') return false
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/ml-anomalies/disposition', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...data, reason: data.reason ?? '', actor: user?.username ?? '' }),
    })
    return response.ok
  })

// Bulk acknowledge (#1566) — the server iterates every open anomaly and
// reuses the single-ack write path (detail.rs's ml_anomaly_ack_all), same
// admin gate as setAck. Returns how many records it flipped, or null on
// refusal/failure.
const ackAll = createServerFn({ method: 'POST' }).handler(async (): Promise<number | null> => {
  const { getSessionUser } = await import('../lib/auth')
  const user = await getSessionUser()
  if (!user || user.role !== 'admin') return null
  const { serviceFetch } = await import('../lib/backend.server')
  const response = await serviceFetch('/api/v1/ml-anomalies/ack-all', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ actor: user?.username ?? '' }),
  })
  if (!response.ok) return null
  const body = (await response.json()) as { changed?: number }
  return typeof body.changed === 'number' ? body.changed : 0
})

// #1566: `docIds` rather than one id, because a row may stand for a whole
// folded run. Acknowledging only the representative would leave its siblings
// open, and the row would come straight back as unacknowledged on the next
// refresh -- the button would look broken while working exactly as written.
function AckControl({ docIds, acks, onChanged }: { docIds: string[]; acks: Record<string, AckRecord>; onChanged: () => void }) {
  const [busy, setBusy] = useState(false)
  if (!docIds.length) return null
  // A folded run is "acknowledged" only when all of it is; a partially
  // acknowledged run still has open findings in it.
  const acked = docIds.every((id) => acks[id]?.Acknowledged ?? false)
  const many = docIds.length > 1
  return (
    <button
      className="btn btn-secondary btn-sm"
      type="button"
      disabled={busy}
      onClick={async () => {
        setBusy(true)
        try {
          const results = await Promise.all(docIds.map((id) => setAck({ data: { key: id, ack: !acked } })))
          if (results.some(Boolean)) onChanged()
        } finally {
          setBusy(false)
        }
      }}
    >
      {busy ? '…' : acked ? `Reopen ${many ? `all ${docIds.length}` : 'anomaly'}` : `Acknowledge ${many ? `all ${docIds.length}` : 'anomaly'}`}
    </button>
  )
}

// #1968: verdicts go on the document, so a folded run is judged as a whole
// here too — disposing only the representative would leave identical
// siblings of the same burst carrying different verdicts. "Retract" assigns
// the open status explicitly (clearing reason/actor/time server-side) so a
// mis-clicked verdict is undoable rather than permanent.
function DispositionControl({ docIds, row, onChanged }: { docIds: string[]; row: StoreRow; onChanged: () => void }) {
  const [busy, setBusy] = useState(false)
  const [selection, setSelection] = useState<Disposition>('true_positive')
  const [reason, setReason] = useState('')
  if (!docIds.length) return null
  const disposed = (DISPOSITIONS as readonly string[]).includes(str(row, 'status'))
  const many = docIds.length > 1
  const apply = async (next: Disposition | 'open') => {
    setBusy(true)
    try {
      const results = await Promise.all(docIds.map((id) => setDisposition({ data: { key: id, status: next, reason } })))
      if (results.some(Boolean)) onChanged()
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <label className="form-label" htmlFor="hp-ml-disposition-select">
        Disposition{many ? ` — applies to all ${docIds.length}` : ''}
      </label>
      <select
        id="hp-ml-disposition-select"
        className="form-input"
        value={selection}
        onChange={(event) => setSelection(event.target.value as Disposition)}
      >
        {DISPOSITIONS.map((value) => (
          <option key={value} value={value}>
            {value.replace('_', ' ')}
          </option>
        ))}
      </select>
      <input
        className="form-input"
        type="text"
        placeholder="why (kept beside the score for the labelled corpus)"
        value={reason}
        onChange={(event) => setReason(event.target.value)}
      />
      <button className="btn btn-sm btn-secondary" type="button" disabled={busy} onClick={() => void apply(selection)}>
        {busy ? '…' : disposed ? `Change to ${selection.replace('_', ' ')}` : 'Record disposition'}
      </button>
      {disposed ? (
        <button className="btn btn-sm btn-secondary" type="button" disabled={busy} onClick={() => void apply('open')}>
          Retract
        </button>
      ) : null}
    </>
  )
}

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/ml-anomalies?offset=${data.offset}&size=25`)
  })

// 24h KPI/aggregation stats, ported from ml_anomalies.go's
// mlAnomalyStatsFrom. total24h is exact (track_total_hits on the filtered
// store query); the severity/IP breakdowns are computed over the newest
// rows of the window — capped at 200 by the two size=100 pages this fetches,
// the same cap Go's polled snapshot (mlAnomalyCacheCap) imposed on these
// very numbers. #2179: `scanned` rides along so the UI can disclose that
// bound next to the buckets instead of presenting a prefix as fleet-wide.
type KpiStats = {
  total24h: number
  scanned: number
  bySeverity: { key: string; count: number }[]
  topSrcIPs: { key: string; count: number }[]
}

const fetchStats = createServerFn({ method: 'GET' }).handler(async (): Promise<KpiStats | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  const window = encodeURIComponent('@timestamp:[now-24h TO *]')
  const first = await serviceJSON<StorePage>(`/api/v1/store/ml-anomalies?offset=0&size=100&q=${window}`)
  if (!first) return null
  let rows = first.rows
  if (first.total > rows.length) {
    const second = await serviceJSON<StorePage>(`/api/v1/store/ml-anomalies?offset=100&size=100&q=${window}`)
    if (second) rows = rows.concat(second.rows)
  }
  const severityCounts = new Map<string, number>()
  const ipCounts = new Map<string, number>()
  for (const row of rows) {
    const severity = str(row, 'severity')
    if (severity) severityCounts.set(severity, (severityCounts.get(severity) ?? 0) + 1)
    const ip = str(row, 'src_ip')
    if (ip) ipCounts.set(ip, (ipCounts.get(ip) ?? 0) + 1)
  }
  const bySeverity = ['critical', 'high', 'medium', 'low']
    .filter((key) => (severityCounts.get(key) ?? 0) > 0)
    .map((key) => ({ key, count: severityCounts.get(key) as number }))
  const topSrcIPs = [...ipCounts.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => (a.count !== b.count ? b.count - a.count : a.key < b.key ? -1 : 1))
    .slice(0, 10)
  return { total24h: first.total, scanned: rows.length, bySeverity, topSrcIPs }
})

// #2396: the all-time open backlog is a server number, not a client
// derivation — the ack sidecar loads wholesale but the dispositioned
// population spans every page of history, so only the service sees enough
// to form the honest union. detail.rs's ml_anomaly_stats computes
// total − |dispositioned ∪ acked| under the same 10000-per-index ceiling
// its siblings carry. null keeps the tile on the old total−acked fallback
// while an un-deployed backend answers this route with a 404.
type Backlog = { total: number; open: number }
const fetchBacklog = createServerFn({ method: 'GET' }).handler(async (): Promise<Backlog | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  // Shape-checked rather than trusted: a stub backend (or any proxy that
  // answers a missing route with an empty JSON body) must land in the same
  // null fallback as an outright failure — an unvalidated {} would turn
  // Math.max(0, undefined) into a NaN on the Open tile.
  const body = await serviceJSON<Partial<Backlog>>('/api/v1/ml-anomalies/stats')
  return typeof body?.total === 'number' && typeof body?.open === 'number'
    ? { total: body.total, open: body.open }
    : null
})

function severityBadge(severity: string) {
  // critical→danger, high→warning, medium→info (ml_anomalies.html:65).
  const cls =
    severity === 'critical'
      ? 'badge badge--danger'
      : severity === 'high'
        ? 'badge badge--warning'
        : severity === 'medium'
          ? 'badge badge--info'
          : 'badge badge--muted'
  return <span className={cls}>{severity}</span>
}

function modelScore(row: StoreRow, key: string): string {
  const scores = row.model_scores as Record<string, unknown> | null | undefined
  const value = scores?.[key]
  return typeof value === 'number' ? value.toFixed(2) : '—'
}

// The two lifecycles in one bucket per row (#1968 kept both: on-document
// dispositions for verdicts worth labelling, sidecar acks for "seen, no
// verdict"). A disposition outranks acks; a partially acknowledged folded
// run reads as open because it still has findings to do.
function lifecycle(row: StoreRow, acks: Record<string, AckRecord>): 'open' | 'acknowledged' | Disposition {
  const doc = str(row, 'status')
  if ((DISPOSITIONS as readonly string[]).includes(doc)) return doc as Disposition
  const acked = idsFor(row).every((id) => acks[id]?.Acknowledged ?? false)
  return acked ? 'acknowledged' : 'open'
}

// Pivot to the exact source event, ported from mlAnomaly.SourceLink():
// source_event_id is a raw ES _id (not one of /events' normalized
// filters), so it goes through /history's raw-query search, pinned to its
// source index because auto-generated IDs are only unique per index.
function sourceEventLink(row: StoreRow) {
  const id = str(row, 'source_event_id')
  const index = str(row, 'source_index')
  if (!id || !index) return <span className="text-muted">—</span>
  return (
    <Link to="/history" search={{ q: `_id:"${id}" AND _index:"${index}"` }}>
      view source
    </Link>
  )
}

function buildColumns(acks: Record<string, AckRecord>): Column<StoreRow>[] {
  return [
    {
      header: 'time',
      render: (row) => {
        const folded = foldedCount(row)
        return (
          <>
            {when(str(row, '@timestamp'))}
            {folded > 1 ? (
              <>
                {' '}
                <span
                  className="badge badge--muted"
                  title={`${folded} anomalies from this address within the same second, scoring within 0.01 of each other, folded into this row. Acknowledging it covers all ${folded}.`}
                >
                  ×{folded}
                </span>
              </>
            ) : null}
          </>
        )
      },
    },
    { header: 'severity', render: (row) => severityBadge(str(row, 'severity')) },
    { header: 'score', className: 'n', render: (row) => num(row, 'composite_score').toFixed(2) },
    {
      header: 'source ip',
      className: 'v',
      render: (row) =>
        str(row, 'src_ip') ? (
          <>
            <Link to="/events" search={{ ip: str(row, 'src_ip') }}>
              {str(row, 'src_ip')}
            </Link>
            {str(row, 'src_country') ? <> <span className="badge badge--info" title={countryName(str(row, 'src_country'))}>{str(row, 'src_country')}</span></> : null}
          </>
        ) : (
          <span className="text-muted">unattributed</span>
        ),
    },
    {
      header: 'model scores',
      className: 'v',
      render: (row) => (
        <small>
          iso {modelScore(row, 'isolation_forest')} • lstm {modelScore(row, 'lstm_ae')} • hbos {modelScore(row, 'hbos')}
        </small>
      ),
    },
    { header: 'explanation', className: 'v', render: (row) => str(row, 'explanation') },
    { header: 'source event', className: 'v', render: (row) => sourceEventLink(row) },
    {
      header: 'status',
      render: (row) => {
        // A stored disposition (#1968) outranks the sidecar acks for its own
        // doc: once an operator has judged the finding, that is the status.
        // Folded siblings carry no fields client-side (collapseRuns keeps
        // ids only), but dispositions are applied group-wide from this very
        // UI, so reading the representative is honest in practice.
        const repStatus = str(row, 'status')
        if ((DISPOSITIONS as readonly string[]).includes(repStatus)) return dispositionBadge(repStatus)
        // #1566: a folded row speaks for every anomaly in it. Reading only
        // the representative's ack would show "acknowledged" over a run
        // that still has open findings inside it.
        const ids = idsFor(row)
        const open = ids.filter((id) => !(acks[id]?.Acknowledged ?? false))
        if (!open.length) {
          const by = acks[ids[0]]?.AckedBy
          return <span className="badge badge--muted">acknowledged{by ? ` by ${by}` : ''}</span>
        }
        return (
          <span className="badge badge--warning">
            {open.length === ids.length ? 'open' : `${open.length} of ${ids.length} open`}
          </span>
        )
      },
    },
    { header: 'event type', detail: true, render: (row) => str(row, 'event_type') },
    { header: 'dst port', detail: true, render: (row) => str(row, 'dst_port') },
    { header: 'proto', detail: true, render: (row) => str(row, 'proto') },
    { header: 'source index', detail: true, render: (row) => str(row, 'source_index') },
    // #1968: the alert must be judgeable without a second query — producing
    // sensor, our side of the flow, and exactly which threshold + promoted
    // model checkpoints produced this score (the #1959 forensics gap).
    {
      header: 'sensor',
      detail: true,
      render: (row) => str(row, 'sensor') || <span className="text-muted">—</span>,
    },
    { header: 'our ip', detail: true, render: (row) => str(row, 'dst_ip') || <span className="text-muted">—</span> },
    {
      header: 'their port',
      detail: true,
      className: 'n',
      render: (row) => {
        const port = num(row, 'src_port')
        return port > 0 ? String(port) : <span className="text-muted">—</span>
      },
    },
    {
      header: 'flow id',
      detail: true,
      className: 'v',
      render: (row) =>
        str(row, 'community_id') ? <code>{str(row, 'community_id')}</code> : <span className="text-muted">—</span>,
    },
    {
      header: 'threshold @ scoring',
      detail: true,
      className: 'n',
      render: (row) =>
        typeof row['alert_threshold'] === 'number' ? row['alert_threshold'].toFixed(4) : <span className="text-muted">—</span>,
    },
    {
      header: 'source class',
      detail: true,
      render: (row) => {
        const value = row['src_internal']
        if (value === undefined || value === null) return <span className="text-muted">—</span>
        return value ? 'internal' : 'external'
      },
    },
    {
      header: 'model state',
      detail: true,
      className: 'v',
      render: (row) =>
        str(row, 'model_state_id') ? (
          <code title="Promoted detector checkpoints behind the score — None until all three models have been trained">
            {str(row, 'model_state_id')}
          </code>
        ) : (
          <span className="badge badge--muted" title="No full detector trio was promoted when this score was computed">
            untrained detectors
          </span>
        ),
    },
  ]
}

export const Route = createFileRoute('/ml-anomalies')({ component: Page })

function Page() {
  const [rows, setRows] = useState<StoreRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
  const [acks, setAcks] = useState<Record<string, AckRecord>>({})
  const [stats, setStats] = useState<KpiStats | null>(null)
  const [backlog, setBacklog] = useState<Backlog | null>(null)
  // #2178: `if (cancelled || !page) return` treated a failed page read and a
  // cancelled mount identically -- the table kept its ghost skeleton and the
  // "Open (all time)" tile derived from a frozen zero.
  const [failed, setFailed] = useState(false)
  const [statsFailed, setStatsFailed] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const [severity, setSeverity] = useState('')
  const [eventType, setEventType] = useState('')
  const [status, setStatus] = useState('')
  const [filtersOpen, setFiltersOpen] = useState(false)
  const activeFilterCount = [severity, eventType, status].filter(Boolean).length

  const refreshAcks = () => {
    fetchAcks().then((result) => {
      if (result) setAcks(result)
    })
  }
  // Same lifecycle as refreshAcks: ack-all and dispositions both change the
  // open backlog, so both callers refresh this beside their own refetch.
  const refreshBacklog = () => {
    fetchBacklog().then((result) => {
      if (result) setBacklog(result)
    })
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps -- load once
  useEffect(refreshAcks, [])

  // Dispositions write onto the documents themselves (#1968), so applying
  // one means refetching rows, not just the ack index. Like any filter
  // change this collapses back to the first page.
  const reload = useCallback(async () => {
    const page = await fetchPage({ data: { offset: 0 } })
    if (!page) return
    setRows(page.rows)
    setTotal(page.total)
  }, [])

  useEffect(() => {
    let cancelled = false
    setRows(null)
    setTotal(0)
    setFailed(false)
    setStatsFailed(false)
    fetchPage({ data: { offset: 0 } })
      .then((page) => {
        if (cancelled) return
        if (!page) {
          setFailed(true)
          return
        }
        setRows(page.rows)
        setTotal(page.total)
      })
      .catch(() => {
        if (!cancelled) setFailed(true)
      })
    fetchStats()
      .then((result) => {
        if (cancelled) return
        if (!result) setStatsFailed(true)
        else setStats(result)
      })
      .catch(() => {
        if (!cancelled) setStatsFailed(true)
      })
    fetchBacklog().then((result) => {
      if (!cancelled && result) setBacklog(result)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- stable server fns + retry nonce
  }, [attempt])

  const viewMore = useCallback(async () => {
    if (!rows || loadingMore) return
    setLoadingMore(true)
    try {
      const page = await fetchPage({ data: { offset: rows.length } })
      if (page) setRows((current) => [...(current ?? []), ...page.rows])
    } finally {
      setLoadingMore(false)
    }
  }, [rows, loadingMore])

  const columns = useMemo(() => buildColumns(acks), [acks])
  // Open across the full index (#1566's "not just the current filter"),
  // not just the loaded page. #2396: computed by ml_anomaly_stats as
  // total − |dispositioned ∪ acked| — verdict-bearing documents stop
  // counting as open on the strength of their sidecar alone. Falls back to
  // the old sidecar-only arithmetic if the stats fetch returns nothing
  // (pre-#2396 backend still serving during a rolling deploy).
  const ackedCount = useMemo(() => Object.values(acks).filter((record) => record.Acknowledged).length, [acks])
  const openCount = backlog ? Math.max(0, backlog.open) : Math.max(0, total - ackedCount)
  const eventTypes = useMemo(
    () => [...new Set((rows ?? []).map((row) => str(row, 'event_type')).filter(Boolean))].sort(),
    [rows],
  )
  const filtered = useMemo(() => {
    if (!rows) return null
    return rows.filter((row) => {
      if (severity && str(row, 'severity') !== severity) return false
      if (eventType && str(row, 'event_type') !== eventType) return false
      // status now spans both lifecycles (#1968): the three on-document
      // dispositions plus the legacy open/acknowledged ack states.
      if (status && lifecycle(row, acks) !== status) return false
      return true
    })
  }, [rows, severity, eventType, status, acks])

  // #1566: fold last, over what the filters actually left on screen. Folding
  // first would group rows the filters then tear apart, leaving a badge
  // counting siblings that are no longer shown.
  const grouped = useMemo(() => (filtered ? collapseRuns(filtered) : null), [filtered])

  return (
    <>
      <InvestigateHeader
        label="Monitor"
        title="ML anomalies"
        subtitle="Statistical outliers across sensor traffic — isolation forest, HBOS and LSTM autoencoder scores composited per event."
        chips={
          <>
            <span className="chip">{total.toLocaleString('en-US')} anomalies</span>
            {openCount > 0 ? (
              <button
                className="btn btn-sm btn-secondary"
                type="button"
                onClick={() =>
                  // Its own copy, verbatim from ml_anomalies.html:38's
                  // data-hp-confirm-* attributes.
                  confirmAction({
                    title: 'Acknowledge every open anomaly?',
                    description: 'Acknowledging suppresses these from the open backlog until each is reopened individually.',
                    warning: `${openCount} open ${openCount === 1 ? 'anomaly' : 'anomalies'} across the full history, not just the current filter.`,
                    confirmLabel: 'Acknowledge all',
                    onConfirm: async () => {
                      const changed = await ackAll()
                      if (changed === null) throw new Error('Acknowledge all failed — admin access required?')
                      refreshAcks()
                      refreshBacklog()
                      return `Acknowledged ${changed} ${changed === 1 ? 'anomaly' : 'anomalies'}`
                    },
                  })
                }
              >
                acknowledge all ({openCount})
              </button>
            ) : null}
          </>
        }
      />
      <p className="note">
        Composite scores from ml-worker's three unsupervised models (Isolation Forest, LSTM-AE, HBOS) — statistical
        outliers, not confirmed attacks. Operator dispositions are stored on the anomaly itself and survive re-scoring.
      </p>
      <div className="metric-grid" id="ml-kpis">
        <div className="metric">
          <div className="metric__value">
            {stats ? (
              stats.total24h
            ) : statsFailed ? (
              /* #2178: the skeleton was only honest while the request lived. */
              <span className="note">load failed</span>
            ) : (
              <span className="skeleton-line" aria-hidden="true" />
            )}
          </div>
          <div className="metric__label">Anomalies, 24h</div>
        </div>
        {/* #1566: a "0 in 24h" tile directly above a table full of week-old
            open items read as "nothing to do here" — surface the open
            backlog alongside the 24h count. */}
        <div className="metric">
          <div className="metric__value">{failed ? <span className="note">load failed</span> : openCount}</div>
          <div className="metric__label">Open (all time)</div>
        </div>
        {(stats?.bySeverity ?? []).map((bucket) => (
          <div className="metric" key={bucket.key}>
            <div className="metric__value">{bucket.count}</div>
            <div className="metric__label">{bucket.key}</div>
          </div>
        ))}
      </div>
      {/* #2179: severity buckets are computed over the newest rows of the
          24h window (bounded by this fetch's 200-row cap), while the total24h
          tile above is exact — disclose when the two can disagree instead of
          letting a quiet prefix stand in for the window. */}
      {stats && stats.scanned < stats.total24h ? (
        <p className="note">
          Severity buckets cover the {stats.scanned.toLocaleString('en-US')} newest anomalies of{' '}
          {stats.total24h.toLocaleString('en-US')} in the 24h window.
        </p>
      ) : null}
      <div className="filters" id="ml-filters">
        <FiltersButton activeCount={activeFilterCount} onClick={() => setFiltersOpen(true)} />
      </div>
      {filtersOpen ? (
        <FiltersModal
          onClose={() => setFiltersOpen(false)}
          onApply={(event) => {
            const data = new FormData(event.currentTarget)
            setSeverity((data.get('severity') as string | null) ?? '')
            setEventType((data.get('event_type') as string | null) ?? '')
            setStatus((data.get('status') as string | null) ?? '')
            setFiltersOpen(false)
          }}
          onClear={() => {
            setSeverity('')
            setEventType('')
            setStatus('')
            setFiltersOpen(false)
          }}
          clearDisabled={activeFilterCount === 0}
        >
          <div className="settings-field">
            <label className="form-label" htmlFor="hp-ml-filter-severity">
              Severity
            </label>
            <select className="form-input" id="hp-ml-filter-severity" name="severity" defaultValue={severity}>
              <option value="">all severities</option>
              {['critical', 'high', 'medium', 'low'].map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>
          <div className="settings-field">
            <label className="form-label" htmlFor="hp-ml-filter-event-type">
              Event type
            </label>
            <select className="form-input" id="hp-ml-filter-event-type" name="event_type" defaultValue={eventType}>
              <option value="">all event types</option>
              {eventTypes.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>
          <div className="settings-field">
            <label className="form-label" htmlFor="hp-ml-filter-status">
              Status
            </label>
            <select className="form-input" id="hp-ml-filter-status" name="status" defaultValue={status}>
              <option value="">all statuses</option>
              <option value="open">open</option>
              <option value="acknowledged">acknowledged</option>
              {DISPOSITIONS.map((value) => (
                <option key={value} value={value}>
                  {value.replace('_', ' ')}
                </option>
              ))}
            </select>
          </div>
        </FiltersModal>
      ) : null}
      <div className="card wide" id="ml-anomaly-scores-card">
        <h2>Model scores over time</h2>
        <p className="note">
          One point per anomaly per detector model, plus the composite — agreement across models is stronger evidence than any
          single high score.
        </p>
        <EChart kind="scatter" url="/api/chart/ml-anomaly-scores" height={300} />
      </div>
      <ModelHealthCard />
      {rows === null && failed ? (
        /* #2178: the same null that meant "still loading" also meant "the
           read died" -- a failed page held ghost rows forever. */
        <ErrorStateBlock
          title="Anomaly scores failed to load"
          hint="The backend request failed — nothing here is cached."
          onRetry={() => setAttempt((n) => n + 1)}
        />
      ) : (
      <MasterDetailTable
        rows={grouped}
        columns={columns}
        rowKey={(row, index) => `${str(row, 'source_event_id')}-${index}`}
        emptyState={{
          title: 'No anomalies scored above the alert threshold yet',
          hint: 'ml-worker scores every event; only those past the threshold are listed here.',
        }}
        total={total}
        onViewMore={viewMore}
        loadingMore={loadingMore}
        inspectorTitle="Anomaly details"
        inspectorExtra={(row) => (
          <>
            {(() => {
              const doc = str(row, 'status')
              if (!(DISPOSITIONS as readonly string[]).includes(doc)) return null
              return (
                <p className="note">
                  Disposition: <strong>{doc.replace('_', ' ')}</strong>
                  {str(row, 'disposition_by') ? ` by ${str(row, 'disposition_by')}` : ''}
                  {str(row, 'disposed_at') ? ` at ${formatTimestamp(str(row, 'disposed_at'))}` : ''}
                  {str(row, 'disposition_reason') ? <> — “{str(row, 'disposition_reason')}”</> : null}
                </p>
              )
            })()}
            {acks[str(row, '_doc_id')]?.Acknowledged ? (
              <p className="note">
                Acknowledged by {acks[str(row, '_doc_id')]?.AckedBy || 'unknown'}
                {acks[str(row, '_doc_id')]?.AckedAt ? ` at ${formatTimestamp((acks[str(row, '_doc_id')]!.AckedAt as string))}` : ''}
              </p>
            ) : null}
            {/* Disposition first (#1968): it's the verdict an operator is
                here to record; the sidecar ack stays for the quick "seen"
                that carries no verdict. */}
            <DispositionControl docIds={idsFor(row)} row={row} onChanged={() => { void reload(); refreshBacklog() }} />
            <AckControl docIds={idsFor(row)} acks={acks} onChanged={() => { refreshAcks(); refreshBacklog() }} />
          </>
        )}
      />
      )}
      {stats && stats.topSrcIPs.length > 0 ? (
        <div className="card wide">
          <h2>Top source IPs, 24h</h2>
          <div className="card__scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>source ip</th>
                  <th>anomalies</th>
                </tr>
              </thead>
              <tbody>
                {stats.topSrcIPs.map((entry) => (
                  <tr key={entry.key}>
                    <td className="v">
                      <Link to="/events" search={{ ip: entry.key }}>
                        {entry.key}
                      </Link>
                    </td>
                    <td className="n">{entry.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </>
  )
}
