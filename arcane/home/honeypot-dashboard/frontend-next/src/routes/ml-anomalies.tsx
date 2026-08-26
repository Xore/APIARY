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
import { confirmAction } from '../components/ConfirmDialog'
import { EChart } from '../components/EChart'
import { FiltersButton, FiltersModal } from '../components/FiltersModal'
import { formatTimestamp } from '../lib/time'
import { collapseRuns, foldedCount, idsFor } from '../lib/mlGrouping'
import { countryName } from '../lib/country'

type AckRecord = { Acknowledged: boolean; AckedBy?: string; AckedAt?: string }

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
  useEffect(() => {
    let cancelled = false
    fetchModelHealth().then((result) => {
      if (!cancelled) setModels(result ?? [])
    })
    return () => {
      cancelled = true
    }
  }, [])
  return (
    <div className="card wide" id="ml-model-health-card">
      <h2>Model health</h2>
      <p className="note">Each detector model's most recent retrain decision — accepted or rejected, and why.</p>
      {models === null ? (
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

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/ml-anomalies?offset=${data.offset}&size=25`)
  })

// 24h KPI/aggregation stats, ported from ml_anomalies.go's
// mlAnomalyStatsFrom. total24h is exact (track_total_hits on the filtered
// store query); the severity/IP breakdowns are computed over the newest
// 200 rows of the window — the same cap Go's polled snapshot
// (mlAnomalyCacheCap) imposed on these very numbers.
type KpiStats = {
  total24h: number
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
  return { total24h: first.total, bySeverity, topSrcIPs }
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
  ]
}

export const Route = createFileRoute('/ml-anomalies')({ component: Page })

function Page() {
  const [rows, setRows] = useState<StoreRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
  const [acks, setAcks] = useState<Record<string, AckRecord>>({})
  const [stats, setStats] = useState<KpiStats | null>(null)
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
  // eslint-disable-next-line react-hooks/exhaustive-deps -- load once
  useEffect(refreshAcks, [])

  useEffect(() => {
    let cancelled = false
    fetchPage({ data: { offset: 0 } }).then((page) => {
      if (cancelled || !page) return
      setRows(page.rows)
      setTotal(page.total)
    })
    fetchStats().then((result) => {
      if (!cancelled) setStats(result)
    })
    return () => {
      cancelled = true
    }
  }, [])

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
  // not just the loaded page: total is exact and the ack index only holds
  // rows an operator touched, so total − acked is the open backlog.
  const ackedCount = useMemo(() => Object.values(acks).filter((record) => record.Acknowledged).length, [acks])
  const openCount = Math.max(0, total - ackedCount)
  const eventTypes = useMemo(
    () => [...new Set((rows ?? []).map((row) => str(row, 'event_type')).filter(Boolean))].sort(),
    [rows],
  )
  const filtered = useMemo(() => {
    if (!rows) return null
    return rows.filter((row) => {
      if (severity && str(row, 'severity') !== severity) return false
      if (eventType && str(row, 'event_type') !== eventType) return false
      if (status) {
        const acked = acks[str(row, '_doc_id')]?.Acknowledged ?? false
        if (status === 'open' ? acked : !acked) return false
      }
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
        outliers, not confirmed attacks.
      </p>
      <div className="metric-grid" id="ml-kpis">
        <div className="metric">
          <div className="metric__value">{stats ? stats.total24h : <span className="skeleton-line" aria-hidden="true" />}</div>
          <div className="metric__label">Anomalies, 24h</div>
        </div>
        {/* #1566: a "0 in 24h" tile directly above a table full of week-old
            open items read as "nothing to do here" — surface the open
            backlog alongside the 24h count. */}
        <div className="metric">
          <div className="metric__value">{openCount}</div>
          <div className="metric__label">Open (all time)</div>
        </div>
        {(stats?.bySeverity ?? []).map((bucket) => (
          <div className="metric" key={bucket.key}>
            <div className="metric__value">{bucket.count}</div>
            <div className="metric__label">{bucket.key}</div>
          </div>
        ))}
      </div>
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
              <option value="">any status</option>
              <option value="open">open</option>
              <option value="acknowledged">acknowledged</option>
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
            {acks[str(row, '_doc_id')]?.Acknowledged ? (
              <p className="note">
                Acknowledged by {acks[str(row, '_doc_id')]?.AckedBy || 'unknown'}
                {acks[str(row, '_doc_id')]?.AckedAt ? ` at ${formatTimestamp((acks[str(row, '_doc_id')]!.AckedAt as string))}` : ''}
              </p>
            ) : null}
            <AckControl docIds={idsFor(row)} acks={acks} onChanged={refreshAcks} />
          </>
        )}
      />
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
