// ML anomalies — the ml-worker's composite-scored outliers.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { StoreListPage, str, num, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'
import { EChart } from '../components/EChart'

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
                  <td>{model.timestamp ? model.timestamp.replace('T', ' ').slice(0, 19) : '—'}</td>
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
    if (user && user.role !== 'admin') return false
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/ml-anomalies/ack', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...data, actor: user?.username ?? '' }),
    })
    return response.ok
  })

function AckControl({ docId, acks, onChanged }: { docId: string; acks: Record<string, AckRecord>; onChanged: () => void }) {
  const [busy, setBusy] = useState(false)
  if (!docId) return null
  const acked = acks[docId]?.Acknowledged ?? false
  return (
    <button
      className="btn btn-secondary btn-sm"
      type="button"
      disabled={busy}
      onClick={async () => {
        setBusy(true)
        try {
          if (await setAck({ data: { key: docId, ack: !acked } })) onChanged()
        } finally {
          setBusy(false)
        }
      }}
    >
      {busy ? '…' : acked ? 'Reopen anomaly' : 'Acknowledge anomaly'}
    </button>
  )
}

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/ml-anomalies?offset=${data.offset}&size=25`)
  })

function severityBadge(severity: string) {
  const cls = severity === 'high' || severity === 'critical' ? 'badge badge--danger' : severity === 'medium' ? 'badge badge--warning' : 'badge badge--muted'
  return <span className={cls}>{severity}</span>
}

const COLUMNS: Column<StoreRow>[] = [
  { header: 'time', render: (row) => when(str(row, '@timestamp')) },
  { header: 'severity', render: (row) => severityBadge(str(row, 'severity')) },
  { header: 'score', className: 'n', render: (row) => num(row, 'composite_score').toFixed(2) },
  { header: 'source ip', className: 'v', render: (row) => str(row, 'src_ip') },
  { header: 'explanation', className: 'v', render: (row) => str(row, 'explanation') },
  { header: 'event type', detail: true, render: (row) => str(row, 'event_type') },
  { header: 'dst port', detail: true, render: (row) => str(row, 'dst_port') },
  { header: 'proto', detail: true, render: (row) => str(row, 'proto') },
  { header: 'source index', detail: true, render: (row) => str(row, 'source_index') },
]

export const Route = createFileRoute('/ml-anomalies')({ component: Page })

function Page() {
  const [acks, setAcks] = useState<Record<string, AckRecord>>({})
  const refreshAcks = () => {
    fetchAcks().then((result) => {
      if (result) setAcks(result)
    })
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps -- load once
  useEffect(refreshAcks, [])
  return (
    <>
      <div className="card wide" id="ml-anomaly-scores-card">
        <h2>Model scores over time</h2>
        <p className="note">
          One point per anomaly per detector model, plus the composite — agreement across models is stronger evidence than any
          single high score.
        </p>
        <EChart kind="scatter" url="/api/chart/ml-anomaly-scores" height={300} />
      </div>
      <ModelHealthCard />
      <StoreListPage
      fetchPage={fetchPage}
      label="Monitor"
      title="ML anomalies"
      subtitle="Statistical outliers across sensor traffic — isolation forest, HBOS and LSTM autoencoder scores composited per event."
      columns={COLUMNS}
      rowKey={(row, index) => `${str(row, 'source_event_id')}-${index}`}
      inspectorTitle="Anomaly details"
      chipNoun="anomalies"
      inspectorExtra={(row) => (
        <>
          {acks[str(row, '_doc_id')]?.Acknowledged ? (
            <p className="note">
              Acknowledged by {acks[str(row, '_doc_id')]?.AckedBy || 'unknown'}
              {acks[str(row, '_doc_id')]?.AckedAt ? ` at ${(acks[str(row, '_doc_id')]!.AckedAt as string).slice(0, 19).replace('T', ' ')}` : ''}
            </p>
          ) : null}
          <AckControl docId={str(row, '_doc_id')} acks={acks} onChanged={refreshAcks} />
        </>
      )}
      />
    </>
  )
}
