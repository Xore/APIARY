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
