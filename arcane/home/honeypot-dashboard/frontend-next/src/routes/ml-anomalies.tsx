// ML anomalies — the ml-worker's composite-scored outliers.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { StoreListPage, str, num, when, type StorePage, type StoreRow } from '../components/StoreList'
import type { Column } from '../components/Investigate'
import { EChart } from '../components/EChart'

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
      />
    </>
  )
}
