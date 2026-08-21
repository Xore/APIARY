// Source health — per-sensor ingestion freshness + ES cluster state.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { formatTimestamp } from '../lib/time'

type SensorHealth = {
  sensor: string
  documents: number
  last_seen: string
  state: 'ACTIVE' | 'QUIET' | 'STALE'
}

type SourceHealth = {
  cluster_status: string
  total_documents: number
  sensors: SensorHealth[]
}

const fetchHealth = createServerFn({ method: 'GET' }).handler(async (): Promise<SourceHealth | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<SourceHealth>('/api/v1/source-health')
})

export const Route = createFileRoute('/source-health')({
  loader: async () => ({ first: fetchHealth() }),
  component: SourceHealthPage,
})

function stateBadge(state: SensorHealth['state']) {
  const cls = state === 'ACTIVE' ? 'badge badge--success' : state === 'QUIET' ? 'badge badge--warning' : 'badge badge--danger'
  return <span className={cls}>{state}</span>
}

const COLUMNS: Column<SensorHealth>[] = [
  { header: 'sensor', className: 'v', render: (row) => row.sensor },
  { header: 'state', render: (row) => stateBadge(row.state) },
  { header: 'documents', className: 'n', render: (row) => row.documents.toLocaleString('en-US') },
  { header: 'last event', render: (row) => formatTimestamp(row.last_seen) },
]

function clusterBadge(status: string) {
  const cls = status === 'green' ? 'badge badge--success' : status === 'yellow' ? 'badge badge--warning' : 'badge badge--danger'
  return <span className={cls}>cluster {status}</span>
}

function SourceHealthPage() {
  const { first } = Route.useLoaderData()
  const [health, setHealth] = useState<SourceHealth | null>(null)
  useEffect(() => {
    let cancelled = false
    first.then((result) => {
      if (!cancelled && result) setHealth(result)
    })
    return () => {
      cancelled = true
    }
  }, [first])
  return (
    <>
      <InvestigateHeader
        label="Operations"
        title="Source health"
        subtitle="Is every sensor still feeding the pipeline? Freshness per source, ordered by most recent event."
        chips={
          health ? (
            <>
              {clusterBadge(health.cluster_status)}
              <span className="chip">{health.total_documents.toLocaleString('en-US')} documents</span>
              <span className="chip">{health.sensors.length} sensors</span>
            </>
          ) : undefined
        }
      />
      <MasterDetailTable
        rows={health ? health.sensors : null}
        columns={COLUMNS}
        rowKey={(row) => row.sensor}
        inspectorTitle="Sensor details"
      />
    </>
  )
}
