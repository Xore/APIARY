// Infrastructure clusters — compact list columns, heavy detail in the
// click-open inspector (per the investigate-consistency round).
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'

type ClusterRow = {
  kind: string
  value: string
  sources: number
  events: number
  sensors: string[]
}

type Page = { total: number; rows: ClusterRow[] }

const fetchClusters = createServerFn({ method: 'GET' }).handler(async () => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<Page>('/api/v1/clusters?size=100')
})

export const Route = createFileRoute('/clusters')({
  loader: async () => ({ page: fetchClusters() }),
  component: Clusters,
})

const COLUMNS: Column<ClusterRow>[] = [
  { header: 'cluster type', render: (row) => <span className="badge badge--muted">{row.kind}</span> },
  { header: 'shared value', className: 'v', render: (row) => row.value },
  { header: 'source IPs', className: 'n', render: (row) => row.sources.toLocaleString('en-US') },
  { header: 'events', className: 'n', render: (row) => row.events.toLocaleString('en-US') },
  {
    header: 'coverage',
    detail: true,
    render: (row) => `${row.sensors.length} sensors: ${row.sensors.join(' ')}`,
  },
  {
    header: '',
    render: (row) => (
      <Link
        className="lnk"
        to="/investigate/cluster"
        search={{ kind: row.kind, value: row.value }}
        title="#354: everything Elasticsearch has correlated for this cluster's member IPs"
      >
        ES &rarr;
      </Link>
    ),
  },
]

function Clusters() {
  const { page } = Route.useLoaderData()
  const [rows, setRows] = useState<ClusterRow[] | null>(null)
  useEffect(() => {
    let cancelled = false
    page.then((result) => {
      if (!cancelled && result) setRows(result.rows)
    })
    return () => {
      cancelled = true
    }
  }, [page])
  return (
    <>
      <InvestigateHeader
        label="Correlation"
        title="Infrastructure clusters"
        subtitle="Shared fingerprints, payloads, autonomous systems, and provider classifications across multiple source IPs."
        chips={<span className="chip">{rows ? `${rows.length} shared pivots` : '…'}</span>}
      />
      <MasterDetailTable
        rows={rows}
        columns={COLUMNS}
        rowKey={(row) => `${row.kind}:${row.value}`}
        inspectorTitle="Row details"
      />
    </>
  )
}
