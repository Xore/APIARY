// Infrastructure clusters — compact list columns, heavy detail in the
// click-open inspector (per the investigate-consistency round). Per-row
// drill-downs mirror dashboard/ui/intel.html's clusters-body: shared-value
// cells and an "investigate →" column, both into the cluster correlation.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { formatTimestamp } from '../lib/time'

type ClusterRow = {
  kind: string
  value: string
  sources: number
  events: number
  sensors: string[]
  generated?: string
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

function drill(row: ClusterRow, children: React.ReactNode) {
  return (
    <Link to="/investigate/cluster" search={{ kind: row.kind, value: row.value }}>
      {children}
    </Link>
  )
}

const COLUMNS: Column<ClusterRow>[] = [
  { header: 'cluster type', render: (row) => <span className="badge badge--muted">{row.kind}</span> },
  { header: 'shared value', className: 'v', render: (row) => drill(row, row.value) },
  { header: 'source IPs', className: 'n', render: (row) => drill(row, row.sources.toLocaleString('en-US')) },
  { header: 'events', className: 'n', render: (row) => drill(row, row.events.toLocaleString('en-US')) },
  {
    header: 'coverage',
    detail: true,
    render: (row) => `${row.sensors.length} sensors: ${row.sensors.join(' ')}`,
  },
  {
    header: '',
    render: (row) => (
      <Link className="lnk" to="/investigate/cluster" search={{ kind: row.kind, value: row.value }}>
        investigate &rarr;
      </Link>
    ),
  },
  {
    // Header is a lone space, not '': MasterDetailTable keys cells by
    // header text, and intel.html's clusters table has two blank link
    // columns just like this.
    header: ' ',
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
  const generated = rows?.find((row) => row.generated)?.generated
  return (
    <>
      <InvestigateHeader
        label="Correlation"
        title="Infrastructure clusters"
        subtitle="Shared fingerprints, payloads, autonomous systems, and provider classifications across multiple source IPs."
        chips={
          <>
            <span className="chip">{rows ? `${rows.length} shared pivots` : '…'}</span>
            <a className="chip" title="Download every infrastructure cluster as CSV" href="/api/export/clusters.csv">
              ⇩ CSV
            </a>
            {generated ? <span className="chip">generated {formatTimestamp(generated)}</span> : null}
          </>
        }
      />
      <MasterDetailTable
        rows={rows}
        columns={COLUMNS}
        rowKey={(row) => `${row.kind}:${row.value}`}
        detailHref={(row) => `/investigate/cluster?kind=${encodeURIComponent(row.kind)}&value=${encodeURIComponent(row.value)}`}
        emptyState={{
          title: 'No multi-source pivots are present in the current correlation window',
          hint: 'Clusters appear once two or more source IPs share a strong signal.',
        }}
        inspectorTitle="Row details"
      />
    </>
  )
}
