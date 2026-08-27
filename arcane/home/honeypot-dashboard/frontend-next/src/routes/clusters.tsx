// Infrastructure clusters — compact list columns, heavy detail in the
// click-open inspector (per the investigate-consistency round). Per-row
// drill-downs mirror dashboard/ui/intel.html's clusters-body: shared-value
// cells and an "investigate →" column, both into the cluster correlation.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'
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
    // #1566: a cluster seen on one sensor read "1 sensors:".
    render: (row) =>
      `${row.sensors.length} ${row.sensors.length === 1 ? 'sensor' : 'sensors'}: ${row.sensors.join(' ')}`,
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
  const streamed = Route.useLoaderData().page
  // #2178: the streamed loader resolves null on any backend failure -- which
  // used to be indistinguishable from "still streaming", so the table sat in
  // opening ghosts forever. A failed stream now surfaces the error block,
  // separate from loading and from a genuinely empty window.
  const [page, setPage] = useState(streamed)
  useEffect(() => setPage(streamed), [streamed])
  const [rows, setRows] = useState<ClusterRow[] | null>(null)
  const [failed, setFailed] = useState(false)
  const retry = useCallback(() => setPage(fetchClusters()), [])
  useEffect(() => {
    let cancelled = false
    setRows(null)
    setFailed(false)
    page.then((result) => {
      if (cancelled) return
      if (result) setRows(result.rows)
      else setFailed(true)
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
            <span className="chip">{rows ? `${rows.length} shared pivots` : failed ? 'load failed' : '…'}</span>
            <a className="chip" title="Download every infrastructure cluster as CSV" href="/api/export/clusters.csv">
              ⇩ CSV
            </a>
            {generated ? <span className="chip">generated {formatTimestamp(generated)}</span> : null}
          </>
        }
      />
      {failed ? (
        <ErrorStateBlock
          title="Infrastructure clusters failed to load"
          hint="The backend request failed — nothing here is cached."
          onRetry={retry}
        />
      ) : (
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
      )}
    </>
  )
}
