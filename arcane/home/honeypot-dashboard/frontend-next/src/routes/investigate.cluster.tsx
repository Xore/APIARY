// Cluster correlation — #354: everything Elasticsearch has correlated for
// a cluster's member source IPs (shared fingerprint/payload-hash/ASN/
// provider class). Entry point: clusters.tsx's "ES →" link. kind/value are
// separate query params (not a packed path segment) — see
// backend-service/src/investigate.rs's cluster handler doc comment for why
// (a shared value containing a space, e.g. "Autonomous system", doesn't
// round-trip identically through one escaped path segment).
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import type { JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'

type Kv = { key: string; count: number }

type EventRow = {
  time: string
  sensor: string
  src_ip: string
  country: string
  port: string
  proto: string
  detail: string
  session: string
  record: JsonRecord
}

type Correlation = {
  total: number
  truncated: boolean
  sensors: Kv[]
  tunnel_connections: number
  tunnel_os_guesses: string[]
  records: EventRow[]
}

type ClusterCorrelation = {
  kind: string
  value: string
  ip_count: number
  correlation: Correlation
}

type SearchParams = { kind: string; value: string }

const fetchCorrelation = createServerFn({ method: 'GET' })
  .inputValidator((input: SearchParams) => input)
  .handler(async ({ data }): Promise<ClusterCorrelation | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    const params = new URLSearchParams({ kind: data.kind, value: data.value })
    return serviceJSON<ClusterCorrelation>(`/api/v1/investigate/cluster?${params.toString()}`)
  })

export const Route = createFileRoute('/investigate/cluster')({
  validateSearch: (search: Record<string, unknown>): SearchParams => ({
    kind: typeof search.kind === 'string' ? search.kind : '',
    value: typeof search.value === 'string' ? search.value : '',
  }),
  loaderDeps: ({ search }) => search,
  loader: async ({ deps }) => ({ first: fetchCorrelation({ data: deps }) }),
  component: InvestigateCluster,
})

const RECORD_COLUMNS: Column<EventRow>[] = [
  { header: 'time', render: (row) => formatTimestamp(row.time) },
  { header: 'sensor', render: (row) => <span className="badge badge--muted">{row.sensor}</span> },
  { header: 'detail', className: 'v', render: (row) => row.detail || row.proto },
  {
    header: 'record',
    detail: true,
    render: (row) => <pre className="hp-md__preview">{JSON.stringify(row.record, null, 2)}</pre>,
  },
]

function MiniTable({ title, rows }: { title: string; rows: Kv[] }) {
  if (rows.length === 0) return null
  return (
    <div className="card half">
      <h2>{title}</h2>
      <div className="card__scroll">
        <table className="data-table">
          <tbody>
            {rows.map((row) => (
              <tr key={row.key}>
                <td className="n">{row.count.toLocaleString('en-US')}</td>
                <td className="v">{row.key}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function InvestigateCluster() {
  const { first } = Route.useLoaderData()
  const { kind, value } = Route.useSearch()
  const [data, setData] = useState<ClusterCorrelation | null | 'missing'>(null)
  // Snapshot time for the header's "generated" chip — the Go shell stamped
  // .Generated at render time (intel.html's cluster-correlation header),
  // and fetch-arrival is this tier's equivalent moment.
  const [generated, setGenerated] = useState('')
  useEffect(() => {
    let cancelled = false
    first.then((result) => {
      if (cancelled) return
      setData(result ?? 'missing')
      setGenerated(new Date().toISOString())
    })
    return () => {
      cancelled = true
    }
  }, [first])

  const backChip = (
    <>
      <Link className="chip" to="/clusters">
        &larr; clusters
      </Link>
      {generated ? <span className="chip">generated {formatTimestamp(generated)}</span> : null}
    </>
  )

  if (data === 'missing') {
    return (
      <InvestigateHeader
        label="Correlation"
        title={value || kind}
        subtitle="This cluster could not be correlated — unknown kind, fewer than two member IPs, or the correlation backend is unavailable."
        chips={backChip}
      />
    )
  }

  const correlation = data ? data.correlation : null

  return (
    <>
      <InvestigateHeader
        label="Correlation"
        title={`${kind}: ${value}`}
        subtitle={
          data
            ? `#354: everything Elasticsearch has correlated across this cluster's ${data.ip_count.toLocaleString('en-US')} member source IPs.`
            : "#354: everything Elasticsearch has correlated across this cluster's member source IPs."
        }
        chips={backChip}
      />
      {correlation && data ? (
        <div className="tw:grid tw:grid-cols-2 tw:sm:grid-cols-3 tw:gap-3 tw:mb-6">
          <div className="metric">
            <div className="metric__value">{data.ip_count.toLocaleString('en-US')}</div>
            <div className="metric__label">Member IPs</div>
          </div>
          <div className="metric">
            <div className="metric__value">{correlation.total.toLocaleString('en-US')}</div>
            <div className="metric__label">Total matches</div>
          </div>
          <div className="metric">
            <div className="metric__value">{correlation.tunnel_connections.toLocaleString('en-US')}</div>
            <div className="metric__label">Tunnel connections</div>
          </div>
        </div>
      ) : null}
      {correlation ? (
        <p className="note">
          {correlation.truncated
            ? `Showing the ${correlation.records.length} most recent of ${correlation.total.toLocaleString('en-US')} total matches.`
            : 'Newest first.'}
          {correlation.tunnel_os_guesses.length > 0
            ? ` p0f OS guesses seen across this cluster’s tunnel connections: ${correlation.tunnel_os_guesses.join(', ')}.`
            : ''}
        </p>
      ) : null}
      <MiniTable title="Sensors" rows={correlation ? correlation.sensors : []} />
      <MasterDetailTable
        rows={correlation ? correlation.records : null}
        columns={RECORD_COLUMNS}
        rowKey={(row, index) => `${row.time}-${index}`}
        inspectorTitle="Correlated record"
      />
    </>
  )
}
