// Network (CIDR) correlation — #354: everything Elasticsearch has
// correlated for a whole address range across honeypot, Suricata, and
// portbridge tunnel records. Entry point: campaigns.tsx's "ES →" link.
// {cidr} always carries a literal "/" (CIDR notation), so it's
// percent-encoded on every hop — see backend-service/src/investigate.rs's
// cidr handler doc comment for why a single encode/decode pass is safe.
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

type CidrCorrelation = {
  cidr: string
  correlation: Correlation
}

const fetchCorrelation = createServerFn({ method: 'GET' })
  .inputValidator((input: { cidr: string }) => input)
  .handler(async ({ data }): Promise<CidrCorrelation | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<CidrCorrelation>(`/api/v1/investigate/cidr/${encodeURIComponent(data.cidr)}`)
  })

export const Route = createFileRoute('/investigate/cidr/$cidr')({
  loader: async ({ params }) => ({ first: fetchCorrelation({ data: { cidr: params.cidr } }) }),
  component: InvestigateCidr,
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

function InvestigateCidr() {
  const { first } = Route.useLoaderData()
  const { cidr } = Route.useParams()
  const [data, setData] = useState<CidrCorrelation | null | 'missing'>(null)
  // Snapshot time for the header's "generated" chip — the Go shell stamped
  // .Generated at render time (intel.html's cidr-correlation header), and
  // fetch-arrival is this tier's equivalent moment.
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

  if (data === 'missing') {
    return (
      <InvestigateHeader
        label="Correlation"
        title={cidr}
        subtitle="This network could not be correlated — invalid range, or the correlation backend is unavailable."
        chips={
          <Link className="chip" to="/campaigns">
            &larr; campaigns
          </Link>
        }
      />
    )
  }

  const correlation = data ? data.correlation : null

  return (
    <>
      <InvestigateHeader
        label="Correlation"
        title={cidr}
        subtitle="#354: everything Elasticsearch has correlated for this network across honeypot, Suricata, and portbridge tunnel records."
        chips={
          <>
            <Link className="chip" to="/campaigns">
              &larr; campaigns
            </Link>
            {/* Go's /events?cidr= chip (intel.html:180) — the events API's
                ip filter is a term query on the ip-mapped source.ip field
                (events.rs), which accepts CIDR notation natively, so ?ip=
                carries the old ?cidr= role. */}
            <Link className="chip" to="/events" search={{ ip: cidr, since: '168h' }}>
              in-memory events for this network
            </Link>
            {generated ? <span className="chip">generated {formatTimestamp(generated)}</span> : null}
          </>
        }
      />
      {correlation ? (
        <div className="metric-grid">
          <div className="metric">
            <div className="metric__value">{correlation.total.toLocaleString('en-US')}</div>
            <div className="metric__label">Total matches</div>
          </div>
          <div className="metric">
            <div className="metric__value">{correlation.tunnel_connections.toLocaleString('en-US')}</div>
            <div className="metric__label">Tunnel connections</div>
          </div>
          <div className="metric">
            <div className="metric__value">{correlation.sensors.length}</div>
            <div className="metric__label">Distinct sensors</div>
          </div>
        </div>
      ) : null}
      {correlation ? (
        <p className="note">
          {correlation.truncated
            ? `Showing the ${correlation.records.length} most recent of ${correlation.total.toLocaleString('en-US')} total matches.`
            : 'Newest first.'}
          {correlation.tunnel_os_guesses.length > 0
            ? ` p0f OS guesses seen over this network’s tunnel connections: ${correlation.tunnel_os_guesses.join(', ')}.`
            : ''}
        </p>
      ) : null}
      <MiniTable title="Sensors" rows={correlation ? correlation.sensors : []} />
      <MasterDetailTable
        rows={correlation ? correlation.records : null}
        columns={RECORD_COLUMNS}
        rowKey={(row, index) => `${row.time}-${index}`}
        inspectorTitle="Correlated record"
        emptyState={{
          title: 'No correlated records were found for this network',
          hint: 'Elasticsearch has nothing indexed against this CIDR yet.',
        }}
      />
    </>
  )
}
