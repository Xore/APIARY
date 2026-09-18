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
import { Badge } from '../components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Skeleton } from '../components/ui/skeleton'
import { Table, TableBody, TableCell, TableRow } from '../components/ui/table'
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
  .validator((input: { cidr: string }) => input)
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
  { header: 'sensor', render: (row) => <Badge variant="secondary">{row.sensor}</Badge> },
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
    <Card className="min-w-0">
      <CardHeader><h2 className="font-semibold leading-none tracking-tight">{title}</h2></CardHeader>
      <CardContent>
        <Table>
          <TableBody>
            {rows.map((row) => (
              <TableRow key={row.key}>
                <TableCell className="w-24 text-right tabular-nums">{row.count.toLocaleString('en-US')}</TableCell>
                <TableCell className="break-words">{row.key}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
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
          <Link className="text-sm text-primary underline-offset-4 hover:underline" to="/campaigns">
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
            <Link className="text-sm text-primary underline-offset-4 hover:underline" to="/campaigns">
              &larr; campaigns
            </Link>
            {correlation ? <span className="text-sm text-muted-foreground">· {correlation.total.toLocaleString('en-US')} correlated events for this network ·</span> : null}
            {/* Go's /events?cidr= chip (intel.html:180) — the events API's
                ip filter is a term query on the ip-mapped source.ip field
                (events.rs), which accepts CIDR notation natively, so ?ip=
                carries the old ?cidr= role. */}
            <Link className="text-sm text-primary underline-offset-4 hover:underline" to="/events" search={{ ip: cidr, since: '168h' }}>
              in-memory events for this network
            </Link>
            {generated ? <Badge variant="secondary">generated {formatTimestamp(generated)}</Badge> : null}
          </>
        }
      />
      {!data ? <Card aria-label="Loading CIDR correlation"><CardContent className="flex flex-col gap-3 pt-6"><Skeleton className="h-7 w-1/3" /><Skeleton className="h-20 w-full" /></CardContent></Card> : null}
      {correlation ? (
        <div className="grid gap-4 sm:grid-cols-3">
          {([
            ['Total matches', correlation.total],
            ['Tunnel connections', correlation.tunnel_connections],
            ['Distinct sensors', correlation.sensors.length],
          ] as const).map(([label, count]) => (
            <Card key={label}><CardHeader><CardTitle className="text-lg"><h2>{label}</h2></CardTitle></CardHeader><CardContent className="text-2xl font-semibold tabular-nums">{count.toLocaleString('en-US')}</CardContent></Card>
          ))}
        </div>
      ) : null}
      {correlation ? (
        <p className="text-sm text-muted-foreground">
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
