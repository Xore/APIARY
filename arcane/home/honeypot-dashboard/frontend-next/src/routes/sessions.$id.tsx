// Session detail — one attacker session's whole story, chronologically:
// summary chips, curated attack-sequence detections, per-session
// leaderboards, ATT&CK techniques, and the full event list.
import { Link, createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { MailCard } from '../components/CapturedMail'
import { ErrorStateBlock } from '../components/ErrorState'
import type { JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'
import { countryName } from '../lib/country'
import { Card, CardContent, CardDescription, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Skeleton } from '../components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'

type Kv = { key: string; count: number }
type Technique = { id: string; name: string; domain: string; evidence: string; count: number; url: string }
type Sequence = { name: string; severity: string; summary: string }

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

type SessionDetail = {
  id: string
  ip: string
  country: string
  first: string
  last: string
  total: number
  sensors: Kv[]
  commands: Kv[]
  credentials: Kv[]
  payloads: Kv[]
  techniques: Technique[]
  sequences: Sequence[]
  events: EventRow[]
}

// #2178: serviceJSON collapsed "no session has this id" (a real 404) and
// "the request failed" into one null, so an outage rendered the terminal
// "No events found for this session id" — asserting absence about a
// session that may simply be unreachable. Tri-state now; the handler
// never rejects.
type SessionFetch = { state: 'session'; session: SessionDetail } | { state: 'missing' } | { state: 'failed' }

const fetchSession = createServerFn({ method: 'GET' })
  .validator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<SessionFetch> => {
    const { serviceJSONResult } = await import('../lib/backend.server')
    const result = await serviceJSONResult<SessionDetail>(`/api/v1/sessions/${encodeURIComponent(data.id)}`)
    if (result.ok) return { state: 'session', session: result.body }
    return result.status === 404 ? { state: 'missing' } : { state: 'failed' }
  })

// Captured mail (#1611 workstream B) lives in components/CapturedMail —
// shared with the sensor detail page since #1856.

export const Route = createFileRoute('/sessions/$id')({
  loader: async ({ params }) => ({ first: fetchSession({ data: { id: params.id } }) }),
  component: SessionPage,
})

const EVENT_COLUMNS: Column<EventRow>[] = [
  { header: 'time', render: (row) => formatTimestamp(row.time) },
  { header: 'sensor', render: (row) => <Badge variant="secondary">{row.sensor}</Badge> },
  { header: 'detail', className: 'v', render: (row) => row.detail || row.proto },
  {
    header: 'record',
    detail: true,
    render: (row) => <pre className="hp-md__preview">{JSON.stringify(row.record, null, 2)}</pre>,
  },
]

// A mailoney session that captured a DATA body — event_detail.rs's own
// mailoney_detail renders it as "DATA: <n> bytes  saved: <path>", so we
// detect it the same way classify.go's renderer keys off it: sensor
// "mailoney" plus a raw honeypot.event of "mail-body".
function hasCapturedMail(events: EventRow[]): boolean {
  return events.some((row) => {
    if (row.sensor !== 'mailoney') return false
    const honeypot = row.record?.honeypot as JsonRecord | undefined
    return honeypot?.event === 'mail-body'
  })
}

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
                <TableCell className="n">{row.count.toLocaleString('en-US')}</TableCell>
                <TableCell className="v">{row.key}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

function SessionPage() {
  const { first } = Route.useLoaderData()
  const { id } = Route.useParams()
  // #2178: `result ?? 'missing'` conflated a failed load with the terminal
  // not-found answer. Tri-state now: 'missing' only on the backend's own
  // 404, 'failed' named with a retry, null while loading.
  const [fetch, setFetch] = useState<SessionFetch | null>(null)
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    let cancelled = false
    setFetch(null)
    ;(attempt === 0 ? first : fetchSession({ data: { id } })).then((result) => {
      if (!cancelled) setFetch(result)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caller-owned loader stream
  }, [first, attempt])

  if (fetch?.state === 'missing') {
    return (
      <InvestigateHeader
        label="Investigate"
        title={`Session ${id}`}
        subtitle="No events found for this session id in the current window."
      />
    )
  }
  if (fetch?.state === 'failed') {
    return (
      <>
        <InvestigateHeader
          label="Investigate"
          title={`Session ${id.slice(0, 24)}`}
          subtitle="The session could not be loaded."
        />
        <ErrorStateBlock
          title="This session failed to load"
          hint="The backend request failed — this says nothing about whether the session exists in the window."
          onRetry={() => setAttempt((n) => n + 1)}
        />
      </>
    )
  }

  const detail = fetch?.state === 'session' ? fetch.session : null

  return (
    <>
      <InvestigateHeader
        label="Investigate"
        title={`Session ${id.slice(0, 24)}`}
        subtitle="Everything this attacker session did, in order — commands, credentials, payloads, and the derived behavior context."
        chips={
          <>
            {/* Quick pivots, session.html:13 — back to the explorer, the
                attacker's profile, this session's filtered event view, and
                the session-scoped CSV export (exports.rs events_csv accepts
                the same session= pivot filter as /api/v1/events). */}
            <Button asChild variant="outline" size="sm"><Link to="/events">← event explorer</Link></Button>
            {detail && detail.ip ? (
              <Button asChild variant="outline" size="sm"><Link to="/investigate/ip/$ip" params={{ ip: detail.ip }}>attacker profile</Link></Button>
            ) : null}
            <Button asChild variant="outline" size="sm"><a href={`/events?session=${encodeURIComponent(id)}`}>filtered events</a></Button>
            <Button asChild variant="outline" size="sm"><a href={`/api/export/events.csv?session=${encodeURIComponent(id)}`}>export CSV ↓</a></Button>
            {detail ? (
              <>
                <Badge variant="secondary">{detail.total.toLocaleString('en-US')} events</Badge>
                <Badge variant="secondary" title={countryName(detail.country)}>{detail.ip}{detail.country ? ` · ${detail.country}` : ''}</Badge>
                <Badge variant="secondary">
                  {formatTimestamp(detail.first)} → {formatTimestamp(detail.last)}
                </Badge>
              </>
            ) : null}
          </>
        }
      />
      {!fetch ? <Card className="col-span-full" aria-label="Loading session detail"><CardContent className="space-y-4 pt-6"><Skeleton className="h-6 w-40" /><Skeleton className="h-24 w-full" /></CardContent></Card> : null}
      {detail?.sequences.map((sequence) => (
        <Card className="col-span-full" key={sequence.name}>
          <CardHeader><h2 className="font-semibold leading-none tracking-tight">
            <Badge variant={sequence.severity === 'critical' ? 'destructive' : 'secondary'}>
              {sequence.severity}
            </Badge>{' '}
            {sequence.name}
          </h2><CardDescription>{sequence.summary}</CardDescription></CardHeader>
        </Card>
      ))}
      {detail && detail.techniques.length > 0 ? (
        <Card className="col-span-full min-w-0">
          <CardHeader><h2 className="font-semibold leading-none tracking-tight">MITRE ATT&amp;CK behavior mapping</h2>
          <CardDescription>Evidence-based behavioral context only; this does not identify or attribute an actor.</CardDescription></CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>domain</TableHead>
                  <TableHead>technique</TableHead>
                  <TableHead>observations</TableHead>
                  <TableHead>evidence</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {detail.techniques.map((technique) => (
                  <TableRow key={technique.id}>
                    <TableCell>
                      <Badge variant="secondary">{technique.domain}</Badge>
                    </TableCell>
                    <TableCell className="v">
                      <a href={technique.url} target="_blank" rel="noopener noreferrer">
                        {technique.id} — {technique.name}
                      </a>
                    </TableCell>
                    <TableCell className="n">{technique.count.toLocaleString('en-US')}</TableCell>
                    <TableCell className="v">{technique.evidence}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ) : null}
      {detail ? (
        <>
          {detail && hasCapturedMail(detail.events) ? <MailCard sessionId={id} /> : null}
          <MiniTable title="Sensors" rows={detail.sensors} />
          <MiniTable title="Commands" rows={detail.commands} />
          <MiniTable title="Credentials" rows={detail.credentials} />
          <MiniTable title="Payloads" rows={detail.payloads} />
        </>
      ) : null}
      <MasterDetailTable
        rows={detail ? detail.events : null}
        columns={EVENT_COLUMNS}
        rowKey={(row, index) => `${row.time}-${index}`}
        inspectorTitle="Event record"
        emptyState={{
          title: 'No events were recorded for this session',
          hint: 'The session was opened but nothing further was captured before it closed.',
        }}
      />
    </>
  )
}
