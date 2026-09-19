// Everything behind one event, on a full page (#1868).
//
// The events list opens a record pane beside the table. That is the right
// shape for scanning — the list stays in view — and the wrong shape for
// working an event: the pane is narrow, it dies on navigation, it cannot
// be linked to or shared, and it holds one document and nothing around it.
// No session, no flow, no payload, no other sensor that saw the same
// connection. There was no full view of an event anywhere in the
// dashboard.
//
// This is that view. It shows the event read in its sensor's own terms
// (the same protocol specs the sensor detail page uses), the complete
// document, and the three questions the pane could never answer: what else
// happened in this session, what else happened on this connection, and
// what else this source did.
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Skeleton } from '../components/ui/skeleton'
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { Alert, AlertTitle, AlertDescription } from '../components/ui/alert'
import { Empty, EmptyHeader, EmptyTitle, EmptyDescription } from '../components/ui/empty'
import { copyWithFlash } from '../lib/flash'
import { type JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'
import { fieldText, meaningfulFields, protocolFor, readField } from '../lib/sensorProtocols'

type RelatedEvent = { time: string; sensor: string; src_ip: string; detail: string }
type Relation = { key: string; total: number; rows: RelatedEvent[] }
// #2047's materialized cross-family summary (flow-links-v1). GET
// /api/v1/event/{id} (event_page.rs) embeds this as the raw flv1-* doc via
// a plain get_doc — it does NOT splice `this_event_in_sample` the way the
// sibling GET /api/v1/event/{id}/connections endpoint does (correlations.rs's
// event_connections); that splice lives on a different route this page
// doesn't call. Rather than add a second fetch just for one boolean, the
// same fact is derived client-side below from `event_ids`, which this raw
// doc already carries. Absent whenever the flow never reached 2+ sensor
// families — most flows never qualify, and that's a normal answer, not an
// error, so this stays optional rather than a field the page can assume.
type FlowLink = {
  community_id: string
  families: string[]
  sensors: string[]
  src_ip: string
  dst_ip: string
  dst_port: number
  first: string
  last: string
  events: number
  event_ids: string[]
}
type EventPage = {
  id: string
  index: string
  time: string
  sensor: string
  src_ip: string
  session: string
  community_id: string
  hashes: string[]
  record: JsonRecord
  session_events: Relation
  flow_events: Relation
  source_events: Relation
  flow_link?: FlowLink | null
}

// #2178: serviceJSON collapsed "no event with this id" (a real 404 — the
// document aged out) into the same null as "the request failed", so an
// outage rendered as confident absence prose about this specific id. The
// union keeps the two separable; the handler never rejects.
type EventFetch = { state: 'event'; event: EventPage } | { state: 'missing' } | { state: 'failed' }

const fetchEvent = createServerFn({ method: 'GET' })
  .validator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<EventFetch> => {
    const { serviceJSONResult } = await import('../lib/backend.server')
    const result = await serviceJSONResult<EventPage>(`/api/v1/event/${encodeURIComponent(data.id)}`)
    if (result.ok) return { state: 'event', event: result.body }
    return result.status === 404 ? { state: 'missing' } : { state: 'failed' }
  })

export const Route = createFileRoute('/event/$id')({
  loader: async ({ params }) => ({ first: fetchEvent({ data: { id: params.id } }) }),
  component: EventDetailPage,
})

function RelationCard({
  title,
  hint,
  relation,
  href,
  hrefLabel,
}: {
  title: string
  hint: string
  relation: Relation
  href?: string
  hrefLabel?: string
}) {
  if (!relation.key) return null
  return (
    <Card className="min-w-0">
      <CardHeader><CardTitle><h2 className="font-serif text-base font-medium">{title}</h2></CardTitle></CardHeader><CardContent className="flex min-w-0 flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        {hint} <code>{relation.key}</code>
        {relation.total > relation.rows.length
          ? ` — ${relation.total.toLocaleString('en-US')} in total, newest ${relation.rows.length} shown.`
          : ''}
      </p>
      {relation.rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">Nothing else matched.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>time</TableHead>
              <TableHead>sensor</TableHead>
              <TableHead>source</TableHead>
              <TableHead>what happened</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {relation.rows.map((row, index) => (
              <TableRow key={`${row.time}-${index}`}>
                <TableCell>{formatTimestamp(row.time)}</TableCell>
                <TableCell>
                  <Badge variant="secondary" className={`badge b-${row.sensor}`}>{row.sensor}</Badge>
                </TableCell>
                <TableCell className="break-all">{row.src_ip || '—'}</TableCell>
                <TableCell className="break-all">{row.detail || '—'}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {href ? (
        <p className="text-sm text-muted-foreground">
          <a className="text-primary underline-offset-4 hover:underline" href={href}>
            {hrefLabel} →
          </a>
        </p>
      ) : null}
    </CardContent></Card>
  )
}

// #2047's cross-family flow summary. An absent flow_link means this event's
// connection never reached two sensor families — normal, not an error — so
// this renders nothing at all rather than an empty-state card that would
// read as a complaint about a common case.
function FlowLinkCard({ link, currentId }: { link: FlowLink; currentId: string }) {
  return (
    <Card className="min-w-0">
      <CardHeader><CardTitle><h2 className="font-serif text-base font-medium">Same connection, seen by {link.families.length} pipelines</h2></CardTitle></CardHeader><CardContent className="flex min-w-0 flex-col gap-4">
      <p className="text-sm text-muted-foreground">
        <code>{link.community_id}</code> — {link.src_ip || '—'} → {link.dst_ip || '—'}
        {link.dst_port ? `:${link.dst_port}` : ''}, {link.events.toLocaleString('en-US')} events across{' '}
        {formatTimestamp(link.first)} – {formatTimestamp(link.last)}.
      </p>
      <div className="flex flex-wrap gap-2 text-sm text-muted-foreground">
        {link.families.map((family) => (
          <Badge key={family} variant="secondary">
            {family}
          </Badge>
        ))}
      </div>
      {link.event_ids.length > 0 ? (
        <ul>
          {link.event_ids.map((id) =>
            // #2047's this_event_in_sample marker: when this event's own id
            // is in the sample, say so plainly rather than rendering it as
            // just another link that happens to point at the page you're
            // already on.
            id === currentId ? (
              <li key={id}>
                <code>{id}</code> — this record
              </li>
            ) : (
              <li key={id}>
                <Link to="/event/$id" params={{ id }}>
                  <code>{id}</code>
                </Link>
              </li>
            ),
          )}
        </ul>
      ) : null}
      <p className="text-sm text-muted-foreground">
        <Link className="text-primary underline-offset-4 hover:underline" to="/events" search={{ community_id: link.community_id }}>
          Open the full flow in the event explorer →
        </Link>
      </p>
    </CardContent></Card>
  )
}

function EventDetailPage() {
  const { id } = Route.useParams()
  const { first } = Route.useLoaderData()
  // #2178: `result ?? 'missing'` collapsed a failed request into the same
  // "this event could not be found" prose as a genuine aged-out id. The
  // fetch now returns an explicit tri-state; 'failed' renders an error
  // block with retry instead of asserting absence.
  const [fetch, setFetch] = useState<EventFetch | null>(null)
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    setFetch(null)
    ;(attempt === 0 ? first : fetchEvent({ data: { id } })).then((result) => {
      if (!cancelled) setFetch(result)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caller-owned loader stream
  }, [first, attempt])

  if (fetch?.state === 'failed') {
    return (
      <section className="flex min-w-0 flex-col gap-6">
        <InvestigateHeader label="Investigate" title="Event" subtitle="The record could not be loaded." />
        <Alert variant="destructive">
          <AlertTitle>This event failed to load</AlertTitle>
          <AlertDescription className="flex flex-col items-start gap-4">
            <p>The backend request failed — this says nothing about whether the event exists.</p>
            <Button variant="outline" onClick={() => setAttempt((n) => n + 1)}>Retry</Button>
          </AlertDescription>
        </Alert>
      </section>
    )
  }

  if (fetch?.state === 'missing') {
    return (
      <section className="flex min-w-0 flex-col gap-6">
        <InvestigateHeader label="Investigate" title="Event" subtitle="This event could not be found." />
        <Empty className="border">
          <EmptyHeader>
            <EmptyTitle className="font-serif text-[17px]">Event not found</EmptyTitle>
            <EmptyDescription>
              No event with id <code className="break-all">{id}</code> is in the index. Events age out of the retention window, so an old link
              can outlive the document it points at.
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      </section>
    )
  }
  const event = fetch?.state === 'event' ? fetch.event : null
  if (event === null) {
    return (
      <section className="flex min-w-0 flex-col gap-6">
        <InvestigateHeader label="Investigate" title="Event" subtitle="Loading the full record." />
        <Skeleton className="h-32 w-full" aria-hidden="true" />
      </section>
    )
  }

  const honeypot = (event.record.honeypot as JsonRecord | undefined) ?? {}
  const spec = protocolFor(event.sensor)

  return (
    <section className="flex min-w-0 flex-col gap-6">
      <InvestigateHeader
        label="Investigate"
        title={`${event.sensor} event`}
        subtitle={
          spec
            ? spec.what
            : 'Everything recorded for this event, as the sensor recorded it — no protocol reading is defined for this sensor yet.'
        }
        chips={
          <section className="flex flex-wrap gap-2">
            <Badge variant="outline">{formatTimestamp(event.time)}</Badge>
            {event.src_ip ? <Badge variant="outline">{event.src_ip}</Badge> : null}
          </section>
        }
      />

      <Card className="min-w-0">
        <CardHeader><CardTitle><h2 className="font-serif text-base font-medium">What this event is</h2></CardTitle></CardHeader><CardContent className="flex min-w-0 flex-col gap-4">
        <Table>
          <TableBody>
            <TableRow>
              <TableCell>Seen</TableCell>
              <TableCell className="break-all">{formatTimestamp(event.time)}</TableCell>
            </TableRow>
            <TableRow>
              <TableCell>Sensor</TableCell>
              <TableCell className="break-all">
                <Link to="/sensors" search={{ sensor: event.sensor }}>{event.sensor}</Link>
              </TableCell>
            </TableRow>
            <TableRow>
              <TableCell>Source</TableCell>
              <TableCell className="break-all">
                {event.src_ip ? (
                  <Link to="/investigate/ip/$ip" params={{ ip: event.src_ip }}>{event.src_ip}</Link>
                ) : (
                  '—'
                )}
              </TableCell>
            </TableRow>
            {/* The protocol's own reading, where one is defined. This is
                the same spec the sensor detail page renders from, so the
                two never disagree about what a field means. */}
            {spec
              ? spec.columns.map((column) => {
                  const value = fieldText(readField(honeypot, column.field))
                  if (!value) return null
                  return (
                    <TableRow key={column.header}>
                      <TableCell>{column.header}</TableCell>
                      <TableCell className="break-all">{value}</TableCell>
                    </TableRow>
                  )
                })
              : meaningfulFields(honeypot).map(([key, value]) => (
                  <TableRow key={key}>
                    <TableCell>{key}</TableCell>
                    <TableCell className="break-all">{fieldText(value)}</TableCell>
                  </TableRow>
                ))}
            <TableRow>
              <TableCell>Document id</TableCell>
              <TableCell className="break-all">
                <code>{event.id}</code>{' '}
                <Button variant="ghost" size="sm" type="button" onClick={() => copyWithFlash(event.id)}>
                  copy
                </Button>
              </TableCell>
            </TableRow>
            <TableRow>
              <TableCell>Index</TableCell>
              <TableCell className="break-all">
                <code>{event.index}</code>
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </CardContent></Card>

      {spec && spec.artefacts.length > 0 ? (
        <Card className="min-w-0">
          <CardHeader><CardTitle><h2 className="font-serif text-base font-medium">What the sensor captured</h2></CardTitle></CardHeader><CardContent className="flex min-w-0 flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            The artefact this protocol exists to capture, not a summary of it.
          </p>
          {spec.artefacts.map((artefact) => {
            const value = readField(honeypot, artefact.field)
            const text = value === undefined ? '' : typeof value === 'string' ? value : JSON.stringify(value, null, 2)
            if (!text) return null
            return (
              <div key={artefact.label}>
                <p className="text-sm font-medium">{artefact.label}</p>
                <pre className="max-h-96 overflow-auto rounded-md bg-muted p-4 text-xs">{text}</pre>
              </div>
            )
          })}
        </CardContent></Card>
      ) : null}

      {event.hashes.length > 0 ? (
        <Card className="min-w-0">
          <CardHeader><CardTitle><h2 className="font-serif text-base font-medium">Hashes in this event</h2></CardTitle></CardHeader><CardContent className="flex min-w-0 flex-col gap-4">
          <p className="text-sm text-muted-foreground">
            Found by shape rather than by field name, because every sensor names its hash differently. Each links to the
            payload record that owns the bytes and the analysis.
          </p>
          <ul>
            {event.hashes.map((hash) => (
              <li key={hash}>
                <Link to="/payload-analysis/$hash" params={{ hash }}>
                  <code>{hash}</code>
                </Link>
              </li>
            ))}
          </ul>
        </CardContent></Card>
      ) : null}

      <RelationCard
        title="The rest of this session"
        hint="Every event sharing session"
        relation={event.session_events}
        href={event.session ? `/sessions/${encodeURIComponent(event.session)}` : undefined}
        hrefLabel="Open the session"
      />
      <RelationCard
        title="The rest of this connection"
        hint="Every sensor that saw the flow"
        relation={event.flow_events}
        href={event.community_id ? `/events?community_id=${encodeURIComponent(event.community_id)}` : undefined}
        hrefLabel="Open the flow in the event explorer"
      />
      {event.flow_link ? <FlowLinkCard link={event.flow_link} currentId={event.id} /> : null}
      <RelationCard
        title="What else this source did"
        hint="Last 24 hours from"
        relation={event.source_events}
        href={event.src_ip ? `/investigate/ip/${encodeURIComponent(event.src_ip)}` : undefined}
        hrefLabel="Open the attacker profile"
      />

      <Card className="min-w-0">
        <CardHeader><CardTitle><h2 className="font-serif text-base font-medium">The complete record</h2></CardTitle></CardHeader><CardContent className="flex min-w-0 flex-col gap-4">
        <p className="text-sm text-muted-foreground">
          Exactly as indexed. Everything above is a reading of this; nothing above is a substitute for it.
        </p>
        <pre className="max-h-96 overflow-auto rounded-md bg-muted p-4 text-xs">{JSON.stringify(event.record, null, 2)}</pre>
      </CardContent></Card>
    </section>
  )
}
