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
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'
import { copyWithFlash } from '../lib/flash'
import { type JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'
import { fieldText, meaningfulFields, protocolFor, readField } from '../lib/sensorProtocols'

type RelatedEvent = { time: string; sensor: string; src_ip: string; detail: string }
type Relation = { key: string; total: number; rows: RelatedEvent[] }
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
}

// #2178: serviceJSON collapsed "no event with this id" (a real 404 — the
// document aged out) into the same null as "the request failed", so an
// outage rendered as confident absence prose about this specific id. The
// union keeps the two separable; the handler never rejects.
type EventFetch = { state: 'event'; event: EventPage } | { state: 'missing' } | { state: 'failed' }

const fetchEvent = createServerFn({ method: 'GET' })
  .inputValidator((input: { id: string }) => input)
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
    <div className="card wide">
      <h2>{title}</h2>
      <p className="note">
        {hint} <code>{relation.key}</code>
        {relation.total > relation.rows.length
          ? ` — ${relation.total.toLocaleString('en-US')} in total, newest ${relation.rows.length} shown.`
          : ''}
      </p>
      {relation.rows.length === 0 ? (
        <p className="empty">Nothing else matched.</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>time</th>
              <th>sensor</th>
              <th>source</th>
              <th>what happened</th>
            </tr>
          </thead>
          <tbody>
            {relation.rows.map((row, index) => (
              <tr key={`${row.time}-${index}`}>
                <td>{formatTimestamp(row.time)}</td>
                <td>
                  <span className={`badge b-${row.sensor}`}>{row.sensor}</span>
                </td>
                <td className="v">{row.src_ip || '—'}</td>
                <td className="v">{row.detail || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {href ? (
        <p className="note">
          <a className="section-link" href={href}>
            {hrefLabel} →
          </a>
        </p>
      ) : null}
    </div>
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
      <>
        <InvestigateHeader label="Investigate" title="Event" subtitle="The record could not be loaded." />
        <ErrorStateBlock
          title="This event failed to load"
          hint="The backend request failed — this says nothing about whether the event exists."
          onRetry={() => setAttempt((n) => n + 1)}
        />
      </>
    )
  }

  if (fetch?.state === 'missing') {
    return (
      <>
        <InvestigateHeader label="Investigate" title="Event" subtitle="This event could not be found." />
        <div className="card wide">
          <p className="empty">
            No event with id <code>{id}</code> is in the index. Events age out of the retention window, so an old link
            can outlive the document it points at.
          </p>
        </div>
      </>
    )
  }
  const event = fetch?.state === 'event' ? fetch.event : null
  if (event === null) {
    return (
      <>
        <InvestigateHeader label="Investigate" title="Event" subtitle="Loading the full record." />
        <span className="skeleton-line" aria-hidden="true" />
      </>
    )
  }

  const honeypot = (event.record.honeypot as JsonRecord | undefined) ?? {}
  const spec = protocolFor(event.sensor)

  return (
    <>
      <InvestigateHeader
        label="Investigate"
        title={`${event.sensor} event`}
        subtitle={
          spec
            ? spec.what
            : 'Everything recorded for this event, as the sensor recorded it — no protocol reading is defined for this sensor yet.'
        }
        chips={
          <>
            <span className="chip">{formatTimestamp(event.time)}</span>
            {event.src_ip ? <span className="chip">{event.src_ip}</span> : null}
          </>
        }
      />

      <div className="card wide">
        <h2>What this event is</h2>
        <table className="data-table">
          <tbody>
            <tr>
              <td>Seen</td>
              <td className="v">{formatTimestamp(event.time)}</td>
            </tr>
            <tr>
              <td>Sensor</td>
              <td className="v">
                <a href={`/sensors?sensor=${encodeURIComponent(event.sensor)}`}>{event.sensor}</a>
              </td>
            </tr>
            <tr>
              <td>Source</td>
              <td className="v">
                {event.src_ip ? (
                  <a href={`/investigate/ip/${encodeURIComponent(event.src_ip)}`}>{event.src_ip}</a>
                ) : (
                  '—'
                )}
              </td>
            </tr>
            {/* The protocol's own reading, where one is defined. This is
                the same spec the sensor detail page renders from, so the
                two never disagree about what a field means. */}
            {spec
              ? spec.columns.map((column) => {
                  const value = fieldText(readField(honeypot, column.field))
                  if (!value) return null
                  return (
                    <tr key={column.header}>
                      <td>{column.header}</td>
                      <td className="v">{value}</td>
                    </tr>
                  )
                })
              : meaningfulFields(honeypot).map(([key, value]) => (
                  <tr key={key}>
                    <td>{key}</td>
                    <td className="v">{fieldText(value)}</td>
                  </tr>
                ))}
            <tr>
              <td>Document id</td>
              <td className="v">
                <code>{event.id}</code>{' '}
                <button className="btn btn-ghost btn-sm" type="button" onClick={() => copyWithFlash(event.id)}>
                  copy
                </button>
              </td>
            </tr>
            <tr>
              <td>Index</td>
              <td className="v">
                <code>{event.index}</code>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      {spec && spec.artefacts.length > 0 ? (
        <div className="card wide">
          <h2>What the sensor captured</h2>
          <p className="note">
            The artefact this protocol exists to capture, not a summary of it.
          </p>
          {spec.artefacts.map((artefact) => {
            const value = readField(honeypot, artefact.field)
            const text = value === undefined ? '' : typeof value === 'string' ? value : JSON.stringify(value, null, 2)
            if (!text) return null
            return (
              <div key={artefact.label}>
                <p className="subtitle">{artefact.label}</p>
                <pre className="code">{text}</pre>
              </div>
            )
          })}
        </div>
      ) : null}

      {event.hashes.length > 0 ? (
        <div className="card wide">
          <h2>Hashes in this event</h2>
          <p className="note">
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
        </div>
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
      <RelationCard
        title="What else this source did"
        hint="Last 24 hours from"
        relation={event.source_events}
        href={event.src_ip ? `/investigate/ip/${encodeURIComponent(event.src_ip)}` : undefined}
        hrefLabel="Open the attacker profile"
      />

      <div className="card wide">
        <h2>The complete record</h2>
        <p className="note">
          Exactly as indexed. Everything above is a reading of this; nothing above is a substitute for it.
        </p>
        <pre className="code">{JSON.stringify(event.record, null, 2)}</pre>
      </div>
    </>
  )
}
