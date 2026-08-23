// Session detail — one attacker session's whole story, chronologically:
// summary chips, curated attack-sequence detections, per-session
// leaderboards, ATT&CK techniques, and the full event list.
import { Link, createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import type { JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'
import { countryName } from '../lib/country'

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

const fetchSession = createServerFn({ method: 'GET' })
  .inputValidator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<SessionDetail | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<SessionDetail>(`/api/v1/sessions/${encodeURIComponent(data.id)}`)
  })

// Captured mail (#1611 workstream B) — mailoney's SMTP DATA body, parsed
// server-side to headers/body/attachment-metadata. Exposed here as plain
// text only: an HTML body is decoded to a string by the backend but never
// rendered, and attachments carry no bytes (metadata rows only) — same
// posture mail.rs's own doc comment insists on.
type MailAddress = { name: string; address: string }
type MailAttachment = { filename: string; content_type: string; size_bytes: number; sha256: string }
type Mail = {
  session_id: string
  body_path: string
  size_bytes: number
  imported_at: string
  from: MailAddress | null
  to: MailAddress[]
  subject: string
  date: string
  message_id: string
  body_text: string
  attachments: MailAttachment[]
}

const fetchMail = createServerFn({ method: 'GET' })
  .inputValidator((input: { id: string }) => input)
  .handler(async ({ data }): Promise<Mail | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Mail>(`/api/v1/mail/${encodeURIComponent(data.id)}`)
  })

export const Route = createFileRoute('/sessions/$id')({
  loader: async ({ params }) => ({ first: fetchSession({ data: { id: params.id } }) }),
  component: SessionPage,
})

const EVENT_COLUMNS: Column<EventRow>[] = [
  { header: 'time', render: (row) => formatTimestamp(row.time) },
  { header: 'sensor', render: (row) => <span className="badge badge--muted">{row.sensor}</span> },
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

function formatAddress(address: MailAddress): string {
  if (!address.address) return address.name || '—'
  return address.name ? `${address.name} <${address.address}>` : address.address
}

function MailCard({ sessionId }: { sessionId: string }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [mail, setMail] = useState<Mail | null | 'missing'>(null)

  const toggle = async () => {
    if (open) {
      setOpen(false)
      return
    }
    setOpen(true)
    if (mail !== null) return
    setBusy(true)
    try {
      const result = await fetchMail({ data: { id: sessionId } })
      setMail(result ?? 'missing')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="card wide" id="captured-mail">
      <h2>Captured mail</h2>
      <p className="note">
        The SMTP DATA body mailoney captured for this session, parsed to headers and plain text. An HTML body is decoded to
        text but never rendered, and attachments are listed as metadata only — no bytes are stored or downloadable here.
      </p>
      <button className="btn btn-secondary btn-sm" type="button" onClick={toggle} disabled={busy}>
        {busy ? 'Loading…' : open ? 'Hide mail' : 'View mail'}
      </button>
      {open ? (
        busy ? (
          <span className="skeleton-line" aria-hidden="true" />
        ) : mail === 'missing' || mail === null ? (
          <p className="empty">No captured mail body found for this session.</p>
        ) : (
          <>
            <table className="data-table" style={{ marginTop: 12 }}>
              <tbody>
                <tr>
                  <td>From</td>
                  <td className="v">{mail.from ? formatAddress(mail.from) : '—'}</td>
                </tr>
                <tr>
                  <td>To</td>
                  <td className="v">{mail.to.length ? mail.to.map(formatAddress).join(', ') : '—'}</td>
                </tr>
                <tr>
                  <td>Subject</td>
                  <td className="v">{mail.subject || '—'}</td>
                </tr>
                <tr>
                  <td>Date</td>
                  <td>{mail.date || '—'}</td>
                </tr>
                <tr>
                  <td>Message-ID</td>
                  <td className="v">{mail.message_id || '—'}</td>
                </tr>
                <tr>
                  <td>Size</td>
                  <td className="n">{mail.size_bytes.toLocaleString('en-US')} bytes</td>
                </tr>
              </tbody>
            </table>
            <p className="subtitle">Body</p>
            <pre className="code">{mail.body_text || '(empty body)'}</pre>
            {mail.attachments.length > 0 ? (
              <>
                <p className="subtitle">Attachments</p>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>filename</th>
                      <th>content-type</th>
                      <th>size</th>
                      <th>sha256</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mail.attachments.map((attachment, index) => (
                      <tr key={`${attachment.sha256}-${index}`}>
                        <td className="v">{attachment.filename || '(unnamed)'}</td>
                        <td>{attachment.content_type || '—'}</td>
                        <td className="n">{attachment.size_bytes.toLocaleString('en-US')} bytes</td>
                        <td className="v">
                          <code>{attachment.sha256}</code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            ) : null}
          </>
        )
      ) : null}
    </div>
  )
}

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

function SessionPage() {
  const { first } = Route.useLoaderData()
  const { id } = Route.useParams()
  const [detail, setDetail] = useState<SessionDetail | null | 'missing'>(null)
  useEffect(() => {
    let cancelled = false
    first.then((result) => {
      if (!cancelled) setDetail(result ?? 'missing')
    })
    return () => {
      cancelled = true
    }
  }, [first])

  if (detail === 'missing') {
    return (
      <InvestigateHeader
        label="Investigate"
        title={`Session ${id}`}
        subtitle="No events found for this session id in the current window."
      />
    )
  }

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
            <Link className="chip" to="/events">
              ← event explorer
            </Link>
            {detail && detail.ip ? (
              <Link className="chip" to="/investigate/ip/$ip" params={{ ip: detail.ip }}>
                attacker profile
              </Link>
            ) : null}
            <a className="chip" href={`/events?session=${encodeURIComponent(id)}`}>
              filtered events
            </a>
            <a className="chip" href={`/api/export/events.csv?session=${encodeURIComponent(id)}`}>
              export CSV ↓
            </a>
            {detail ? (
              <>
                <span className="chip">{detail.total.toLocaleString('en-US')} events</span>
                <span className="chip" title={countryName(detail.country)}>{detail.ip}{detail.country ? ` · ${detail.country}` : ''}</span>
                <span className="chip">
                  {formatTimestamp(detail.first)} → {formatTimestamp(detail.last)}
                </span>
              </>
            ) : null}
          </>
        }
      />
      {detail?.sequences.map((sequence) => (
        <div className="card wide" key={sequence.name}>
          <h2>
            <span className={sequence.severity === 'critical' ? 'badge badge--danger' : 'badge badge--warning'}>
              {sequence.severity}
            </span>{' '}
            {sequence.name}
          </h2>
          <p className="note">{sequence.summary}</p>
        </div>
      ))}
      {detail && detail.techniques.length > 0 ? (
        <div className="card wide">
          <h2>MITRE ATT&amp;CK behavior mapping</h2>
          <p className="note">Evidence-based behavioral context only; this does not identify or attribute an actor.</p>
          <div className="card__scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>domain</th>
                  <th>technique</th>
                  <th>observations</th>
                  <th>evidence</th>
                </tr>
              </thead>
              <tbody>
                {detail.techniques.map((technique) => (
                  <tr key={technique.id}>
                    <td>
                      <span className="badge badge--muted">{technique.domain}</span>
                    </td>
                    <td className="v">
                      <a href={technique.url} target="_blank" rel="noopener noreferrer">
                        {technique.id} — {technique.name}
                      </a>
                    </td>
                    <td className="n">{technique.count.toLocaleString('en-US')}</td>
                    <td className="v">{technique.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
      {detail ? (
        <>
          {hasCapturedMail(detail.events) ? <MailCard sessionId={id} /> : null}
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
