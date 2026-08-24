// The three sensors that had a hand-written reading before the catalog
// existed (#1538): mailoney's SMTP conversations, http-honeypot's raw
// requests, and tanner's requests with its emulator detections.
//
// They read their protocols more closely than the generic path in
// lib/sensorProtocols can -- grouping a mailoney session across its
// envelope and body lines, pulling tanner's detection payload out of a
// nested response object -- so they stay. Moved out of routes/sensors.tsx
// when every sensor became its own page (#1904); this is the same code,
// rendered from the sensor's page rather than from a tab on a shared one.
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { MasterDetailTable, type Column } from './Investigate'
import { CapturedMailInline } from './CapturedMail'
import { formatTimestamp } from '../lib/time'

type MailoneySession = {
  session_id: string
  when: string
  ip: string
  port: number
  logged_in: boolean
  user: string
  pass: string
  mail_from: string[]
  rcpt_to: string[]
  body_size: number
  truncated: boolean
  body_path: string
  body_preview: string
}

type HttpRequest = {
  id: string
  when: string
  ip: string
  method: string
  host: string
  path: string
  query: string
  user_agent: string
  headers: Record<string, string>
  body: string
  username: string
  password: string
  auth_type: string
  status: number
  category: string
  tarpitted: boolean
  tarpit_bytes: number
  tarpit_ms: number
}

type TannerRequest = {
  id: string
  when: string
  ip: string
  method: string
  path: string
  user_agent: string
  headers: Record<string, string>
  username: string
  password: string
  tarpitted: boolean
  tarpit_bytes: number
  tarpit_ms: number
  post_data: Record<string, string>
  cookies: Record<string, string>
  detection_name: string
  detection_payload: string
}

type SensorDetail = {
  mailoney: MailoneySession[]
  http_requests: HttpRequest[]
  tanner: TannerRequest[]
}

const fetchSensors = createServerFn({ method: 'GET' }).handler(async (): Promise<SensorDetail | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<SensorDetail>('/api/v1/sensors')
})

// #1856: which sensors exist, according to the events rather than
// according to a list someone maintained. Twenty-six sensors produce
// events; this page covered three, because the three were hardcoded.
function clock(iso: string): string {
  return formatTimestamp(iso)
}

function kvList(map: Record<string, string>) {
  const entries = Object.entries(map)
  if (entries.length === 0) return ''
  return (
    <pre className="hp-md__preview">
      {entries.map(([key, value]) => `${key}: ${value}`).join('\n')}
    </pre>
  )
}

const MAILONEY_COLUMNS: Column<MailoneySession>[] = [
  { header: 'seen', render: (row) => clock(row.when) },
  { header: 'source', className: 'v', render: (row) => `${row.ip}${row.port ? `:${row.port}` : ''}` },
  {
    header: 'auth',
    render: (row) =>
      row.logged_in ? <span className="badge badge--warning">{row.user} / {row.pass}</span> : <span className="badge badge--muted">none</span>,
  },
  { header: 'mail from', className: 'v', render: (row) => row.mail_from.join(' · ') },
  { header: 'rcpt to', className: 'v', render: (row) => row.rcpt_to.join(' · ') },
  { header: 'body', className: 'n', render: (row) => (row.body_size ? `${row.body_size} B${row.truncated ? ' (truncated)' : ''}` : '') },
  { header: 'session', detail: true, render: (row) => row.session_id },
  {
    header: 'body preview',
    detail: true,
    render: (row) => (row.body_preview ? <pre className="hp-md__preview">{row.body_preview}</pre> : ''),
  },
  {
    // #1856: the preview is the first few bytes of the SMTP conversation
    // and is usually "QUIT" -- so the mail sensor's own detail view showed
    // an envelope and never the mail. The parsed message (headers, body,
    // attachments with hashes) is fetched on demand, because it lives in a
    // separate index behind a two-step join and most rows are never opened.
    header: 'captured message',
    detail: true,
    render: (row) =>
      row.body_path ? (
        <CapturedMailInline sessionId={row.session_id} />
      ) : (
        <span className="note">This session never sent a DATA body.</span>
      ),
  },
]

const HTTP_COLUMNS: Column<HttpRequest>[] = [
  { header: 'seen', render: (row) => clock(row.when) },
  { header: 'source ip', className: 'v', render: (row) => row.ip },
  { header: 'request', className: 'v', render: (row) => <code>{row.method} {row.path}{row.query ? `?${row.query}` : ''}</code> },
  { header: 'status', className: 'n', render: (row) => String(row.status || '') },
  {
    header: 'tarpit',
    render: (row) => (row.tarpitted ? <span className="badge badge--success">{row.tarpit_ms} ms</span> : ''),
  },
  { header: 'host', detail: true, render: (row) => row.host },
  { header: 'user agent', detail: true, render: (row) => row.user_agent },
  { header: 'credentials', detail: true, render: (row) => (row.username ? `${row.username} / ${row.password} (${row.auth_type})` : '') },
  { header: 'category', detail: true, render: (row) => row.category },
  { header: 'headers', detail: true, render: (row) => kvList(row.headers) },
  {
    header: 'body',
    detail: true,
    render: (row) => (row.body ? <pre className="hp-md__preview">{row.body}</pre> : ''),
  },
]

const TANNER_COLUMNS: Column<TannerRequest>[] = [
  { header: 'seen', render: (row) => clock(row.when) },
  { header: 'source ip', className: 'v', render: (row) => row.ip },
  { header: 'request', className: 'v', render: (row) => <code>{row.method} {row.path}</code> },
  {
    header: 'detection',
    render: (row) => (row.detection_name ? <span className="badge badge--danger">{row.detection_name}</span> : ''),
  },
  {
    header: 'tarpit',
    render: (row) => (row.tarpitted ? <span className="badge badge--success">{row.tarpit_ms} ms</span> : ''),
  },
  { header: 'user agent', detail: true, render: (row) => row.user_agent },
  { header: 'credentials', detail: true, render: (row) => (row.username ? `${row.username} / ${row.password}` : '') },
  { header: 'post data', detail: true, render: (row) => kvList(row.post_data) },
  { header: 'cookies', detail: true, render: (row) => kvList(row.cookies) },
  {
    header: 'detection payload',
    detail: true,
    render: (row) => (row.detection_payload ? <pre className="hp-md__preview">{row.detection_payload}</pre> : ''),
  },
  { header: 'headers', detail: true, render: (row) => kvList(row.headers) },
]

/** Whether this sensor has a hand-written reading of its own. */
export function hasCuratedView(sensor: string): boolean {
  return sensor === 'mailoney' || sensor === 'http-honeypot' || sensor === 'tanner'
}

/** The curated reading for one sensor, or null when it has none. */
export function CuratedSensorView({ sensor }: { sensor: string }) {
  const [detail, setDetail] = useState<SensorDetail | null>(null)
  useEffect(() => {
    let cancelled = false
    fetchSensors().then((result) => {
      if (!cancelled && result) setDetail(result)
    })
    return () => {
      cancelled = true
    }
  }, [])

  if (sensor === 'mailoney') {
    return (
      <div className="card wide">
        <h2 className="label-section">mailoney — SMTP conversations</h2>
        <p className="card__meta">
          Grouped by mailoney session — AUTH PLAIN credentials, the MAIL FROM / RCPT TO envelope, and the captured
          message itself. Newest first, last 48h.
        </p>
        <MasterDetailTable
          rows={detail ? detail.mailoney : null}
          columns={MAILONEY_COLUMNS}
          rowKey={(row) => row.session_id}
          detailHref={(row) => `/sessions/${encodeURIComponent(row.session_id)}`}
          inspectorTitle="SMTP session"
          emptyState={{
            title: 'No mailoney SMTP activity in the last 48h',
            hint: 'Nothing has talked SMTP to this sensor in the current window.',
          }}
        />
      </div>
    )
  }

  if (sensor === 'http-honeypot') {
    return (
      <div className="card wide">
        <h2 className="label-section">http-honeypot — requests</h2>
        <p className="card__meta">
          Every request&apos;s own method, path, headers, and body — not just the generic &quot;METHOD path&quot;
          summary line. Newest first, last 48h.
        </p>
        <MasterDetailTable
          rows={detail ? detail.http_requests : null}
          columns={HTTP_COLUMNS}
          rowKey={(row, index) => `${row.when}-${index}`}
          detailHref={(row) => (row.id ? `/event/${encodeURIComponent(row.id)}` : undefined)}
          inspectorTitle="HTTP request"
          emptyState={{
            title: 'No http-honeypot activity in the last 48h',
            hint: 'Nothing has hit this sensor over HTTP in the current window.',
          }}
        />
      </div>
    )
  }

  if (sensor === 'tanner') {
    return (
      <div className="card wide">
        <h2 className="label-section">tanner — requests &amp; detections</h2>
        <p className="card__meta">
          Every request tanner&apos;s web emulator handled — submitted POST fields, cookies, and (when one of its 10
          emulators matched) the attack detection and captured execution result. Newest first, last 48h.
        </p>
        <MasterDetailTable
          rows={detail ? detail.tanner : null}
          columns={TANNER_COLUMNS}
          rowKey={(row, index) => `${row.when}-${index}`}
          detailHref={(row) => (row.id ? `/event/${encodeURIComponent(row.id)}` : undefined)}
          inspectorTitle="Tanner request"
          emptyState={{
            title: 'No tanner activity in the last 48h',
            hint: 'Nothing has reached the tanner sensor in the current window.',
          }}
        />
      </div>
    )
  }

  return null
}
