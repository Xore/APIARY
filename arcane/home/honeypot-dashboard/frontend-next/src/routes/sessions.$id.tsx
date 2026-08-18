// Session detail — one attacker session's whole story, chronologically:
// summary chips, curated attack-sequence detections, per-session
// leaderboards, ATT&CK techniques, and the full event list.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'

type Kv = { key: string; count: number }
type Technique = { id: string; count: number; url: string }
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
  record: Record<string, unknown>
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

export const Route = createFileRoute('/sessions/$id')({
  loader: async ({ params }) => ({ first: fetchSession({ data: { id: params.id } }) }),
  component: SessionPage,
})

const EVENT_COLUMNS: Column<EventRow>[] = [
  { header: 'time', render: (row) => row.time.replace('T', ' ').slice(0, 19) },
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
          detail ? (
            <>
              <span className="chip">{detail.total.toLocaleString('en-US')} events</span>
              <span className="chip">{detail.ip}{detail.country ? ` · ${detail.country}` : ''}</span>
              <span className="chip">
                {detail.first.replace('T', ' ').slice(0, 19)} → {detail.last.replace('T', ' ').slice(11, 19)}
              </span>
            </>
          ) : undefined
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
        <div className="filters">
          {detail.techniques.map((technique) => (
            <a className="chip" key={technique.id} href={technique.url} target="_blank" rel="noopener noreferrer">
              {technique.id} × {technique.count.toLocaleString('en-US')}
            </a>
          ))}
        </div>
      ) : null}
      {detail ? (
        <>
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
      />
    </>
  )
}
