// Per-IP investigation — one source address's whole profile: summary
// chips, technique tags, behavior leaderboards, session links, and the
// newest events with the record inspector.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import type { JsonRecord } from '../lib/json'

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

type IpProfile = {
  ip: string
  total: number
  first: string
  last: string
  country: string
  asn: string
  sensors: Kv[]
  ports: Kv[]
  protos: Kv[]
  credentials: Kv[]
  commands: Kv[]
  sessions: Kv[]
  techniques: Kv[]
  events: EventRow[]
}

type BlockState = { IP: string; Blocked: boolean; Active: boolean; BlockedBy?: string; ExpiresAt?: string }

const fetchProfile = createServerFn({ method: 'GET' })
  .inputValidator((input: { ip: string }) => input)
  .handler(async ({ data }): Promise<IpProfile | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<IpProfile>(`/api/v1/investigate/ip/${encodeURIComponent(data.ip)}`)
  })

const fetchBlockState = createServerFn({ method: 'GET' })
  .inputValidator((input: { ip: string }) => input)
  .handler(async ({ data }): Promise<BlockState | null> => {
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/ip-block/${encodeURIComponent(data.ip)}`)
    return response.ok ? ((await response.json()) as BlockState) : null
  })

const setBlock = createServerFn({ method: 'POST' })
  .inputValidator((input: { ip: string; blocked: boolean; expires_days?: number }) => input)
  .handler(async ({ data }): Promise<boolean> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // Admin-gated at the BFF, same posture as the legacy action (#914).
    if (user && user.role !== 'admin') return false
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/ip-block', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...data, actor: user?.username ?? '' }),
    })
    return response.ok
  })

function BlockControl({ ip }: { ip: string }) {
  const [state, setState] = useState<BlockState | null>(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    let cancelled = false
    fetchBlockState({ data: { ip } }).then((result) => {
      if (!cancelled) setState(result)
    })
    return () => {
      cancelled = true
    }
  }, [ip])
  if (state === null) return null
  return (
    <button
      className={state.Active ? 'chip is-active' : 'chip'}
      type="button"
      disabled={busy}
      title={
        state.Active
          ? `Blocked${state.BlockedBy ? ` by ${state.BlockedBy}` : ''} — the VPS blackhole list drops this IP. Click to unblock.`
          : 'Add this IP to the manual blackhole list (portbridge drops it within 5 minutes).'
      }
      onClick={async () => {
        setBusy(true)
        try {
          const ok = await setBlock({ data: { ip, blocked: !state.Active } })
          if (ok) {
            const fresh = await fetchBlockState({ data: { ip } })
            if (fresh) setState(fresh)
          }
        } finally {
          setBusy(false)
        }
      }}
    >
      {busy ? '…' : state.Active ? '⛔ blocked — unblock' : 'block this IP'}
    </button>
  )
}

export const Route = createFileRoute('/investigate/ip/$ip')({
  loader: async ({ params }) => ({ first: fetchProfile({ data: { ip: params.ip } }) }),
  component: InvestigateIp,
})

const EVENT_COLUMNS: Column<EventRow>[] = [
  { header: 'time', render: (row) => row.time.replace('T', ' ').slice(0, 19) },
  { header: 'sensor', render: (row) => <span className="badge badge--muted">{row.sensor}</span> },
  { header: 'port', className: 'n', render: (row) => (row.port ? `:${row.port}` : '') },
  { header: 'detail', className: 'v', render: (row) => row.detail || row.proto },
  {
    header: 'record',
    detail: true,
    render: (row) => <pre className="hp-md__preview">{JSON.stringify(row.record, null, 2)}</pre>,
  },
]

function MiniTable({ title, rows, linkTo }: { title: string; rows: Kv[]; linkTo?: (key: string) => string }) {
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
                <td className="v">{linkTo ? <a href={linkTo(row.key)}>{row.key}</a> : row.key}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function InvestigateIp() {
  const { first } = Route.useLoaderData()
  const { ip } = Route.useParams()
  const [profile, setProfile] = useState<IpProfile | null | 'missing'>(null)
  useEffect(() => {
    let cancelled = false
    first.then((result) => {
      if (!cancelled) setProfile(result ?? 'missing')
    })
    return () => {
      cancelled = true
    }
  }, [first])

  if (profile === 'missing') {
    return (
      <InvestigateHeader label="Investigate" title={ip} subtitle="No events from this address in the current window." />
    )
  }

  return (
    <>
      <InvestigateHeader
        label="Investigate"
        title={ip}
        subtitle="Everything this source address did across every sensor — behavior, credentials, sessions and raw events."
        chips={
          profile ? (
            <>
              <span className="chip">{profile.total.toLocaleString('en-US')} events</span>
              {profile.country ? <span className="badge badge--info">{profile.country}</span> : null}
              {profile.asn ? <span className="chip">{profile.asn}</span> : null}
              <span className="chip">
                {profile.first.replace('T', ' ').slice(0, 19)} → {profile.last.replace('T', ' ').slice(0, 19)}
              </span>
              <Link className="chip" to="/events" search={{ ip }}>
                open in explorer →
              </Link>
              <BlockControl ip={ip} />
            </>
          ) : undefined
        }
      />
      {profile && profile.techniques.length > 0 ? (
        <div className="filters">
          {profile.techniques.map((technique) => (
            <a
              className="chip"
              key={technique.key}
              href={`https://attack.mitre.org/techniques/${technique.key.replace('.', '/')}/`}
              target="_blank"
              rel="noopener noreferrer"
            >
              {technique.key} × {technique.count.toLocaleString('en-US')}
            </a>
          ))}
        </div>
      ) : null}
      {profile ? (
        <>
          <MiniTable title="Sensors" rows={profile.sensors} />
          <MiniTable title="Targeted ports" rows={profile.ports} />
          <MiniTable title="Protocols" rows={profile.protos} />
          <MiniTable title="Credentials tried" rows={profile.credentials} />
          <MiniTable title="Commands" rows={profile.commands} />
          <MiniTable title="Sessions" rows={profile.sessions} linkTo={(key) => `/sessions/${encodeURIComponent(key)}`} />
        </>
      ) : null}
      <MasterDetailTable
        rows={profile ? profile.events : null}
        columns={EVENT_COLUMNS}
        rowKey={(row, index) => `${row.time}-${index}`}
        inspectorTitle="Event record"
      />
    </>
  )
}
