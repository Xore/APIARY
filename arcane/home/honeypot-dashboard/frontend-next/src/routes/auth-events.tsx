// Auth-failure events — Keycloak login failures against the dashboard's
// own realm (auth-failure-events store). Ports auth_events.html's page
// anatomy (#1653): the 24h failed-login KPI tile, the "Failures by
// client, 24h" and "Top source IPs, 24h" aggregation cards, the
// username-tried column, and client/IP pivot links with the
// unattributed-tunnel fallback.
import { useEffect, useMemo, useState } from 'react'
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { StoreListPage, str, when, type StorePage } from '../components/StoreList'
import type { Column } from '../components/Investigate'
import type { StoreRow } from '../components/StoreList'

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage>(`/api/v1/store/auth-events?offset=${data.offset}&size=25`)
  })

// The 24h stats window. The Go page aggregated server-side over the full
// 24h; here the newest 200 store rows back the same three read-outs —
// the auth-failure family is genuinely low-volume (it records failed
// logins against our own IdP, not honeypot traffic), so 200 covers the
// window in practice. The row-count chip states the scope honestly.
const fetchStatsWindow = createServerFn({ method: 'GET' }).handler(async (): Promise<StorePage | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<StorePage>('/api/v1/store/auth-events?offset=0&size=200')
})

function detail(row: StoreRow, key: string): string {
  const details = row.details as StoreRow | undefined
  const value = details?.[key]
  return typeof value === 'string' ? value : ''
}

const COLUMNS: Column<StoreRow>[] = [
  { header: 'time', render: (row) => when(str(row, '@timestamp')) },
  { header: 'type', render: (row) => <span className="badge badge--warning">{str(row, 'type')}</span> },
  {
    header: 'ip',
    className: 'v',
    primary: true,
    render: (row) =>
      str(row, 'ip_address') ? (
        <Link to="/events" search={{ ip: str(row, 'ip_address') }} onClick={(event) => event.stopPropagation()}>
          {str(row, 'ip_address')}
        </Link>
      ) : (
        <span className="badge badge--muted">unattributed</span>
      ),
  },
  { header: 'error', className: 'v', render: (row) => str(row, 'error') },
  { header: 'username tried', className: 'v', render: (row) => detail(row, 'username') || '—' },
  { header: 'client', className: 'v', render: (row) => str(row, 'client_id') },
  { header: 'realm', detail: true, render: (row) => str(row, 'realm') },
  { header: 'redirect', detail: true, render: (row) => detail(row, 'redirect_uri') },
  { header: 'user', detail: true, render: (row) => str(row, 'user_id') },
]

function TopTable({ title, header, rows }: { title: string; header: string; rows: Array<[string, number]> }) {
  if (rows.length === 0) return null
  return (
    <div className="card half">
      <h2>{title}</h2>
      <div className="card__scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>{header}</th>
              <th>failures</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([key, count]) => (
              <tr key={key}>
                <td className="v">{key}</td>
                <td className="n">{count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function AuthStats() {
  const [window24, setWindow24] = useState<StoreRow[] | null>(null)
  useEffect(() => {
    let cancelled = false
    fetchStatsWindow().then((page) => {
      if (!cancelled && page) setWindow24(page.rows)
    })
    return () => {
      cancelled = true
    }
  }, [])

  const stats = useMemo(() => {
    if (!window24) return null
    const cutoff = Date.now() - 24 * 3600 * 1000
    const recent = window24.filter((row) => {
      const at = Date.parse(str(row, '@timestamp'))
      return !Number.isNaN(at) && at >= cutoff
    })
    const tally = (key: (row: StoreRow) => string) => {
      const counts = new Map<string, number>()
      for (const row of recent) {
        const value = key(row)
        if (value) counts.set(value, (counts.get(value) ?? 0) + 1)
      }
      return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)
    }
    return {
      total: recent.length,
      byClient: tally((row) => str(row, 'client_id')),
      byIP: tally((row) => str(row, 'ip_address')),
    }
  }, [window24])

  if (!stats) return null
  return (
    <>
      <div className="tw:grid tw:grid-cols-2 tw:sm:grid-cols-4 tw:gap-3 tw:mb-6">
        <div className="metric">
          <div className="metric__value">{stats.total.toLocaleString('en-US')}</div>
          <div className="metric__label">Failed logins, 24h</div>
        </div>
      </div>
      <div className="tw:grid tw:grid-cols-12 tw:gap-3.5" style={{ marginBottom: 14 }}>
        <TopTable title="Failures by client, 24h" header="client" rows={stats.byClient} />
        <TopTable title="Top source IPs, 24h" header="source ip" rows={stats.byIP} />
      </div>
    </>
  )
}

export const Route = createFileRoute('/auth-events')({ component: Page })

function Page() {
  return (
    <StoreListPage
      fetchPage={fetchPage}
      label="Monitor"
      title="Auth-failure events"
      subtitle="Failed logins against Keycloak, across every gateway-fronted app and the dashboard's own native OIDC — redacted, never tokens/codes/cookies."
      columns={COLUMNS}
      rowKey={(row, index) => `${str(row, 'event_id')}-${index}`}
      inspectorTitle="Event details"
      chipNoun="events"
      beforeTable={<AuthStats />}
      layout="cards"
    />
  )
}
