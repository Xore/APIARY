// Overview — OV-E focus elements at full width: hero greeting + single
// search, boxless serif KPI strip. Data flows through a server function
// (the BFF tier) to the Rust service's /api/v1/overview/kpis; the route
// renders instantly with skeleton values and hydrates when the deferred
// KPI promise resolves — the skeleton-first hard rule, framework-native.
import { Await, createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { Suspense } from 'react'

type OverviewKpis = {
  total: number
  last24h: number
  previous24h: number
  change24h: string
  unique_ips: number
  ready: boolean
}

const fetchKpis = createServerFn({ method: 'GET' }).handler(async (): Promise<OverviewKpis | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<OverviewKpis>('/api/v1/overview/kpis')
})

export const Route = createFileRoute('/')({
  loader: async () => ({ kpis: fetchKpis() }),
  component: Overview,
})

function greeting(change: string): string {
  const hour = new Date().getHours()
  const salutation = hour < 5 ? 'Good night' : hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening'
  const clause = change.startsWith('+')
    ? 'traffic is running hotter than usual.'
    : change.startsWith('-')
      ? 'traffic is quieter than usual.'
      : 'traffic is at its usual rhythm.'
  return `${salutation} — ${clause}`
}

function KpiValue({ value }: { value: number | null }) {
  if (value === null) return <span className="skeleton-line" aria-hidden="true" />
  return <>{value.toLocaleString('en-US')}</>
}

function KpiStrip({ kpis }: { kpis: OverviewKpis | null }) {
  return (
    <div className="tw:grid tw:grid-cols-2 tw:sm:grid-cols-3 tw:xl:grid-cols-5 tw:gap-3 tw:mb-6" id="overview-kpis">
      <a className="metric" href="/events" title="Open all normalized events in the current dashboard window">
        <div className="metric__value">
          <KpiValue value={kpis && kpis.ready ? kpis.total : null} />
        </div>
        <div className="metric__label">All events</div>
      </a>
      <a className="metric" href="/events?since=24h" title="Open events received during the last 24 hours">
        <div className="metric__value">
          <KpiValue value={kpis && kpis.ready ? kpis.last24h : null} />
          {kpis?.change24h ? (
            <span
              className={kpis.change24h.startsWith('-') ? 'metric__delta metric__delta--down' : 'metric__delta'}
              title="Compared with the directly preceding 24-hour period"
            >
              {kpis.change24h}
            </span>
          ) : null}
        </div>
        <div className="metric__label">Events in 24 hours</div>
      </a>
      <a className="metric" href="/ips" title="Distinct attacker source addresses observed by the sensors">
        <div className="metric__value">
          <KpiValue value={kpis && kpis.ready ? kpis.unique_ips : null} />
        </div>
        <div className="metric__label">Attack sources</div>
      </a>
    </div>
  )
}

function Overview() {
  const { kpis } = Route.useLoaderData()
  return (
    <>
      <header className="hp-hero">
        <div className="label-section">Honeypot command center</div>
        <Suspense fallback={<h1>{greeting('')}</h1>}>
          <Await promise={kpis}>{(data) => <h1>{greeting(data?.change24h ?? '')}</h1>}</Await>
        </Suspense>
        <p className="hp-hero__status">
          Live attack telemetry, captured evidence, correlated campaigns, and collection health in one operational view.
        </p>
        <button className="hp-hero__search" type="button">
          <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <span>Investigate anything — IP, session, hash, credential, country…</span>
        </button>
      </header>
      <Suspense fallback={<KpiStrip kpis={null} />}>
        <Await promise={kpis}>{(data) => <KpiStrip kpis={data} />}</Await>
      </Suspense>
    </>
  )
}
