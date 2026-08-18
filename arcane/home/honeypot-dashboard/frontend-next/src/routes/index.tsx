// Overview — the five-tab operational view ported from overview.html:
// hero + KPI strip, then Live operations / Collection health / Threat
// landscape / Attacker behavior / Evidence & campaigns. Skeleton-first:
// the shell renders instantly, every panel hydrates from its deferred
// promise.
import { Await, createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { Suspense, useEffect, useState } from 'react'
import { AttackMap, Heatmap, Tbl, type HeatRow, type Kv, type MapPoint } from '../components/OverviewPanels'
import { EChart } from '../components/EChart'

type OverviewKpis = {
  total: number
  last24h: number
  previous24h: number
  change24h: string
  unique_ips: number
  ready: boolean
}

type SensorFeed = { name: string; count: number; last_seen: string; state: string }

type Dashboard = {
  protocols: Kv[]
  top_ports: Kv[]
  countries: Kv[]
  asns: Kv[]
  top_ips: Kv[]
  top_paths: Kv[]
  top_creds: Kv[]
  top_commands: Kv[]
  clients: Kv[]
  fingerprints: Kv[]
  alerts: Kv[]
  alert_cats: Kv[]
  logins: number
  heatmap: HeatRow[]
  map_points: MapPoint[]
  sensors: SensorFeed[]
}

type EventRow = {
  time: string
  sensor: string
  src_ip: string
  country: string
  port: string
  detail: string
  proto: string
}

type StoreRow = Record<string, unknown>

const fetchKpis = createServerFn({ method: 'GET' }).handler(async (): Promise<OverviewKpis | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<OverviewKpis>('/api/v1/overview/kpis')
})

const fetchDashboard = createServerFn({ method: 'GET' }).handler(async (): Promise<Dashboard | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<Dashboard>('/api/v1/overview/dashboard')
})

const fetchRecent = createServerFn({ method: 'GET' }).handler(async () => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<{ total: number; rows: EventRow[] }>('/api/v1/events?size=18')
})

const fetchCampaignsSummary = createServerFn({ method: 'GET' }).handler(async () => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<{ total: number; rows: StoreRow[] }>('/api/v1/campaigns?size=15')
})

const fetchPayloadsSummary = createServerFn({ method: 'GET' }).handler(async () => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<{ total: number; rows: StoreRow[] }>('/api/v1/payloads?size=15')
})

export const Route = createFileRoute('/')({
  loader: async () => ({
    kpis: fetchKpis(),
    dashboard: fetchDashboard(),
    recent: fetchRecent(),
    campaigns: fetchCampaignsSummary(),
    payloads: fetchPayloadsSummary(),
  }),
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

function KpiStrip({ kpis, logins, payloads }: { kpis: OverviewKpis | null; logins: number | null; payloads: number | null }) {
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
      <a className="metric" href="/events?kind=login" title="Authentication attempts captured by interactive honeypots">
        <div className="metric__value">
          <KpiValue value={logins} />
        </div>
        <div className="metric__label">Login attempts</div>
      </a>
      <a className="metric" href="/payloads" title="Distinct payload binaries captured safely">
        <div className="metric__value">
          <KpiValue value={payloads} />
        </div>
        <div className="metric__label">Captured payloads</div>
      </a>
    </div>
  )
}

const TABS = [
  { id: 'live', label: 'Live operations' },
  { id: 'health', label: 'Collection health' },
  { id: 'threats', label: 'Threat landscape' },
  { id: 'behavior', label: 'Attacker behavior' },
  { id: 'evidence', label: 'Evidence & campaigns' },
] as const

type TabId = (typeof TABS)[number]['id']

function usePromise<T>(promise: Promise<T | null>): T | null {
  const [value, setValue] = useState<T | null>(null)
  useEffect(() => {
    let cancelled = false
    promise.then((result) => {
      if (!cancelled) setValue(result)
    })
    return () => {
      cancelled = true
    }
  }, [promise])
  return value
}

function Overview() {
  const data = Route.useLoaderData()
  const dashboard = usePromise(data.dashboard)
  const recent = usePromise(data.recent)
  const campaigns = usePromise(data.campaigns)
  const payloads = usePromise(data.payloads)
  const [tab, setTab] = useState<TabId>('live')

  const str = (row: StoreRow, key: string) => (typeof row[key] === 'string' ? (row[key] as string) : '')
  const num = (row: StoreRow, key: string) => (typeof row[key] === 'number' ? (row[key] as number) : 0)

  return (
    <>
      <header className="hp-hero" id="overview-header">
        <div className="label-section">Honeypot command center</div>
        <Suspense fallback={<h1>{greeting('')}</h1>}>
          <Await promise={data.kpis}>{(kpis) => <h1>{greeting(kpis?.change24h ?? '')}</h1>}</Await>
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

      <Suspense fallback={<KpiStrip kpis={null} logins={null} payloads={null} />}>
        <Await promise={data.kpis}>
          {(kpis) => (
            <KpiStrip kpis={kpis} logins={dashboard ? dashboard.logins : null} payloads={payloads ? payloads.total : null} />
          )}
        </Await>
      </Suspense>

      <div className="tabs" role="tablist" aria-label="Dashboard views">
        {TABS.map((entry, index) => (
          <button
            key={entry.id}
            className={tab === entry.id ? 'tab active' : 'tab'}
            type="button"
            role="tab"
            aria-selected={tab === entry.id}
            onClick={() => setTab(entry.id)}
          >
            <span>{String(index + 1).padStart(2, '0')}</span>
            {entry.label}
          </button>
        ))}
      </div>

      {tab === 'live' ? (
        <div className="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" role="tabpanel">
          <div className="section-heading">
            <div>
              <h2>Current activity</h2>
              <p>What is happening now, when traffic arrived, and where it originated.</p>
            </div>
            <a className="section-link" href="/events?since=24h">View last 24 hours →</a>
          </div>
          <div className="card wide chart-card">
            <h2>Activity — last 24h</h2>
            <Heatmap rows={dashboard ? dashboard.heatmap : null} />
          </div>
          <div className="card wide map-card">
            <h2>Attack origins — live geographic view</h2>
            <AttackMap points={dashboard ? dashboard.map_points : null} />
            <p className="note">
              Approximate geolocation only. One marker per city, accumulating every IP that geolocated there; radius is weighted by
              event count. Map data © OpenStreetMap contributors.
            </p>
          </div>
          <div className="section-heading">
            <div>
              <h2>Live event stream</h2>
              <p>A balanced sample of the newest normalized events across all sensors.</p>
            </div>
            <a className="section-link" href="/events">Open full event explorer →</a>
          </div>
          <div className="card wide" id="recent-events-card">
            <h2>Recent events</h2>
            {recent === null ? (
              <>
                <span className="skeleton-line" aria-hidden="true" />
                <span className="skeleton-line" aria-hidden="true" />
                <span className="skeleton-line" aria-hidden="true" />
              </>
            ) : (
              <div className="card__scroll">
                <table className="recent data-table">
                  <thead>
                    <tr><th>time</th><th>sensor</th><th>source ip</th><th>port</th><th>detail</th></tr>
                  </thead>
                  <tbody>
                    {recent.rows.map((row, index) => (
                      <tr key={`${row.time}-${index}`}>
                        <td>{row.time.replace('T', ' ').slice(0, 19)}</td>
                        <td><span className="badge badge--muted">{row.sensor}</span></td>
                        <td className="v">
                          {row.src_ip}{' '}
                          {row.country ? <span className="badge badge--info">{row.country}</span> : null}
                        </td>
                        <td className="n">{row.port ? `:${row.port}` : ''}</td>
                        <td className="v">{row.detail || row.proto}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      ) : null}

      {tab === 'health' ? (
        <div className="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" role="tabpanel">
          <div className="section-heading">
            <div>
              <h2>Collection status</h2>
              <p>Sensor activity and the protocols currently attracting traffic.</p>
            </div>
            <a className="section-link" href="/source-health">Open pipeline health →</a>
          </div>
          <div className="card half sensor-card">
            <h2>Sensor feeds</h2>
            {dashboard === null ? (
              <>
                <span className="skeleton-line" aria-hidden="true" />
                <span className="skeleton-line" aria-hidden="true" />
              </>
            ) : (
              <>
                <p className="note">
                  Showing all {dashboard.sensors.length} sensors. Active = recent traffic, quiet = online with no recent event,
                  stale = its feed has stopped updating. A quiet honeypot is not necessarily offline.
                </p>
                <div className="card__scroll">
                  <table className="data-table">
                    <tbody>
                      {dashboard.sensors.map((sensor) => (
                        <tr key={sensor.name}>
                          <td className="n">{sensor.count.toLocaleString('en-US')}</td>
                          <td><span className={`badge b-${sensor.name}`}>{sensor.name}</span></td>
                          <td className={`state s-${sensor.state}`}>{sensor.state}</td>
                          <td className="ago">{sensor.last_seen.replace('T', ' ').slice(0, 19)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>
          <Tbl title="Protocols probed" rows={dashboard ? dashboard.protocols : null} half />
          <div className="card wide" id="ml-backlog-card">
            <h2>ML classification backlog — last 7 days</h2>
            <EChart kind="line" url="/api/chart/ml-backlog" height={280} />
            <p className="note">
              Average queue depth per hour for events awaiting ml-worker classification. A rising line means the backlog is
              growing, not draining.
            </p>
          </div>
        </div>
      ) : null}

      {tab === 'threats' ? (
        <div className="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" role="tabpanel">
          <div className="section-heading">
            <div>
              <h2>Threat landscape</h2>
              <p>Highest-volume sources, targets, locations, and network ownership.</p>
            </div>
            <a className="section-link" href="/ips">Investigate all sources →</a>
          </div>
          <Tbl title="Top source IPs" rows={dashboard ? dashboard.top_ips : null} />
          <Tbl title="Top targeted ports" rows={dashboard ? dashboard.top_ports : null} />
          <Tbl title="Top countries" rows={dashboard ? dashboard.countries : null} />
          <Tbl title="Top autonomous systems" rows={dashboard ? dashboard.asns : null} half id="overview-asns-card" />
          <div className="card wide" id="netflow-bytes-card">
            <h2>Traffic volume — bytes/hour, last 7 days</h2>
            <EChart kind="line" url="/api/chart/netflow-bytes" height={280} />
            <p className="note">
              Summed from every captured flow's byte count. A spike stands out here even when it doesn't in the event-count
              heatmap.
            </p>
          </div>
          <div className="card wide" id="netflow-packets-card">
            <h2>Traffic volume — packets/hour, last 7 days</h2>
            <EChart kind="line" url="/api/chart/netflow-packets" height={280} />
          </div>
          <div className="card wide" id="anomaly-trend-card">
            <h2>Protocol-conformance violations by protocol, over time</h2>
            <p className="note">
              Traffic that doesn't conform to the protocol it claims to be — often scanning tools or deliberate IDS-evasion
              attempts.
            </p>
            <EChart kind="line" url="/api/chart/anomaly-trend" height={280} />
          </div>
          <div className="card wide" id="dionaea-cves-card">
            <h2>Top exploited CVEs / named incidents — last 7 days</h2>
            <p className="note">Real exploit identities dionaea itself recognized in captured traffic (e.g. DoublePulsar/EternalBlue).</p>
            <EChart kind="bar" url="/api/chart/dionaea-cves" height={320} />
          </div>
        </div>
      ) : null}

      {tab === 'behavior' ? (
        <div className="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" role="tabpanel">
          <div className="section-heading">
            <div>
              <h2>Attacker behavior</h2>
              <p>Authentication attempts, executed commands, client identity, and reusable fingerprints.</p>
            </div>
            <a className="section-link" href="/commands">Review all commands →</a>
          </div>
          <Tbl title="Top credentials (user / pass)" rows={dashboard ? dashboard.top_creds : null} hint="authentication events only" />
          <Tbl title="Top commands" rows={dashboard ? dashboard.top_commands : null} hint="no shell commands captured yet — fed by cowrie and multipot sessions" />
          <Tbl title="SSH/telnet clients" rows={dashboard ? dashboard.clients : null} hint="no client banners yet — fed by cowrie" />
          <Tbl title="Top fingerprints (HASSH / JA3 / JA4 / User-Agent)" rows={dashboard ? dashboard.fingerprints : null} half hint="no protocol or client fingerprints captured yet" />
          <Tbl title="Top HTTP paths" rows={dashboard ? dashboard.top_paths : null} half hint="no web probes yet — fed by http-honeypot and tanner" />
          <div className="card wide" id="os-distribution-card">
            <h2>Attacker OS distribution</h2>
            <p className="note">p0f's passive OS fingerprint, resolved from the portbridge tunnel join — a best-effort guess, not certainty.</p>
            <EChart kind="pie" url="/api/chart/os-distribution" height={360} />
          </div>
          <div className="card wide" id="tls-fingerprints-card">
            <h2>TLS scanner fingerprints (JA4) — wire-level, last 7 days</h2>
            <p className="note">Every TLS handshake against a non-dashboard port, alert or not. Click a bar to copy the full hash.</p>
            <EChart kind="barh" url="/api/chart/tls-fingerprints" height={360} />
          </div>
          <div className="card wide" id="ssh-fingerprints-card">
            <h2>SSH client software — wire-level, last 7 days</h2>
            <p className="note">Every SSH handshake's client software banner, not just ones that triggered an alert.</p>
            <EChart kind="barh" url="/api/chart/ssh-fingerprints" height={360} />
          </div>
          <div className="card wide" id="endlessh-held-card">
            <h2>Attacker time wasted (endlessh tarpit)</h2>
            <p className="note">Time attackers/bots spent stuck talking to nothing before giving up.</p>
            <EChart kind="bar" url="/api/chart/endlessh-held-histogram" height={320} />
          </div>
        </div>
      ) : null}

      {tab === 'evidence' ? (
        <div className="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" role="tabpanel">
          <div className="section-heading">
            <div>
              <h2>Detection and evidence</h2>
              <p>IDS findings, captured artifacts, and cross-sensor campaign correlation.</p>
            </div>
            <a className="section-link" href="/payloads">Open payload analysis →</a>
          </div>
          <Tbl title="Suricata alerts" rows={dashboard ? dashboard.alerts : null} half hint="No Suricata alerts in this window — pipeline status lives under Source & pipeline health." />
          <Tbl title="Alert categories" rows={dashboard ? dashboard.alert_cats : null} half hint="No Suricata alerts in this window." />
          <div className="card wide">
            <h2>Captured payloads</h2>
            <p className="note">Inert copies of malware and high-confidence scripts. Static analysis never executes the payload.</p>
            {payloads === null ? (
              <>
                <span className="skeleton-line" aria-hidden="true" />
                <span className="skeleton-line" aria-hidden="true" />
              </>
            ) : (
              <div className="card__scroll">
                <table className="data-table">
                  <thead>
                    <tr><th>seen</th><th>sha-256</th><th>kind</th></tr>
                  </thead>
                  <tbody>
                    {payloads.rows.map((row, index) => (
                      <tr key={`${str(row, 'Hash')}-${index}`}>
                        <td>{str(row, 'MtimeUTC').replace('T', ' ').slice(0, 19)}</td>
                        <td className="v"><a href="/payloads">{str(row, 'Hash')}</a></td>
                        <td><span className="badge badge--muted">{str(row, 'Kind')}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          <div className="card wide">
            <h2>Correlated campaigns — rolling 7 days</h2>
            <p className="note">
              Groups related source networks across sensors. Score rises with volume, sensor/port spread, reused credentials,
              payloads, IDS alerts, and matching fingerprints.
            </p>
            {campaigns === null ? (
              <>
                <span className="skeleton-line" aria-hidden="true" />
                <span className="skeleton-line" aria-hidden="true" />
              </>
            ) : (
              <div className="card__scroll">
                <table className="recent data-table">
                  <thead>
                    <tr><th>network</th><th>events</th><th>ips</th><th>sensors</th><th>last seen</th></tr>
                  </thead>
                  <tbody>
                    {campaigns.rows.map((row, index) => (
                      <tr key={`${str(row, 'cidr')}-${index}`}>
                        <td className="v"><a href="/campaigns">{str(row, 'cidr')}</a></td>
                        <td className="n">{num(row, 'events').toLocaleString('en-US')}</td>
                        <td className="n">{num(row, 'unique_ips').toLocaleString('en-US')}</td>
                        <td className="n">{Array.isArray(row.sensors) ? (row.sensors as string[]).length : 0}</td>
                        <td>{str(row, 'last').replace('T', ' ').slice(0, 19)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      ) : null}

      <footer id="overview-footer">APIARY • defensive sensor • do not expose without auth</footer>
    </>
  )
}
