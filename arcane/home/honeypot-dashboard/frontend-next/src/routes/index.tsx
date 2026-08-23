// Overview — the five-tab operational view ported from overview.html:
// hero + KPI strip, then Live operations / Collection health / Threat
// landscape / Attacker behavior / Evidence & campaigns. Skeleton-first:
// the shell renders instantly, every panel hydrates from its deferred
// promise.
import { Await, Link, createFileRoute, useRouter } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { Suspense, useEffect, useState } from 'react'
import { AttackMap, AttackVectors, Heatmap, Tbl, type HeatRow, type Kv, type MapPoint } from '../components/OverviewPanels'
import { EChart } from '../components/EChart'
import { copyWithFlash } from '../lib/flash'
import { isLivePaused } from '../lib/live'
import type { JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'
import { useSidebarViewTabs } from '../lib/viewTabs'
import { countryName } from '../lib/country'

type OverviewKpis = {
  total: number
  last24h: number
  previous24h: number
  change24h: string
  unique_ips: number
  /** Per-hour counts, oldest first — the 24h tile's sparkline (3B). */
  hourly: number[]
  ready: boolean
}

type SensorFeed = { name: string; count: number; last_seen: string; state: string }

type PayloadRow = { shasum: string; download: string; count: number; link: string; vt: string }

type Dashboard = {
  protocols: Kv[]
  top_ports: Kv[]
  countries: Kv[]
  asns: Kv[]
  providers: Kv[]
  top_ips: Kv[]
  top_paths: Kv[]
  top_creds: Kv[]
  top_commands: Kv[]
  clients: Kv[]
  fingerprints: Kv[]
  alerts: Kv[]
  alert_cats: Kv[]
  payloads: PayloadRow[]
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
  session: string
  record: JsonRecord
}

type StoreRow = JsonRecord

type Presentation = {
  dashboard_title?: string
  dashboard_subtitle?: string
  footer_text?: string
  banner_text?: string
  banner_severity?: string
}

const fetchKpis = createServerFn({ method: 'GET' }).handler(async (): Promise<OverviewKpis | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<OverviewKpis>('/api/v1/overview/kpis')
})

const fetchPresentation = createServerFn({ method: 'GET' }).handler(async (): Promise<Presentation | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  const config = await serviceJSON<{ payload?: { presentation?: Presentation } }>('/api/v1/config')
  return config?.payload?.presentation ?? null
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


// overview.html:34-52's hp-hero__links. Two states, both dropped in the
// port: a freshness line once data is in, and a warming note before the
// first collection pass finishes. The warming half is the one that
// matters — without it a cold index and an idle honeypot look identical,
// which is precisely the confusion #1142 introduced this state to end.
//
// The Go tier printed its server-side snapshot time (.Generated). The
// Rust overview endpoint exposes no such field, so rather than invent one
// this reports when *this view* last pulled data — which is what the
// reader actually wants from "updated", and is honest about being a fetch
// time. Set in an effect so the server and client renders agree.
function HeroFreshness({ ready, kpis }: { ready: boolean; kpis: OverviewKpis | null }) {
  const [updated, setUpdated] = useState<Date | null>(null)
  useEffect(() => {
    if (ready) setUpdated(new Date())
  }, [ready, kpis])
  if (!ready) {
    return (
      <span className="gen">
        <span className="status-dot" aria-hidden="true" /> Warming up — running the first collection pass.
      </span>
    )
  }
  if (!updated) return null
  return <span className="gen">updated {formatTimestamp(updated.toISOString())} • refreshes automatically</span>
}

export const Route = createFileRoute('/')({
  loader: async () => ({
    kpis: fetchKpis(),
    dashboard: fetchDashboard(),
    recent: fetchRecent(),
    campaigns: fetchCampaignsSummary(),
    payloads: fetchPayloadsSummary(),
    presentation: fetchPresentation(),
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

/** The 24h tile's hourly-rhythm sparkline (overview.html:65-68).
 * page_hero.go's hourlySpark rules: normalize against the busiest hour,
 * floor at 4% so silent hours stay visible as a baseline tick, render
 * nothing while the whole day is empty. */
function KpiSpark({ hourly }: { hourly: number[] | undefined }) {
  if (!hourly || hourly.length === 0) return null
  const max = Math.max(...hourly)
  if (max === 0) return null
  return (
    <div className="metric__spark" aria-hidden="true">
      {hourly.map((count, index) => (
        <i key={index} style={{ height: `${Math.max(4, Math.floor((count * 100) / max))}%` }} />
      ))}
    </div>
  )
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
        <KpiSpark hourly={kpis?.hourly} />
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

/** One stream row, ported from events.html's shared "everow" template:
 * per-cell pivot links, hover quick actions, and a row click that expands
 * the full normalized record inline (the stream stays compact until
 * asked, #1565's JSON-wall fix). */
function RecentEventRow({ row, open, onToggle }: { row: EventRow; open: boolean; onToggle: () => void }) {
  const stop = (event: React.MouseEvent) => event.stopPropagation()
  return (
    <>
      <tr className={open ? 'selected' : undefined} onClick={onToggle}>
        <td data-hp-time>{formatTimestamp(row.time)}</td>
        <td>
          <a className={`badge b-${row.sensor}`} href={`/events?sensor=${encodeURIComponent(row.sensor)}`} onClick={stop}>
            {row.sensor}
          </a>
        </td>
        <td className="v">
          {row.src_ip ? (
            <a href={`/events?ip=${encodeURIComponent(row.src_ip)}`} title={`attack chain for ${row.src_ip}`} onClick={stop}>
              {row.src_ip}
            </a>
          ) : (
            <span
              className="badge badge--muted"
              title="This event reached the sensor over the WireGuard tunnel and could not be joined back to a real client address."
            >
              unattributed
            </span>
          )}
          {row.country ? (
            <>
              {' '}
              <a className="badge badge--info" title={countryName(row.country)} href={`/events?country=${encodeURIComponent(row.country)}`} onClick={stop}>
                {row.country}
              </a>
            </>
          ) : null}
        </td>
        <td className="n">
          {row.port ? (
            <a href={`/events?port=${encodeURIComponent(row.port)}`} onClick={stop}>
              :{row.port}
            </a>
          ) : (
            ''
          )}
        </td>
        <td className="v">{row.detail || row.proto}</td>
        <td className="hp-row-actions-cell">
          <div className="hp-row-actions">
            {row.src_ip ? (
              <button
                type="button"
                title="Copy source IP"
                onClick={(event) => {
                  event.stopPropagation()
                  copyWithFlash(row.src_ip)
                }}
              >
                ⧁
              </button>
            ) : null}
            {row.session ? (
              <a href={`/sessions/${encodeURIComponent(row.session)}`} title="Replay session" onClick={stop}>
                ▶
              </a>
            ) : null}
            {row.src_ip ? (
              <a href={`/investigate/ip/${encodeURIComponent(row.src_ip)}`} title="Attacker profile" onClick={stop}>
                👤
              </a>
            ) : null}
          </div>
        </td>
      </tr>
      {open ? (
        <tr>
          <td colSpan={6}>
            <article className="card wide tw:mt-3" aria-label="Full normalized event">
              <h3>Normalized event</h3>
              <p className="note">Complete read-only record as stored by the pipeline.</p>
              {row.src_ip || row.session ? (
                <p className="note">
                  {row.src_ip ? (
                    <a className="lnk" href={`/investigate/ip/${encodeURIComponent(row.src_ip)}`}>
                      attacker profile for {row.src_ip}
                    </a>
                  ) : null}
                  {row.src_ip && row.session ? ' • ' : null}
                  {row.session ? (
                    <a className="lnk sess" href={`/sessions/${encodeURIComponent(row.session)}`}>
                      replay session {row.session}
                    </a>
                  ) : null}
                </p>
              ) : null}
              <div className="card__scroll">
                <pre className="code">{JSON.stringify(row.record, null, 2)}</pre>
              </div>
            </article>
          </td>
        </tr>
      ) : null}
    </>
  )
}

function Overview() {
  const data = Route.useLoaderData()
  const dashboard = usePromise(data.dashboard)
  const recent = usePromise(data.recent)
  const campaigns = usePromise(data.campaigns)
  const payloads = usePromise(data.payloads)
  const presentation = usePromise(data.presentation)
  const [tab, setTab] = useState<TabId>('live')
  // Design pick 7D: the overview's five view tabs relocate into the
  // sidebar rail below the Overview nav item; below 520px (off-canvas
  // sidebar) they render inline right here instead.
  const viewTabs = useSidebarViewTabs({
    label: 'Dashboard views',
    tabs: TABS,
    active: tab,
    onSelect: (id) => setTab(id as TabId),
    idPrefix: 'ov',
  })
  // Heatmap sensor picker (overview.html:94-120): one selection narrows
  // both the heatmap and its attack-vectors companion panel. The rows
  // already carry their sensor, so the narrowing is purely client-side.
  const [heatSensor, setHeatSensor] = useState('')
  const [openEvent, setOpenEvent] = useState<number | null>(null)
  const router = useRouter()

  // Auto-refresh (legacy 60s replaceHoneypotPage cycle): re-run the
  // loaders while the tab is visible; hidden tabs skip the tick, and the
  // shell's shared LIVE switch pauses it entirely (resume refetches now).
  useEffect(() => {
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible' && !isLivePaused()) void router.invalidate()
    }, 60_000)
    const onResume = () => void router.invalidate()
    window.addEventListener('hp-live-resumed', onResume)
    return () => {
      clearInterval(timer)
      window.removeEventListener('hp-live-resumed', onResume)
    }
  }, [router])

  const str = (row: StoreRow, key: string) => (typeof row[key] === 'string' ? (row[key] as string) : '')
  const num = (row: StoreRow, key: string) => (typeof row[key] === 'number' ? (row[key] as number) : 0)

  return (
    <>
      <header className="hp-hero" id="overview-header">
        {presentation?.banner_text ? (
          <div className={presentation.banner_severity === 'critical' ? 'badge badge--danger' : 'badge badge--warning'}>
            {presentation.banner_text}
          </div>
        ) : null}
        <div className="label-section">{presentation?.dashboard_title || 'Honeypot command center'}</div>
        <Suspense fallback={<h1>{greeting('')}</h1>}>
          <Await promise={data.kpis}>{(kpis) => <h1>{greeting(kpis?.change24h ?? '')}</h1>}</Await>
        </Suspense>
        <p className="hp-hero__status">
          {presentation?.dashboard_subtitle ||
            'Live attack telemetry, captured evidence, correlated campaigns, and collection health in one operational view.'}
          {/* overview.html:28's second line. The admin-configurable
              subtitle survived the port but the metric sentence under it
              did not, so the hero said what the dashboard is for without
              ever saying what it is currently seeing. */}
          <Suspense fallback={null}>
            <Await promise={data.kpis}>
              {(kpis) =>
                kpis?.ready ? (
                  <>
                    <br />
                    {kpis.last24h.toLocaleString('en-US')} events in 24h
                    {kpis.change24h ? ` (${kpis.change24h})` : ''} • {kpis.unique_ips.toLocaleString('en-US')} attack sources
                    {payloads ? ` • ${payloads.total.toLocaleString('en-US')} captured payloads` : ''}
                  </>
                ) : null
              }
            </Await>
          </Suspense>
        </p>
        <button className="hp-hero__search" type="button" onClick={() => import('../components/CommandPalette').then((m) => m.openCommandPalette())}>
          <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <span>Investigate anything — IP, session, hash, credential, country…</span>
          {/* CommandPalette.tsx:54 really does bind "/" — the hint was
              dropped in the port even though the shortcut still works. */}
          <kbd>/</kbd>
        </button>
        <div className="hp-hero__links">
          <Suspense fallback={null}>
            <Await promise={data.kpis}>{(kpis) => <HeroFreshness ready={Boolean(kpis?.ready)} kpis={kpis} />}</Await>
          </Suspense>
        </div>
      </header>

      <Suspense fallback={<KpiStrip kpis={null} logins={null} payloads={null} />}>
        <Await promise={data.kpis}>
          {(kpis) => (
            <KpiStrip kpis={kpis} logins={dashboard ? dashboard.logins : null} payloads={payloads ? payloads.total : null} />
          )}
        </Await>
      </Suspense>

      {viewTabs}

      {tab === 'live' ? (
        <div className="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" role="tabpanel" id="ov-panel-live" aria-labelledby="ov-live">
          <div className="section-heading">
            <div>
              <h2>Current activity</h2>
              <p>What is happening now, when traffic arrived, and where it originated.</p>
            </div>
            <a className="section-link" href="/events?since=24h">View last 24 hours →</a>
          </div>
          <div className="card wide chart-card">
            <h2>Activity — last 24h</h2>
            <Heatmap
              rows={dashboard ? dashboard.heatmap.filter((row) => !heatSensor || row.sensor === heatSensor) : null}
            />
            {dashboard ? (
              <AttackVectors
                sensors={dashboard.sensors.map((sensor) => sensor.name)}
                sensor={heatSensor}
                onSensorChange={setHeatSensor}
              />
            ) : null}
          </div>
          <div className="card wide map-card">
            <h2>Attack origins — live geographic view</h2>
            <AttackMap points={dashboard ? dashboard.map_points : null} />
            <p className="note">
              Approximate geolocation only. One marker per city, accumulating every IP that geolocated there. Map data ©
              OpenStreetMap contributors.
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
                    <tr><th>time</th><th>sensor</th><th>source ip</th><th>port</th><th>detail</th><th></th></tr>
                  </thead>
                  <tbody>
                    {recent.rows.map((row, index) => (
                      <RecentEventRow
                        key={`${row.time}-${index}`}
                        row={row}
                        open={openEvent === index}
                        onToggle={() => setOpenEvent(openEvent === index ? null : index)}
                      />
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      ) : null}

      {tab === 'health' ? (
        <div className="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" role="tabpanel" id="ov-panel-health" aria-labelledby="ov-health">
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
                          <td className="ago">{formatTimestamp(sensor.last_seen)}</td>
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
              Average queue depth per hour for honeypot-v2-* and suricata-v2-* events awaiting ml-worker classification. A
              rising line means the backlog is growing, not draining — see{' '}
              <a href="https://github.com/Xore/APIARY/issues/1227" target="_blank" rel="noopener noreferrer">
                #1227
              </a>
              .
            </p>
          </div>
        </div>
      ) : null}

      {tab === 'threats' ? (
        <div className="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" role="tabpanel" id="ov-panel-threats" aria-labelledby="ov-threats">
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
          {/* #1565 (overview.html:258-259): ASNs and provider classes are a
              deliberate half/half pair; the ids let theme.css widen the
              busier ASN card. */}
          <Tbl title="Top autonomous systems" rows={dashboard ? dashboard.asns : null} half id="overview-asns-card" />
          <Tbl title="Network/provider classes" rows={dashboard ? dashboard.providers : null} half id="overview-providers-card" />
          <div className="card wide" id="netflow-bytes-card">
            <h2>Traffic volume — bytes/hour, last 7 days</h2>
            <p className="note">
              Summed from every captured flow&apos;s byte count, all sensors and ports combined. A spike stands out here even
              when it doesn&apos;t in the event-count activity heatmap above.
            </p>
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
            <p className="note">
              Real, human-readable exploit identities dionaea itself recognized in the traffic it captured (e.g.
              DoublePulsar/EternalBlue), not a generic incident-kind label.
            </p>
            <EChart kind="bar" url="/api/chart/dionaea-cves" height={320} />
          </div>
        </div>
      ) : null}

      {tab === 'behavior' ? (
        <div className="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" role="tabpanel" id="ov-panel-behavior" aria-labelledby="ov-behavior">
          <div className="section-heading">
            <div>
              <h2>Attacker behavior</h2>
              <p>Authentication attempts, executed commands, client identity, and reusable fingerprints.</p>
            </div>
            <a className="section-link" href="/commands">Review all commands →</a>
          </div>
          <Tbl title="Top credentials (user / pass)" rows={dashboard ? dashboard.top_creds : null} hint="authentication events only" />
          <Tbl title="Top commands" rows={dashboard ? dashboard.top_commands : null} hint="No shell commands captured yet — fed by cowrie and multipot sessions." />
          <Tbl title="SSH/telnet clients" rows={dashboard ? dashboard.clients : null} hint="No client banners yet — fed by cowrie." />
          <Tbl title="Top fingerprints (HASSH / JA3 / JA4 / User-Agent)" rows={dashboard ? dashboard.fingerprints : null} half hint="No protocol or client fingerprints captured yet." />
          <Tbl title="Top HTTP paths" rows={dashboard ? dashboard.top_paths : null} half hint="No web probes yet — fed by http-honeypot and tanner." />
          <div className="card wide" id="os-distribution-card">
            <h2>Attacker OS distribution</h2>
            <p className="note">
              p0f&apos;s own passive OS fingerprint, resolved from the portbridge tunnel join (#241) — a best-effort guess
              from TCP/IP stack behavior, not a claim of certainty.
            </p>
            <EChart kind="pie" url="/api/chart/os-distribution" height={360} />
          </div>
          <div className="card wide" id="tcp-stack-clusters-card">
            <h2>Attacker TCP-stack clusters (JA4T)</h2>
            <p className="note">
              Unique attackers per TCP handshake fingerprint, from Zeek. Deliberately not an OS name — it groups hosts
              that share a network stack without guessing which one, so it does not go stale as operating systems move on.
              Read it alongside the OS chart above: p0f resolves three quarters of connections here to a Linux kernel
              retired in 2017.
            </p>
            <EChart kind="pie" url="/api/chart/tcp-stack-clusters" height={360} />
          </div>
          <div className="card wide" id="ics-functions-card">
            <h2>ICS function codes — what they asked the PLCs to do</h2>
            <p className="note">
              Per-transaction detail from the ICS parsers, across Modbus, S7comm and DNP3. These events are rare and
              the scanning around them is not — one sample held 3,600 connections to the DNP3 port and two actual DNP3
              requests, both filesystem reconnaissance. An alert-only view loses exactly those two.
            </p>
            <EChart kind="barh" url="/api/chart/ics-functions" height={360} />
          </div>
          <div className="card wide" id="decoy-requests-card">
            <h2>Decoy requests (TLS-terminated) — last 7 days</h2>
            <p className="note">
              What was requested from the Host-routed decoys behind Traefik. These exist in no other index: Traefik
              terminates TLS for them, so a wire sensor sees the handshake and then ciphertext.
            </p>
            <EChart kind="barh" url="/api/chart/decoy-requests" height={360} />
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
        <div className="dashboard-panel tw:grid tw:grid-cols-12 tw:gap-3.5" role="tabpanel" id="ov-panel-evidence" aria-labelledby="ov-evidence">
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
            {/* overview.html:400-412's columns: seen count → the payload's
                events, hash → static analysis, target path → events,
                lookup → static analysis + VirusTotal. */}
            {dashboard === null ? (
              <>
                <span className="skeleton-line" aria-hidden="true" />
                <span className="skeleton-line" aria-hidden="true" />
              </>
            ) : dashboard.payloads.length === 0 ? (
              <p className="empty">No payloads captured yet — cowrie logs downloads/uploads during a shell session.</p>
            ) : (
              <div className="card__scroll">
                <table className="data-table">
                  <thead>
                    <tr><th>seen</th><th>sha-256</th><th>attacker target path</th><th>lookup</th></tr>
                  </thead>
                  <tbody>
                    {dashboard.payloads.map((row) => (
                      <tr key={row.shasum}>
                        <td className="n">
                          <a href={row.link} title="show events for this payload">{row.count.toLocaleString('en-US')}</a>
                        </td>
                        <td className="v">
                          <a href={`/payload-analysis/${row.shasum}`} title="static analysis of this payload">{row.shasum}</a>
                        </td>
                        <td className="v">
                          <a href={row.link} title="show events for this captured artifact">{row.download}</a>
                        </td>
                        <td className="v">
                          <a className="lnk" href={`/payload-analysis/${row.shasum}`}>static analysis →</a>{' '}
                          <a className="lnk" href={row.vt} target="_blank" rel="noopener noreferrer">VirusTotal →</a>
                        </td>
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
                    {/* intel.html:136-149 (campaignrows-summary): every
                        cell deep-links to the campaign's own CIDR
                        investigation. */}
                    {campaigns.rows.map((row, index) => {
                      const cidr = str(row, 'cidr')
                      return (
                        <tr key={`${cidr}-${index}`}>
                          <td className="v">
                            <Link to="/investigate/cidr/$cidr" params={{ cidr }}>{cidr}</Link>
                          </td>
                          <td className="n">
                            <Link to="/investigate/cidr/$cidr" params={{ cidr }} title="show campaign events">
                              {num(row, 'events').toLocaleString('en-US')}
                            </Link>
                          </td>
                          <td className="n">
                            <Link to="/investigate/cidr/$cidr" params={{ cidr }} title="show campaign source addresses">
                              {num(row, 'unique_ips').toLocaleString('en-US')}
                            </Link>
                          </td>
                          <td className="v">
                            <Link to="/investigate/cidr/$cidr" params={{ cidr }} title="show campaign sensor activity">
                              {Array.isArray(row.sensors) ? (row.sensors as string[]).join(' ') : ''}
                            </Link>
                          </td>
                          <td>{formatTimestamp(str(row, 'last'))}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      ) : null}

      <footer id="overview-footer">
        {presentation?.footer_text || 'APIARY • defensive sensor • do not expose without auth'}
      </footer>
    </>
  )
}
