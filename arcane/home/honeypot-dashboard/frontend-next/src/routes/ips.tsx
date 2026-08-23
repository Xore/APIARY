// Attack sources — AS-D profile card grid with View-more + skeleton-first,
// every column of the old table on each card.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useMemo } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { AttackMap, type MapPoint } from '../components/OverviewPanels'
import { usePaginatedList, useResolved } from '../lib/hooks'
import { formatTimestamp } from '../lib/time'
import { countryName } from '../lib/country'

type SourceRow = {
  ip: string
  country: string
  events: number
  logins: number
  sessions: number
  sensors: string[]
  first: string
  last: string
}

type SourcesPage = { total_unique: number; rows: SourceRow[] }

const fetchSources = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }) => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<SourcesPage>(`/api/v1/sources?offset=${data.offset}&size=25`)
  })

// /api/v1/sources rows carry only a country code, no coordinates, so the
// map reuses /api/v1/overview/dashboard's map_points — the same geolocated
// origins the overview map plots (ips.html:56-64 shares the overview map).
const fetchMapPoints = createServerFn({ method: 'GET' }).handler(async (): Promise<MapPoint[] | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  const dashboard = await serviceJSON<{ map_points: MapPoint[] }>('/api/v1/overview/dashboard')
  return dashboard ? dashboard.map_points : null
})

export const Route = createFileRoute('/ips')({
  loader: async () => ({ first: fetchSources({ data: { offset: 0 } }), mapPoints: fetchMapPoints() }),
  component: Sources,
})

function when(iso: string): string {
  return formatTimestamp(iso)
}

function SkeletonCards({ count }: { count: number }) {
  return (
    <>
      {Array.from({ length: count }, (_, i) => (
        <div key={`skel-${i}`} className="hp-skel-batch" aria-hidden="true">
          <div className="skeleton-line" />
          <div className="skeleton-line" />
          <div className="skeleton-line" />
        </div>
      ))}
    </>
  )
}

function Sources() {
  const { first, mapPoints } = Route.useLoaderData()
  const points = useResolved(mapPoints)
  // SourcesPage names its count total_unique, not total — adapt to the
  // {total, rows} shape usePaginatedList expects. Memoized so the adapted
  // promise's identity stays stable across renders (it's an effect dep).
  const adaptedFirst = useMemo(() => first.then((page) => (page ? { total: page.total_unique, rows: page.rows } : null)), [first])
  const { rows, total, loadingMore, viewMore } = usePaginatedList(adaptedFirst, async (offset) => {
    const page = await fetchSources({ data: { offset } })
    return page ? { total: page.total_unique, rows: page.rows } : null
  })

  return (
    <>
      <InvestigateHeader
        label="Attack sources"
        title="Source IPs"
        subtitle="Every source address observed by the sensors, with event volume, geolocation, and activity window."
        chips={
          <>
            <span className="chip">{total.toLocaleString('en-US')} unique IPs</span>
            <a className="chip" title="Download every attack source as CSV" href="/api/export/ips.csv">
              ⇩ CSV
            </a>
          </>
        }
      />
      {/* Map-first (ips.html:56-64, AS-C): where-then-who — the attack-origins
          map leads the page, marker clicks open the related events. */}
      <div className="card wide" id="ips-map">
        <h2>Attack origins</h2>
        <AttackMap points={points ?? null} />
      </div>
      <div className="card wide" id="ips-table">
        <div className="hp-src-grid">
          {rows === null ? (
            <SkeletonCards count={10} />
          ) : (
            rows.map((row) => (
              <div key={row.ip} className="hp-src-card">
                <div className="hp-src-card__head">
                  <a className="hp-src-card__ip" href={`/investigate/ip/${encodeURIComponent(row.ip)}`} title="Open full investigation">
                    {row.ip}
                  </a>
                  {row.country ? (
                    <a className="badge badge--info" title={countryName(row.country)} href={`/events?country=${encodeURIComponent(row.country)}`}>
                      {row.country}
                    </a>
                  ) : null}
                </div>
                {/* Distinct stat destinations per ips.html:10-14. */}
                <div className="hp-src-card__stats">
                  <a href={`/events?ip=${encodeURIComponent(row.ip)}`}>
                    <b>{row.events.toLocaleString('en-US')}</b>
                    <span>events</span>
                  </a>
                  <a href={`/events?ip=${encodeURIComponent(row.ip)}&kind=login`} title={`login attempts from ${row.ip}`}>
                    <b>{row.logins.toLocaleString('en-US')}</b>
                    <span>logins</span>
                  </a>
                  <a href={`/investigate/ip/${encodeURIComponent(row.ip)}`} title={`attack chain and sessions for ${row.ip}`}>
                    <b>{row.sessions.toLocaleString('en-US')}</b>
                    <span>sessions</span>
                  </a>
                </div>
                <span className="hp-src-card__sensors">
                  {/* The class on each anchor keeps the muted sensors-line look
                      (overrides the global a color) with per-sensor hover. */}
                  {row.sensors.map((sensor, i) => (
                    <span key={sensor}>
                      {i > 0 ? ' ' : null}
                      <a
                        className="hp-src-card__sensors"
                        href={`/events?ip=${encodeURIComponent(row.ip)}&sensor=${encodeURIComponent(sensor)}`}
                        title={`${sensor} activity for ${row.ip}`}
                      >
                        {sensor}
                      </a>
                    </span>
                  ))}
                </span>
                <div className="hp-src-card__when">
                  <span>{when(row.first)}</span> → <span>{when(row.last)}</span>
                </div>
              </div>
            ))
          )}
          {loadingMore ? <SkeletonCards count={5} /> : null}
        </div>
        {rows !== null && rows.length < Math.min(total, 1000) ? (
          <div className="hp-lazy-controls" aria-live="polite">
            <span>
              {rows.length.toLocaleString('en-US')} of {total.toLocaleString('en-US')} entries
            </span>
            <button className="btn btn-secondary btn-sm" type="button" onClick={viewMore} disabled={loadingMore}>
              View more
            </button>
          </div>
        ) : null}
      </div>
    </>
  )
}
