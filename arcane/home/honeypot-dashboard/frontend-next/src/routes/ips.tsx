// Attack sources — AS-D profile card grid with View-more + skeleton-first,
// every column of the old table on each card.
import { Skeleton } from '../components/ui/skeleton'
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useMemo } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { AttackMap, type MapPoint } from '../components/OverviewPanels'
import { ErrorStateBlock } from '../components/ErrorState'
import { usePaginatedList, useResolved } from '../lib/hooks'
import { formatTimestamp } from '../lib/time'
import { countryName } from '../lib/country'
import { Button } from '../components/ui/button'
import { Badge } from '../components/ui/badge'
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card'

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
  .validator((input: { offset: number }) => input)
  .handler(async ({ data }) => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<SourcesPage>(`/api/v1/sources?offset=${data.offset}&size=25`)
  })

// /api/v1/sources rows carry only a country code, no coordinates, so the
// map reuses /api/v1/overview/dashboard's map_points — the same geolocated
// origins the overview map plots (ips.html:56-64 shares the overview map).
// ?parts=map_points (#1963): this page wants one slice of eighteen, and
// there is no reason to sweep every leaderboard aggregation for it.
const fetchMapPoints = createServerFn({ method: 'GET' }).handler(async (): Promise<MapPoint[] | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  const dashboard = await serviceJSON<{ map_points: MapPoint[] }>('/api/v1/overview/dashboard?parts=map_points')
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
  // Shape-true ghost of hp-src-card (#1967): ip + country head, the three
  // stat destinations, a sensors line and the when-range -- not three
  // generic bars. The stats cells copy the loaded card's flex/padding so
  // the three-column rhythm is already standing when numbers land.
  return (
    <>
      {Array.from({ length: count }, (_, i) => (
        <div key={`skel-${i}`} className="flex flex-col gap-2 rounded-[14px] bg-muted p-4" aria-hidden="true">
          <div className="flex items-center justify-between gap-2">
            <Skeleton className="h-4 w-full" style={{ display: 'block', width: '42%' }} />
            <Skeleton className="h-4 w-full" style={{ display: 'block', width: 34, height: 16, borderRadius: 999 }} />
          </div>
          <div className="flex">
            {[0, 1, 2].map((j) => (
              <span key={j} style={{ flex: 1, minWidth: 0, padding: j === 0 ? '0 var(--space-md) 0 0' : '0 var(--space-md)', borderLeft: j === 0 ? 'none' : '1px solid var(--border-100)' }}>
                <Skeleton className="h-4 w-full" style={{ display: 'block', width: 36, height: 17 }} />
                <Skeleton className="h-4 w-full" style={{ display: 'block', width: 48, height: 10 }} />
              </span>
            ))}
          </div>
          <Skeleton className="h-4 w-full" style={{ display: 'block', width: '68%' }} />
          <Skeleton className="h-4 w-full" style={{ display: 'block', width: '46%' }} />
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
  const { rows, total, loadingMore, viewMore, failed, retry } = usePaginatedList(adaptedFirst, async (offset) => {
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
            <span className="chip">{failed ? 'load failed' : `${total.toLocaleString('en-US')} unique IPs`}</span>
            <Link className="chip" title="Download every attack source as CSV" to="/api/export/$name" params={{ name: 'ips.csv' }} reloadDocument>
              ⇩ CSV
            </Link>
          </>
        }
      />
      {/* Map-first (ips.html:56-64, AS-C): where-then-who — the attack-origins
          map leads the page, marker clicks open the related events. */}
      <Card id="ips-map">
        <CardHeader>
          <CardTitle>Attack origins</CardTitle>
        </CardHeader>
        <CardContent>
          <AttackMap points={points ?? null} />
        </CardContent>
      </Card>
      <Card id="ips-table">
        <div className="grid grid-cols-[repeat(auto-fill,minmax(250px,1fr))] gap-4">
          {failed ? null : rows === null ? (
            <SkeletonCards count={10} />
          ) : (
            rows.map((row) => (
              <div key={row.ip} className="flex flex-col gap-2 rounded-[14px] bg-muted p-4">
                <div className="flex items-center justify-between gap-2">
                  <Link className="hp-src-card__ip" to="/investigate/ip/$ip" params={{ ip: row.ip }} title="Open full investigation">
                    {row.ip}
                  </Link>
                  {row.country ? (
                    <Link to="/events" search={{ country: row.country }} title={countryName(row.country)}>
                      <Badge variant="secondary">{row.country}</Badge>
                    </Link>
                  ) : null}
                </div>
                {/* Distinct stat destinations per ips.html:10-14. */}
                <div className="flex [&_a]:min-w-0 [&_a]:flex-1 [&_a]:border-l [&_a]:border-border [&_a]:px-4 [&_a]:text-foreground [&_a]:no-underline [&_a:first-child]:border-l-0 [&_a:first-child]:pl-0 [&_b]:block [&_b]:font-serif [&_b]:text-[17px] [&_b]:font-medium [&_span]:text-[10.5px] [&_span]:text-muted-foreground">
                  <Link to="/events" search={{ ip: row.ip }}>
                    <b>{row.events.toLocaleString('en-US')}</b>
                    <span>events</span>
                  </Link>
                  <Link to="/events" search={{ ip: row.ip, kind: 'login' }} title={`login attempts from ${row.ip}`}>
                    <b>{row.logins.toLocaleString('en-US')}</b>
                    <span>logins</span>
                  </Link>
                  <Link to="/investigate/ip/$ip" params={{ ip: row.ip }} title={`attack chain and sessions for ${row.ip}`}>
                    <b>{row.sessions.toLocaleString('en-US')}</b>
                    <span>sessions</span>
                  </Link>
                </div>
                <span className="hp-src-card__sensors">
                  {/* The class on each anchor keeps the muted sensors-line look
                      (overrides the global a color) with per-sensor hover. */}
                  {row.sensors.map((sensor, i) => (
                    <span key={sensor}>
                      {i > 0 ? ' ' : null}
                      <Link
                        className="hp-src-card__sensors"
                        to="/events"
                        search={{ ip: row.ip, sensor }}
                        title={`${sensor} activity for ${row.ip}`}
                      >
                        {sensor}
                      </Link>
                    </span>
                  ))}
                </span>
                <div className="font-mono text-[10.5px] text-muted-foreground">
                  <span>{when(row.first)}</span> → <span>{when(row.last)}</span>
                </div>
              </div>
            ))
          )}
          {failed ? (
            /* #2178: a failed source fetch used to hold ten ghost cards
               exactly like a slow one would -- no way to tell an outage
               from an unloaded page. */
            <ErrorStateBlock
              title="Source list failed to load"
              hint="The backend request failed — nothing here is cached."
              onRetry={retry}
            />
          ) : null}
          {!failed && loadingMore ? <SkeletonCards count={5} /> : null}
        </div>
        {rows !== null && rows.length < Math.min(total, 1000) ? (
          <div className="flex items-center justify-center gap-4 pt-4 pb-1 [&>span:first-child]:text-xs [&>span:first-child]:text-muted-foreground" aria-live="polite">
            <span>
              {rows.length.toLocaleString('en-US')} of {total.toLocaleString('en-US')} entries
            </span>
            <Button variant="secondary" size="sm" type="button" onClick={viewMore} disabled={loadingMore}>
              View more
            </Button>
          </div>
        ) : null}
      </Card>
    </>
  )
}
