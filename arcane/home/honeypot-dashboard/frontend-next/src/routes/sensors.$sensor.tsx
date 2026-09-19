// One sensor: what it has been doing, and everything it saw (#1887).
//
// /sensors lists every sensor and shows its captured events. What it could
// not answer is "what has this one been doing" — volume, who reached it,
// what they asked it for. The fleet overview cannot answer that either,
// because it counts every sensor's events the same way.
//
// That flattening loses exactly the thing a sensor is for. HellPot is a
// tarpit whose job is holding a connection as long as a client will stay —
// observed at 26 and 60 hours, single connections swallowing 500 MB — and
// in a fleet-wide event count it is indistinguishable from a sensor that
// answers a request and closes. So the measures and the leaderboards here
// are the sensor's own, chosen server-side per protocol.
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'
import { SensorEventsTable } from '../components/SensorEvents'
import { formatTimestamp } from '../lib/time'
import { protocolFor, type SensorEventRow } from '../lib/sensorProtocols'
import { countryName } from '../lib/country'
import { useSidebarViewTabs } from '../lib/viewTabs'
import { CuratedSensorView, hasCuratedView } from '../components/CuratedSensorViews'
import { Card, CardContent, CardDescription, CardHeader } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Skeleton } from '../components/ui/skeleton'
import { Table, TableBody, TableCell, TableRow } from '../components/ui/table'

type Row = { key: string; count: number }
type TopList = { label: string; rows: Row[] }
type Measure = { label: string; total: number; max: number; unit: string }
type Overview = {
  sensor: string
  window: string
  events: number
  unique_sources: number
  first_seen: string
  last_seen: string
  hourly: number[]
  top_sources: Row[]
  top_countries: Row[]
  top_lists: TopList[]
  measures: Measure[]
}

const fetchOverview = createServerFn({ method: 'GET' })
  .validator((input: { sensor: string }) => input)
  .handler(async ({ data }): Promise<Overview | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Overview>(`/api/v1/sensors/${encodeURIComponent(data.sensor)}/overview`)
  })

type SensorSummary = { sensor: string; events: number; last_seen: string }

const fetchCatalog = createServerFn({ method: 'GET' }).handler(
  async (): Promise<{ sensors: SensorSummary[] } | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON('/api/v1/sensors/catalog')
  },
)

const fetchEvents = createServerFn({ method: 'GET' })
  .validator((input: { sensor: string }) => input)
  .handler(async ({ data }): Promise<{ sensor: string; total: number; rows: SensorEventRow[] } | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON(`/api/v1/sensors/${encodeURIComponent(data.sensor)}/events?limit=200`)
  })

export const Route = createFileRoute('/sensors/$sensor')({
  loader: async ({ params }) => ({
    overview: fetchOverview({ data: { sensor: params.sensor } }),
    events: fetchEvents({ data: { sensor: params.sensor } }),
    catalog: fetchCatalog(),
  }),
  component: SensorPage,
})

/** A measure in the units the sensor measures it in.
 *
 *  A tarpit's whole output is time and bytes wasted, and "1244160000 ms"
 *  communicates none of it. */
function measureValue(measure: Measure): string {
  const { total, unit } = measure
  if (unit === 'bytes') {
    const units = ['B', 'KB', 'MB', 'GB', 'TB']
    let value = total
    let index = 0
    while (value >= 1024 && index < units.length - 1) {
      value /= 1024
      index += 1
    }
    return `${value.toFixed(value >= 100 || index === 0 ? 0 : 1)} ${units[index]}`
  }
  if (unit === 'duration_ms' || unit === 'duration_s') {
    const seconds = unit === 'duration_ms' ? total / 1000 : total
    if (seconds >= 86400) return `${(seconds / 86400).toFixed(1)} days`
    if (seconds >= 3600) return `${(seconds / 3600).toFixed(1)} hours`
    if (seconds >= 60) return `${(seconds / 60).toFixed(0)} min`
    return `${seconds.toFixed(0)} s`
  }
  return total.toLocaleString('en-US')
}

function measurePeak(measure: Measure): string {
  return measureValue({ ...measure, total: measure.max })
}

/** Events per hour over the window. Same shape as the KPI sparkline: a
 *  floor so a quiet hour still reads as a baseline rather than a gap. */
function Activity({ hourly }: { hourly: number[] }) {
  if (hourly.length === 0) return null
  const peak = Math.max(...hourly)
  if (peak === 0) return <p className="empty">No activity in this window.</p>
  return (
    <svg viewBox={`0 0 ${hourly.length * 5} 100`} preserveAspectRatio="none" className="h-16 w-full text-primary" aria-hidden="true">
      {hourly.map((count, index) => (
        <rect key={index} x={index * 5} y={100 - Math.max(3, Math.round((count * 100) / peak))} width="3" height={Math.max(3, Math.round((count * 100) / peak))} fill="currentColor" />
      ))}
    </svg>
  )
}

function TopTable({ label, rows, href }: { label: string; rows: Row[]; href?: (key: string) => string }) {
  if (rows.length === 0) return null
  const most = rows[0].count
  return (
    <Card className="min-w-0">
      <CardHeader><h2 className="text-sm font-semibold">{label}</h2></CardHeader>
      <CardContent><Table>
        <TableBody>
          {rows.map((row) => (
            <TableRow key={row.key}>
              <TableCell className="v">
                {href ? <a href={href(row.key)}>{row.key}</a> : row.key}
              </TableCell>
              <TableCell className="n">{row.count.toLocaleString('en-US')}</TableCell>
              <TableCell>
                <progress value={row.count} max={most} aria-label={`${row.key}: ${row.count} of ${most}`} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table></CardContent>
    </Card>
  )
}

function SensorPage() {
  const { sensor } = Route.useParams()
  const { overview, events, catalog } = Route.useLoaderData()
  const navigate = useNavigate()
  // #2178: all three streamed loads collapsed failure into "not arrived",
  // so an outage meant an eternal overview skeleton-line, an event table
  // riding its loading rows forever, and — worst — a navigation rail with
  // NO sensors on it, stranding the page's only way to move between
  // sensors. Each stream now names its own failure; one retry re-runs all
  // three.
  const [view, setView] = useState<Overview | null>(null)
  const [viewFailed, setViewFailed] = useState(false)
  const [rows, setRows] = useState<{ total: number; rows: SensorEventRow[] } | null>(null)
  const [eventsFailed, setEventsFailed] = useState(false)
  const [sensors, setSensors] = useState<SensorSummary[]>([])
  const [catalogFailed, setCatalogFailed] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const retry = () => setAttempt((n) => n + 1)

  useEffect(() => {
    let cancelled = false
    setView(null)
    setViewFailed(false)
    setRows(null)
    setEventsFailed(false)
    setSensors([])
    setCatalogFailed(false)
    // attempt === 0 honours the streamed loader promises it was handed; a
    // retry cannot replay those, so it re-issues the server fns directly.
    const overviewP = attempt === 0 ? overview : fetchOverview({ data: { sensor } })
    const eventsP = attempt === 0 ? events : fetchEvents({ data: { sensor } })
    const catalogP = attempt === 0 ? catalog : fetchCatalog()
    overviewP.then((result) => {
      if (cancelled) return
      if (result) setView(result)
      else setViewFailed(true)
    })
    eventsP.then((result) => {
      if (!cancelled && result) setRows({ total: result.total, rows: result.rows })
      else if (!cancelled) setEventsFailed(true)
    })
    catalogP.then((result) => {
      if (cancelled) return
      if (result) setSensors(result.sensors)
      else setCatalogFailed(true)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caller-owned loader streams
  }, [overview, events, catalog, attempt])

  // #1904: every sensor is an entry in the rail, and picking one opens its
  // own page. There is no roster view: a wall of twenty-seven tiles is
  // something to read before anything can be chosen, and it gave dionaea's
  // 17.8M events the same weight as wordpot's 38. The rail is where this
  // dashboard already puts "one of several views", including the three
  // sensors that had hand-written readings long before the rest.
  const viewTabs = useSidebarViewTabs({
    label: 'Sensors',
    tabs: sensors.map((entry) => ({ id: entry.sensor, label: entry.sensor })),
    active: sensor,
    onSelect: (id) => void navigate({ to: '/sensors/$sensor', params: { sensor: id } }),
    idPrefix: 'sd',
  })

  const spec = protocolFor(sensor)

  return (
    <>
      <InvestigateHeader
        label="Investigate"
        title={sensor}
        subtitle={
          spec
            ? spec.what
            : 'Everything this sensor recorded, as it recorded it — no protocol reading is defined for it yet.'
        }
        chips={
          view ? (
            <>
              <Badge variant="secondary">{view.events.toLocaleString('en-US')} events / 7d</Badge>
              <Badge variant="secondary">{view.unique_sources.toLocaleString('en-US')} unique sources</Badge>
              {view.last_seen ? <Badge variant="secondary">last {formatTimestamp(view.last_seen)}</Badge> : null}
            </>
          ) : undefined
        }
      />
      {catalogFailed ? (
        // #2178: an empty rail used to read as "the roster has no sensors"
        // rather than "the catalog request failed" — the page's only
        // between-sensor navigation silently vanished.
        <p className="note text-danger" role="alert">
          The sensor roster failed to load, so the per-sensor navigation above is missing this load.{' '}
          <Button type="button" variant="link" size="sm" onClick={retry}>
            Retry
          </Button>
        </p>
      ) : null}
      {viewTabs}

      {view === null && viewFailed ? (
        <ErrorStateBlock
          title="This sensor's overview failed to load"
          hint="The backend request failed — this says nothing about how active the sensor is."
          onRetry={retry}
        />
      ) : view === null ? (
        <Card className="col-span-full" aria-label="Loading sensor overview">
          <CardContent className="space-y-4 pt-6"><Skeleton className="h-6 w-40" /><Skeleton className="h-24 w-full" /></CardContent>
        </Card>
      ) : (
        <>
          {view.measures.length > 0 ? (
            <Card className="col-span-full">
              <CardHeader><h2 className="font-semibold leading-none tracking-tight">What this sensor did</h2>
              <CardDescription>
                The quantities this sensor exists to produce, over the last 7 days — not an event count, which says the
                same thing about every sensor.
              </CardDescription></CardHeader>
              <CardContent className="grid grid-cols-[repeat(auto-fit,minmax(160px,1fr))] gap-4">
                {view.measures.map((measure) => (
                  <Card className="min-w-0" key={measure.label}>
                    <CardHeader><h2 className="text-sm font-semibold">{measure.label}</h2></CardHeader>
                    <CardContent><div className="text-2xl font-semibold tabular-nums">{measureValue(measure)}</div>
                    <p className="text-sm text-muted-foreground">most in one event: {measurePeak(measure)}</p></CardContent>
                  </Card>
                ))}
              </CardContent>
            </Card>
          ) : null}

          <Card className="col-span-full">
            <CardHeader><h2 className="font-semibold leading-none tracking-tight">Activity</h2>
            <CardDescription>
              Events per hour over the last 7 days. First seen {view.first_seen ? formatTimestamp(view.first_seen) : '—'}.
            </CardDescription></CardHeader>
            <CardContent><Activity hourly={view.hourly} /></CardContent>
          </Card>

          <Card className="col-span-full">
            <CardHeader><h2 className="font-semibold leading-none tracking-tight">Who reached it</h2></CardHeader>
            <CardContent className="grid grid-cols-[repeat(auto-fit,minmax(160px,1fr))] gap-4">
              <TopTable
                label="source addresses"
                rows={view.top_sources}
                href={(ip) => `/investigate/ip/${encodeURIComponent(ip)}`}
              />
              <TopTable
                label="countries"
                rows={view.top_countries.map((row) => ({ ...row, key: countryName(row.key) || row.key }))}
              />
            </CardContent>
          </Card>

          {view.top_lists.length > 0 ? (
            <Card className="col-span-full">
              <CardHeader><h2 className="font-semibold leading-none tracking-tight">What they asked it for</h2>
              <CardDescription>
                This sensor&apos;s own leaderboards — the fields that mean something for this protocol, rather than the
                same five for every sensor.
              </CardDescription></CardHeader>
              <CardContent className="grid grid-cols-[repeat(auto-fit,minmax(160px,1fr))] gap-4">
                {view.top_lists.map((list) => (
                  <TopTable key={list.label} label={list.label} rows={list.rows} />
                ))}
              </CardContent>
            </Card>
          ) : null}
        </>
      )}

      {/* A sensor with a hand-written reading gets it; the rest get the
          generic one, which is strictly more than the nothing they had. */}
      {eventsFailed ? (
        <Card className="col-span-full p-6">
          <ErrorStateBlock
            title="This sensor's events failed to load"
            hint="The backend request failed — the event list below this page normally rides here."
            onRetry={retry}
          />
        </Card>
      ) : null}
      {hasCuratedView(sensor) ? (
        <CuratedSensorView sensor={sensor} />
      ) : eventsFailed ? null : (
        <Card className="col-span-full p-6">
          <SensorEventsTable sensor={sensor} rows={rows?.rows ?? null} total={rows?.total} />
        </Card>
      )}
    </>
  )
}
