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
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import type React from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { SensorEventsTable } from '../components/SensorEvents'
import { formatTimestamp } from '../lib/time'
import { protocolFor, type SensorEventRow } from '../lib/sensorProtocols'
import { countryName } from '../lib/country'

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
  .inputValidator((input: { sensor: string }) => input)
  .handler(async ({ data }): Promise<Overview | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Overview>(`/api/v1/sensors/${encodeURIComponent(data.sensor)}/overview`)
  })

const fetchEvents = createServerFn({ method: 'GET' })
  .inputValidator((input: { sensor: string }) => input)
  .handler(async ({ data }): Promise<{ sensor: string; total: number; rows: SensorEventRow[] } | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON(`/api/v1/sensors/${encodeURIComponent(data.sensor)}/events?limit=200`)
  })

export const Route = createFileRoute('/sensors/$sensor')({
  loader: async ({ params }) => ({
    overview: fetchOverview({ data: { sensor: params.sensor } }),
    events: fetchEvents({ data: { sensor: params.sensor } }),
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
    <div className="metric__spark" aria-hidden="true">
      {hourly.map((count, index) => (
        // The height is the datum -- this hour against the busiest one.
        // Everything about how the bar looks belongs to .metric__spark.
        <i key={index} style={{ height: `${Math.max(3, Math.round((count * 100) / peak))}%` }} />
      ))}
    </div>
  )
}

function TopTable({ label, rows, href }: { label: string; rows: Row[]; href?: (key: string) => string }) {
  if (rows.length === 0) return null
  const most = rows[0].count
  return (
    <div>
      <p className="subtitle">{label}</p>
      <table className="data-table">
        <tbody>
          {rows.map((row) => (
            <tr key={row.key}>
              <td className="v">
                {href ? <a href={href(row.key)}>{row.key}</a> : row.key}
              </td>
              <td className="n">{row.count.toLocaleString('en-US')}</td>
              {/* A leaderboard's shape matters as much as its order: one
                  value at 90% is a different story from ten at 10% each.
                  .progress is the theme's own bar and reads its fill from
                  --v, so the percentage is data and the appearance is not
                  ours to decide. */}
              <td>
                <span className="progress" aria-hidden="true">
                  <span style={{ ['--v' as string]: Math.max(4, Math.round((row.count * 100) / most)) } as React.CSSProperties} />
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function SensorPage() {
  const { sensor } = Route.useParams()
  const { overview, events } = Route.useLoaderData()
  const [view, setView] = useState<Overview | null>(null)
  const [rows, setRows] = useState<{ total: number; rows: SensorEventRow[] } | null>(null)

  useEffect(() => {
    let cancelled = false
    overview.then((result) => {
      if (!cancelled) setView(result)
    })
    events.then((result) => {
      if (!cancelled && result) setRows({ total: result.total, rows: result.rows })
    })
    return () => {
      cancelled = true
    }
  }, [overview, events])

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
              <span className="chip">{view.events.toLocaleString('en-US')} events / 7d</span>
              <span className="chip">{view.unique_sources.toLocaleString('en-US')} unique sources</span>
              {view.last_seen ? <span className="chip">last {formatTimestamp(view.last_seen)}</span> : null}
            </>
          ) : undefined
        }
      />
      <p className="note">
        <Link to="/sensors">← every sensor</Link>
      </p>

      {view === null ? (
        <span className="skeleton-line" aria-hidden="true" />
      ) : (
        <>
          {view.measures.length > 0 ? (
            <div className="card wide">
              <h2>What this sensor did</h2>
              <p className="note">
                The quantities this sensor exists to produce, over the last 7 days — not an event count, which says the
                same thing about every sensor.
              </p>
              <div className="metric-grid">
                {view.measures.map((measure) => (
                  <div className="metric" key={measure.label}>
                    <div className="metric__value">{measureValue(measure)}</div>
                    <div className="metric__label">{measure.label}</div>
                    <div className="metric__trend">most in one event: {measurePeak(measure)}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          <div className="card wide">
            <h2>Activity</h2>
            <p className="note">
              Events per hour over the last 7 days. First seen {view.first_seen ? formatTimestamp(view.first_seen) : '—'}.
            </p>
            <Activity hourly={view.hourly} />
          </div>

          <div className="card wide">
            <h2>Who reached it</h2>
            <div className="metric-grid">
              <TopTable
                label="source addresses"
                rows={view.top_sources}
                href={(ip) => `/investigate/ip/${encodeURIComponent(ip)}`}
              />
              <TopTable
                label="countries"
                rows={view.top_countries.map((row) => ({ ...row, key: countryName(row.key) || row.key }))}
              />
            </div>
          </div>

          {view.top_lists.length > 0 ? (
            <div className="card wide">
              <h2>What they asked it for</h2>
              <p className="note">
                This sensor&apos;s own leaderboards — the fields that mean something for this protocol, rather than the
                same five for every sensor.
              </p>
              <div className="metric-grid">
                {view.top_lists.map((list) => (
                  <TopTable key={list.label} label={list.label} rows={list.rows} />
                ))}
              </div>
            </div>
          ) : null}
        </>
      )}

      <div className="card wide">
        <SensorEventsTable sensor={sensor} rows={rows?.rows ?? null} total={rows?.total} />
      </div>
    </>
  )
}
