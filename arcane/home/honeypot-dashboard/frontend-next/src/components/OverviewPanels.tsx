// Overview panel primitives, ported from the legacy templates: the "tbl"
// top-N card, the per-sensor hourly heatmap (Xore/theme's .heatmap
// component, CSS-var intensity), the per-sensor attack-vectors
// drill-down (#471), and the leaflet attack map.
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useRef, useState } from 'react'

export type Kv = { key: string; count: number; link: string }

export function Tbl({
  title,
  rows,
  half,
  hint,
  id,
}: {
  title: string
  rows: Kv[] | null
  half?: boolean
  hint?: string
  id?: string
}) {
  return (
    <div className={half ? 'card half' : 'card'} id={id}>
      <h2>{title}</h2>
      {rows === null ? (
        <>
          <span className="skeleton-line" aria-hidden="true" />
          <span className="skeleton-line" aria-hidden="true" />
          <span className="skeleton-line" aria-hidden="true" />
        </>
      ) : rows.length === 0 ? (
        <p className="empty">{hint ?? 'No data in this window.'}</p>
      ) : (
        <div className="card__scroll">
          <table className="data-table">
            <tbody>
              {rows.map((row) => (
                <tr key={row.key}>
                  <td className="n">
                    <a href={row.link} title="show matching events">
                      {row.count.toLocaleString('en-US')}
                    </a>
                  </td>
                  <td className="v">
                    <a href={row.link}>{row.key}</a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export type HeatRow = { sensor: string; cells: { label: string; count: number; pct: number }[] }

export function Heatmap({ rows }: { rows: HeatRow[] | null }) {
  if (rows === null) return <div className="skeleton" style={{ height: 90 }} aria-hidden="true" />
  if (rows.length === 0) return <p className="empty">No events in the last 24 hours.</p>
  return (
    <>
      <div className="card__scroll">
        <div className="heatmap" aria-label="Hourly event activity per sensor, last 24 hours">
          {rows.map((row) => (
            <div className="heatmap__row" key={row.sensor}>
              <span className="heatmap__label">{row.sensor}</span>
              <div className="heatmap__cells">
                {row.cells.map((cell) => (
                  <span
                    key={cell.label}
                    className="heatmap__cell"
                    title={`${cell.label} — ${cell.count.toLocaleString('en-US')} events`}
                    tabIndex={0}
                    style={{ ['--v' as string]: cell.pct }}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="heatmap__legend">
        <span>Less</span>
        {[0, 25, 50, 75, 100].map((v) => (
          <span key={v} className="heatmap__cell" style={{ ['--v' as string]: v }} />
        ))}
        <span>More</span>
      </div>
      <p className="note">Every sensor's activity in the last 24 hours, hour by hour. Hover or focus a cell for the exact count.</p>
    </>
  )
}

type Vectors = { sensor: string; ports: Kv[]; protocols: Kv[] }

const fetchVectors = createServerFn({ method: 'GET' })
  .inputValidator((input: { sensor: string }) => input)
  .handler(async ({ data }): Promise<Vectors | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Vectors>(`/api/v1/attack-vectors?sensor=${encodeURIComponent(data.sensor)}`)
  })

/// The heatmap's companion drill-down (#471): pick one sensor, see which
/// ports/protocols actually drew its last-24h traffic.
export function AttackVectors({ sensors }: { sensors: string[] }) {
  const [sensor, setSensor] = useState('')
  const [vectors, setVectors] = useState<Vectors | null>(null)
  useEffect(() => {
    if (!sensor) {
      setVectors(null)
      return
    }
    let cancelled = false
    setVectors(null)
    fetchVectors({ data: { sensor } }).then((result) => {
      if (!cancelled) setVectors(result)
    })
    return () => {
      cancelled = true
    }
  }, [sensor])
  const options = sensors.filter((name) => name !== 'suricata' && name !== 'portbridge')
  return (
    <>
      <div className="filters">
        <select className="input" aria-label="Sensor drill-down" value={sensor} onChange={(event) => setSensor(event.target.value)}>
          <option value="">All sensors</option>
          {options.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
        {sensor ? (
          <button className="chip" type="button" onClick={() => setSensor('')}>
            × all sensors
          </button>
        ) : null}
      </div>
      {sensor && vectors === null ? <span className="skeleton-line" aria-hidden="true" /> : null}
      {vectors ? (
        <div className="tw:grid tw:grid-cols-2 tw:gap-3">
          {(
            [
              ['Targeted ports', vectors.ports],
              ['Protocols', vectors.protocols],
            ] as const
          ).map(([title, rows]) => (
            <div key={title}>
              <p className="note">{title} — {vectors.sensor}, last 24h</p>
              {rows.length === 0 ? (
                <p className="empty">No traffic in the window.</p>
              ) : (
                <table className="data-table">
                  <tbody>
                    {rows.map((row) => (
                      <tr key={row.key}>
                        <td className="n">
                          <a href={row.link}>{row.count.toLocaleString('en-US')}</a>
                        </td>
                        <td className="v">
                          <a href={row.link}>{row.key}</a>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          ))}
        </div>
      ) : null}
    </>
  )
}

export type MapPoint = { city: string; country: string; lat: number; lon: number; events: number; ips: number }

export function AttackMap({ points }: { points: MapPoint[] | null }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const mapRef = useRef<import('leaflet').Map | null>(null)

  useEffect(() => {
    const container = containerRef.current
    if (!container || !points || points.length === 0) return
    let disposed = false
    ;(async () => {
      const L = (await import('leaflet')).default
      await import('leaflet/dist/leaflet.css')
      if (disposed || mapRef.current) return
      const map = L.map(container, { worldCopyJump: true, minZoom: 1 }).setView([25, 10], 2)
      mapRef.current = map
      L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
      }).addTo(map)
      const maxEvents = points.reduce((max, point) => Math.max(max, point.events), 1)
      for (const point of points) {
        const radius = 40_000 + 400_000 * Math.sqrt(point.events / maxEvents)
        L.circle([point.lat, point.lon], {
          radius,
          color: 'var(--accent)',
          weight: 1,
          fillOpacity: 0.35,
        })
          .bindTooltip(
            `${point.city || 'Unknown city'}, ${point.country} — ${point.ips.toLocaleString('en-US')} IPs, ${point.events.toLocaleString('en-US')} events`,
          )
          .addTo(map)
      }
    })()
    return () => {
      disposed = true
      mapRef.current?.remove()
      mapRef.current = null
    }
  }, [points])

  if (points === null) return <div className="skeleton" style={{ height: 320 }} aria-hidden="true" />
  if (points.length === 0) return <p className="empty">No geolocated sources in this window.</p>
  return (
    <div className="map-shell">
      <div ref={containerRef} id="attack-map" className="leaflet-map" role="region" aria-label="interactive map of geolocated attack origins" style={{ minHeight: 380 }} />
    </div>
  )
}
