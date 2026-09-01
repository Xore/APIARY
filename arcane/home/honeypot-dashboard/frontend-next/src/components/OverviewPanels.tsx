// Overview panel primitives, ported from the legacy templates: the "tbl"
// top-N card, the per-sensor hourly heatmap (Xore/theme's .heatmap
// component, CSS-var intensity), the per-sensor attack-vectors
// drill-down (#471), and the leaflet attack map.
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useRef, useState } from 'react'
import { ErrorStateBlock } from './ErrorState'
import { DEFAULT_MAP_PREFS, pullMapPrefs, type MapPrefs } from '../lib/prefs'

export type Kv = { key: string; count: number; link: string }

export function Tbl({
  title,
  rows,
  half,
  hint,
  id,
  failed,
}: {
  title: string
  rows: Kv[] | null
  half?: boolean
  hint?: string
  id?: string
  failed?: boolean
}) {
  return (
    <div className={half ? 'card half' : 'card'} id={id}>
      <h2>{title}</h2>
      {rows === null ? (
        failed ? (
          /* #2178: null both starts and ends the skeleton here; a failed
             dashboard slice must not pose as one still loading forever. */
          <p className="empty" role="alert">
            Load failed — the backend request didn’t answer.
          </p>
        ) : (
          <>
            <span className="skeleton-line" aria-hidden="true" />
            <span className="skeleton-line" aria-hidden="true" />
            <span className="skeleton-line" aria-hidden="true" />
          </>
        )
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

export function Heatmap({ rows, failed }: { rows: HeatRow[] | null; failed?: boolean }) {
  if (rows === null)
    return failed ? (
      // #2178: a dead /overview/dashboard read held this block forever.
      <p className="empty" role="alert">
        Load failed — the backend request didn’t answer.
      </p>
    ) : (
      <div className="skeleton" style={{ height: 90 }} aria-hidden="true" />
    )
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
  .validator((input: { sensor: string }) => input)
  .handler(async ({ data }): Promise<Vectors | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Vectors>(`/api/v1/attack-vectors?sensor=${encodeURIComponent(data.sensor)}`)
  })

/// The heatmap's companion drill-down (#471): pick one sensor, see which
/// ports/protocols actually drew its last-24h traffic. The picker is
/// controlled by the card (overview.html:94-120): the same selection also
/// narrows the heatmap above to that sensor's row.
export function AttackVectors({
  sensors,
  sensor,
  onSensorChange,
}: {
  sensors: string[]
  sensor: string
  onSensorChange: (sensor: string) => void
}) {
  const [vectors, setVectors] = useState<Vectors | null>(null)
  // #2178: a failed drill-down used to hold its skeleton line forever --
  // null result and "still fetching" were the same value to the old render.
  // Hand-rolled rather than useServerQuery because an empty sensor pick
  // must not fire a request at all.
  const [failed, setFailed] = useState(false)
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    let cancelled = false
    setVectors(null)
    setFailed(false)
    if (!sensor) return
    fetchVectors({ data: { sensor } })
      .then((result) => {
        if (cancelled) return
        if (result === null || result === undefined) setFailed(true)
        else setVectors(result)
      })
      .catch(() => {
        if (!cancelled) setFailed(true)
      })
    return () => {
      cancelled = true
    }
  }, [sensor, attempt])
  const options = sensors.filter((name) => name !== 'suricata' && name !== 'portbridge')
  return (
    <>
      <div className="filters">
        <select className="form-input" aria-label="Sensor drill-down" value={sensor} onChange={(event) => onSensorChange(event.target.value)}>
          <option value="">All sensors</option>
          {options.map((name) => (
            <option key={name} value={name}>
              {name}
            </option>
          ))}
        </select>
        {sensor ? (
          <button className="chip" type="button" onClick={() => onSensorChange('')}>
            × all sensors
          </button>
        ) : null}
      </div>
      {sensor && vectors === null && !failed ? <span className="skeleton-line" aria-hidden="true" /> : null}
      {failed ? (
        <ErrorStateBlock
          title="Attack-vector drill-down failed to load"
          hint="The backend request failed."
          onRetry={() => setAttempt((n) => n + 1)}
        />
      ) : null}
      {vectors ? (
        <div className="hp-duo">
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

export type MapPoint = { city: string; country: string; lat: number; lon: number; events: number; ips: number; url: string }

// Fixed marker size regardless of event count — scaling by count made dense
// cities' circles grow large enough to overlap and obscure neighboring markers.
// #1846: pixels, not metres.
//
// This was `L.circle` with a 60 km radius, which is a radius on the *ground*.
// Leaflet then scales it with the map, so zooming in to compare two cities
// grew each marker into a 60 km disc and merged them into their neighbours --
// worst exactly where the detail was wanted.
//
// `L.circleMarker` takes its radius in screen pixels, so a marker stays the
// same size on screen and converges on its city as you zoom. No zoom handler
// to keep in step with the zoom levels either.
//
// The marker means "attacks came from around here", not "this area", so a
// ground radius was never the right unit for it.
const MARKER_RADIUS_PX = 6

// #2528: basemap -> tile source. `osm` is the only value preferences.rs's
// BASEMAPS (and config.rs's behavior.map_provider enum) accept today, so
// this table has one entry -- but it is a lookup keyed on the preference
// value rather than a hardcoded URL, so a second basemap becomes selectable
// the moment it is added here, the same way a vendored theme becomes
// selectable without a frontend redeploy (prefs.ts's isThemeName). An
// unrecognised value (an old preference doc, a config rollback) falls back
// to `osm` rather than rendering no tiles.
const BASEMAP_TILES: Record<string, { url: string; attribution: string }> = {
  osm: { url: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png', attribution: '© OpenStreetMap contributors' },
}

export function basemapTile(basemap: string | undefined): { url: string; attribution: string } {
  return BASEMAP_TILES[basemap ?? 'osm'] ?? BASEMAP_TILES.osm
}

export type MapCluster = { lat: number; lon: number; points: MapPoint[] }

// Coarse grid clustering for the "Cluster markers" preference. Not
// zoom-aware -- before this control was wired, every point always rendered
// as its own marker regardless of the saved preference, so any merging is
// the meaningful behaviour change; a zoom-tracking implementation is future
// work if this grid proves too coarse or too fine.
//
// `clustering: false` is the point-per-marker behaviour AttackMap always had
// (each point comes back as its own single-point cluster, unmerged).
const CLUSTER_GRID_DEGREES = 4

export function clusterPoints(points: MapPoint[], clustering: boolean): MapCluster[] {
  if (!clustering) return points.map((point) => ({ lat: point.lat, lon: point.lon, points: [point] }))
  const cells = new Map<string, MapCluster>()
  for (const point of points) {
    const cellLat = Math.round(point.lat / CLUSTER_GRID_DEGREES) * CLUSTER_GRID_DEGREES
    const cellLon = Math.round(point.lon / CLUSTER_GRID_DEGREES) * CLUSTER_GRID_DEGREES
    const key = `${cellLat}:${cellLon}`
    const existing = cells.get(key)
    if (existing) existing.points.push(point)
    else cells.set(key, { lat: cellLat, lon: cellLon, points: [point] })
  }
  return [...cells.values()]
}

export function AttackMap({ points, failed }: { points: MapPoint[] | null; failed?: boolean }) {
  const containerRef = useRef<HTMLDivElement>(null)
  const mapRef = useRef<import('leaflet').Map | null>(null)
  // Torn down alongside the map itself; the ResizeObserver outlives the
  // async import that creates it, so it needs its own handle.
  const cleanupRef = useRef<(() => void) | null>(null)
  // #2528: settings.tsx PUTs these and, until now, nothing read them back --
  // an operator could toggle "cluster markers" or "map animation", watch the
  // save succeed, and see this map render identically either way. Same
  // best-effort client fetch LiveToasts uses for its own preferences: instant
  // paint with the compiled defaults, reconciled once the request lands.
  const [prefs, setPrefs] = useState<MapPrefs>(DEFAULT_MAP_PREFS)

  useEffect(() => {
    let cancelled = false
    pullMapPrefs().then((result) => {
      if (!cancelled) setPrefs(result)
    })
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    const container = containerRef.current
    if (!container || !points || points.length === 0) return
    let disposed = false
    ;(async () => {
      const L = (await import('leaflet')).default
      await import('leaflet/dist/leaflet.css')
      if (disposed || mapRef.current) return
      const map = L.map(container, {
        worldCopyJump: true,
        minZoom: 1,
        // `map_animation`: off means off everywhere Leaflet animates --
        // zoom transitions, the fade-in on tile/marker load, and markers
        // easing to their new screen position during a zoom.
        zoomAnimation: prefs.animation,
        fadeAnimation: prefs.animation,
        markerZoomAnimation: prefs.animation,
      })
      mapRef.current = map

      // #1565: the map is built before the card has settled at its final
      // width, so leaflet sizes its tile grid against whatever the container
      // measured at construction time and never revisits it. Measured at an
      // 1854px viewport, that left six 256px tile columns covering 1536px of
      // a 1442px container from the wrong origin -- a 92px strip of bare
      // card down the right edge, which reads as a rendering fault rather
      // than as ocean.
      //
      // invalidateSize() re-measures and recomputes the grid, which is the
      // whole fix; the setView after it re-centres on the world at the same
      // zoom the card has always used, so the full world stays visible
      // rather than being cropped to fill the width.
      const fitWorld = () => {
        map.invalidateSize({ animate: false })
        map.setView([25, 10], 2, { animate: false })
      }
      fitWorld()

      // A card that changes width -- a sidebar opening, a window resize,
      // the print stylesheet -- puts the strip straight back otherwise.
      const observer = new ResizeObserver(fitWorld)
      observer.observe(container)
      cleanupRef.current = () => observer.disconnect()
      const tile = basemapTile(prefs.basemap)
      L.tileLayer(tile.url, { attribution: tile.attribution }).addTo(map)

      // Tabbable, announced, Enter/Space-activated -- the same wiring the
      // single-point markers always had (hp-app.js:519-533), now shared with
      // cluster markers so grouping points does not cost them keyboard access.
      const activate = (circle: import('leaflet').CircleMarker, label: string, go: () => void) => {
        circle.on('click', go)
        circle.on('add', () => {
          const el = circle.getElement()
          if (!el) return
          el.setAttribute('tabindex', '0')
          el.setAttribute('role', 'link')
          el.setAttribute('aria-label', label)
          el.addEventListener('keydown', (event) => {
            const key = (event as KeyboardEvent).key
            if (key === 'Enter' || key === ' ') {
              event.preventDefault()
              go()
            }
          })
        })
      }

      for (const cluster of clusterPoints(points, prefs.clustering)) {
        if (cluster.points.length === 1) {
          const point = cluster.points[0]
          const circle = L.circleMarker([point.lat, point.lon], {
            radius: MARKER_RADIUS_PX,
            color: 'var(--accent)',
            weight: 1,
            fillOpacity: 0.35,
          }).bindTooltip(
            `${point.city || 'Unknown city'}, ${point.country} — ${point.ips.toLocaleString('en-US')} IPs, ${point.events.toLocaleString('en-US')} events`,
          )
          activate(
            circle,
            `${point.city && point.country ? `${point.city}, ${point.country}` : point.city || point.country || 'Unknown location'}, ${point.events.toLocaleString('en-US')} events`,
            () => {
              if (point.url) location.assign(point.url)
            },
          )
          circle.addTo(map)
          continue
        }
        // A cluster: same fixed pixel radius as a single marker (#1846 --
        // growing it by count is what made dense cities overlap), a denser
        // fill so it reads as several origins merged rather than one, and a
        // tooltip naming how many. There is no single canonical URL for a
        // merged group, so activating one zooms in on it instead of
        // navigating -- close enough to split it back into its members.
        const events = cluster.points.reduce((sum, point) => sum + point.events, 0)
        const ips = cluster.points.reduce((sum, point) => sum + point.ips, 0)
        const circle = L.circleMarker([cluster.lat, cluster.lon], {
          radius: MARKER_RADIUS_PX,
          color: 'var(--accent)',
          weight: 2,
          fillOpacity: 0.75,
        }).bindTooltip(
          `${cluster.points.length} sources near here — ${ips.toLocaleString('en-US')} IPs, ${events.toLocaleString('en-US')} events`,
        )
        activate(
          circle,
          `${cluster.points.length} sources near here, ${events.toLocaleString('en-US')} events`,
          () => map.setView([cluster.lat, cluster.lon], Math.min(map.getZoom() + 3, 8)),
        )
        circle.addTo(map)
      }
    })()
    return () => {
      disposed = true
      cleanupRef.current?.()
      cleanupRef.current = null
      mapRef.current?.remove()
      mapRef.current = null
    }
  }, [points, prefs.basemap, prefs.clustering, prefs.animation])

  if (points === null)
    return failed ? (
      // #2178: same lie as the heatmap -- an outage rendered as a forever
      // half-built map.
      <p className="empty" role="alert">
        Load failed — the backend request didn’t answer.
      </p>
    ) : (
      <div className="skeleton" style={{ height: 320 }} aria-hidden="true" />
    )
  if (points.length === 0) return <p className="empty">No geolocated sources in this window.</p>
  return (
    <div className="map-shell">
      <div ref={containerRef} id="attack-map" className="leaflet-map" role="region" aria-label="interactive map of geolocated attack origins" style={{ minHeight: 380 }} />
    </div>
  )
}
