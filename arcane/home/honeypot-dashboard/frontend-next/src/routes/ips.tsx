// Attack sources — AS-D profile card grid with View-more + skeleton-first,
// every column of the old table on each card.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useMemo } from 'react'
import { InvestigateHeader } from '../components/Investigate'
import { usePaginatedList } from '../lib/hooks'

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

export const Route = createFileRoute('/ips')({
  loader: async () => ({ first: fetchSources({ data: { offset: 0 } }) }),
  component: Sources,
})

function when(iso: string): string {
  return iso.replace('T', ' ').slice(0, 19)
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
  const { first } = Route.useLoaderData()
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
                  {row.country ? <span className="badge badge--info">{row.country}</span> : null}
                </div>
                <div className="hp-src-card__stats">
                  <a href={`/events?ip=${encodeURIComponent(row.ip)}`}>
                    <b>{row.events.toLocaleString('en-US')}</b>
                    <span>events</span>
                  </a>
                  <a href={`/events?ip=${encodeURIComponent(row.ip)}`}>
                    <b>{row.logins.toLocaleString('en-US')}</b>
                    <span>logins</span>
                  </a>
                  <a href={`/events?ip=${encodeURIComponent(row.ip)}`}>
                    <b>{row.sessions.toLocaleString('en-US')}</b>
                    <span>sessions</span>
                  </a>
                </div>
                <span className="hp-src-card__sensors">{row.sensors.join(' ')}</span>
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
