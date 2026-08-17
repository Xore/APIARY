// Event explorer — EV-D feed rhythm on the ported stack: full-width table
// with minute-break rows, the normalized-record pane opening only on row
// click (outside-click closes), explicit "View more" paging with
// skeleton-first batches. Data: server function → Rust /api/v1/events.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useRef, useState } from 'react'

type EventRow = {
  time: string
  sensor: string
  src_ip: string
  country: string
  port: string
  proto: string
  detail: string
  session: string
  record: unknown
}

type EventsPage = { total: number; offset: number; rows: EventRow[] }

const BACKEND = process.env.BACKEND_URL ?? 'http://127.0.0.1:8081'

const fetchEvents = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<EventsPage | null> => {
    try {
      const response = await fetch(`${BACKEND}/api/v1/events?offset=${data.offset}&size=25`, {
        headers: { 'x-service-token': process.env.SERVICE_TOKEN ?? '' },
        signal: AbortSignal.timeout(15_000),
      })
      if (!response.ok) return null
      return (await response.json()) as EventsPage
    } catch {
      return null
    }
  })

export const Route = createFileRoute('/events')({
  loader: async () => ({ first: fetchEvents({ data: { offset: 0 } }) }),
  component: Events,
})

function minuteOf(iso: string): string {
  return iso.slice(0, 16)
}

function clock(iso: string): string {
  return iso.slice(11, 16)
}

function SkeletonRows({ count }: { count: number }) {
  return (
    <>
      {Array.from({ length: count }, (_, i) => (
        <tr key={`skel-${i}`} className="hp-skel-batch" aria-hidden="true">
          <td colSpan={6}>
            <span className="skeleton-line" />
          </td>
        </tr>
      ))}
    </>
  )
}

function Events() {
  const { first } = Route.useLoaderData()
  const [rows, setRows] = useState<EventRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
  const [selected, setSelected] = useState<number | null>(null)
  const paneRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    let cancelled = false
    first.then((page) => {
      if (cancelled || !page) return
      setRows(page.rows)
      setTotal(page.total)
    })
    return () => {
      cancelled = true
    }
  }, [first])

  // Outside-click closes the record pane (per Xore) — clicks inside the
  // pane or the list are handled by their own logic.
  useEffect(() => {
    if (selected === null) return
    const onClick = (event: MouseEvent) => {
      const target = event.target as Element
      if (paneRef.current?.contains(target) || listRef.current?.contains(target)) return
      setSelected(null)
    }
    document.addEventListener('click', onClick)
    return () => document.removeEventListener('click', onClick)
  }, [selected])

  const viewMore = useCallback(async () => {
    if (!rows || loadingMore) return
    setLoadingMore(true)
    try {
      const page = await fetchEvents({ data: { offset: rows.length } })
      if (page) {
        setRows((current) => [...(current ?? []), ...page.rows])
        setTotal(page.total)
      }
    } finally {
      setLoadingMore(false)
    }
  }, [rows, loadingMore])

  const open = selected !== null && rows !== null
  return (
    <>
      <header className="overview-header">
        <div>
          <div className="label-section">Investigate</div>
          <h1>event explorer</h1>
          <p className="subtitle">Every normalized event across all sensors — pivot on any value, or export the exact filtered scope.</p>
        </div>
      </header>
      <div className="filters">
        <span className="chip">{total.toLocaleString('en-US')} events</span>
      </div>
      <div className={open ? 'hp-md hp-md--active hp-md--open wide' : 'hp-md hp-md--active wide'} id="events-grid">
        <div className="hp-md__list" ref={listRef}>
          <div className="card wide">
            <table className="recent data-table">
              <thead>
                <tr>
                  <th>time</th>
                  <th>sensor</th>
                  <th>source ip</th>
                  <th>port</th>
                  <th>detail</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {rows === null ? (
                  <SkeletonRows count={12} />
                ) : (
                  rows.map((row, index) => {
                    const breakLabel = index === 0 || minuteOf(rows[index - 1].time) !== minuteOf(row.time) ? clock(row.time) : null
                    return (
                      <FragmentRow
                        key={`${row.time}-${index}`}
                        row={row}
                        breakLabel={breakLabel}
                        selected={selected === index}
                        onSelect={() => setSelected(selected === index ? null : index)}
                      />
                    )
                  })
                )}
                {loadingMore ? <SkeletonRows count={Math.min(25, Math.max(1, total - (rows?.length ?? 0)))} /> : null}
              </tbody>
            </table>
            {rows !== null && rows.length < total ? (
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
        </div>
        <div className="hp-md__pane" ref={paneRef}>
          {open && rows[selected] ? (
            <div className="card">
              <button className="hp-md__close" type="button" aria-label="Close details" title="Close details" onClick={() => setSelected(null)}>
                ×
              </button>
              <h2>Normalized event</h2>
              <p className="card__meta">Complete read-only record as stored by the pipeline.</p>
              <div className="card__scroll">
                <pre className="code">{JSON.stringify(rows[selected].record, null, 2)}</pre>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </>
  )
}

function FragmentRow({
  row,
  breakLabel,
  selected,
  onSelect,
}: {
  row: EventRow
  breakLabel: string | null
  selected: boolean
  onSelect: () => void
}) {
  return (
    <>
      {breakLabel ? (
        <tr className="hp-feed-break" aria-hidden="true">
          <td colSpan={6}>— {breakLabel} —</td>
        </tr>
      ) : null}
      <tr className={selected ? 'selected' : undefined} onClick={onSelect}>
        <td data-hp-time>{row.time.replace('T', ' ').slice(0, 19)}</td>
        <td>
          <span className="badge badge--muted">{row.sensor}</span>
        </td>
        <td className="v">
          {row.src_ip}
          {row.country ? (
            <>
              {' '}
              <span className="badge badge--info">{row.country}</span>
            </>
          ) : null}
        </td>
        <td className="n">{row.port ? `:${row.port}` : ''}</td>
        <td className="v">{row.detail || row.proto}</td>
        <td />
      </tr>
    </>
  )
}
