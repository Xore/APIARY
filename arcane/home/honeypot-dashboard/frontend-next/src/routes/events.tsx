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

export type EventFilters = {
  ip?: string
  sensor?: string
  country?: string
  port?: string
  proto?: string
  kind?: string
}

type FilterValues = { sensors: string[]; countries: string[]; protos: string[]; ports: string[]; kinds: string[] }

const fetchEvents = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number; filters?: EventFilters }) => input)
  .handler(async ({ data }): Promise<EventsPage | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    const params = new URLSearchParams({ offset: String(data.offset), size: '25' })
    for (const [key, value] of Object.entries(data.filters ?? {})) {
      if (value) params.set(key, value)
    }
    return serviceJSON<EventsPage>(`/api/v1/events?${params}`)
  })

const fetchFilterValues = createServerFn({ method: 'GET' }).handler(async (): Promise<FilterValues | null> => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<FilterValues>('/api/v1/filter-values')
})

export const Route = createFileRoute('/events')({
  // Pivot links across the dashboard land here with filters in the URL
  // (/events?ip=…, ?kind=login, ?country=CN, ?since=24h).
  validateSearch: (search: Record<string, unknown>): EventFilters & { since?: string } => {
    const pick = (key: string) => (typeof search[key] === 'string' ? (search[key] as string) : undefined)
    return {
      ip: pick('ip'),
      sensor: pick('sensor'),
      country: pick('country'),
      port: pick('port'),
      proto: pick('proto'),
      kind: pick('kind'),
      since: pick('since'),
    }
  },
  loaderDeps: ({ search }) => search,
  loader: async ({ deps }) => ({ first: fetchEvents({ data: { offset: 0, filters: deps } }) }),
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
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const [values, setValues] = useState<FilterValues | null>(null)
  const [rows, setRows] = useState<EventRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [loadingMore, setLoadingMore] = useState(false)
  const [selected, setSelected] = useState<number | null>(null)
  const filtersActive = Boolean(search.ip || search.sensor || search.country || search.port || search.proto || search.kind || search.since)
  // Live tail is unfiltered by design (the legacy stream is too); it
  // pauses automatically while a filter scope is active.
  const [live, setLive] = useState(!filtersActive)

  useEffect(() => {
    let cancelled = false
    fetchFilterValues().then((result) => {
      if (!cancelled && result) setValues(result)
    })
    return () => {
      cancelled = true
    }
  }, [])

  const setFilter = useCallback(
    (key: keyof EventFilters | 'since', value: string) => {
      setRows(null)
      setSelected(null)
      void navigate({ search: (current: Record<string, unknown>) => ({ ...current, [key]: value || undefined }) })
    },
    [navigate],
  )
  const paneRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  // Live tail via the BFF's SSE proxy: new events prepend in arrival
  // order; the selected index shifts with them so the open record stays
  // the same row. Capped so an all-day tab doesn't grow unbounded.
  useEffect(() => {
    if (!live) return
    const source = new EventSource('/api/live')
    const onEvent = (event: MessageEvent) => {
      let row: EventRow
      try {
        row = JSON.parse(event.data) as EventRow
      } catch {
        return
      }
      setRows((current) => (current === null ? current : [row, ...current].slice(0, 500)))
      setTotal((count) => count + 1)
      setSelected((index) => (index === null ? null : Math.min(index + 1, 499)))
    }
    source.addEventListener('event', onEvent)
    return () => {
      source.removeEventListener('event', onEvent)
      source.close()
    }
  }, [live])

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
      const page = await fetchEvents({ data: { offset: rows.length, filters: search } })
      if (page) {
        setRows((current) => [...(current ?? []), ...page.rows])
        setTotal(page.total)
      }
    } finally {
      setLoadingMore(false)
    }
  }, [rows, loadingMore, search])

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
        <button
          className={live ? 'chip is-active' : 'chip'}
          type="button"
          aria-pressed={live}
          title={live ? 'Live tail on — new events stream in as they arrive' : 'Live tail off'}
          onClick={() => setLive((current) => !current)}
        >
          {live ? '● live' : '○ paused'}
        </button>
        <input
          className="input"
          type="search"
          placeholder="source ip"
          defaultValue={search.ip ?? ''}
          aria-label="Filter by source IP"
          onKeyDown={(event) => {
            if (event.key === 'Enter') setFilter('ip', (event.target as HTMLInputElement).value.trim())
          }}
          onBlur={(event) => {
            if (event.target.value.trim() !== (search.ip ?? '')) setFilter('ip', event.target.value.trim())
          }}
        />
        {(
          [
            ['sensor', values?.sensors],
            ['country', values?.countries],
            ['proto', values?.protos],
            ['port', values?.ports],
            ['kind', values?.kinds],
          ] as const
        ).map(([key, options]) => (
          <select
            key={key}
            className="input"
            aria-label={`Filter by ${key}`}
            value={(search[key] as string | undefined) ?? ''}
            onChange={(event) => setFilter(key, event.target.value)}
          >
            <option value="">{key}: all</option>
            {(options ?? []).map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        ))}
        {filtersActive ? (
          <button className="chip" type="button" onClick={() => void navigate({ search: {} })}>
            × clear filters
          </button>
        ) : null}
        <button
          className="chip"
          type="button"
          disabled={!rows || rows.length === 0}
          title="Download the currently loaded rows as CSV"
          onClick={() => {
            if (!rows) return
            const esc = (value: string) => `"${value.replaceAll('"', '""')}"`
            const csv = [
              'time,sensor,source_ip,country,port,proto,detail,session',
              ...rows.map((row) =>
                [row.time, row.sensor, row.src_ip, row.country, row.port, row.proto, row.detail, row.session]
                  .map((value) => esc(String(value ?? '')))
                  .join(','),
              ),
            ].join('\n')
            const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }))
            const link = document.createElement('a')
            link.href = url
            link.download = 'honeypot-events.csv'
            link.click()
            URL.revokeObjectURL(url)
          }}
        >
          ⇩ CSV
        </button>
        <button
          className="chip"
          type="button"
          disabled={!rows || rows.length === 0}
          title="Download the currently loaded rows' full records as JSON"
          onClick={() => {
            if (!rows) return
            const url = URL.createObjectURL(
              new Blob([JSON.stringify(rows.map((row) => row.record), null, 2)], { type: 'application/json' }),
            )
            const link = document.createElement('a')
            link.href = url
            link.download = 'honeypot-events.json'
            link.click()
            URL.revokeObjectURL(url)
          }}
        >
          ⇩ JSON
        </button>
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
