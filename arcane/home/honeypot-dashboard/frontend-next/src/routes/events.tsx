// Event explorer — EV-D feed rhythm on the ported stack: full-width table
// with minute-break rows, the normalized-record pane opening only on row
// click (outside-click closes), explicit "View more" paging with
// skeleton-first batches. Data: server function → Rust /api/v1/events.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useRef, useState } from 'react'
import { copyWithFlash } from '../lib/flash'
import { setConnectionHealthy, useLiveState } from '../lib/live'
import type { JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'

/** Detail-pane pivot groups, extracted server-side (events.rs) so this
 * page never re-derives per-sensor field naming. Empty string = absent. */
type EventPivots = {
  persona: string
  site: string
  asset: string
  fingerprint: string
  fingerprint_kind: string
  command: string
  user: string
  pass: string
  path: string
  shasum: string
  asn: string
  org: string
  provider: string
  alert: string
  category: string
  tty_replay: string
}

type EventRow = {
  time: string
  sensor: string
  src_ip: string
  country: string
  port: string
  proto: string
  detail: string
  session: string
  pivots: EventPivots
  record: JsonRecord
}

type EventsPage = { total: number; offset: number; rows: EventRow[] }

export type EventFilters = {
  ip?: string
  sensor?: string
  country?: string
  port?: string
  proto?: string
  kind?: string
  /** Captured-payload hash pivot, arrived at via a link (e.g. RevDeck's
   * "related events") — not a manual filter control in this bar. */
  shasum?: string
  // Detail-pane pivot filters (#1653) — reached via links, rendered as
  // removable chips, passed straight through to /api/v1/events.
  persona?: string
  site?: string
  asset?: string
  fingerprint?: string
  cmd?: string
  cred?: string
  path?: string
  asn?: string
  org?: string
  provider?: string
  sig?: string
  cat?: string
}

const PIVOT_KEYS = [
  'shasum',
  'persona',
  'site',
  'asset',
  'fingerprint',
  'cmd',
  'cred',
  'path',
  'asn',
  'org',
  'provider',
  'sig',
  'cat',
] as const

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
    const filters: EventFilters & { since?: string } = {
      ip: pick('ip'),
      sensor: pick('sensor'),
      country: pick('country'),
      port: pick('port'),
      proto: pick('proto'),
      kind: pick('kind'),
      since: pick('since'),
    }
    for (const key of PIVOT_KEYS) filters[key] = pick(key)
    return filters
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
  const filtersActive = Boolean(
    search.ip ||
      search.sensor ||
      search.country ||
      search.port ||
      search.proto ||
      search.kind ||
      search.since ||
      PIVOT_KEYS.some((key) => search[key]),
  )
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
  // Subordinate to the shell's shared LIVE switch (lib/live.ts): pausing
  // drops the stream, resuming reopens it, and the connection's own
  // open/error state feeds the topbar's stalled indicator (#210).
  const { paused: livePaused } = useLiveState()
  useEffect(() => {
    if (!live || livePaused) return
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
    source.addEventListener('open', () => setConnectionHealthy(true))
    source.addEventListener('error', () => setConnectionHealthy(false))
    return () => {
      source.removeEventListener('event', onEvent)
      source.close()
      // Leaving the page (or pausing) isn't a connection failure.
      setConnectionHealthy(true)
    }
  }, [live, livePaused])

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
          className="form-input"
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
            className="form-input"
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
        {/* Link-borne pivot scopes render as removable chips — there is no
            manual control for them, so without a chip an operator can't
            see or clear the scope they arrived with. */}
        {PIVOT_KEYS.filter((key) => search[key]).map((key) => (
          <button
            key={key}
            className="chip is-active"
            type="button"
            title={`Remove the ${key} scope`}
            onClick={() => setFilter(key, '')}
          >
            {key}: {(search[key] as string).length > 40 ? `${(search[key] as string).slice(0, 37)}…` : search[key]} ×
          </button>
        ))}
        {filtersActive ? (
          <button className="chip" type="button" onClick={() => void navigate({ search: {} })}>
            × clear filters
          </button>
        ) : null}
        <a
          className="chip"
          title="Download every event matching the current filter scope as CSV — not just the rows loaded here"
          href={`/api/export/events.csv?${new URLSearchParams(
            Object.fromEntries(Object.entries(search).filter(([, value]) => value !== undefined)) as Record<string, string>,
          ).toString()}`}
        >
          ⇩ CSV
        </a>
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
                        onPivot={setFilter}
                      />
                    )
                  })
                )}
                {loadingMore ? <SkeletonRows count={Math.min(25, Math.max(1, total - (rows?.length ?? 0)))} /> : null}
              </tbody>
            </table>
            {rows !== null && rows.length === 0 ? (
              /* Design refresh pick 8B (events.html:129-134): a zero-match
                 filter scope gets an explanation and a way out, never a
                 silent empty table. */
              <div className="empty-state">
                <div>
                  <div className="empty-state__icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <circle cx="11" cy="11" r="7" />
                      <line x1="21" y1="21" x2="16.65" y2="16.65" />
                    </svg>
                  </div>
                  <div className="empty-state__title">No events match this filter</div>
                  <p className="empty-state__hint">Loosen a filter chip above, or widen the time window.</p>
                  <button className="empty-state__action" type="button" onClick={() => void navigate({ search: {} })}>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
                      <line x1="2" y1="21" x2="22" y2="17" />
                    </svg>
                    Clear filters
                  </button>
                </div>
              </div>
            ) : null}
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
              <p className="note">Complete read-only record as stored by the pipeline.</p>
              {rows[selected].src_ip || rows[selected].session ? (
                <p className="note">
                  {rows[selected].src_ip ? (
                    <a className="lnk" href={`/investigate/ip/${encodeURIComponent(rows[selected].src_ip)}`}>
                      attacker profile for {rows[selected].src_ip}
                    </a>
                  ) : null}
                  {rows[selected].src_ip && rows[selected].session ? ' • ' : null}
                  {rows[selected].session ? (
                    <a className="lnk sess" href={`/sessions/${encodeURIComponent(rows[selected].session)}`}>
                      replay session {rows[selected].session}
                    </a>
                  ) : null}
                </p>
              ) : null}
              <EventMeta row={rows[selected]} onPivot={setFilter} />
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

/** The detail pane's pivot-link groups — the port of events.html:22-28's
 * .eventmeta block: decoy identity, shared-value pivots, network origin,
 * sensor detection, session recording, and the payload actions menu. A
 * group renders only when it has at least one value. */
function EventMeta({ row, onPivot }: { row: EventRow; onPivot: (key: keyof EventFilters, value: string) => void }) {
  const p = row.pivots
  const link = (key: keyof EventFilters, value: string, label: string, title: string) => (
    <a
      className="lnk"
      href={`/events?${key}=${encodeURIComponent(value)}`}
      title={title}
      onClick={(event) => {
        event.preventDefault()
        onPivot(key, value)
      }}
    >
      {label}
    </a>
  )
  const groups: Array<{ label: string; title: string; items: React.ReactNode[] }> = [
    {
      label: 'decoy',
      title: 'Which emulated identity was targeted',
      items: [
        p.persona ? link('persona', p.persona, `persona ${p.persona}`, 'show events for this honeypot persona') : null,
        p.site ? link('site', p.site, `site ${p.site}`, 'show events for this fictional site') : null,
        p.asset ? link('asset', p.asset, `asset ${p.asset}`, 'show events for this emulated asset') : null,
      ],
    },
    {
      label: 'pivot',
      title: 'Pivot to every other event sharing this value',
      items: [
        row.session ? (
          <a className="lnk sess" href={`/sessions/${encodeURIComponent(row.session)}`} title="replay the complete session">
            session {row.session}
          </a>
        ) : null,
        p.fingerprint
          ? link(
              'fingerprint',
              p.fingerprint,
              `${p.fingerprint_kind || 'fingerprint'}: ${p.fingerprint}`,
              'show every event with this exact fingerprint',
            )
          : null,
        p.command ? link('cmd', p.command, 'command', 'show every occurrence of this exact command') : null,
        p.user || p.pass
          ? link('cred', `${p.user} / ${p.pass}`, 'credentials', 'show every use of these credentials')
          : null,
        p.path ? link('path', p.path, `path ${p.path}`, 'show every request for this exact path') : null,
      ],
    },
    {
      label: 'origin',
      title: 'Where the source address is routed',
      items: [
        p.asn ? link('asn', p.asn, `AS${p.asn}`, 'show events from this autonomous system') : null,
        p.org ? link('org', p.org, p.org, 'show events from this network organization') : null,
        p.provider ? link('provider', p.provider, p.provider, 'show events from this provider class') : null,
      ],
    },
    {
      label: 'detection',
      title: 'How the sensor classified this event',
      items: [
        p.alert ? link('sig', p.alert, 'signature', 'show alerts with this signature') : null,
        p.category ? link('cat', p.category, `category ${p.category}`, 'show events in this category') : null,
      ],
    },
  ]
  return (
    <div className="eventmeta">
      {groups.map((group) => {
        const items = group.items.filter(Boolean)
        if (items.length === 0) return null
        return (
          <div className="eventmeta__group" key={group.label}>
            <span className="eventmeta__label" title={group.title}>
              {group.label}
            </span>
            {items.map((item, index) => (
              <span key={index}>{item}</span>
            ))}
          </div>
        )
      })}
      {p.tty_replay ? (
        <div className="eventmeta__group">
          <span className="eventmeta__label" title="Full replayable capture of this session">
            recording
          </span>
          <a className="lnk" href={p.tty_replay} title="watch the session play back in-browser">
            view recording
          </a>
        </div>
      ) : null}
      {p.shasum ? (
        <div className="eventmeta__group">
          <span className="eventmeta__label" title="Actions available for this event">
            actions
          </span>
          <a className="lnk" href={`/payload-analysis/${encodeURIComponent(p.shasum)}`} title="static analysis of the captured payload">
            static analysis
          </a>
          <a
            className="lnk"
            href={`https://www.virustotal.com/gui/file/${encodeURIComponent(p.shasum)}`}
            target="_blank"
            rel="noopener noreferrer"
          >
            VirusTotal
          </a>
        </div>
      ) : null}
    </div>
  )
}

function FragmentRow({
  row,
  breakLabel,
  selected,
  onSelect,
  onPivot,
}: {
  row: EventRow
  breakLabel: string | null
  selected: boolean
  onSelect: () => void
  onPivot: (key: keyof EventFilters | 'ip', value: string) => void
}) {
  // Cell pivots must not also toggle the record pane.
  const pivot = (event: React.MouseEvent, key: keyof EventFilters | 'ip', value: string) => {
    event.stopPropagation()
    onPivot(key, value)
  }
  return (
    <>
      {breakLabel ? (
        <tr className="hp-feed-break" aria-hidden="true">
          <td colSpan={6}>— {breakLabel} —</td>
        </tr>
      ) : null}
      <tr className={selected ? 'selected' : undefined} onClick={onSelect}>
        <td data-hp-time>{formatTimestamp(row.time)}</td>
        <td>
          {/* Per-sensor badge coloring (theme.css's b-{sensor} classes) +
              sensor pivot, events.html:11. */}
          <a
            className={`badge b-${row.sensor}`}
            href={`/events?sensor=${encodeURIComponent(row.sensor)}`}
            onClick={(event) => {
              event.preventDefault()
              pivot(event, 'sensor', row.sensor)
            }}
          >
            {row.sensor}
          </a>
        </td>
        <td className="v">
          {row.src_ip ? (
            <a
              href={`/events?ip=${encodeURIComponent(row.src_ip)}`}
              title={`attack chain for ${row.src_ip}`}
              onClick={(event) => {
                event.preventDefault()
                pivot(event, 'ip', row.src_ip)
              }}
            >
              {row.src_ip}
            </a>
          ) : (
            <span
              className="badge badge--muted"
              title="This event reached the sensor over the WireGuard tunnel and could not be joined back to a real client address. The tunnel peer is our own VPS, so it is deliberately not shown as the source."
            >
              unattributed
            </span>
          )}
          {row.country ? (
            <>
              {' '}
              <a
                className="badge badge--info"
                href={`/events?country=${encodeURIComponent(row.country)}`}
                onClick={(event) => {
                  event.preventDefault()
                  pivot(event, 'country', row.country)
                }}
              >
                {row.country}
              </a>
            </>
          ) : null}
        </td>
        <td className="n">
          {row.port ? (
            <a
              href={`/events?port=${encodeURIComponent(row.port)}`}
              onClick={(event) => {
                event.preventDefault()
                pivot(event, 'port', row.port)
              }}
            >
              :{row.port}
            </a>
          ) : (
            ''
          )}
        </td>
        <td className="v">{row.detail || row.proto}</td>
        {/* Hover-revealed quick actions (design pick 14B, events.html:31-37). */}
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
              <a href={`/sessions/${encodeURIComponent(row.session)}`} title="Replay session" onClick={(event) => event.stopPropagation()}>
                ▶
              </a>
            ) : null}
            {row.src_ip ? (
              <a
                href={`/investigate/ip/${encodeURIComponent(row.src_ip)}`}
                title="Attacker profile"
                onClick={(event) => event.stopPropagation()}
              >
                👤
              </a>
            ) : null}
          </div>
        </td>
      </tr>
    </>
  )
}
