// Event explorer — EV-D feed rhythm on the ported stack: full-width table
// with minute-break rows, the normalized-record pane opening only on row
// click (outside-click closes), explicit "View more" paging with
// skeleton-first batches. Data: server function → Rust /api/v1/events.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useRef, useState } from 'react'
import { FiltersButton, FiltersModal } from '../components/FiltersModal'
import { RowActions, RowIcons } from '../components/RowActions'
import { copyWithFlash } from '../lib/flash'
import { subscribeLiveEvents, useLiveState } from '../lib/live'
import type { JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'
import { countryName } from '../lib/country'

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
  /** DNP3 control-function severity ("critical"/"high"/""). */
  ics_severity: string
}

type EventRow = {
  /** The document id, when the row came from a search hit — the events
   *  list has one, the SSE live stream does not. Drives the full-detail
   *  action, which is simply absent for a row with no id (#1868). */
  id?: string
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

type CorrelatedIp = { ip: string; count: number; checked: boolean }
type EventsPage = { total: number; offset: number; rows: EventRow[]; fingerprint_ips: CorrelatedIp[] | null }

export type EventFilters = {
  ip?: string
  sensor?: string
  country?: string
  port?: string
  proto?: string
  kind?: string
  /** #1783: one flow across every sensor that saw it. Reached from an event's
   * own record, not typed by hand — it is the shared v1 hash Zeek, huginn,
   * Suricata and portbridge each compute for the same connection. */
  community_id?: string
  /** Captured-payload hash pivot, arrived at via a link (e.g. RevDeck's
   * "related events") — not a manual filter control in this bar. */
  shasum?: string
  // Detail-pane pivot filters (#1653) — reached via links, rendered as
  // removable chips, passed straight through to /api/v1/events.
  persona?: string
  site?: string
  asset?: string
  session?: string
  fingerprint?: string
  cmd?: string
  cred?: string
  path?: string
  asn?: string
  org?: string
  provider?: string
  sig?: string
  cat?: string
  /** #1682: the "Isolate IP…" checklist's comma-separated narrowing —
   * distinct from `ip` (single-IP attack-chain view), applies alongside
   * `fingerprint`. */
  ips?: string
}

const PIVOT_KEYS = [
  // #1783: one flow across every sensor. Base64, so it must survive URL
  // encoding intact -- an unencoded '+' becomes a space and matches nothing.
  'community_id',
  'shasum',
  'session',
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

type InvestigationConfig = { kibana: string; evebox: string; arkime: string }

// #1682: events.html's "Open in Kibana/EveBox/Arkime" menu
// (dashboard/links.go's investigationURL/investigationBase), dropped in
// the port even though these tools are actually deployed
// (arcane/home/honeypot-elk). Per-tool env var wins outright; otherwise
// derived from HONEYPOT_DOMAIN as https://{kibana,evebox,arkime}.<domain>
// (the common subdomain-per-tool layout). Neither set = no link, same as
// the Go tier — an absent menu entry over a guess. Doesn't need a
// session, just deployment config, so this is a plain fetch rather than
// running through lib/auth.ts.
const fetchInvestigationConfig = createServerFn({ method: 'GET' }).handler(async (): Promise<InvestigationConfig> => {
  const domain = (process.env.HONEYPOT_DOMAIN ?? '').trim().replace(/\.+$/, '')
  const base = (kind: string, explicit: string | undefined) => {
    const trimmed = (explicit ?? '').trim()
    if (trimmed) return trimmed
    return domain ? `https://${kind}.${domain}` : ''
  }
  return {
    kibana: base('kibana', process.env.KIBANA_PUBLIC_URL),
    evebox: base('evebox', process.env.EVEBOX_PUBLIC_URL),
    arkime: base('arkime', process.env.ARKIME_PUBLIC_URL),
  }
})

// notfound.example./.example is RFC 2606's reserved "definitely not a
// real deployment" TLD — the same placeholder-host guard links.go's
// isPlaceholderHost used, so a doc-example value left in .env by mistake
// renders as absent rather than a working-looking link to nowhere.
function isPlaceholderHost(base: string): boolean {
  try {
    const host = new URL(base).hostname.toLowerCase()
    return host === 'example' || host.endsWith('.example')
  } catch {
    return true
  }
}

// #1783: the flow key, when the record carries one.
//
// Every sensor added by #1742 writes network.community_id, and it agrees
// across Zeek, huginn, Suricata and portbridge because all four compute the
// same v1 hash of the same 5-tuple. It is a far sharper pivot than the source
// address: a scanner opens thousands of connections, and `ip == x` answers
// "what else did this host do", never "what happened on this connection".
//
// Read off the full ECS record rather than a dedicated column -- events.rs
// already returns it there, deliberately, for exactly this use.
function flowKey(row: EventRow): string | undefined {
  const network = (row.record as Record<string, unknown> | undefined)?.network
  if (!network || typeof network !== 'object') return undefined
  const id = (network as Record<string, unknown>).community_id
  return typeof id === 'string' && id.length > 0 ? id : undefined
}

function investigationLinks(row: EventRow, config: InvestigationConfig): { kibana?: string; evebox?: string; arkime?: string } {
  const ip = row.src_ip
  const flow = flowKey(row)
  // Neither key means nothing worth linking to.
  if (!ip && !flow) return {}
  const links: { kibana?: string; evebox?: string; arkime?: string } = {}

  // Community ID is base64 and contains '+', '/' and '='. Every one of these
  // goes through encodeURIComponent already, which matters more than usual
  // here: an unencoded '+' is read as a space by the receiving app, so the
  // link would resolve to a valid-looking search that quietly matches nothing.
  if (config.evebox && !isPlaceholderHost(config.evebox)) {
    // EveBox searches Suricata's own documents, which carry community_id.
    const q = flow ? `community_id:"${flow}"` : ip
    links.evebox = `${config.evebox.replace(/\/+$/, '')}/#/inbox?q=${encodeURIComponent(q)}`
  }
  if (config.kibana && !isPlaceholderHost(config.kibana)) {
    const when = new Date(row.time)
    const from = new Date(when.getTime() - 5 * 60_000).toISOString()
    const to = new Date(when.getTime() + 5 * 60_000).toISOString()
    const g = encodeURIComponent(`(time:(from:'${from}',to:'${to}'))`)
    // Quote the value: a bare community_id contains characters KQL treats as
    // syntax. The IP fallback stays unquoted, matching prior behaviour.
    const query = flow ? `network.community_id:"${flow}"` : ip
    const a = encodeURIComponent(`(query:(language:kuery,query:'${query}'))`)
    links.kibana = `${config.kibana.replace(/\/+$/, '')}/app/discover#/?_g=${g}&_a=${a}`
  }
  if (config.arkime && !isPlaceholderHost(config.arkime)) {
    // Arkime indexes Community ID natively, so this retrieves the packets for
    // this one flow rather than every session the address ever opened.
    const expression = flow ? `communityId == "${flow}"` : `ip == ${ip}`
    links.arkime = `${config.arkime.replace(/\/+$/, '')}/sessions?date=-1&expression=${encodeURIComponent(expression)}`
  }
  return links
}

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
      ips: pick('ips'),
    }
    for (const key of PIVOT_KEYS) filters[key] = pick(key)
    return filters
  },
  loaderDeps: ({ search }) => search,
  loader: async ({ deps }) => ({
    first: fetchEvents({ data: { offset: 0, filters: deps } }),
    investigationConfig: await fetchInvestigationConfig(),
  }),
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
  const { first, investigationConfig } = Route.useLoaderData()
  const search = Route.useSearch()
  const navigate = Route.useNavigate()
  const [values, setValues] = useState<FilterValues | null>(null)
  const [rows, setRows] = useState<EventRow[] | null>(null)
  const [total, setTotal] = useState(0)
  const [fingerprintIps, setFingerprintIps] = useState<CorrelatedIp[] | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)
  // #1845: the open record is remembered by identity, not by position.
  //
  // It was an index into `rows`, which the loader refetch replaces
  // wholesale -- so after a refresh index 3 was a different event, and the
  // pane silently swapped which record it showed while looking unchanged.
  // The live tail had a hand-written `index + 1` to compensate for a
  // single prepend, which worked for that one path and could not work for
  // the refetch, where an arbitrary number of rows appear at once.
  //
  // Keyed by the document id, the pane follows its event and closes on its
  // own once that event drops off the end of the list -- and the index
  // arithmetic disappears, because there is no position to keep in sync.
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  /** A row's stable identity. The document id when the row came from a
   *  search hit; otherwise a composite that is stable for the same event,
   *  which is what the SSE stream can offer (it carries a _source and no
   *  hit, so there is no id to send). */
  const rowKey = (row: EventRow, index: number) =>
    row.id ?? `${row.time}|${row.sensor}|${row.src_ip}|${row.session}|${index}`
  const selectedRow = selectedKey === null || rows === null
    ? null
    : (rows.find((row, index) => rowKey(row, index) === selectedKey) ?? null)
  const [filtersOpen, setFiltersOpen] = useState(false)
  const baseFilterCount = [search.ip, search.sensor, search.country, search.proto, search.port, search.kind].filter(
    Boolean,
  ).length
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
      setSelectedKey(null)
      void navigate({ search: (current: Record<string, unknown>) => ({ ...current, [key]: value || undefined }) })
    },
    [navigate],
  )
  const paneRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  // Live tail over the shell's shared SSE stream (lib/live.ts — one
  // connection for the whole app, #1564): new events prepend in arrival
  // order. The open record needs no adjustment as they arrive, because it
  // is tracked by identity rather than by position (#1845). Capped so an
  // all-day tab doesn't grow unbounded. The shared layer owns pause/resume
  // and connection health.
  const { paused: livePaused } = useLiveState()
  useEffect(() => {
    if (!live || livePaused) return
    return subscribeLiveEvents((data) => {
      let row: EventRow
      try {
        row = JSON.parse(data) as EventRow
      } catch {
        return
      }
      setRows((current) => (current === null ? current : [row, ...current].slice(0, 500)))
      setTotal((count) => count + 1)
    })
  }, [live, livePaused])

  useEffect(() => {
    let cancelled = false
    first.then((page) => {
      if (cancelled || !page) return
      setRows(page.rows)
      setTotal(page.total)
      setFingerprintIps(page.fingerprint_ips)
    })
    return () => {
      cancelled = true
    }
  }, [first])

  // Outside-click closes the record pane (per Xore) — clicks inside the
  // pane or the list are handled by their own logic.
  useEffect(() => {
    if (selectedKey === null) return
    const onClick = (event: MouseEvent) => {
      const target = event.target as Element
      if (paneRef.current?.contains(target) || listRef.current?.contains(target)) return
      setSelectedKey(null)
    }
    document.addEventListener('click', onClick)
    return () => document.removeEventListener('click', onClick)
  }, [selectedKey])

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

  const open = selectedRow !== null
  return (
    <>
      <header className="overview-header">
        <div>
          <div className="label-section">Investigate</div>
          <h1>Event explorer</h1>
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
        <FiltersButton activeCount={baseFilterCount} onClick={() => setFiltersOpen(true)} />
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
        {fingerprintIps && fingerprintIps.length >= 2 ? (
          <IsolateIpMenu ips={fingerprintIps} onApply={(value) => setFilter('ips', value)} />
        ) : null}
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
      {filtersOpen ? (
        <FiltersModal
          onClose={() => setFiltersOpen(false)}
          onApply={(event) => {
            const data = new FormData(event.currentTarget)
            const next: Record<string, string | undefined> = {}
            for (const key of ['ip', 'sensor', 'country', 'proto', 'port', 'kind'] as const) {
              next[key] = (data.get(key) as string | null)?.trim() || undefined
            }
            setRows(null)
            setSelectedKey(null)
            setFiltersOpen(false)
            void navigate({ search: (current: Record<string, unknown>) => ({ ...current, ...next }) })
          }}
          onClear={() => {
            setRows(null)
            setSelectedKey(null)
            setFiltersOpen(false)
            void navigate({
              search: (current: Record<string, unknown>) => ({
                ...current,
                ip: undefined,
                sensor: undefined,
                country: undefined,
                proto: undefined,
                port: undefined,
                kind: undefined,
              }),
            })
          }}
          clearDisabled={baseFilterCount === 0}
        >
          <div className="settings-field">
            <label className="form-label" htmlFor="hp-ev-filter-ip">
              Source IP
            </label>
            <input className="form-input" id="hp-ev-filter-ip" name="ip" type="search" defaultValue={search.ip ?? ''} />
          </div>
          {(
            [
              ['sensor', 'Sensor', values?.sensors],
              ['country', 'Country', values?.countries],
              ['proto', 'Protocol', values?.protos],
              ['port', 'Port', values?.ports],
              ['kind', 'Kind', values?.kinds],
            ] as const
          ).map(([key, label, options]) => (
            <div className="settings-field" key={key}>
              <label className="form-label" htmlFor={`hp-ev-filter-${key}`}>
                {label}
              </label>
              <select className="form-input" id={`hp-ev-filter-${key}`} name={key} defaultValue={(search[key] as string | undefined) ?? ''}>
                <option value="">all</option>
                {(options ?? []).map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>
          ))}
        </FiltersModal>
      ) : null}
      <div className={open ? 'hp-md hp-md--active hp-md--open wide' : 'hp-md hp-md--active wide'} id="events-grid">
        <div className="hp-md__list" ref={listRef}>
          <div className="card wide">
            <table className="recent data-table data-table--responsive">
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
                        selected={selectedKey === rowKey(row, index)}
                        onSelect={() =>
                          setSelectedKey(selectedKey === rowKey(row, index) ? null : rowKey(row, index))
                        }
                        onPivot={setFilter}
                        investigationConfig={investigationConfig}
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
          {open && selectedRow ? (
            <div className="card">
              <button className="hp-md__close" type="button" aria-label="Close details" title="Close details" onClick={() => setSelectedKey(null)}>
                ×
              </button>
              <h2>Normalized event</h2>
              <p className="note">Complete read-only record as stored by the pipeline.</p>
              {/* These two pages render an event's context far more fully
                  than the inspector's own record dump. They were here as
                  inline `.lnk` text and read as footnotes; as buttons they
                  are findable, which is the whole point of the pane. The
                  address and session id stay in the tooltips (and in the
                  table column and EventMeta below) so nothing is lost. */}
              {selectedRow.src_ip || selectedRow.session ? (
                <div className="tw:flex tw:flex-wrap tw:gap-2 tw:mb-3">
                  {selectedRow.src_ip ? (
                    <a
                      className="btn btn-sm btn-secondary"
                      href={`/investigate/ip/${encodeURIComponent(selectedRow.src_ip)}`}
                      title={`attacker profile for ${selectedRow.src_ip}`}
                    >
                      Open attacker profile →
                    </a>
                  ) : null}
                  {selectedRow.session ? (
                    <a
                      className="btn btn-sm btn-secondary sess"
                      href={`/sessions/${encodeURIComponent(selectedRow.session)}`}
                      title={`replay session ${selectedRow.session}`}
                    >
                      Open session replay →
                    </a>
                  ) : null}
                </div>
              ) : null}
              <EventMeta row={selectedRow} onPivot={setFilter} investigationConfig={investigationConfig} />
              <div className="card__scroll">
                <pre className="code">{JSON.stringify(selectedRow.record, null, 2)}</pre>
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
// #1682: events.html:76-99's "Isolate IP…" checklist — check/uncheck IPs
// to narrow a fingerprint match down to one attacker among several
// sharing it. .action-menu/.hp-open-in-menu (theme.css) give the
// disclosure its outside-click-close and close-siblings-on-toggle for
// free (theme.js); the checklist rows themselves have no bespoke class in
// theme.css to reuse (the Go template's .hp-ip-filter-* was never a
// generic pattern), so they're plain labeled checkboxes.
function IsolateIpMenu({ ips, onApply }: { ips: CorrelatedIp[]; onApply: (value: string) => void }) {
  const [pending, setPending] = useState<Set<string>>(() => new Set(ips.filter((entry) => entry.checked).map((entry) => entry.ip)))
  const anyUnchecked = ips.some((entry) => !pending.has(entry.ip))
  return (
    <details className="hp-open-in action-menu">
      <summary title="Check or uncheck IPs to isolate one attacker among several sharing this fingerprint">
        Isolate IP…
      </summary>
      <div className="dropdown hp-open-in-menu" role="menu" style={{ width: 260 }}>
        <div className="hp-open-in-heading">
          IPs behind this fingerprint <span className="tw:text-muted">({pending.size}/{ips.length})</span>
        </div>
        <div style={{ display: 'flex', gap: 6, padding: '2px 10px 6px' }}>
          <button
            className="btn btn-sm btn-secondary"
            type="button"
            onClick={() => setPending(new Set(ips.map((entry) => entry.ip)))}
          >
            All
          </button>
          <button className="btn btn-sm btn-secondary" type="button" onClick={() => setPending(new Set())}>
            None
          </button>
        </div>
        <div style={{ maxHeight: 260, overflowY: 'auto', padding: '0 10px' }}>
          {ips.map((entry) => (
            <label key={entry.ip} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0', fontSize: 13 }}>
              <input
                type="checkbox"
                checked={pending.has(entry.ip)}
                onChange={(event) => {
                  setPending((current) => {
                    const next = new Set(current)
                    if (event.target.checked) next.add(entry.ip)
                    else next.delete(entry.ip)
                    return next
                  })
                }}
              />
              <span className="mono" style={{ flex: 1 }}>
                {entry.ip}
              </span>
              <span className="tw:text-muted">{entry.count.toLocaleString('en-US')}</span>
            </label>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 6, padding: '8px 10px 4px' }}>
          <button
            className="btn btn-sm btn-primary"
            type="button"
            onClick={() => onApply(anyUnchecked ? Array.from(pending).join(',') : '')}
          >
            Apply
          </button>
          {ips.some((entry) => !entry.checked) || anyUnchecked ? (
            <button
              className="btn btn-sm btn-secondary"
              type="button"
              onClick={() => {
                setPending(new Set(ips.map((entry) => entry.ip)))
                onApply('')
              }}
            >
              Reset
            </button>
          ) : null}
        </div>
      </div>
    </details>
  )
}

// Ported from dashboard/geoip.go's intelBadgeClass. The threat-intel worker
// folds its CIDR verdict into `source.as.type` (backend-service's
// threat_intel.rs), which is the same field this pivot reads — so a
// blocklisted or Tor-exit source already arrives here labelled, and only
// the colouring was missing.
function intelBadgeClass(label: string): string {
  if (label.startsWith('blocklist:')) return 'badge--danger'
  if (label === 'tor-exit') return 'badge--warning'
  return 'badge--muted'
}

// Ported from dashboard/dnp3_severity.go's icsSeverityBadgeClass — the same
// critical/high/muted vocabulary ml-anomalies and agent-campaigns use.
function icsSeverityBadgeClass(severity: string): string {
  if (severity === 'critical') return 'badge--danger'
  if (severity === 'high') return 'badge--warning'
  return 'badge--muted'
}

// `/tty-replay/<shasum>` -> `<shasum>`, empty for anything that does not
// look like one so a malformed pivot cannot become a download URL.
function recordingShasum(ttyReplay: string): string {
  const last = ttyReplay.split('/').pop() ?? ''
  return /^[0-9a-fA-F]{32,64}$/.test(last) ? last : ''
}

function EventMeta({
  row,
  onPivot,
  investigationConfig,
}: {
  row: EventRow
  onPivot: (key: keyof EventFilters, value: string) => void
  investigationConfig: InvestigationConfig
}) {
  const p = row.pivots
  const openIn = investigationLinks(row, investigationConfig)
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
  // Same shape as `link`, but rendered as a severity-coloured badge. The Go
  // tier drew the origin class this way (events.html:25) so a blocklisted
  // or Tor-exit source was visible at a glance instead of reading as one
  // more grey pivot link.
  const badgeLink = (key: keyof EventFilters, value: string, label: string, title: string) => (
    <a
      className={`badge ${intelBadgeClass(value)}`}
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
        p.provider ? badgeLink('provider', p.provider, p.provider, 'show events with this provider classification') : null,
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
          {/* events.html:27 offered all three; the port kept only the
              viewer, so a session could be watched but never taken out of
              the dashboard. The shasum is the last segment of the replay
              route — pivots.shasum is deliberately blank for a
              cowrie.log.closed event, because that hash identifies the
              recording, not a captured payload. */}
          {recordingShasum(p.tty_replay) ? (
            <>
              <a
                className="lnk"
                href={`/api/recording/${encodeURIComponent(recordingShasum(p.tty_replay))}/cast`}
                title="download as an asciinema-compatible .cast file"
              >
                .cast
              </a>
              <a
                className="lnk"
                href={`/api/recording/${encodeURIComponent(recordingShasum(p.tty_replay))}/raw`}
                title="download the raw cowrie TTY log"
              >
                raw
              </a>
            </>
          ) : null}
        </div>
      ) : null}
      {p.shasum || openIn.kibana || openIn.evebox || openIn.arkime ? (
        <div className="eventmeta__group">
          <span className="eventmeta__label" title="Actions available for this event">
            actions
          </span>
          <ActionsMenu shasum={p.shasum} openIn={openIn} />
        </div>
      ) : null}
    </div>
  )
}

// events.html:28's actions menu. The port flattened it into a row of bare
// `.lnk` text — five links with no grouping and no indication which are
// local pages and which leave the dashboard. theme.css still carries the
// whole `.hp-open-in` disclosure (its outside-click-close and
// close-siblings-on-toggle come from theme.js for free), so this is a
// markup restoration, not new design: an "Analysis" group for the local
// payload pages, an "Open in" group for the external tools, each external
// item carrying its own mark, a one-line description of what that tool is
// for, and a corner arrow saying it opens elsewhere.
const OPEN_IN_TOOLS = [
  {
    key: 'evebox' as const,
    name: 'EveBox',
    description: 'Filtered alert inbox',
    icon: (
      <>
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <polyline points="9 12 11 14 15 10" />
      </>
    ),
  },
  {
    key: 'kibana' as const,
    name: 'Kibana',
    description: 'Search historical telemetry',
    icon: (
      <>
        <line x1="12" y1="20" x2="12" y2="10" />
        <line x1="18" y1="20" x2="18" y2="4" />
        <line x1="6" y1="20" x2="6" y2="16" />
      </>
    ),
  },
  {
    key: 'arkime' as const,
    name: 'Arkime',
    description: 'Inspect packets and sessions',
    icon: (
      <>
        <circle cx="18" cy="5" r="3" />
        <circle cx="6" cy="12" r="3" />
        <circle cx="18" cy="19" r="3" />
        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
      </>
    ),
  },
]

const GLYPH_PROPS = {
  width: 15,
  height: 15,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
} as const

const ExternalGlyph = (
  <svg {...GLYPH_PROPS}>
    <line x1="7" y1="17" x2="17" y2="7" />
    <polyline points="7 7 17 7 17 17" />
  </svg>
)

function ActionsMenu({
  shasum,
  openIn,
}: {
  shasum: string
  openIn: { kibana?: string; evebox?: string; arkime?: string }
}) {
  const tools = OPEN_IN_TOOLS.filter((tool) => openIn[tool.key])
  return (
    <details className="hp-open-in action-menu">
      <summary title="Actions for this event">&#8942;</summary>
      <div className="dropdown hp-open-in-menu" role="menu">
        {shasum ? (
          <>
            <div className="hp-open-in-heading">Analysis</div>
            <a
              className="hp-open-in-item"
              href={`/payload-analysis/${encodeURIComponent(shasum)}`}
              role="menuitem"
              title="static analysis of the captured payload"
            >
              <span>Static analysis</span>
            </a>
            <a
              className="hp-open-in-item"
              href={`https://www.virustotal.com/gui/file/${encodeURIComponent(shasum)}`}
              target="_blank"
              rel="noopener noreferrer"
              role="menuitem"
            >
              <span>VirusTotal</span>
            </a>
          </>
        ) : null}
        {tools.length > 0 ? (
          <>
            <div className="hp-open-in-heading">Open in</div>
            {tools.map((tool) => (
              <a
                key={tool.key}
                className="hp-open-in-item"
                href={openIn[tool.key]}
                target="_blank"
                rel="noopener noreferrer"
                role="menuitem"
              >
                <svg {...GLYPH_PROPS}>{tool.icon}</svg>
                <span>
                  <strong>{tool.name}</strong>
                  <small>{tool.description}</small>
                </span>
                {ExternalGlyph}
              </a>
            ))}
          </>
        ) : null}
      </div>
    </details>
  )
}

function FragmentRow({
  row,
  breakLabel,
  selected,
  onSelect,
  onPivot,
  investigationConfig,
}: {
  row: EventRow
  breakLabel: string | null
  selected: boolean
  onSelect: () => void
  onPivot: (key: keyof EventFilters | 'ip', value: string) => void
  /** #1868: the external tool links are derived per row from the deployment's
   *  configured tool URLs, so the row needs the config to offer them. */
  investigationConfig: InvestigationConfig
}) {
  const openIn = investigationLinks(row, investigationConfig)
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
        <td data-hp-time data-label="time">{formatTimestamp(row.time)}</td>
        <td data-label="sensor">
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
        <td className="v" data-label="source ip">
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
                title={countryName(row.country)}
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
        <td className="n" data-label="port">
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
        <td className="v" data-label="detail">
          {row.pivots.ics_severity ? (
            <>
              <span
                className={`badge ${icsSeverityBadgeClass(row.pivots.ics_severity)}`}
                title="DNP3 control-function severity: this app_function code changes equipment or device state"
              >
                {row.pivots.ics_severity}
              </span>{' '}
            </>
          ) : null}
          {row.detail || row.proto}
        </td>
        {/* Hover-revealed quick actions (design pick 14B, events.html:31-37).
            #1868: these were bare text -- `⧁`, `▶`, and an emoji `👤` --
            which rendered live as the literal string "⧁👤" and read as
            unfinished beside the SVG marks used everywhere else. They now
            go through RowActions, so they are drawn the same way here and
            on the overview, and each carries a real accessible name
            rather than a lone glyph inside a link.

            The full-detail action leads the strip because it is the one
            an operator reaches for most, and until now there was no full
            view of an event anywhere. The external tools follow it: they
            were behind the ⋮ disclosure, two clicks away, while the two
            actions that were one click away were the least useful of the
            set. The disclosure stays -- it carries what each tool is for,
            which an icon cannot. */}
        <td className="hp-row-actions-cell" data-label="">
          <RowActions
            actions={[
              row.id ? { label: 'Open full details', icon: RowIcons.detail, href: `/event/${encodeURIComponent(row.id)}` } : null,
              row.src_ip ? { label: 'Copy source IP', icon: RowIcons.copy, onClick: () => copyWithFlash(row.src_ip) } : null,
              row.session ? { label: 'Replay session', icon: RowIcons.replay, href: `/sessions/${encodeURIComponent(row.session)}` } : null,
              row.src_ip ? { label: 'Attacker profile', icon: RowIcons.profile, href: `/investigate/ip/${encodeURIComponent(row.src_ip)}` } : null,
              row.pivots.shasum
                ? { label: 'Payload analysis', icon: RowIcons.payload, href: `/payload-analysis/${encodeURIComponent(row.pivots.shasum)}` }
                : null,
              openIn.evebox ? { label: 'Open in EveBox', icon: RowIcons.evebox, href: openIn.evebox, external: true } : null,
              openIn.kibana ? { label: 'Open in Kibana', icon: RowIcons.kibana, href: openIn.kibana, external: true } : null,
              openIn.arkime ? { label: 'Open in Arkime', icon: RowIcons.arkime, href: openIn.arkime, external: true } : null,
            ]}
          />
        </td>
      </tr>
    </>
  )
}
