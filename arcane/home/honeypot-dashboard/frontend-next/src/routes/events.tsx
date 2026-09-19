// Event explorer — EV-D feed rhythm on the ported stack: full-width table
// with minute-break rows, the normalized-record pane opening only on row
// click (outside-click closes), explicit "View more" paging with
// skeleton-first batches. Data: server function → Rust /api/v1/events.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useMemo, useRef, useState, memo } from 'react'
import { ErrorStateBlock } from '../components/ErrorState'
import { FiltersButton, FiltersModal } from '../components/FiltersModal'
import { InvestigateHeader, SkeletonRows } from '../components/Investigate'
import { RowActions, RowIcons } from '../components/RowActions'
import { Badge, badgeVariants } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card'
import { Checkbox } from '../components/ui/checkbox'
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '../components/ui/empty'
import { Field, FieldLabel } from '../components/ui/field'
import { Input } from '../components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table'
import { copyWithFlash } from '../lib/flash'
import { subscribeLiveEvents, useLiveState } from '../lib/live'
import type { JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'
import { countryName } from '../lib/country'
import { Download, FilterX, Search } from 'lucide-react'

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
  /** What the request carried (#1888); http-honeypot only, often empty. */
  payload_class: string
}

type EventRow = {
  /** #1876: the address the request claimed, when it disagrees with the
   *  one the connection resolved to. Present only on a conflict. */
  src_ip_claimed?: string
  /** The document id — search hits carry it (#1868), and since #1962 the
   *  SSE live stream does too (live.rs emits via row_from_hit). Drives
   *  the full-detail action and stable row/selection identity; simply
   *  absent for a row from an older backend still on row_from_source. */
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
  /** #2045: city drill-in from an overview map pin — reached via links
   * only (the backend now buckets map pins per-city), rendered as a chip. */
  city?: string
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

type FilterValues = { sensors: string[]; countries: string[]; cities?: string[]; protos: string[]; ports: string[]; kinds: string[] }

// Suggestions only -- since_to_range (backend) accepts any short alphanumeric
// duration, e.g. `24h` or `90d`, not just this list.
const SINCE_SUGGESTIONS: [string, string][] = [
  ['24h', 'Last 24 hours'],
  ['7d', 'Last 7 days'],
  ['30d', 'Last 30 days'],
  ['90d', 'Last 90 days'],
  ['365d', 'Last 365 days'],
]

const fetchEvents = createServerFn({ method: 'GET' })
  .validator((input: { offset: number; filters?: EventFilters }) => input)
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
      city: pick('city'),
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

/** A row's stable identity (#1962): the document id from either source —
 *  search hits carried it since #1868, the SSE stream since live.rs
 *  switched to row_from_hit — else an id-less composite fallback for a
 *  payload from a not-yet-restarted backend. Position-free by
 *  construction: a live prepend must never shift it. Module scope because
 *  FragmentRow's memoized rendering (#1965) derives its key with it too,
 *  and every prop reference has to stay stable across renders. */
function rowKey(row: EventRow): string {
  return row.id || `${row.time}|${row.sensor}|${row.src_ip}|${row.session}`
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
  // Identity itself lives in the module-scope rowKey() (shared with
  // FragmentRow's keys, #1965).
  const selectedRow = selectedKey === null || rows === null
    ? null
    : (rows.find((row) => rowKey(row) === selectedKey) ?? null)
  // #1965: precompute list keys once per rows change. Keys come from
  // rowKey(row); true duplicates (possible only via the id-less fallback)
  // get a #n suffix so React never sees a duplicate key. The minute-break
  // labels ride along so the render below stays a pure map over stable
  // tuples.
  const keyedRows = useMemo(() => {
    if (rows === null) return null
    const seen = new Map<string, number>()
    return rows.map((row, index) => {
      const base = rowKey(row)
      const n = seen.get(base) ?? 0
      seen.set(base, n + 1)
      const breakLabel =
        index === 0 || minuteOf(rows[index - 1].time) !== minuteOf(row.time) ? clock(row.time) : null
      return { row, key: n === 0 ? base : `${base}#${n}`, breakLabel }
    })
  }, [rows])
  const [filtersOpen, setFiltersOpen] = useState(false)
  const baseFilterCount = [
    search.ip,
    search.sensor,
    search.country,
    search.city,
    search.proto,
    search.port,
    search.kind,
    search.since,
  ].filter(Boolean).length
  const filtersActive = Boolean(
    search.ip ||
      search.sensor ||
      search.country ||
      search.city ||
      search.port ||
      search.proto ||
      search.kind ||
      search.since ||
      PIVOT_KEYS.some((key) => search[key]),
  )
  // Live tail is unfiltered by design (the legacy stream is too); it
  // pauses automatically while a filter scope is active.
  //
  // #1961: that pause has to follow the *current* scope, not the URL the
  // page happened to arrive with. `useState(!filtersActive)` captured the
  // answer exactly once at mount — TanStack Router keeps this component
  // instance across search-param changes, so a pivot clicked after
  // arrival left the SSE subscription running and unfiltered events kept
  // prepending into a filtered table, inflating rows.length past unfetched
  // matching rows and silently skewing viewMore()'s offset paging. So the
  // operator's on/off choice is stored (`livePreferred`) and the effective
  // state is derived on every render; clearing the filters lets the tail
  // pick straight back up if it was on underneath.
  const [livePreferred, setLivePreferred] = useState(!filtersActive)
  const live = livePreferred && !filtersActive

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
  // Stable toggle for the memoized FragmentRow (#1965): identity-stable
  // callbacks are what let unchanged rows skip re-rendering entirely
  // during a live prepend.
  const toggleSelect = useCallback((key: string) => {
    setSelectedKey((current) => (current === key ? null : key))
  }, [])
  const paneRef = useRef<HTMLDivElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  // Live tail over the shell's shared SSE stream (lib/live.ts — one
  // connection for the whole app, #1564): new events prepend in arrival
  // order. The open record needs no adjustment as they arrive, because it
  // is tracked by identity rather than by position (#1845). Capped so an
  // all-day tab doesn't grow unbounded. The shared layer owns pause/resume
  // and connection health.
  const { paused: livePaused } = useLiveState()
  // #1965: buffer frames and coalesce them into one setState per 250ms
  // window instead of one render pass per SSE frame. A busy feed emits
  // tens of events a second; each uncoalesced pass reconciled — and with
  // the old positional keys, remounted — up to 500 rows. The buffer is
  // flushed oldest-last so prepending preserves arrival order.
  const liveBufferRef = useRef<EventRow[]>([])
  const liveFlushRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const flushLiveBuffer = useCallback(() => {
    if (liveFlushRef.current !== null) {
      clearTimeout(liveFlushRef.current)
      liveFlushRef.current = null
    }
    const batch = liveBufferRef.current.reverse()
    liveBufferRef.current = []
    if (batch.length > 0) {
      setRows((current) => (current === null ? current : [...batch, ...current].slice(0, 500)))
      setTotal((count) => count + batch.length)
    }
  }, [])
  useEffect(() => {
    if (!live || livePaused) return
    const unsubscribe = subscribeLiveEvents((data) => {
      let row: EventRow
      try {
        row = JSON.parse(data) as EventRow
      } catch {
        return
      }
      liveBufferRef.current.push(row)
      if (liveFlushRef.current === null) {
        liveFlushRef.current = setTimeout(flushLiveBuffer, 250)
      }
    })
    return () => {
      // Pause / filter change / unmount must not silently drop whatever
      // the current window was still holding.
      unsubscribe()
      flushLiveBuffer()
    }
  }, [live, livePaused, flushLiveBuffer])

  // #2178: a failed first page settled as null and the table rode its
  // opening ghosts forever — during exactly the outage when an operator is
  // most likely to come looking. `failed` names the state; retry re-fetches
  // page zero through the ordinary paging fn, since the streamed loader
  // promise cannot be re-run. The live tail needs no guard change: its
  // flush already refuses to prepend into null rows.
  const [failed, setFailed] = useState(false)
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    let cancelled = false
    setFailed(false)
    ;(attempt === 0 ? first : fetchEvents({ data: { offset: 0, filters: search } })).then((page) => {
      if (cancelled) return
      if (!page) {
        setFailed(true)
        return
      }
      setRows(page.rows)
      setTotal(page.total)
      setFingerprintIps(page.fingerprint_ips)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caller-owned loader stream; search read at retry time only
  }, [first, attempt])

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
      <InvestigateHeader label="Investigate" title="Event explorer" subtitle="Every normalized event across all sensors — pivot on any value, or export the exact filtered scope." />
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <Badge variant="outline">{total.toLocaleString('en-US')} events</Badge>
        <Button
          variant={live ? 'default' : 'outline'} size="sm"
          type="button"
          aria-pressed={live}
          title={
            filtersActive
              ? 'Live tail is unavailable while a filter scope is active — the stream is unfiltered, so its rows would pollute this view. Clear the filters to resume.'
              : live
                ? 'Live tail on — new events stream in as they arrive'
                : 'Live tail off'
          }
          onClick={() => setLivePreferred((current) => !current)}
        >
          {live ? '● live' : '○ paused'}
        </Button>
        <FiltersButton activeCount={baseFilterCount} onClick={() => setFiltersOpen(true)} />
        {/* Link-borne pivot scopes render as removable chips — there is no
            manual control for them, so without a chip an operator can't
            see or clear the scope they arrived with. */}
        {PIVOT_KEYS.filter((key) => search[key]).map((key) => (
          <Button
            key={key}
            variant="secondary" size="sm"
            type="button"
            title={`Remove the ${key} scope`}
            onClick={() => setFilter(key, '')}
          >
            {key}: {(search[key] as string).length > 40 ? `${(search[key] as string).slice(0, 37)}…` : search[key]} ×
          </Button>
        ))}
        {fingerprintIps && fingerprintIps.length >= 2 ? (
          <IsolateIpMenu ips={fingerprintIps} onApply={(value) => setFilter('ips', value)} />
        ) : null}
        {filtersActive ? (
          <Button variant="outline" size="sm" type="button" onClick={() => void navigate({ search: {} })}>
            × clear filters
          </Button>
        ) : null}
        <Button asChild variant="outline" size="sm"><a
          title="Download every event matching the current filter scope as CSV — not just the rows loaded here"
          href={`/api/export/events.csv?${new URLSearchParams(
            Object.fromEntries(Object.entries(search).filter(([, value]) => value !== undefined)) as Record<string, string>,
          ).toString()}`}
        >
          <Download />CSV
        </a></Button>
        <Button
          variant="outline" size="sm"
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
          <Download />JSON
        </Button>
      </div>
      {filtersOpen ? (
        <FiltersModal
          onClose={() => setFiltersOpen(false)}
          onApply={(event) => {
            const data = new FormData(event.currentTarget)
            const next: Record<string, string | undefined> = {}
            for (const key of ['ip', 'sensor', 'country', 'city', 'proto', 'port', 'kind', 'since'] as const) {
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
                city: undefined,
                proto: undefined,
                port: undefined,
                kind: undefined,
                since: undefined,
              }),
            })
          }}
          clearDisabled={baseFilterCount === 0}
        >
          <Field><FieldLabel htmlFor="hp-ev-filter-ip">Source IP</FieldLabel><Input id="hp-ev-filter-ip" name="ip" type="search" defaultValue={search.ip ?? ''} /></Field>
          {(
            [
              ['sensor', 'Sensor', values?.sensors],
              ['country', 'Country', values?.countries],
              ['city', 'City', values?.cities],
              ['proto', 'Protocol', values?.protos],
              ['port', 'Port', values?.ports],
              ['kind', 'Kind', values?.kinds],
            ] as const
          ).map(([key, label, options]) => (
            <Field key={key}><FieldLabel htmlFor={`hp-ev-filter-${key}`}>{label}</FieldLabel><Input id={`hp-ev-filter-${key}`} name={key} defaultValue={(search[key] as string | undefined) ?? ''} list={`hp-ev-${key}-values`} placeholder="all" /><datalist id={`hp-ev-${key}-values`}>{(options ?? []).map((option) => <option key={option} value={option} />)}</datalist></Field>
          ))}
          <Field>
            <FieldLabel htmlFor="hp-ev-filter-since">Since</FieldLabel>
            <Input
              id="hp-ev-filter-since"
              name="since"
              type="text"
              defaultValue={search.since ?? ''}
              list="hp-ev-since-suggestions"
            />
            <datalist id="hp-ev-since-suggestions">
              {SINCE_SUGGESTIONS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </datalist>
          </Field>
        </FiltersModal>
      ) : null}
      <div className={open ? 'hp-md hp-md--active hp-md--open wide' : 'hp-md hp-md--active wide'} id="events-grid">
        <div className="hp-md__list" ref={listRef}>
          <Card className="min-w-0 overflow-hidden">
            <Table className="min-w-[760px]">
              <TableHeader><TableRow><TableHead>time</TableHead><TableHead>sensor</TableHead><TableHead>source ip</TableHead><TableHead>port</TableHead><TableHead>detail</TableHead><TableHead><span className="sr-only">actions</span></TableHead></TableRow></TableHeader>
              <TableBody>
                {keyedRows === null ? (
                  /* Ghosts mirror the six real columns (#1967): time short,
                     sensor short, source ip long, port short, detail long,
                     actions stub. Suppressed while failed — a failure keeps
                     promising data otherwise (#2178); the alert below speaks. */
                  failed ? null : <SkeletonRows count={12} cols={6} wide={[2, 4]} stub={[5]} />
                ) : (
                  keyedRows.map(({ row, key, breakLabel }) => (
                    <FragmentRow
                      key={key}
                      row={row}
                      breakLabel={breakLabel}
                      selectedKey={selectedKey}
                      onToggle={toggleSelect}
                      onPivot={setFilter}
                      investigationConfig={investigationConfig}
                    />
                  ))
                )}
                {loadingMore ? (
                  <SkeletonRows count={Math.min(25, Math.max(1, total - (rows?.length ?? 0)))} cols={6} wide={[2, 4]} stub={[5]} />
                ) : null}
              </TableBody>
            </Table>
            {rows !== null && rows.length === 0 ? (
              /* Design refresh pick 8B (events.html:129-134): a zero-match
                 filter scope gets an explanation and a way out, never a
                 silent empty table. */
              <Empty><EmptyHeader><EmptyMedia variant="icon"><Search /></EmptyMedia><EmptyTitle>No events match this filter</EmptyTitle><EmptyDescription>Loosen a filter chip above, or widen the time window.</EmptyDescription></EmptyHeader><Button variant="outline" size="sm" type="button" onClick={() => void navigate({ search: {} })}><FilterX />Clear filters</Button></Empty>
            ) : null}
            {rows === null && failed ? (
              /* #2178: the load failure itself — named here, beside the same
                 table whose emptiness it would otherwise have imitated. */
              <ErrorStateBlock
                title="Events failed to load"
                hint="The backend request failed — this says nothing about whether events exist in the window."
                onRetry={() => setAttempt((n) => n + 1)}
              />
            ) : null}
            {rows !== null && rows.length < total ? (
              <div className="flex flex-wrap items-center justify-between gap-3 border-t p-4 text-sm text-muted-foreground" aria-live="polite">
                <span>
                  {rows.length.toLocaleString('en-US')} of {total.toLocaleString('en-US')} entries
                </span>
                <Button variant="secondary" size="sm" type="button" onClick={viewMore} disabled={loadingMore}>
                  View more
                </Button>
              </div>
            ) : null}
          </Card>
        </div>
        <div className="hp-md__pane" ref={paneRef}>
          {open && selectedRow ? (
            <Card className="relative">
              <Button className="absolute right-3 top-3" variant="ghost" size="icon" type="button" aria-label="Close details" title="Close details" onClick={() => setSelectedKey(null)}>
                ×
              </Button>
              <CardHeader><CardTitle><h2>Normalized event</h2></CardTitle><CardDescription>Complete read-only record as stored by the pipeline.</CardDescription></CardHeader>
              <CardContent className="space-y-4">
              {/* These two pages render an event's context far more fully
                  than the inspector's own record dump. They were here as
                  inline `.lnk` text and read as footnotes; as buttons they
                  are findable, which is the whole point of the pane. The
                  address and session id stay in the tooltips (and in the
                  table column and EventMeta below) so nothing is lost. */}
              {selectedRow.src_ip || selectedRow.session ? (
                <div className="flex flex-wrap gap-2">
                  {selectedRow.src_ip ? (
                    <Button asChild variant="secondary" size="sm"><a
                      href={`/investigate/ip/${encodeURIComponent(selectedRow.src_ip)}`}
                      title={`attacker profile for ${selectedRow.src_ip}`}
                    >
                      Open attacker profile →
                    </a></Button>
                  ) : null}
                  {selectedRow.session ? (
                    <Button asChild variant="secondary" size="sm"><a
                      href={`/sessions/${encodeURIComponent(selectedRow.session)}`}
                      title={`replay session ${selectedRow.session}`}
                    >
                      Open session replay →
                    </a></Button>
                  ) : null}
                </div>
              ) : null}
              <EventMeta row={selectedRow} onPivot={setFilter} />
              <div className="max-h-[32rem] overflow-auto rounded-md bg-muted p-3">
                <pre className="whitespace-pre-wrap break-all font-mono text-xs">{JSON.stringify(selectedRow.record, null, 2)}</pre>
              </div>
              </CardContent>
            </Card>
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
    <details className="relative">
      <summary className="cursor-pointer rounded-md border border-input bg-background px-3 py-1.5 text-xs font-medium shadow-sm" title="Check or uncheck IPs to isolate one attacker among several sharing this fingerprint">
        Isolate IP…
      </summary>
      <Card className="absolute left-0 top-full z-50 mt-2 w-80 max-w-[calc(100vw-2rem)]" role="menu">
        <CardHeader className="pb-3"><CardTitle className="text-sm">IPs behind this fingerprint <span className="text-muted-foreground">({pending.size}/{ips.length})</span></CardTitle></CardHeader>
        <CardContent className="space-y-3">
        <div className="flex gap-2">
          <Button variant="outline" size="sm" type="button" onClick={() => setPending(new Set(ips.map((entry) => entry.ip)))}>All</Button>
          <Button variant="outline" size="sm" type="button" onClick={() => setPending(new Set())}>None</Button>
        </div>
        <div className="max-h-64 space-y-1 overflow-auto">
          {ips.map((entry) => (
            <label key={entry.ip} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-muted">
              <Checkbox
                checked={pending.has(entry.ip)}
                onCheckedChange={(checked) => {
                  setPending((current) => {
                    const next = new Set(current)
                    if (checked) next.add(entry.ip)
                    else next.delete(entry.ip)
                    return next
                  })
                }}
              />
              <span className="min-w-0 flex-1 font-mono">{entry.ip}</span>
              <Badge variant="secondary">{entry.count.toLocaleString('en-US')}</Badge>
            </label>
          ))}
        </div>
        <div className="flex gap-2">
          <Button size="sm"
            type="button"
            onClick={() => onApply(anyUnchecked ? Array.from(pending).join(',') : '')}
          >
            Apply
          </Button>
          {ips.some((entry) => !entry.checked) || anyUnchecked ? (
            <Button variant="secondary" size="sm"
              type="button"
              onClick={() => {
                setPending(new Set(ips.map((entry) => entry.ip)))
                onApply('')
              }}
            >
              Reset
            </Button>
          ) : null}
        </div></CardContent>
      </Card>
    </details>
  )
}

// Ported from dashboard/geoip.go's intelBadgeClass. The threat-intel worker
// folds its CIDR verdict into `source.as.type` (backend-service's
// threat_intel.rs), which is the same field this pivot reads — so a
// blocklisted or Tor-exit source already arrives here labelled, and only
// the colouring was missing.
function intelBadgeVariant(label: string): 'destructive' | 'default' | 'secondary' {
  if (label.startsWith('blocklist:')) return 'destructive'
  if (label === 'tor-exit') return 'default'
  return 'secondary'
}

// Ported from dashboard/dnp3_severity.go's icsSeverityBadgeClass — the same
// critical/high/muted vocabulary ml-anomalies and agent-campaigns use.
function icsSeverityVariant(severity: string): 'destructive' | 'default' | 'secondary' {
  if (severity === 'critical') return 'destructive'
  if (severity === 'high') return 'default'
  return 'secondary'
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
}: {
  row: EventRow
  onPivot: (key: keyof EventFilters, value: string) => void
}) {
  const p = row.pivots
  const link = (key: keyof EventFilters, value: string, label: string, title: string) => (
    <a
      className="text-primary hover:underline"
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
      className={badgeVariants({ variant: intelBadgeVariant(value) })}
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
          <a className="text-primary hover:underline" href={`/sessions/${encodeURIComponent(row.session)}`} title="replay the complete session">
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
    <div className="grid gap-2 sm:grid-cols-2">
      {groups.map((group) => {
        const items = group.items.filter(Boolean)
        if (items.length === 0) return null
        return (
          <Card className="min-w-0 p-3 shadow-sm" key={group.label}>
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground" title={group.title}>
              {group.label}
            </h3>
            <div className="flex min-w-0 flex-wrap gap-2 text-sm">
            {items.map((item, index) => (
              <span key={index}>{item}</span>
            ))}
            </div>
          </Card>
        )
      })}
      {p.tty_replay ? (
        <Card className="min-w-0 p-3 shadow-sm">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground" title="Full replayable capture of this session">
            recording
          </h3>
          <div className="flex flex-wrap gap-2"><Button asChild variant="secondary" size="sm"><a href={p.tty_replay} title="watch the session play back in-browser">
            view recording
          </a></Button>
          {/* events.html:27 offered all three; the port kept only the
              viewer, so a session could be watched but never taken out of
              the dashboard. The shasum is the last segment of the replay
              route — pivots.shasum is deliberately blank for a
              cowrie.log.closed event, because that hash identifies the
              recording, not a captured payload. */}
          {recordingShasum(p.tty_replay) ? (
            <>
              <Button asChild variant="ghost" size="sm"><a
                href={`/api/recording/${encodeURIComponent(recordingShasum(p.tty_replay))}/cast`}
                title="download as an asciinema-compatible .cast file"
              >
                .cast
              </a></Button>
              <Button asChild variant="ghost" size="sm"><a
                href={`/api/recording/${encodeURIComponent(recordingShasum(p.tty_replay))}/raw`}
                title="download the raw cowrie TTY log"
              >
                raw
              </a></Button>
            </>
          ) : null}
          </div>
        </Card>
      ) : null}
      {/* #1898: the actions menu was here as well as on the row, so every
          action existed twice and the two could drift. The row strip is the
          one place actions live now -- it rests visible, its extras open on
          approach, and the external tools are a group inside it rather than
          a disclosure that costs a click to look into. */}
    </div>
  )
}

/** #1965: memoized so a live prepend re-renders exactly one new row
 *  instead of reconciling all 500. That only pays off if prop references
 *  hold steady across renders — hence module-scope rowKey, the stable
 *  onToggle callback, and passing selectedKey down for the row to derive
 *  its own selection instead of receiving a fresh closure per render.
 *  Keys are non-positional (#1962/#1965), so a prepend no longer remounts
 *  the table either. */
const FragmentRow = memo(function FragmentRow({
  row,
  breakLabel,
  selectedKey,
  onToggle,
  onPivot,
  investigationConfig,
}: {
  row: EventRow
  breakLabel: string | null
  /** Derived here from the module-scope rowKey rather than passed as a
   *  ready-made boolean: a boolean would have to be recomputed per row
   *  through a fresh closure, which defeats memo()'s shallow compare. */
  selectedKey: string | null
  onToggle: (key: string) => void
  onPivot: (key: keyof EventFilters | 'ip', value: string) => void
  /** #1868: the external tool links are derived per row from the deployment's
   *  configured tool URLs, so the row needs the config to offer them. */
  investigationConfig: InvestigationConfig
}) {
  const openIn = investigationLinks(row, investigationConfig)
  const key = rowKey(row)
  const selected = selectedKey === key
  // Cell pivots must not also toggle the record pane.
  const pivot = (event: React.MouseEvent, key: keyof EventFilters | 'ip', value: string) => {
    event.stopPropagation()
    onPivot(key, value)
  }
  return (
    <>
      {breakLabel ? (
        <TableRow className="bg-muted/40 hover:bg-muted/40" aria-hidden="true"><TableCell className="py-1 text-xs text-muted-foreground" colSpan={6}>— {breakLabel} —</TableCell></TableRow>
      ) : null}
      <TableRow data-state={selected ? 'selected' : undefined} className="cursor-pointer" onClick={() => onToggle(key)}>
        <TableCell data-hp-time data-label="time">{formatTimestamp(row.time)}</TableCell>
        <TableCell data-label="sensor">
          {/* Per-sensor badge coloring (theme.css's b-{sensor} classes) +
              sensor pivot, events.html:11. */}
          <a
            className={badgeVariants({ variant: 'secondary' })}
            href={`/events?sensor=${encodeURIComponent(row.sensor)}`}
            onClick={(event) => {
              event.preventDefault()
              pivot(event, 'sensor', row.sensor)
            }}
          >
            {row.sensor}
          </a>
        </TableCell>
        <TableCell data-label="source ip">
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
            <Badge variant="secondary"
              title="This event reached the sensor over the WireGuard tunnel and could not be joined back to a real client address. The tunnel peer is our own VPS, so it is deliberately not shown as the source."
            >
              unattributed
            </Badge>
          )}
          {/* #1876: two joins resolved this event to different addresses.
              The one shown is the connection-derived answer; this is what
              the request *claimed*, kept because on the portbridge path a
              disagreement is an attacker setting their own
              X-Forwarded-For, and hiding it would hide the attempt. */}
          {row.src_ip_claimed ? (
            <>
              {' '}
              <Badge
                title={`This request also claimed to come from ${row.src_ip_claimed}, which disagrees with the address portbridge recorded for the connection. The connection is the stronger evidence, so it is the one shown; the claim is likely forged.`}
              >
                claims {row.src_ip_claimed}
              </Badge>
            </>
          ) : null}
          {row.country ? (
            <>
              {' '}
              <a
                className={badgeVariants({ variant: 'outline' })}
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
        </TableCell>
        <TableCell className="text-right tabular-nums" data-label="port">
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
        </TableCell>
        <TableCell data-label="detail">
          {row.pivots.ics_severity ? (
            <>
              <Badge
                variant={icsSeverityVariant(row.pivots.ics_severity)}
                title="DNP3 control-function severity: this app_function code changes equipment or device state"
              >
                {row.pivots.ics_severity}
              </Badge>{' '}
            </>
          ) : null}
          {row.pivots.payload_class ? (
            <>
              <Badge
                variant="outline"
                title="What this request carried, as opposed to what it asked for — the path is in the category column"
              >
                {row.pivots.payload_class}
              </Badge>{' '}
            </>
          ) : null}
          {row.detail || row.proto}
        </TableCell>
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
        <TableCell data-label="">
          <RowActions
            actions={[
              // First is what rests on screen, so it is the one an operator
              // reaches for most: everything behind this event.
              row.id ? { label: 'Open full details', icon: RowIcons.detail, href: `/event/${encodeURIComponent(row.id)}` } : null,
              row.src_ip ? { label: 'Copy source IP', icon: RowIcons.copy, onClick: () => copyWithFlash(row.src_ip) } : null,
              row.session ? { label: 'Replay session', icon: RowIcons.replay, href: `/sessions/${encodeURIComponent(row.session)}` } : null,
              row.src_ip ? { label: 'Attacker profile', icon: RowIcons.profile, href: `/investigate/ip/${encodeURIComponent(row.src_ip)}` } : null,
              row.pivots.shasum
                ? { label: 'Payload analysis', icon: RowIcons.payload, href: `/payload-analysis/${encodeURIComponent(row.pivots.shasum)}` }
                : null,
            ]}
            groups={[
              // The external tools are a category, not four unrelated
              // actions, and they were previously behind a ⋮ menu that
              // duplicated the strip. One icon says they exist; they appear
              // beside it on approach.
              {
                label: 'Open in',
                icon: RowIcons.openIn,
                actions: [
                  openIn.evebox ? { label: 'Open in EveBox', icon: RowIcons.evebox, href: openIn.evebox, external: true } : null,
                  openIn.kibana ? { label: 'Open in Kibana', icon: RowIcons.kibana, href: openIn.kibana, external: true } : null,
                  openIn.arkime ? { label: 'Open in Arkime', icon: RowIcons.arkime, href: openIn.arkime, external: true } : null,
                  // Was reachable only from the ⋮ menu. It is an external
                  // destination like the others, so it belongs here rather
                  // than being lost with the menu.
                  row.pivots.shasum
                    ? {
                        label: 'Look up on VirusTotal',
                        icon: RowIcons.payload,
                        href: `https://www.virustotal.com/gui/file/${encodeURIComponent(row.pivots.shasum)}`,
                        external: true,
                      }
                    : null,
                ],
              },
            ]}
          />
        </TableCell>
      </TableRow>
    </>
  )
})
