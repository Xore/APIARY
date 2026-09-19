import { Card, CardHeader, CardContent } from '../components/ui/card'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/table'
import { Button } from '../components/ui/button'
import { Badge } from '../components/ui/badge'
import { Field, FieldLabel } from '../components/ui/field'
import { Input } from '../components/ui/input'
// Per-IP investigation — one source address's whole profile: summary
// chips, tabbed Activity/Indicators/Correlation views (ips.html's
// attacker-profile layout, #1682), and the newest events with the record
// inspector.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../components/ui/tabs'
import type { JsonRecord } from '../lib/json'
import { formatTimestamp } from '../lib/time'
import { countryName } from '../lib/country'

type Kv = { key: string; count: number }
type Technique = { id: string; name: string; domain: string; evidence: string; count: number; url: string }

type EventRow = {
  time: string
  sensor: string
  src_ip: string
  country: string
  port: string
  proto: string
  detail: string
  session: string
  record: JsonRecord
}

type Correlation = {
  total: number
  truncated: boolean
  sensors: Kv[]
  tunnel_connections: number
  tunnel_os_guesses: string[]
  records: EventRow[]
}

type IpProfile = {
  ip: string
  total: number
  first: string
  last: string
  country: string
  asn: string
  sensors: Kv[]
  ports: Kv[]
  protos: Kv[]
  credentials: Kv[]
  commands: Kv[]
  sessions: Kv[]
  techniques: Technique[]
  /** #1689: this address was both carried by an analysed sample (floss
   * decoded a reference to it) and reached by a sandbox detonation of that
   * same sample. Advisory context only — the manual block action is
   * deliberately not gated on it. */
  confirmed_malicious: boolean
  payloads: Kv[]
  alerts: Kv[]
  fingerprints: Kv[]
  paths: Kv[]
  events: EventRow[]
  correlation: Correlation
}

type BlockState = { IP: string; Blocked: boolean; Active: boolean; BlockedBy?: string; ExpiresAt?: string }

// #2178: serviceJSON collapsed "the request failed" into the same null the
// route read as "No events from this address" — on the page an operator
// consults before deciding whether to keep or lift a block, an outage
// asserting a whole address's history was empty. Tri-state now; the
// handler never rejects.
type ProfileFetch = { state: 'profile'; profile: IpProfile } | { state: 'missing' } | { state: 'failed' }

const fetchProfile = createServerFn({ method: 'GET' })
  .validator((input: { ip: string }) => input)
  .handler(async ({ data }): Promise<ProfileFetch> => {
    const { serviceJSONResult } = await import('../lib/backend.server')
    const result = await serviceJSONResult<IpProfile>(`/api/v1/investigate/ip/${encodeURIComponent(data.ip)}`)
    if (result.ok) return { state: 'profile', profile: result.body }
    return result.status === 404 ? { state: 'missing' } : { state: 'failed' }
  })

const fetchBlockState = createServerFn({ method: 'GET' })
  .validator((input: { ip: string }) => input)
  .handler(async ({ data }): Promise<BlockState | null> => {
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch(`/api/v1/ip-block/${encodeURIComponent(data.ip)}`)
    return response.ok ? ((await response.json()) as BlockState) : null
  })

const setBlock = createServerFn({ method: 'POST' })
  .validator((input: { ip: string; blocked: boolean; expires_days?: number }) => input)
  .handler(async ({ data }): Promise<boolean> => {
    const { getSessionUser } = await import('../lib/auth')
    const user = await getSessionUser()
    // Admin-gated at the BFF, same posture as the legacy action (#914).
    if (!user || user.role !== 'admin') return false
    const { serviceFetch } = await import('../lib/backend.server')
    const response = await serviceFetch('/api/v1/ip-block', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...data, actor: user?.username ?? '' }),
    })
    return response.ok
  })

function BlockControl({ ip }: { ip: string }) {
  const [state, setState] = useState<BlockState | null>(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    let cancelled = false
    fetchBlockState({ data: { ip } }).then((result) => {
      if (!cancelled) setState(result)
    })
    return () => {
      cancelled = true
    }
  }, [ip])
  const apply = async (blocked: boolean, expiresDays?: number) => {
    setBusy(true)
    try {
      const ok = await setBlock({ data: { ip, blocked, ...(expiresDays ? { expires_days: expiresDays } : {}) } })
      if (ok) {
        const fresh = await fetchBlockState({ data: { ip } })
        if (fresh) setState(fresh)
      }
    } finally {
      setBusy(false)
    }
  }
  if (state === null) return null
  // ips.html:101-102. The port collapsed both states into one `chip
  // is-active` toggle — a class theme.css has no rule for, so blocking an
  // address looked identical to any other inert chip, and the expiry input
  // was dropped outright. That second part was not cosmetic: the whole
  // pipeline behind it survived the port (the server fn validator accepts
  // expires_days and spreads it straight through to ip_block.rs), so with
  // no control to set it every block placed through this UI was permanent.
  if (state.Active) {
    return (
      <span className="hp-row">
        <Badge variant="destructive">
          blocked{state.BlockedBy ? ` by ${state.BlockedBy}` : ''}
          {state.ExpiresAt ? `, expires ${formatTimestamp(state.ExpiresAt)}` : ''}
        </Badge>
        <Button
          variant="secondary"
          size="sm"
          type="button"
          disabled={busy}
          title="Remove this IP from the manual blackhole list."
          onClick={() => void apply(false)}
        >
          {busy ? '…' : 'unblock'}
        </Button>
      </span>
    )
  }
  return (
    <form
      className="flex flex-wrap items-end gap-2"
      onSubmit={(event) => {
        event.preventDefault()
        const raw = new FormData(event.currentTarget).get('expires_days')
        const days = Number(raw)
        void apply(true, Number.isFinite(days) && days > 0 ? days : undefined)
      }}
    >
      <Field className="w-auto min-w-28 gap-1"><FieldLabel htmlFor="attacker-block-expires">expire after</FieldLabel>
      <Input
        type="number"
        id="attacker-block-expires"
        name="expires_days"
        min="1"
        placeholder="never"
        className="w-28"
      />
      </Field>
      <span>day(s)</span>
      <Button
        variant="destructive"
        size="sm"
        type="submit"
        disabled={busy}
        title="Drop this IP's connections at portbridge going forward; does not retroactively affect anything already logged"
      >
        {busy ? '…' : 'block'}
      </Button>
    </form>
  )
}

export const Route = createFileRoute('/investigate/ip/$ip')({
  loader: async ({ params }) => ({ first: fetchProfile({ data: { ip: params.ip } }) }),
  component: InvestigateIp,
})

const EVENT_COLUMNS: Column<EventRow>[] = [
  { header: 'time', render: (row) => formatTimestamp(row.time) },
  { header: 'sensor', render: (row) => <Badge variant="secondary">{row.sensor}</Badge> },
  { header: 'port', className: 'n', render: (row) => (row.port ? `:${row.port}` : '') },
  { header: 'detail', className: 'v', render: (row) => row.detail || row.proto },
  {
    header: 'record',
    detail: true,
    render: (row) => <pre className="hp-md__preview">{JSON.stringify(row.record, null, 2)}</pre>,
  },
]

function MiniTable({ title, rows, linkTo }: { title: string; rows: Kv[]; linkTo?: (key: string) => string }) {
  if (rows.length === 0) return null
  return (
    <Card className="min-w-0 shadow-none">
      <CardHeader className="p-4 pb-2"><h2>{title}</h2></CardHeader>
      <CardContent className="min-w-0 p-4 pt-0">
        <Table>
          <TableBody>
            {rows.map((row) => (
              <TableRow key={row.key}>
                <TableCell className="n">{row.count.toLocaleString('en-US')}</TableCell>
                <TableCell className="v">{linkTo ? <a href={linkTo(row.key)}>{row.key}</a> : row.key}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

function TechniquesTable({ techniques }: { techniques: Technique[] }) {
  if (techniques.length === 0) return null
  return (
    <Card className="min-w-0 shadow-none">
      <CardHeader className="p-4 pb-2">
        <h2>MITRE ATT&amp;CK behavior mapping</h2>
        <p className="note">Evidence-based behavioral context only; this does not identify or attribute an actor.</p>
      </CardHeader>
      <CardContent className="min-w-0 p-4 pt-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>domain</TableHead>
              <TableHead>technique</TableHead>
              <TableHead>observations</TableHead>
              <TableHead>evidence</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {techniques.map((technique) => (
              <TableRow key={technique.id}>
                <TableCell>
                  <Badge variant="secondary">{technique.domain}</Badge>
                </TableCell>
                <TableCell className="v">
                  <a href={technique.url} target="_blank" rel="noopener noreferrer">
                    {technique.id} — {technique.name}
                  </a>
                </TableCell>
                <TableCell className="n">{technique.count.toLocaleString('en-US')}</TableCell>
                <TableCell className="v">{technique.evidence}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

const CORRELATION_COLUMNS: Column<EventRow>[] = [
  { header: 'time', render: (row) => formatTimestamp(row.time) },
  { header: 'sensor', render: (row) => <Badge variant="secondary">{row.sensor}</Badge> },
  { header: 'summary', className: 'v', render: (row) => row.detail || row.proto },
]

function CorrelationPanel({ correlation }: { correlation: Correlation }) {
  return (
    <>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-4">
        <Card>
          <CardContent className="p-4">
            <div className="text-sm text-muted-foreground">Total ES matches</div>
            <div className="text-2xl font-semibold">{correlation.total.toLocaleString('en-US')}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-sm text-muted-foreground">Tunnel connections</div>
            <div className="text-2xl font-semibold">{correlation.tunnel_connections.toLocaleString('en-US')}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-sm text-muted-foreground">Distinct sensors</div>
            <div className="text-2xl font-semibold">{correlation.sensors.length}</div>
          </CardContent>
        </Card>
      </div>
      <Card>
        <h2>Elasticsearch correlation</h2>
        <p className="note">
          Everything the backend has seen for this IP across honeypot, Suricata, and portbridge tunnel records — not
          limited to the in-memory window above.
          {correlation.truncated
            ? ` Showing the ${correlation.records.length.toLocaleString('en-US')} most recent of ${correlation.total.toLocaleString('en-US')} total matches.`
            : ''}
        </p>
        {correlation.tunnel_os_guesses.length > 0 ? (
          <p>
            <strong>p0f OS guesses seen over this tunnel:</strong> {correlation.tunnel_os_guesses.join(', ')}
          </p>
        ) : null}
        {correlation.records.length > 0 ? (
          <CardContent>
            <Table className="recent">
              <TableHeader>
                <TableRow>
                  <TableHead>time</TableHead>
                  <TableHead>sensor</TableHead>
                  <TableHead>summary</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {correlation.records.map((record, index) => (
                  <TableRow key={`${record.time}-${index}`}>
                    <TableCell>{formatTimestamp(record.time)}</TableCell>
                    <TableCell>{record.sensor}</TableCell>
                    <TableCell className="v">{record.detail || record.proto}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        ) : (
          <p className="empty">No Elasticsearch correlation records were found for this IP.</p>
        )}
      </Card>
      <Card>
        <h2>Attack progression</h2>
        <p className="note">Chronological, oldest to newest; capped to the latest 250 matching records.</p>
        <MasterDetailTable
          rows={[...correlation.records].reverse()}
          columns={CORRELATION_COLUMNS}
          rowKey={(row, index) => `progression-${row.time}-${index}`}
          emptyState={{
            title: 'No Elasticsearch correlation records were found for this IP',
            hint: 'This address has been seen, but nothing correlatable has been indexed for it yet.',
          }}
          inspectorTitle="Event record"
        />
      </Card>
    </>
  )
}

function InvestigateIp() {
  const { first } = Route.useLoaderData()
  const { ip } = Route.useParams()
  // #2178: `result ?? 'missing'` rendered a failed profile fetch as "No
  // events from this address in the current window." — a confident
  // negative about everything this IP ever did. Tri-state now: null while
  // loading, 'missing' only for a settled not-found, 'failed' named.
  const [fetch, setFetch] = useState<ProfileFetch | null>(null)
  const [attempt, setAttempt] = useState(0)
  const [tab, setTab] = useState('activity')
  useEffect(() => {
    let cancelled = false
    setFetch(null)
    ;(attempt === 0 ? first : fetchProfile({ data: { ip } })).then((result) => {
      if (!cancelled) setFetch(result)
    })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- caller-owned loader stream
  }, [first, attempt])

  if (fetch?.state === 'failed') {
    return (
      <>
        <InvestigateHeader label="Investigate" title={ip} subtitle="The profile could not be loaded." />
        <ErrorStateBlock
          title="This attacker profile failed to load"
          hint="The backend request failed — this says nothing about whether the address has history. Do not treat it as an empty profile."
          onRetry={() => setAttempt((n) => n + 1)}
        />
      </>
    )
  }

  if (fetch?.state === 'missing') {
    return (
      <InvestigateHeader label="Investigate" title={ip} subtitle="No events from this address in the current window." />
    )
  }

  const profile = fetch?.state === 'profile' ? fetch.profile : null

  return (
    <>
      <InvestigateHeader
        label="Investigate"
        title={ip}
        subtitle="Everything this source address did across every sensor — behavior, credentials, sessions and raw events."
        chips={
          profile ? (
            <>
              <span className="chip">{profile.total.toLocaleString('en-US')} events</span>
              {/* #1689: only rendered when true. An absent badge means "no
                  such corroboration", not "benign" — most addresses here are
                  hostile and simply never appeared in an analysed sample. */}
              {profile.confirmed_malicious ? (
                <Badge
                  variant="destructive"
                  title="A sandbox detonation of a sample that references this address actually connected to it — two independent pipelines agree. Informational: the block action is not gated on this."
                >
                  confirmed malicious (sandbox)
                </Badge>
              ) : null}
              {profile.country ? <Badge variant="secondary" title={countryName(profile.country)}>{profile.country}</Badge> : null}
              {profile.asn ? <span className="chip">{profile.asn}</span> : null}
              <span className="chip">
                {formatTimestamp(profile.first)} → {formatTimestamp(profile.last)}
              </span>
              <Link className="chip" to="/events" search={{ ip }}>
                all matching events →
              </Link>
              <Link className="chip" to="/recordings" search={{ ip }} title="TTY session recordings from this IP, if any">
                session recordings
              </Link>
              <a className="chip" href={`/api/export/events.csv?ip=${encodeURIComponent(ip)}`}>
                export CSV ↓
              </a>
              <BlockControl ip={ip} />
            </>
          ) : undefined
        }
      />
      {profile ? (
        <>
          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="activity">Activity</TabsTrigger>
              <TabsTrigger value="indicators">Indicators</TabsTrigger>
              <TabsTrigger value="correlation">Correlation & timeline</TabsTrigger>
            </TabsList>
            <TabsContent value="activity">
              <Card>
                <CardContent className="p-6">
                  <div className="grid min-w-0 gap-4 md:grid-cols-2">
                    <MiniTable title="Sensors contacted" rows={profile.sensors} />
                    <MiniTable title="Credentials attempted" rows={profile.credentials} />
                    <MiniTable title="Commands" rows={profile.commands} />
                    <MiniTable title="HTTP paths" rows={profile.paths} />
                    <MiniTable title="Targeted ports" rows={profile.ports} />
                    <MiniTable title="Protocols" rows={profile.protos} />
                    <MiniTable title="Sessions" rows={profile.sessions} linkTo={(key) => `/sessions/${encodeURIComponent(key)}`} />
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
            <TabsContent value="indicators">
              <Card>
                <CardContent className="p-6">
                  <div className="grid min-w-0 gap-4 md:grid-cols-2">
                    <MiniTable title="Payload hashes" rows={profile.payloads} linkTo={(key) => `/payload-analysis/${encodeURIComponent(key)}`} />
                    <MiniTable title="Alerts" rows={profile.alerts} />
                    <MiniTable title="Fingerprints" rows={profile.fingerprints} />
                  </div>
                  <TechniquesTable techniques={profile.techniques} />
                </CardContent>
              </Card>
            </TabsContent>
            <TabsContent value="correlation">
              <Card>
                <CardContent className="p-6">
                  <CorrelationPanel correlation={profile.correlation} />
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </>
      ) : (
        <MasterDetailTable rows={null} columns={EVENT_COLUMNS} rowKey={(row, index) => `${row.time}-${index}`} inspectorTitle="Event record" />
      )}
    </>
  )
}
