// Attacker identities — attackers-v1 store (the identity worker's durable
// entities), shared master-detail kit. The row inspector carries the full
// Overview/Indicators dossier ui/attackers.html renders for a selected
// entity (#1540's two-tab split), so every persisted field stays visible
// even when empty and hydration can't make evidence appear to vanish.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { EChart } from '../components/EChart'
import { AttackerGraph } from '../components/AttackerGraph'
import { ErrorStateBlock } from '../components/ErrorState'
import { Badge } from '../components/ui/badge'
import { Button } from '../components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { usePaginatedList } from '../lib/hooks'
import { formatTimestamp } from '../lib/time'
import { copyWithFlash } from '../lib/flash'

type AttackerRow = {
  id: string
  ips: string[]
  fingerprints: string[]
  payloads: string[]
  credentials: string[]
  sensors: string[]
  events: number
  first: string
  last: string
  updated: string
  // Absent (not empty) when the entity has none — attacker_identity.rs's
  // Entity skips serializing empty verdicts/techniques, same as Go.
  verdicts?: string[]
  techniques?: string[]
  // #2047 scan shape over this entity's evidence window: >=25 distinct
  // destinations is "horizontal", >=25 ports across <=5 hosts is
  // "vertical". Absent (not empty string) when neither threshold applies —
  // attacker_identity.rs skip_serializing_if's it, same absent-not-empty
  // convention as verdicts/techniques above.
  scan?: 'horizontal' | 'vertical'
  dest_ips?: number
  ports_touched?: number
}

type Page = { total: number; rows: AttackerRow[] }

const fetchAttackers = createServerFn({ method: 'GET' })
  .validator((input: { offset: number }) => input)
  .handler(async ({ data }) => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/attackers?offset=${data.offset}&size=25`)
  })

export const Route = createFileRoute('/attackers')({
  loader: async () => ({ first: fetchAttackers({ data: { offset: 0 } }) }),
  component: Attackers,
})

const COLUMNS: Column<AttackerRow>[] = [
  {
    header: 'entity',
    className: 'v',
    render: (row) => (
      <span className="hp-token-url">
        <code title={row.id}>{row.id.slice(0, 8)}</code>
        <Button
          type="button"
          variant="ghost" size="sm"
          title="copy full entity id"
          onClick={(event) => {
            event.stopPropagation()
            copyWithFlash(row.id, 'entity id')
          }}
        >
          copy
        </Button>
      </span>
    ),
  },
  { header: 'ips', className: 'n', render: (row) => row.ips.length.toLocaleString('en-US') },
  { header: 'events', className: 'n', render: (row) => row.events.toLocaleString('en-US') },
  {
    header: 'sensors',
    className: 'v',
    render: (row) => (
      <>
        {row.sensors.map((sensor) => (
          <Badge key={sensor} variant="secondary">
            {sensor}
          </Badge>
        ))}
      </>
    ),
  },
  { header: 'first', className: 'v', render: (row) => formatTimestamp(row.first) },
  { header: 'last', className: 'v', render: (row) => formatTimestamp(row.last) },
  // attackers.html:98's per-row Ghidra marker — a bare "verdict" badge so
  // sandbox-analyzed entities stand out in the list.
  {
    header: 'verdict',
    render: (row) => (row.verdicts?.length ? <Badge>verdict</Badge> : null),
  },
  // #2047 scan-shape badge, same row as the verdict chip above — absent
  // (not a badge reading "none") when the entity's window never crossed
  // either threshold.
  {
    header: 'scan',
    render: (row) => (row.scan ? <Badge variant="secondary">{row.scan}</Badge> : null),
  },
]

// One bounded evidence list of the dossier (attackers.html's scrolling card
// regions): every recorded value rendered, or the field's own "no X
// recorded" line so an empty field reads as evidence of absence.
function EvidenceList<T>({
  title,
  items,
  empty,
  render,
}: {
  title: string
  items: T[]
  empty: string
  render: (item: T) => React.ReactNode
}) {
  return (
    <Card className="min-w-0"><CardHeader><CardTitle><h2>{title} ({items.length})</h2></CardTitle></CardHeader><CardContent>
      {items.length ? (
        <div className="max-h-64 overflow-auto divide-y">
          {items.map((item, index) => (
            <div className="min-w-0 break-all py-2 text-sm" key={index}>
              {render(item)}
            </div>
          ))}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">{empty}</p>
      )}
    </CardContent></Card>
  )
}

// attckTechniqueURL (intelligence.go:42) — the canonical MITRE page for a
// bare technique ID, sub-technique dots becoming path segments.
function attckTechniqueURL(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replaceAll('.', '/')}/`
}

function Dossier({ row }: { row: AttackerRow }) {
  const [tab, setTab] = useState('overview')
  // recordingsURLForIPs (recordings.go:57) — /recordings scoped to every
  // member IP via the shared ?ips= filter.
  const recordingsURL = row.ips.length
    ? `/recordings?${row.ips.map((ip) => `ips=${encodeURIComponent(ip)}`).join('&')}`
    : null
  const verdicts = row.verdicts ?? []
  const techniques = row.techniques ?? []
  return (
    <Tabs value={tab} onValueChange={setTab} className="min-w-0 space-y-4">
      <TabsList aria-label="Attacker entity views">
        <TabsTrigger value="overview" id="attacker-dossier-tab-overview" aria-controls="attacker-dossier-panel-overview">Overview</TabsTrigger>
        <TabsTrigger value="indicators" id="attacker-dossier-tab-indicators" aria-controls="attacker-dossier-panel-indicators">Indicators</TabsTrigger>
      </TabsList>
      <TabsContent value="overview" id="attacker-dossier-panel-overview" aria-labelledby="attacker-dossier-tab-overview" className="space-y-4">
        <Card><CardHeader><CardTitle><h2>Identity</h2></CardTitle></CardHeader><CardContent>
        <div className="flex flex-wrap justify-between gap-2 border-b py-2 text-sm">
          <span className="text-muted-foreground">entity</span>
          <span className="break-all font-mono">{row.id}</span>
        </div>
        <div className="flex flex-wrap justify-between gap-2 border-b py-2 text-sm">
          <span className="text-muted-foreground">events</span>
          <span className="font-mono">{row.events.toLocaleString('en-US')}</span>
        </div>
        <div className="flex flex-wrap justify-between gap-2 border-b py-2 text-sm">
          <span className="text-muted-foreground">updated</span>
          <span>{row.updated ? formatTimestamp(row.updated) : 'not recorded'}</span>
        </div>
        <div className="flex flex-wrap justify-between gap-2 border-b py-2 text-sm">
          <span className="text-muted-foreground">first seen</span>
          <span>{row.first ? formatTimestamp(row.first) : 'not recorded'}</span>
        </div>
        <div className="flex flex-wrap justify-between gap-2 border-b py-2 text-sm">
          <span className="text-muted-foreground">last seen</span>
          <span>{row.last ? formatTimestamp(row.last) : 'not recorded'}</span>
        </div>
        {row.scan ? (
          <div className="flex flex-wrap justify-between gap-2 border-b py-2 text-sm">
            <span className="text-muted-foreground">scan shape</span>
            <span>
              <Badge variant="secondary">{row.scan}</Badge>{' '}
              {row.scan === 'horizontal'
                ? `${row.dest_ips ?? 0} distinct destinations`
                : `${row.ports_touched ?? 0} distinct ports across ${row.dest_ips ?? 0} hosts`}
            </span>
          </div>
        ) : null}
        {recordingsURL ? (
          <div className="pt-4">
            <a className="text-sm text-primary hover:underline" href={recordingsURL} title="TTY session recordings from this entity's member IPs, if any">
              session recordings →
            </a>
          </div>
        ) : null}
        </CardContent></Card>
        <EvidenceList
          title="Sensors"
          items={row.sensors}
          empty="No sensors recorded for this identity."
          render={(sensor) => <Badge variant="secondary">{sensor}</Badge>}
        />
        <EvidenceList
          title="Member IPs"
          items={row.ips}
          empty="No member IPs recorded for this identity."
          render={(ip) => (
            <a className="font-mono text-primary hover:underline" href={`/investigate/ip/${encodeURIComponent(ip)}`}>
              {ip}
            </a>
          )}
        />
        <Card><CardHeader><CardTitle><h2>Entity {row.id.slice(0, 8)} — member IPs</h2></CardTitle></CardHeader><CardContent><AttackerGraph id={row.id} /></CardContent></Card>
        <Card><CardHeader><CardTitle><h2>Fingerprint fusion — why this entity merged</h2></CardTitle>
        {/* Fusion radar (#1280): which signal categories 2+ member IPs
            actually share — the visual evidence for the merge decision. */}
        <p className="note">
          Signal values shared by 2 or more of this entity's member IPs, by category. A value only one member IP exhibits is real
          telemetry but not evidence for this specific merge.
        </p></CardHeader><CardContent><EChart kind="radar" url={`/api/chart/attacker-fusion?id=${encodeURIComponent(row.id)}`} height={280} /></CardContent></Card>
      </TabsContent>
      <TabsContent value="indicators" id="attacker-dossier-panel-indicators" aria-labelledby="attacker-dossier-tab-indicators" className="space-y-4">
        <EvidenceList
          title="Credential pairs"
          items={row.credentials}
          empty="No credential pairs recorded for this identity."
          render={(pair) => <code className="font-mono">{pair}</code>}
        />
        <EvidenceList
          title="Fingerprints"
          items={row.fingerprints}
          empty="No fingerprints recorded for this identity."
          render={(fingerprint) => <code className="font-mono">{fingerprint}</code>}
        />
        <EvidenceList
          title="Payload hashes"
          items={row.payloads}
          empty="No payload hashes recorded for this identity."
          render={(hash) => (
            <a className="font-mono text-primary hover:underline" href={`/payload-analysis/${encodeURIComponent(hash)}`}>
              {hash}
            </a>
          )}
        />
        <EvidenceList
          title="Ghidra verdicts"
          items={verdicts}
          empty="No Ghidra verdicts recorded for this identity."
          render={(verdict) => <Badge>{verdict}</Badge>}
        />
        {/* #1260: the worker's own durable technique-coverage field (bare
            IDs) — not the richer per-event attackTechnique the ATT&CK
            coverage grid elsewhere computes. */}
        <EvidenceList
          title="ATT&CK techniques"
          items={techniques}
          empty="No ATT&CK techniques recorded for this identity."
          render={(technique) => (
            <a className="text-primary hover:underline" href={attckTechniqueURL(technique)} target="_blank" rel="noopener noreferrer">
              {technique}
            </a>
          )}
        />
      </TabsContent>
    </Tabs>
  )
}

function Attackers() {
  const { first } = Route.useLoaderData()
  const { rows, total, loadingMore, viewMore, failed, retry } = usePaginatedList(first, (offset) => fetchAttackers({ data: { offset } }))
  // attackers.html:21's "real merges" count. The Go tier computed it over
  // every attackers-v1 doc (attackers.go's attackersData); here only the
  // loaded pages are in hand, so it grows as the operator pages deeper —
  // sorted by events desc, multi-IP entities cluster at the top.
  const merged = rows === null ? null : rows.filter((row) => row.ips.length > 1).length
  return (
    <>
      <InvestigateHeader
        label="Correlation"
        title="Attacker identities"
        subtitle="Durable entities merged across IP churn by shared fingerprint, payload, and credential signals."
        chips={
          <>
            <Link className="text-sm text-primary hover:underline" to="/">
              ← dashboard
            </Link>
            <Link className="text-sm text-primary hover:underline" to="/campaigns">
              network campaigns
            </Link>
            <Link className="text-sm text-primary hover:underline" to="/clusters">
              infrastructure clusters
            </Link>
            <Badge variant="secondary">{failed ? 'load failed' : `${total.toLocaleString('en-US')} identities`}</Badge>
            {merged !== null ? <Badge variant="secondary">{merged.toLocaleString('en-US')} merged across &gt;1 IP</Badge> : null}
          </>
        }
      />
      {failed ? (
        <ErrorStateBlock
          title="Attacker identities failed to load"
          hint="The backend request failed — nothing here is cached."
          onRetry={retry}
        />
      ) : (
        <MasterDetailTable
          rows={rows}
          columns={COLUMNS}
          rowKey={(row) => row.id}
          emptyState={{
            title: 'No attacker entities yet',
            hint: 'attacker-identity-worker merges IPs sharing 2+ strong signals — fingerprint, payload hash, credential pair — into durable entities as traffic accumulates.',
          }}
          total={total}
          onViewMore={viewMore}
          loadingMore={loadingMore}
          inspectorTitle="Identity details"
          inspectorExtra={(row) => <Dossier row={row} />}
        />
      )}
    </>
  )
}
