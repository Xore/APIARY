// Attacker identities — attackers-v1 store (the identity worker's durable
// entities), shared master-detail kit. The row inspector carries the full
// Overview/Indicators dossier ui/attackers.html renders for a selected
// entity (#1540's two-tab split), so every persisted field stays visible
// even when empty and hydration can't make evidence appear to vanish.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { EChart } from '../components/EChart'
import { AttackerGraph } from '../components/AttackerGraph'
import { Tabs, TabPanel } from '../components/Tabs'
import { usePaginatedList } from '../lib/hooks'
import { formatTimestamp } from '../lib/time'

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
}

type Page = { total: number; rows: AttackerRow[] }

const fetchAttackers = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }) => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<Page>(`/api/v1/attackers?offset=${data.offset}&size=25`)
  })

export const Route = createFileRoute('/attackers')({
  loader: async () => ({ first: fetchAttackers({ data: { offset: 0 } }) }),
  component: Attackers,
})

const COLUMNS: Column<AttackerRow>[] = [
  { header: 'entity', className: 'v', render: (row) => row.id.slice(0, 8) },
  { header: 'ips', className: 'n', render: (row) => row.ips.length.toLocaleString('en-US') },
  { header: 'events', className: 'n', render: (row) => row.events.toLocaleString('en-US') },
  {
    header: 'sensors',
    className: 'v',
    render: (row) => (
      <>
        {row.sensors.map((sensor) => (
          <span key={sensor} className="badge badge--muted">
            {sensor}
          </span>
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
    render: (row) => (row.verdicts?.length ? <span className="badge badge--accent">verdict</span> : null),
  },
]

// One bounded evidence list of the dossier (attackers.html's card__scroll
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
    <>
      <h2>
        {title} ({items.length})
      </h2>
      {items.length ? (
        <div className="card__scroll">
          {items.map((item, index) => (
            <div className="card__row" key={index}>
              {render(item)}
            </div>
          ))}
        </div>
      ) : (
        <p className="empty">{empty}</p>
      )}
    </>
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
    <>
      <Tabs
        tabs={[
          { id: 'overview', label: 'Overview' },
          { id: 'indicators', label: 'Indicators' },
        ]}
        active={tab}
        onSelect={setTab}
        label="Attacker entity views"
        idPrefix="attacker-dossier"
      />
      <TabPanel id="overview" active={tab} idPrefix="attacker-dossier" className="dashboard-panel">
        <h2>Identity</h2>
        <div className="card__row">
          <span className="card__label">entity</span>
          <span className="card__value card__value--mono">{row.id}</span>
        </div>
        <div className="card__row">
          <span className="card__label">events</span>
          <span className="card__value card__value--mono">{row.events.toLocaleString('en-US')}</span>
        </div>
        <div className="card__row">
          <span className="card__label">updated</span>
          <span className="card__value">{row.updated ? formatTimestamp(row.updated) : 'not recorded'}</span>
        </div>
        <div className="card__row">
          <span className="card__label">first seen</span>
          <span className="card__value">{row.first ? formatTimestamp(row.first) : 'not recorded'}</span>
        </div>
        <div className="card__row">
          <span className="card__label">last seen</span>
          <span className="card__value">{row.last ? formatTimestamp(row.last) : 'not recorded'}</span>
        </div>
        {recordingsURL ? (
          <div className="card__footer">
            <a className="lnk" href={recordingsURL} title="TTY session recordings from this entity's member IPs, if any">
              session recordings →
            </a>
          </div>
        ) : null}
        <EvidenceList
          title="Sensors"
          items={row.sensors}
          empty="No sensors recorded for this identity."
          render={(sensor) => <span className="badge badge--muted">{sensor}</span>}
        />
        <EvidenceList
          title="Member IPs"
          items={row.ips}
          empty="No member IPs recorded for this identity."
          render={(ip) => (
            <a className="card__value card__value--mono" href={`/investigate/ip/${encodeURIComponent(ip)}`}>
              {ip}
            </a>
          )}
        />
        <h2>Entity {row.id.slice(0, 8)} — member IPs</h2>
        <AttackerGraph id={row.id} />
        <h2>Fingerprint fusion — why this entity merged</h2>
        {/* Fusion radar (#1280): which signal categories 2+ member IPs
            actually share — the visual evidence for the merge decision. */}
        <p className="note">
          Signal values shared by 2 or more of this entity's member IPs, by category. A value only one member IP exhibits is real
          telemetry but not evidence for this specific merge.
        </p>
        <EChart kind="radar" url={`/api/chart/attacker-fusion?id=${encodeURIComponent(row.id)}`} height={280} />
      </TabPanel>
      <TabPanel id="indicators" active={tab} idPrefix="attacker-dossier" className="dashboard-panel">
        <EvidenceList
          title="Credential pairs"
          items={row.credentials}
          empty="No credential pairs recorded for this identity."
          render={(pair) => <code className="card__value card__value--mono">{pair}</code>}
        />
        <EvidenceList
          title="Fingerprints"
          items={row.fingerprints}
          empty="No fingerprints recorded for this identity."
          render={(fingerprint) => <code className="card__value card__value--mono">{fingerprint}</code>}
        />
        <EvidenceList
          title="Payload hashes"
          items={row.payloads}
          empty="No payload hashes recorded for this identity."
          render={(hash) => (
            <a className="card__value card__value--mono" href={`/payload-analysis/${encodeURIComponent(hash)}`}>
              {hash}
            </a>
          )}
        />
        <EvidenceList
          title="Ghidra verdicts"
          items={verdicts}
          empty="No Ghidra verdicts recorded for this identity."
          render={(verdict) => <span className="badge badge--accent">{verdict}</span>}
        />
        {/* #1260: the worker's own durable technique-coverage field (bare
            IDs) — not the richer per-event attackTechnique the ATT&CK
            coverage grid elsewhere computes. */}
        <EvidenceList
          title="ATT&CK techniques"
          items={techniques}
          empty="No ATT&CK techniques recorded for this identity."
          render={(technique) => (
            <a className="badge badge--info" href={attckTechniqueURL(technique)} target="_blank" rel="noopener noreferrer">
              {technique}
            </a>
          )}
        />
      </TabPanel>
    </>
  )
}

function Attackers() {
  const { first } = Route.useLoaderData()
  const { rows, total, loadingMore, viewMore } = usePaginatedList(first, (offset) => fetchAttackers({ data: { offset } }))
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
            <a className="chip" href="/">
              ← dashboard
            </a>
            <a className="chip" href="/campaigns">
              network campaigns
            </a>
            <a className="chip" href="/clusters">
              infrastructure clusters
            </a>
            <span className="chip">{total.toLocaleString('en-US')} identities</span>
            {merged !== null ? <span className="chip">{merged.toLocaleString('en-US')} merged across &gt;1 IP</span> : null}
          </>
        }
      />
      <MasterDetailTable
        rows={rows}
        columns={COLUMNS}
        rowKey={(row) => row.id}
        total={total}
        onViewMore={viewMore}
        loadingMore={loadingMore}
        inspectorTitle="Identity details"
        inspectorExtra={(row) => <Dossier row={row} />}
      />
    </>
  )
}
