// Correlated campaigns — compact core columns; ports/sensors detail in the
// click-open inspector (investigate-consistency rules). Column set and the
// score-explanation note mirror dashboard/ui/intel.html's campaigns-body.
import { createFileRoute, Link } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { useCallback, useEffect, useState } from 'react'
import { InvestigateHeader, MasterDetailTable, type Column } from '../components/Investigate'
import { ErrorStateBlock } from '../components/ErrorState'
import { formatTimestamp } from '../lib/time'

type CampaignRow = {
  cidr: string
  score: number
  events: number
  unique_ips: number
  sensors: string[]
  ports: string[]
  creds: number
  payloads: number
  alerts: number
  providers: string[]
  fingerprints: number
  explanation: string
  first: string
  last: string
  // asns/sequence are optional on purpose: correlator-worker's campaigns-v1
  // docs don't carry them (dashboard/campaigns.go's
  // readCampaignsFromWorkerIndex documents the same presentation-only gap
  // for the Go tier), so both columns render empty until the worker does.
  asns?: string[]
  sequence?: string[] | string
  generated?: string
  // #2047 scan shape. Note the field names differ from attackers-v1's
  // dest_ips/ports_touched -- correlator.rs writes campaigns-v1 with
  // dst_ips_touched/ports_touched_counted instead, and "" (empty string,
  // not absent) here when neither threshold applies.
  scan?: string
  dst_ips_touched?: number
  ports_touched_counted?: number
}

const fetchCampaigns = createServerFn({ method: 'GET' }).handler(async () => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<{ total: number; rows: CampaignRow[] }>('/api/v1/campaigns?size=100')
})

// GET /api/v1/cred-reuse — fleet-wide credential-pair reuse across distinct
// source IPs (correlations.rs's CredEdge). Fleet-wide rather than scoped to
// one campaign or entity, so this lives on the campaigns view rather than
// an individual entity page, where it would lose every cross-entity edge.
type CredEdge = {
  user: string
  pass: string
  unique_ips: number
  ips: string[]
  sensors: string[]
  events: number
  first: string
  last: string
}

const fetchCredReuse = createServerFn({ method: 'GET' }).handler(async () => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<CredEdge[]>('/api/v1/cred-reuse')
})

export const Route = createFileRoute('/campaigns')({
  loader: async () => ({ page: fetchCampaigns(), credReuse: fetchCredReuse() }),
  component: Campaigns,
})

function CredReuseCard({ edges }: { edges: CredEdge[] | null }) {
  // Silence, not an empty-state complaint, when nothing has been reused
  // yet or the fetch is still in flight — this mirrors the flow_link
  // absence convention on the event page.
  if (!edges || edges.length === 0) return null
  return (
    <div className="card wide">
      <h2>Reused credentials</h2>
      <p className="note">
        Username/password pairs tried by 2 or more distinct source IPs — the shared-wordlist signal that survives
        across campaigns, not just within one.
      </p>
      <table className="data-table">
        <thead>
          <tr>
            <th>credential</th>
            <th>ips</th>
            <th>sensors</th>
            <th>events</th>
            <th>last</th>
          </tr>
        </thead>
        <tbody>
          {edges.slice(0, 25).map((edge) => (
            <tr key={`${edge.user}:${edge.pass}`}>
              <td className="v">
                <code>
                  {edge.user}:{edge.pass}
                </code>
              </td>
              <td className="n">{edge.unique_ips.toLocaleString('en-US')}</td>
              <td className="v">{edge.sensors.join(' ')}</td>
              <td className="n">{edge.events.toLocaleString('en-US')}</td>
              <td>{formatTimestamp(edge.last)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// Every glance cell deep-links into the campaign's correlation drill-down,
// matching intel.html's campaignrows where each cell is an anchor.
function drill(row: CampaignRow, title: string, children: React.ReactNode) {
  return (
    <Link to="/investigate/cidr/$cidr" params={{ cidr: row.cidr }} title={title}>
      {children}
    </Link>
  )
}

const COLUMNS: Column<CampaignRow>[] = [
  { header: 'score', className: 'n', render: (row) => drill(row, 'investigate this campaign', row.score) },
  { header: 'network', className: 'v', render: (row) => drill(row, 'investigate this campaign', row.cidr) },
  { header: 'events', className: 'n', render: (row) => drill(row, 'show campaign events', row.events.toLocaleString('en-US')) },
  { header: 'ips', className: 'n', render: (row) => drill(row, 'show campaign source addresses', row.unique_ips.toLocaleString('en-US')) },
  // #2047 scan-shape badge, beside events/ips where the other volume
  // columns already live. "" (the common case) renders nothing.
  {
    header: 'scan',
    className: 'v',
    render: (row) => (row.scan ? <span className="badge badge--warning">{row.scan}</span> : null),
  },
  {
    header: 'sensors',
    className: 'v',
    render: (row) =>
      drill(
        row,
        'show campaign sensor activity',
        row.sensors.slice(0, 5).join(' ') + (row.sensors.length > 5 ? ` +${row.sensors.length - 5}` : ''),
      ),
  },
  { header: 'last', render: (row) => formatTimestamp(row.last) },
  { header: 'why correlated', detail: true, render: (row) => row.explanation },
  { header: 'all sensors', detail: true, render: (row) => row.sensors.join(' ') },
  { header: 'ports', detail: true, render: (row) => row.ports.join(' ') },
  {
    header: 'scan shape',
    detail: true,
    render: (row) =>
      row.scan
        ? `${row.scan} (${row.dst_ips_touched ?? 0} hosts, ${row.ports_touched_counted ?? 0} ports)`
        : '',
  },
  { header: 'creds', detail: true, render: (row) => row.creds },
  { header: 'files', detail: true, render: (row) => row.payloads },
  { header: 'alerts', detail: true, render: (row) => row.alerts },
  { header: 'ASNs', detail: true, render: (row) => (row.asns ?? []).join(' ') },
  { header: 'fingerprints', detail: true, render: (row) => row.fingerprints },
  { header: 'provider', detail: true, render: (row) => row.providers.join(' ') },
  {
    header: 'sequence',
    detail: true,
    render: (row) => (Array.isArray(row.sequence) ? row.sequence.join(' ← ') : (row.sequence ?? '')),
  },
  { header: 'first', detail: true, render: (row) => formatTimestamp(row.first) },
  {
    header: '',
    render: (row) => (
      <Link
        className="lnk"
        to="/investigate/cidr/$cidr"
        params={{ cidr: row.cidr }}
        title="#354: everything Elasticsearch has correlated for this network across honeypot, Suricata, and portbridge tunnel records"
      >
        ES &rarr;
      </Link>
    ),
  },
]

function Campaigns() {
  const streamed = Route.useLoaderData().page
  const streamedCredReuse = Route.useLoaderData().credReuse
  // #2178: the streamed loader resolves null on any backend failure -- which
  // used to be indistinguishable from "still streaming", so the table sat in
  // opening ghosts forever. A failed stream now surfaces the error block,
  // separate from loading and from a genuinely empty correlation window.
  const [page, setPage] = useState(streamed)
  useEffect(() => setPage(streamed), [streamed])
  const [rows, setRows] = useState<CampaignRow[] | null>(null)
  const [failed, setFailed] = useState(false)
  const retry = useCallback(() => setPage(fetchCampaigns()), [])
  useEffect(() => {
    let cancelled = false
    setRows(null)
    setFailed(false)
    page.then((result) => {
      if (cancelled) return
      if (result) setRows(result.rows)
      else setFailed(true)
    })
    return () => {
      cancelled = true
    }
  }, [page])
  // A failed cred-reuse fetch degrades to "nothing shown" rather than a
  // second error block on this page — the campaigns table above is the
  // page's main content and already has its own failure/retry handling.
  const [credEdges, setCredEdges] = useState<CredEdge[] | null>(null)
  useEffect(() => {
    let cancelled = false
    streamedCredReuse.then((result) => {
      if (!cancelled && result) setCredEdges(result)
    })
    return () => {
      cancelled = true
    }
  }, [streamedCredReuse])
  const generated = rows?.find((row) => row.generated)?.generated
  return (
    <>
      <InvestigateHeader
        label="Correlation"
        title="Correlated campaigns"
        subtitle="Related source networks grouped across sensors over a rolling 7-day window."
        chips={
          <>
            <span className="chip">{rows ? `${rows.length} active networks` : failed ? 'load failed' : '…'}</span>
            <a className="chip" title="Download every correlated campaign as CSV" href="/api/export/campaigns.csv">
              ⇩ CSV
            </a>
            {generated ? <span className="chip">generated {formatTimestamp(generated)}</span> : null}
          </>
        }
      />
      <p className="note">
        Score combines volume, unique sources, sensor and port spread, reused credentials, captured payloads, and IDS
        alerts. Select a network for its complete event chain.
      </p>
      {failed ? (
        <ErrorStateBlock
          title="Correlated campaigns failed to load"
          hint="The backend request failed — nothing here is cached."
          onRetry={retry}
        />
      ) : (
        <MasterDetailTable
          rows={rows}
          columns={COLUMNS}
          rowKey={(row) => row.cidr}
          detailHref={(row) => `/investigate/cidr/${encodeURIComponent(row.cidr)}`}
          emptyState={{
            title: 'No active campaigns in the selected correlation window',
            hint: 'Widen the window, or wait for more traffic to correlate into one.',
          }}
        />
      )}
      <CredReuseCard edges={credEdges} />
    </>
  )
}
