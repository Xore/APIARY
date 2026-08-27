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
}

const fetchCampaigns = createServerFn({ method: 'GET' }).handler(async () => {
  const { serviceJSON } = await import('../lib/backend.server')
  return serviceJSON<{ total: number; rows: CampaignRow[] }>('/api/v1/campaigns?size=100')
})

export const Route = createFileRoute('/campaigns')({
  loader: async () => ({ page: fetchCampaigns() }),
  component: Campaigns,
})

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
    </>
  )
}
