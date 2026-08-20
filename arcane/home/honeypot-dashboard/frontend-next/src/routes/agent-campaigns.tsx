// Agent campaigns — agent-intrusion-worker's correlated AI-agent activity.
import { createFileRoute } from '@tanstack/react-router'
import { createServerFn } from '@tanstack/react-start'
import { StoreListPage, when, type StorePage } from '../components/StoreList'
import type { Column } from '../components/Investigate'

// Matches build_campaign_verdict's document shape
// (honeypot-agent-intrusion-worker/analysis/agent-intrusion-corpus/worker.py)
// exactly — this store has one real shape, unlike the generic StoreRow
// pages that proxy several heterogeneous sources.
type AgentCampaignRow = {
  '@timestamp': string
  campaign_id: string
  start: string
  end: string
  severity: string
  matched_categories: string[]
  correlation_identifiers: string[]
  event_count: number
}

const fetchPage = createServerFn({ method: 'GET' })
  .inputValidator((input: { offset: number }) => input)
  .handler(async ({ data }): Promise<StorePage<AgentCampaignRow> | null> => {
    const { serviceJSON } = await import('../lib/backend.server')
    return serviceJSON<StorePage<AgentCampaignRow>>(`/api/v1/store/agent-campaigns?offset=${data.offset}&size=25`)
  })

const COLUMNS: Column<AgentCampaignRow>[] = [
  { header: 'detected', render: (row) => when(row['@timestamp']) },
  {
    header: 'severity',
    render: (row) => <span className={row.severity === 'high' ? 'badge badge--danger' : 'badge badge--warning'}>{row.severity}</span>,
  },
  { header: 'campaign', className: 'v', render: (row) => row.campaign_id },
  { header: 'categories', className: 'v', render: (row) => row.matched_categories.join(' ') },
  { header: 'events', className: 'n', render: (row) => row.event_count.toLocaleString('en-US') },
  { header: 'window', detail: true, render: (row) => `${when(row.start)} → ${when(row.end)}` },
  { header: 'identifiers', detail: true, render: (row) => row.correlation_identifiers.join(', ') },
]

export const Route = createFileRoute('/agent-campaigns')({ component: Page })

function Page() {
  return (
    <StoreListPage
      fetchPage={fetchPage}
      label="Monitor"
      title="Agent campaigns"
      subtitle="Correlated AI-agent intrusion activity — encoded egress, tool-use fingerprints, and cross-sensor automation patterns."
      columns={COLUMNS}
      rowKey={(row, index) => `${row.campaign_id}-${index}`}
      inspectorTitle="Campaign details"
      chipNoun="campaigns"
    />
  )
}
